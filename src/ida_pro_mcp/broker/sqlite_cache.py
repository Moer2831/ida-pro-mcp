"""IDA 静态信息 SQLite 持久化缓存

设计目标（与历史实现的关键差异见各函数 docstring）：

- 在 IDA 插件进程中运行后台守护线程，空闲时分块提取 IDB 静态信息
  (strings / string_xrefs / functions / function_xrefs / globals / imports)
  并写入与 IDB 同目录的 `<idb>.mcp.sqlite`。
- **峰值内存 O(块)**：不再把整库物化成 Python 对象，而是按游标切片，
  每块经一次 `execute_sync` 派发到 IDA 主线程，块间让出消息循环，
  GUI 不会长时间卡死。
- **表级增量**：先做一遍"只哈希不建对象"的指纹 pass，指纹未变的表直接
  跳过写库（`IDA_MCP_CACHE_INCREMENTAL=0` 可关闭）。
- **原子切换**：新数据写入影子表，最后一次事务内 DROP/RENAME/建索引，
  读者要么看到旧快照要么看到新快照，不存在"空表窗口"。
- **失败安全**：任何一层失败只丢弃影子表；超过行数/RSS 上限则放弃该表
  本轮刷新，旧快照保持可读，并把原因写进 meta 供 `cache_status` 观测。

配置项见 `cache_config.load_cache_config()`。
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .cache_config import (
    ALL_TABLES,
    MIN_CHUNK_ROWS,
    CacheConfig,
    AdaptiveChunker,
    load_cache_config,
)
from .cache_extract import Fingerprint, build_extractors
from .cache_rss import exceeds_rss_limit
from .cache_writer import (
    META_IDB_MTIME,
    STATUS_DEGRADED,
    STATUS_ERROR,
    STATUS_PARTIAL,
    STATUS_READY,
    CacheWriter,
    TableProgress,
)

# ============================================================================
# 路径解析
# ============================================================================


def resolve_cache_path(idb_path: str) -> Optional[str]:
    """根据 IDB 路径计算缓存数据库路径 (`xxx.i64` -> `xxx.i64.mcp.sqlite`)。"""
    if not idb_path:
        return None
    return idb_path + ".mcp.sqlite"


# ============================================================================
# 统计
# ============================================================================


@dataclass
class CacheStats:
    """一轮构建的结果统计。"""

    strings: int = 0
    string_xrefs: int = 0
    functions: int = 0
    function_xrefs: int = 0
    globals_: int = 0
    imports: int = 0
    elapsed_ms: float = 0.0
    peak_rss_mb: float = 0.0
    chunks: int = 0
    slow_dispatches: int = 0
    tables_skipped: tuple[str, ...] = ()
    tables_aborted: tuple[str, ...] = ()
    tables_cleared: tuple[str, ...] = ()
    partial: bool = False
    reason: str = ""
    status: str = STATUS_READY

    def as_dict(self) -> dict[str, Any]:
        return {
            "strings": self.strings,
            "string_xrefs": self.string_xrefs,
            "functions": self.functions,
            "function_xrefs": self.function_xrefs,
            "globals": self.globals_,
            "imports": self.imports,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "peak_rss_mb": round(self.peak_rss_mb, 1),
            "chunks": self.chunks,
            "slow_dispatches": self.slow_dispatches,
            "tables_skipped": list(self.tables_skipped),
            "tables_aborted": list(self.tables_aborted),
            "tables_cleared": list(self.tables_cleared),
            "partial": self.partial,
            "reason": self.reason,
            "status": self.status,
        }


# ============================================================================
# 构建核心（可注入依赖，便于无 IDA 单测）
# ============================================================================


def _tables_unchanged(
    writer: CacheWriter, group: str, tables: list[str], digest: str
) -> bool:
    """指纹一致 + 所有目标表存在且有行数记录 → 可整组跳过。"""
    if not digest:
        return False
    if writer.stored_fingerprint(group) != digest:
        return False
    for table in tables:
        if not writer.table_exists(table):
            return False
        if writer.stored_count(table) < 0:
            return False
    return True


def _fingerprint_extractor(
    extractor: Any,
    chunker: AdaptiveChunker,
    *,
    should_stop: Callable[[], bool],
    wait_ready: Optional[Callable[[], bool]] = None,
) -> tuple[Optional[str], int]:
    """只读 pass：分块哈希指定提取器覆盖的数据，返回 (digest, 块数)。

    `wait_ready` 为派发前置条件（IDA 空闲且刚保存过则等静默窗口）；不满足时不派发，
    直接返回 (None, chunks)，由调用方按 `NOT_READY_REASON` 中止本轮。
    """
    from .cache_backend import run_on_ida_main

    fingerprint = Fingerprint()
    cursor = 0
    chunks = 0
    while True:
        if should_stop():
            return (None, chunks)
        if wait_ready is not None and not wait_ready():
            return (None, chunks)
        started = time.perf_counter()
        result = run_on_ida_main(
            lambda: extractor.chunk(
                cursor, chunker.next_size(), collect=False, fingerprint=fingerprint
            )
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        _warn_if_slow_dispatch(extractor.name, elapsed_ms)
        if result is None:
            return (None, chunks)
        chunker.observe(max(1, result.items), elapsed_ms)
        chunks += 1
        cursor = result.cursor
        if result.done:
            break
    return (fingerprint.digest(), chunks)


def _warn_if_slow_dispatch(label: str, elapsed_ms: float) -> bool:
    """单次派发明显偏慢时打日志（下次卡顿时 Output 窗口能直接看出卡在哪一步）。"""
    if elapsed_ms < DISPATCH_WARN_SEC * 1000.0:
        return False
    print(
        f"[MCP][cache] 派发耗时 {elapsed_ms:.0f}ms（>{DISPATCH_WARN_SEC:.0f}s）: {label}"
        " —— IDA 可能正忙（保存/分析/模态对话框），已按空闲门控等待",
        file=sys.stderr,
    )
    return True


def build_cache(
    db_path: str,
    backend: Any,
    config: Optional[CacheConfig] = None,
    *,
    writer_factory: Callable[[str, CacheConfig], CacheWriter] = CacheWriter,
    chunker: Optional[AdaptiveChunker] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    wait_ready: Optional[Callable[[], bool]] = None,
    rss_limit_mb: Optional[int] = None,
    idb_mtime: float = 0.0,
) -> CacheStats:
    """执行一轮缓存构建（守护线程与单测共用同一实现）。

    Args:
        db_path: 目标 SQLite 路径。
        backend: 实现 `cache_extract.CacheBackend` 的后端（IDA 或测试假件）。
        config: 缓存配置，缺省读环境变量。
        writer_factory: 写入器工厂（单测可注入以观察调用序列）。
        chunker: 自适应分块器（缺省按 config 构造）。
        should_stop: 取消回调，返回 True 时优雅收尾（保留旧快照）。
        wait_ready: 派发前置条件（IDA 空闲且不在保存后的静默窗口内）；返回 False 时
            本轮以 `NOT_READY_REASON` 中止并保留旧快照，等下次触发重试。
        rss_limit_mb: 覆盖配置里的 RSS 上限（单测用）。
    """
    cfg = config or load_cache_config()
    stop = should_stop or (lambda: False)
    ready = wait_ready or (lambda: True)
    chunker = chunker or AdaptiveChunker(
        chunk_rows=cfg.chunk_rows,
        target_ms=cfg.target_chunk_ms,
        # 显式配置比 MIN_CHUNK_ROWS 更小时以配置为准，避免自适应把块"放大"回 100 行
        min_rows=max(1, min(cfg.chunk_rows, MIN_CHUNK_ROWS)),
    )
    stats = CacheStats()
    started_at = time.perf_counter()
    skipped: list[str] = []
    aborted: list[str] = []
    cleared: list[str] = []
    reasons: list[str] = []
    status = STATUS_READY
    error = ""
    committed = 0

    writer = writer_factory(db_path, cfg)
    writer.open()
    try:
        extractors = build_extractors(
            backend,
            want_xrefs=cfg.wants_xrefs,
            want_globals=cfg.wants_globals,
            full_fp=cfg.fingerprint_full,
        )
        for extractor in extractors:
            tables = [t for t in extractor.tables if cfg.table_enabled(t)]
            if not tables:
                continue
            if stop():
                reasons.append("stopped")
                stats.partial = True
                break

            digest: Optional[str] = None
            if cfg.incremental:
                digest, fp_chunks = _fingerprint_extractor(
                    extractor, chunker, should_stop=stop, wait_ready=ready
                )
                stats.chunks += fp_chunks
                if not ready():
                    # 指纹 pass 因"不可派发"中止：不要带着半截状态继续建表
                    reasons.append(NOT_READY_REASON)
                    stats.partial = True
                    break
                if digest and _tables_unchanged(writer, extractor.name, tables, digest):
                    for table in tables:
                        writer.skip_table(table, fingerprint=digest)
                    skipped.extend(tables)
                    continue

            for table in tables:
                writer.begin_table(table)
            counts = {table: 0 for table in tables}
            cursor = 0
            limit_hit = ""
            rss_hit = False
            dispatch_failed = False
            not_ready = False

            while True:
                if stop():
                    reasons.append("stopped")
                    stats.partial = True
                    break
                if not ready():
                    # IDA 正忙（保存/分析/模态框）：本轮中止、保留旧快照，等下次触发重试
                    not_ready = True
                    break
                started = time.perf_counter()
                result = _next_chunk(extractor, cursor, chunker)
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                if _warn_if_slow_dispatch(extractor.name, elapsed_ms):
                    stats.slow_dispatches += 1
                if result is None:
                    dispatch_failed = True
                    break
                stats.chunks += 1
                chunker.observe(max(1, result.row_count or result.items), elapsed_ms)

                for table in tables:
                    rows = result.rows_for(table)
                    if rows:
                        writer.write_chunk(table, rows)
                        counts[table] += len(rows)
                        if cfg.max_rows and counts[table] > cfg.max_rows:
                            limit_hit = table
                            break
                if limit_hit:
                    break

                rss = writer.sample_rss()
                limit = cfg.max_rss_mb if rss_limit_mb is None else rss_limit_mb
                if exceeds_rss_limit(limit, rss):
                    rss_hit = True
                    reasons.append(f"rss>{limit}MB (rss={rss:.0f}MB)")
                    status = STATUS_DEGRADED
                    break

                cursor = result.cursor
                if result.done:
                    break

            if limit_hit or rss_hit or dispatch_failed or not_ready:
                if not_ready:
                    detail = "IDA 忙或刚保存过（空闲门控未放行），本轮放弃，稍后重试"
                elif dispatch_failed:
                    detail = "提取派发失败（IDA 主线程不可达）"
                elif limit_hit:
                    detail = f"超过 IDA_MCP_CACHE_MAX_ROWS={cfg.max_rows}（表 {limit_hit}）"
                else:
                    detail = (
                        f"超过 IDA_MCP_CACHE_MAX_RSS_MB（rss={writer.sample_rss():.0f}MB）"
                    )
                for table in tables:
                    writer.abort_table(table, error=detail)
                aborted.extend(tables)
                stats.partial = True
                reasons.append(NOT_READY_REASON if not_ready else detail)
                if rss_hit or dispatch_failed or not_ready:
                    break
                continue

            if stats.partial:
                for table in tables:
                    writer.abort_table(table, error="stopped")
                aborted.extend(tables)
                break

            for table in tables:
                writer.commit_table(table, fingerprint=digest, count=counts[table])
                committed += 1

        # scope 收窄（例如从 full 切到 minimal）时，把本轮范围外的表清空：
        # 否则那些表会继续返回上一轮构建的**过期**数据（尤其 cross-reference）。
        for table in ALL_TABLES:
            if cfg.table_enabled(table):
                continue
            if writer.table_exists(table) and writer.stored_count(table) != 0:
                writer.clear_table(table, reason="scope-excluded")
                cleared.append(table)

        stats.tables_skipped = tuple(skipped)
        stats.tables_aborted = tuple(aborted)
        stats.tables_cleared = tuple(cleared)
        stats.reason = "; ".join(reasons)
        # 没有可用快照时绝不能让 status 变成 ready：否则读侧不再返回 -32001，
        # 却可能查到一张空表。此时降级为 partial（读侧据此继续报"未就绪"）。
        final_status = status
        if not writer.had_snapshot and status != STATUS_ERROR:
            if committed == 0 or stats.partial:
                final_status = STATUS_PARTIAL
        stats.status = final_status
        if idb_mtime:
            writer.set_meta(META_IDB_MTIME, str(float(idb_mtime)))
        writer.finish(
            status=final_status,
            error=error,
            partial=stats.partial,
            degraded_reason=stats.reason,
            skipped=skipped,
        )
    except Exception as exc:  # noqa: BLE001 - 构建失败必须留下可诊断痕迹
        # 已有可用快照时绝不能因为一次刷新失败就把缓存"下线"：保持 ready 继续
        # 服务旧快照，只把失败原因写进 last_error/degraded_reason + partial=1。
        error = str(exc)
        stats.reason = error
        stats.partial = True
        stats.status = STATUS_READY if writer.had_snapshot else STATUS_ERROR
        try:
            writer.finish(
                status=stats.status,
                error=error,
                partial=True,
                degraded_reason=error,
            )
        except Exception:  # noqa: BLE001
            pass
    finally:
        stats.elapsed_ms = (time.perf_counter() - started_at) * 1000.0
        stats.peak_rss_mb = writer.peak_rss_mb
        _fill_counts(writer, stats)
        writer.close()
    return stats


def _next_chunk(extractor: Any, cursor: int, chunker: AdaptiveChunker) -> Any:
    """把一块提取派发到 IDA 主线程（GUI 用 execute_sync，无头直调）。"""
    from .cache_backend import run_on_ida_main

    return run_on_ida_main(
        lambda: extractor.chunk(cursor, chunker.next_size(), collect=True)
    )


def _fill_counts(writer: CacheWriter, stats: CacheStats) -> None:
    """用 meta 里记录的行数回填统计（跳过的表也能报出正确数值）。"""
    stats.strings = max(0, writer.stored_count("strings"))
    stats.string_xrefs = max(0, writer.stored_count("string_xrefs"))
    stats.functions = max(0, writer.stored_count("functions"))
    stats.function_xrefs = max(0, writer.stored_count("function_xrefs"))
    stats.globals_ = max(0, writer.stored_count("globals"))
    stats.imports = max(0, writer.stored_count("imports"))


# ============================================================================
# 后台守护线程
# ============================================================================

REFRESH_INTERVAL_SEC = 30 * 60  # 30 分钟兜底轮询
IDLE_POLL_SEC = 2.0  # 兜底探测（无主线程定时器时）的节奏
IDLE_WATCH_INTERVAL_MS = 500  # 主线程空闲定时器的刷新间隔
IDLE_WATCH_POLL_SEC = 0.25  # 守护线程检查空闲标志的节奏
SAVE_QUIET_SEC = 5.0  # 收到 IDB 保存信号后再等多久才允许派发
DISPATCH_WARN_SEC = 5.0  # 单次派发超过该时长就打日志（用于诊断卡顿）
NOT_READY_REASON = "not-ready"


@dataclass
class IdaIdleState:
    """IDA 主线程空闲状态：**由主线程定时器写、守护线程只读**。

    为什么不直接派发询问：`MFF_READ` 的官方语义是"只在 IDA 空闲时才执行"，用它去问
    "IDA 空闲了吗"会形成循环等待 —— 保存 IDB 期间 IDA 不是 idle，请求排队；而排队中的
    请求又让 IDA 一直不算 idle，最终把 IDA 卡死（实测：保存完成后守护线程仍拿不到结果，
    缓存库再无任何写入）。所以空闲判定必须由主线程自己维护，守护线程只读一个普通变量。
    """

    quiet_sec: float = SAVE_QUIET_SEC
    idle: bool = False
    last_save_ts: float = 0.0
    last_tick_ts: float = 0.0
    ticks: int = 0

    def mark_save(self, now: Optional[float] = None) -> None:
        """记录一次"IDB 正在保存"信号（由 IDB_Hooks.savebase 在主线程调用）。"""
        self.last_save_ts = time.monotonic() if now is None else float(now)
        self.idle = False

    def set_idle(self, idle: bool, now: Optional[float] = None) -> None:
        """主线程定时器写入最新空闲状态。"""
        ts = time.monotonic() if now is None else float(now)
        self.idle = bool(idle)
        self.last_tick_ts = ts
        self.ticks += 1

    def is_ready(self, now: Optional[float] = None) -> bool:
        """当前是否适合派发需要读库的提取请求。"""
        if not self.idle:
            return False
        if self.last_save_ts <= 0:
            return True
        ts = time.monotonic() if now is None else float(now)
        return (ts - self.last_save_ts) >= self.quiet_sec

    def snapshot(self) -> dict[str, Any]:
        return {
            "idle": self.idle,
            "ticks": self.ticks,
            "last_save_ts": round(self.last_save_ts, 3),
            "quiet_sec": self.quiet_sec,
        }


@dataclass
class _DaemonHandle:
    idb_path: str
    db_path: str
    thread: Optional[threading.Thread]
    stop_event: threading.Event
    force_event: threading.Event
    last_stats: Optional[CacheStats] = None
    last_error: Optional[str] = None
    last_idb_mtime: float = 0.0
    idb_hook: Optional[object] = None
    progress: TableProgress = field(default_factory=TableProgress)
    builds: int = 0
    idle_state: IdaIdleState = field(default_factory=IdaIdleState)
    idle_timer_id: int = -1
    idle_backend: Any = None
    slow_dispatches: int = 0
    pauses: int = 0


_daemons: dict[str, _DaemonHandle] = {}
_daemons_lock = threading.Lock()


def _ida_idb_mtime(idb_path: str) -> float:
    try:
        return float(os.path.getmtime(idb_path))
    except OSError:
        return 0.0


def _run_build_once(
    handle: _DaemonHandle,
    backend: Any,
    config: CacheConfig,
) -> CacheStats:
    """执行一轮构建并刷新守护线程状态。"""
    stats = build_cache(
        handle.db_path,
        backend,
        config,
        should_stop=handle.stop_event.is_set,
        wait_ready=handle.idle_state.is_ready,
        idb_mtime=_ida_idb_mtime(handle.idb_path),
    )
    handle.last_stats = stats
    handle.builds += 1
    if NOT_READY_REASON in stats.reason:
        handle.pauses += 1
    handle.slow_dispatches += stats.slow_dispatches
    handle.progress = TableProgress(
        table="",
        phase="idle",
        rows=0,
        total=0,
        elapsed_ms=stats.elapsed_ms,
        peak_rss_mb=stats.peak_rss_mb,
    )
    handle.last_error = None if stats.status != "error" else stats.reason
    handle.last_idb_mtime = _ida_idb_mtime(handle.idb_path)
    print(
        f"[MCP][cache] 构建完成 {handle.db_path}: "
        f"strings={stats.strings} ({stats.string_xrefs} xrefs), "
        f"functions={stats.functions} ({stats.function_xrefs} xrefs), "
        f"globals={stats.globals_}, imports={stats.imports}, "
        f"chunks={stats.chunks}, skipped={list(stats.tables_skipped)}, "
        f"elapsed={stats.elapsed_ms:.0f}ms, peak_rss={stats.peak_rss_mb:.0f}MB, "
        f"status={stats.status}"
        + (f", reason={stats.reason}" if stats.reason else ""),
        file=sys.stderr,
    )
    return stats


def _default_backend_factory() -> Any:
    from .cache_backend import IdaCacheBackend

    return IdaCacheBackend()


# 测试可替换（单测注入假后端即可覆盖整个守护线程主循环，不需要 IDA）
_backend_factory: Callable[[], Any] = _default_backend_factory


def _install_idle_watcher(handle: _DaemonHandle, backend: Any) -> bool:
    """用 IDA **主线程定时器**维护空闲标志（必须在主线程调用本函数）。

    此后守护线程只读 `handle.idle_state`，不再派发任何"是否空闲"的请求 ——
    那正是把 IDA 卡死的循环等待路径（MFF_READ 只在 idle 时执行，而排队的请求又让
    IDA 一直不算 idle）。
    """
    handle.idle_backend = backend

    def _tick() -> int:
        try:
            handle.idle_state.set_idle(bool(backend.is_idle()))
        except Exception:  # noqa: BLE001 - 定时器回调绝不能抛
            pass
        return IDLE_WATCH_INTERVAL_MS

    try:
        import ida_kernwin  # type: ignore

        handle.idle_timer_id = int(
            ida_kernwin.register_timer(IDLE_WATCH_INTERVAL_MS, _tick)
        )
        return True
    except Exception:  # noqa: BLE001 - 无 IDA / 注册失败 → 退化为兜底探测
        handle.idle_timer_id = -1
        return False


def _uninstall_idle_watcher(handle: _DaemonHandle) -> None:
    if handle.idle_timer_id < 0:
        return
    try:
        import ida_kernwin  # type: ignore

        ida_kernwin.unregister_timer(handle.idle_timer_id)
    except Exception:  # noqa: BLE001
        pass
    handle.idle_timer_id = -1


def _probe_idle_once(handle: _DaemonHandle) -> None:
    """兜底探测（仅在主线程定时器不可用时使用）。

    必须 `db_read=False`（MFF_FAST）：只查状态、不查数据库；用 MFF_READ 会要求
    IDA 先 idle，从而形成循环等待。
    """
    backend = handle.idle_backend
    if backend is None:
        handle.idle_state.set_idle(True)  # 无 IDA（单测）视为空闲
        return
    from .cache_backend import run_on_ida_main

    probe = run_on_ida_main(backend.is_idle, db_read=False)
    if probe is None:
        return  # 派发不可达：保持上次状态，由调用方按停止事件退出
    handle.idle_state.set_idle(bool(probe))


def _wait_for_idle(handle: _DaemonHandle) -> bool:
    """等待"可以安全构建"：IDA 空闲，且距上次 IDB 保存信号已过静默窗口。

    本函数**只等待、不派发**（派发才是卡死根因）。stop_event 置位时返回 False。
    """
    has_timer = handle.idle_timer_id >= 0
    while not handle.stop_event.is_set():
        if not has_timer:
            _probe_idle_once(handle)
        if handle.idle_state.is_ready():
            return True
        handle.stop_event.wait(IDLE_WATCH_POLL_SEC)
    return False


def _daemon_loop(handle: _DaemonHandle) -> None:
    """守护线程主循环。

    1. 首次：等"空闲门控"放行后做一轮构建。
    2. 之后：等待 force_event（IDB 保存 / refresh_cache 工具）或 30 分钟兜底；
       IDB mtime 未变化时跳过重建（除非是被 force 唤醒）。
    3. 若某轮因 IDA 正忙（保存/分析中）而门控未放行，立刻重新排队重试，
       而不是干等 30 分钟。
    """
    config = load_cache_config()
    if config.disabled:
        print(
            "[MCP][cache] IDA_MCP_DISABLE_CACHE=1，缓存守护线程未启动。",
            file=sys.stderr,
        )
        return

    backend = handle.idle_backend or _backend_factory()
    handle.idle_backend = backend
    print(
        f"[MCP][cache] 守护线程启动，目标数据库: {handle.db_path} "
        f"(scope={config.scope}, chunk={config.chunk_rows}, "
        f"incremental={int(config.incremental)}, fp={config.fingerprint}, "
        f"idle_timer={'on' if handle.idle_timer_id >= 0 else 'fallback'})",
        file=sys.stderr,
    )

    def _build() -> bool:
        """跑一轮构建；返回是否应立即重试（门控曾未放行）。"""
        try:
            stats = _run_build_once(handle, backend, config)
        except Exception as exc:  # noqa: BLE001
            handle.last_error = str(exc)
            print(f"[MCP][cache] 构建失败: {exc}", file=sys.stderr)
            return False
        return NOT_READY_REASON in stats.reason

    if _wait_for_idle(handle):
        retry = _build()
        if retry:
            handle.force_event.set()

    while not handle.stop_event.is_set():
        triggered = handle.force_event.wait(REFRESH_INTERVAL_SEC)
        if handle.stop_event.is_set():
            break
        handle.force_event.clear()
        if not triggered:
            mtime = _ida_idb_mtime(handle.idb_path)
            if mtime and mtime == handle.last_idb_mtime:
                print(
                    f"[MCP][cache] IDB 未变化，跳过重建: {handle.idb_path}",
                    file=sys.stderr,
                )
                continue
        if not _wait_for_idle(handle):
            break
        if _build():
            # 门控未放行（IDA 忙/刚保存）：短暂等待后重新排队，避免空转到 30 分钟兜底
            handle.stop_event.wait(IDLE_POLL_SEC)
            handle.force_event.set()


def _make_idb_save_hook(handle: _DaemonHandle) -> Any:
    """在 IDA 主线程中创建并注册 IDB_Hooks 子类实例（保存 IDB 即触发刷新）。"""
    import ida_idp  # type: ignore

    class _Hook(ida_idp.IDB_Hooks):
        def savebase(self) -> int:
            # 保存期间 IDA 不是 idle：先标记"刚保存过"，让守护线程等一个静默窗口，
            # 避免在写库过程中派发 MFF_READ 请求（那会循环等待并卡死 IDA）。
            handle.idle_state.mark_save()
            handle.force_event.set()
            return 0

    hook = _Hook()
    hook.hook()
    return hook


def start_cache_daemon(idb_path: str) -> Optional[str]:
    """启动与指定 IDB 关联的 SQLite 缓存后台守护线程。

    返回最终使用的数据库路径。重复调用幂等：同一 `idb_path` 已在运行时
    直接返回既有路径；`IDA_MCP_DISABLE_CACHE=1` 时返回 None 且不建线程。
    """
    config = load_cache_config()
    if config.disabled:
        return None

    db_path = resolve_cache_path(idb_path)
    if not db_path:
        return None

    with _daemons_lock:
        existing = _daemons.get(idb_path)
        if existing and existing.thread is not None and existing.thread.is_alive():
            return existing.db_path

        handle = _DaemonHandle(
            idb_path=idb_path,
            db_path=db_path,
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
        )
        # 空闲状态由主线程定时器维护（本函数在 IDA 主线程调用）：
        # 守护线程只读标志，绝不派发"是否空闲"的请求 —— 那是卡死 IDA 的根因。
        try:
            handle.idle_backend = _backend_factory()
            _install_idle_watcher(handle, handle.idle_backend)
        except Exception as exc:  # noqa: BLE001
            print(f"[MCP][cache] 空闲监视器安装失败（改用兜底探测）: {exc}", file=sys.stderr)
        thread = threading.Thread(
            target=_daemon_loop,
            args=(handle,),
            name=f"mcp-sqlite-cache:{os.path.basename(idb_path)}",
            daemon=True,
        )
        handle.thread = thread
        try:
            handle.idb_hook = _make_idb_save_hook(handle)
        except Exception as exc:  # noqa: BLE001
            print(f"[MCP][cache] IDB_Hooks 注册失败: {exc}", file=sys.stderr)
        _daemons[idb_path] = handle
        thread.start()

    return db_path


def request_refresh(idb_path: str) -> bool:
    """唤醒指定 IDB 对应的守护线程立即进行一次刷新。"""
    with _daemons_lock:
        handle = _daemons.get(idb_path)
    if handle is None:
        return False
    handle.force_event.set()
    return True


def stop_cache_daemon(idb_path: str, *, timeout: float = 5.0) -> None:
    """停止指定守护线程并清理状态。"""
    with _daemons_lock:
        handle = _daemons.pop(idb_path, None)
    if handle is None:
        return
    handle.stop_event.set()
    handle.force_event.set()  # 唤醒等待
    _uninstall_idle_watcher(handle)
    thread = handle.thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=timeout)


def daemon_snapshot(idb_path: str) -> dict[str, Any]:
    """诊断用：返回守护线程当前状态（未启动时 running=False）。"""
    with _daemons_lock:
        handle = _daemons.get(idb_path)
    if handle is None:
        return {"running": False, "idb_path": idb_path}
    return {
        "running": bool(handle.thread and handle.thread.is_alive()),
        "idb_path": handle.idb_path,
        "db_path": handle.db_path,
        "builds": handle.builds,
        "pauses": handle.pauses,
        "slow_dispatches": handle.slow_dispatches,
        "idle_state": handle.idle_state.snapshot(),
        "idle_timer_id": handle.idle_timer_id,
        "last_error": handle.last_error,
        "last_stats": handle.last_stats.as_dict() if handle.last_stats else None,
        "progress": handle.progress.as_meta(),
    }
