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
        _touch_heartbeat()  # 我们自己刚在主线程跑完，别让过期心跳把本轮判死
        chunker.observe(max(1, result.items), elapsed_ms)
        chunks += 1
        cursor = result.cursor
        if result.done:
            break
    return (fingerprint.digest(), chunks)


def _warn_if_slow_dispatch(label: str, elapsed_ms: float) -> bool:
    """单次派发明显偏慢时打日志（下次卡顿时 Output 窗口能直接看出卡在哪一步）。

    注意：慢**不一定**是 IDA 忙 —— 也可能是我们自己给的单块太大（历史缺陷：指纹模式
    不受分块预算约束，整表一次抽完）。所以消息里两种可能都提，并交给分块/门控去处理。
    """
    if elapsed_ms < DISPATCH_WARN_SEC * 1000.0:
        return False
    print(
        f"[MCP][cache] 派发耗时 {elapsed_ms:.0f}ms（>{DISPATCH_WARN_SEC:.0f}s）: {label}"
        " —— 单块偏大或 IDA 正忙；已按分块自适应与空闲门控继续",
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
    expected_bytes: int = 0,
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
        expected_bytes: 预估本轮需要的字节数（用于磁盘预检；0 表示只按现有库大小估）。
    """
    cfg = config or load_cache_config()
    stop = should_stop or (lambda: False)
    ready = wait_ready or (lambda: True)
    disk_problem = _disk_preflight(
        db_path, expected_bytes=expected_bytes, factor=cfg.disk_headroom_factor
    )
    if disk_problem:
        # 磁盘不够就**拒绝构建**（而不是写一半把盘写满）：保留旧快照，报明确原因，
        # 且不参与"立刻重试"逻辑（重试同样会失败，只会白烧 IO）。
        print(f"[MCP][cache] 拒绝构建：{disk_problem}", file=sys.stderr)
        refused = CacheStats()
        refused.status = STATUS_ERROR
        refused.reason = DISK_RISK_REASON
        refused.elapsed_ms = 0.0
        return refused
    chunker = chunker or AdaptiveChunker(
        # 首块从较小值起步：实测大库（13.5 万函数）上用配置值 20000 起步，单次派发要
        # 6.4 秒，界面会明显卡一下；从 2000 起步约 0.6 秒，之后自适应再放大。
        chunk_rows=min(cfg.chunk_rows, INITIAL_CHUNK_ROWS),
        target_ms=cfg.target_chunk_ms,
        # 显式配置比 MIN_CHUNK_ROWS 更小时以配置为准，避免自适应把块"放大"回 100 行
        min_rows=max(1, min(cfg.chunk_rows, MIN_CHUNK_ROWS)),
        # 配置值同时是**硬上限**：否则自适应可能在快机器上把单块放大到远超配置，
        # 又变回"一次派发占住主线程好几秒"。
        max_rows=max(1, cfg.chunk_rows),
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
                _touch_heartbeat()  # 同上：派发成功 = 主线程在跑我们的回调
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
NOT_READY_BACKOFF_MAX_SEC = 30.0  # 连续因门控放弃时的最大退避
INITIAL_CHUNK_ROWS = 2_000  # 每轮/每个 pass 的**首块**行数上限（自适应会随后放大）
MIN_FREE_DISK_BYTES = 256 * 1024 * 1024  # 磁盘预检下限（首次构建没有历史大小时用）
CACHE_TO_IDB_RATIO = 0.35  # 缓存库大小 ≈ IDB × 该值（实测 1.46GB IDB → 419MB 缓存）
DISK_RISK_REASON = "disk-space"
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
    # 显式刷新请求（refresh_cache 工具）：不受"保存合并窗口"限制
    force_now: bool = False
    # 上一轮成功构建时的 IDB 廉价签名与配置签名（用于跳过"什么都没变"的重建）
    last_build_sig: str = ""
    last_build_config: str = ""
    last_build_sig_valid: bool = False
    last_build_monotonic: float = 0.0


_daemons: dict[str, _DaemonHandle] = {}
_daemons_lock = threading.Lock()

# 主线程心跳（`refresh_idle_states` 每次被插件定时器调用时更新）。
# 派发前要求它足够新鲜：主线程被长任务占住 = 采样不可信 = 不许派发。
HEARTBEAT_STALE_SEC = 2.0
_last_heartbeat: float = 0.0


def _ida_idb_mtime(idb_path: str) -> float:
    try:
        return float(os.path.getmtime(idb_path))
    except OSError:
        return 0.0


def _idb_sig(idb_path: str) -> str:
    """IDB 文件的廉价签名（大小 + mtime 秒）。

    用于跳过"IDB 根本没变"的重建：大库上指纹 pass 是 O(条目数) 的主线程工作量，
    没必要在什么都没变时白跑一遍。
    """
    try:
        st = os.stat(idb_path)
        return f"{st.st_size}:{int(st.st_mtime)}"
    except OSError:
        return ""


def _config_sig(config: CacheConfig) -> str:
    """构建配置签名：配置变了就必须重建（否则指纹会拿旧配置的库当"没变"）。"""
    return (
        f"{config.scope}|{config.chunk_rows}|{config.incremental}|"
        f"{config.fingerprint}|{config.max_rows}|{','.join(config.tables())}"
    )


def _idb_unchanged(handle: _DaemonHandle, config: CacheConfig) -> bool:
    """IDB 与配置都与上一轮**成功**构建一致 → 本轮可以整轮跳过。"""
    if not handle.last_build_sig_valid or not handle.last_build_sig:
        return False
    if handle.last_build_config != _config_sig(config):
        return False
    return _idb_sig(handle.idb_path) == handle.last_build_sig


def _coalesce_wait(handle: _DaemonHandle, min_interval: float) -> float:
    """保存触发时还需等多久才允许重建（把连续保存合并成一轮）。"""
    if min_interval <= 0 or handle.last_build_monotonic <= 0:
        return 0.0
    return max(0.0, handle.last_build_monotonic + min_interval - time.monotonic())


def _cache_db_size(db_path: str) -> int:
    """缓存库当前大小（含 -wal/-shm；不存在按 0）。"""
    total = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.path.getsize(db_path + suffix)
        except OSError:
            continue
    return total


def _expected_cache_bytes(handle: _DaemonHandle) -> int:
    """预估本轮缓存库需要多大（磁盘预检用）。

    有现成缓存库时以它为准（重建后大小基本相当）；首次构建没有历史大小时，用 IDB
    大小 × 经验比例估算（实测 1.46GB IDB 产出 419MB 缓存 ≈ 0.29，这里取 0.35 留余量）。
    """
    current = _cache_db_size(handle.db_path)
    if current > 0:
        return current
    try:
        return int(os.path.getsize(handle.idb_path) * CACHE_TO_IDB_RATIO)
    except OSError:
        return 0


def _disk_preflight(db_path: str, *, expected_bytes: int, factor: float) -> str:
    """构建前的磁盘空间预检：返回非空字符串表示**空间不足，应拒绝构建**。

    为什么需要：缓存库大约是 IDB 的 0.3 倍（实测 1.46GB IDB → 419MB 缓存），而换表时
    新旧表会同时存在（峰值约 2× 最大表）。10GB 级 IDB 上缓存可达数 GB，写爆磁盘会变成
    生产事故 —— 后果比"缓存旧一点"严重得多。宁可拒绝并给出明确提示。
    """
    import shutil

    try:
        free = shutil.disk_usage(os.path.dirname(os.path.abspath(db_path)) or ".").free
    except OSError:
        return ""  # 探测不了就别挡路（例如网络盘/权限受限）
    need = int(max(_cache_db_size(db_path), max(0, expected_bytes)) * max(0.0, factor))
    if need < MIN_FREE_DISK_BYTES:
        need = MIN_FREE_DISK_BYTES
    if free >= need:
        return ""
    return (
        f"可用空间不足：需要约 {need / 1e9:.2f}GB（含换表峰值，倍率 {factor:.1f}），"
        f"实际可用 {free / 1e9:.2f}GB。可清理磁盘，或调小 "
        f"IDA_MCP_DISK_HEADROOM_FACTOR / 用 IDA_MCP_CACHE_SCOPE=minimal 减少数据量。"
    )


def _run_build_once(
    handle: _DaemonHandle,
    backend: Any,
    config: CacheConfig,
) -> CacheStats:
    """执行一轮构建并刷新守护线程状态。"""
    sig_at_start = _idb_sig(handle.idb_path)
    stats = build_cache(
        handle.db_path,
        backend,
        config,
        should_stop=handle.stop_event.is_set,
        wait_ready=lambda: _gate_ready(handle),
        idb_mtime=_ida_idb_mtime(handle.idb_path),
        # 首次构建时缓存库还不存在，用 IDB 大小按经验比例预估（磁盘预检需要）
        expected_bytes=_expected_cache_bytes(handle),
    )
    handle.last_stats = stats
    handle.builds += 1
    if NOT_READY_REASON in stats.reason:
        handle.pauses += 1
    handle.slow_dispatches += stats.slow_dispatches
    handle.last_build_monotonic = time.monotonic()
    # 只有"完整成功"的一轮才允许下次整轮跳过；用**构建开始时**的签名（构建期间若发生
    # 保存，签名就对不上，下一轮自然会重跑，不会漏更新）。
    handle.last_build_sig = sig_at_start
    handle.last_build_config = _config_sig(config)
    handle.last_build_sig_valid = (
        stats.status == "ready"
        and not stats.partial
        and NOT_READY_REASON not in stats.reason
    )
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


def refresh_idle_states() -> int:
    """刷新所有守护线程的"IDA 是否空闲"标志（**必须在 IDA 主线程调用**）。

    由插件在 `init()` 里注册的定时器周期调用。**不要在守护线程启动路径里注册定时器** ——
    实测：在定时器回调（或 IDB 钩子）里调用 `ida_kernwin.register_timer()` 会把 IDA 主线程
    锁死（表现为启动即无响应、CPU 零增长）。所以空闲状态由"启动时注册好的那一个定时器"
    统一刷新，而不是每个守护线程自己注册。

    本函数同时打一次"主线程心跳"：定时器能跑 = 主线程没被长任务占住。派发前会校验
    心跳新鲜度（见 `_gate_ready`）—— 这是保存卡死的第二道闸：主线程卡在 `save_database()`
    里时定时器不会触发，空闲标志会停在上一次的 True，若此时派发 `MFF_READ`，请求会排进
    IDA 的队列，而长任务内部的 `qwait` 又在等队列排空 → 循环等待、IDA 全线程 Wait。

    返回**成功刷新**的守护线程数量（探测抛异常的不计入，但也不影响其它实例）。
    """
    global _last_heartbeat
    _last_heartbeat = time.monotonic()
    with _daemons_lock:
        handles = [h for h in _daemons.values() if h.idle_backend is not None]
    refreshed = 0
    for handle in handles:
        try:
            handle.idle_state.set_idle(bool(handle.idle_backend.is_idle()))
        except Exception:  # noqa: BLE001 - 单个实例失败不影响其它
            continue
        refreshed += 1
    return refreshed


def _touch_heartbeat() -> None:
    """记录"主线程刚刚执行完我们的一次派发"。

    为什么必须这么做：一次派发偏慢时（大库/块偏大），主线程在整个派发期间跑不了插件
    定时器，心跳会过期；若派发一结束就用过期心跳判定"IDA 忙"，本轮会被整轮放弃并立刻
    重试 —— 实测在 13.5 万函数的 GameAssembly 库上形成"每次抽一大块 + 立即放弃"的
    死循环（约 13 秒一轮），IDA 界面因此长期无响应。

    派发成功本身就证明主线程活着并在执行我们的回调，所以刷新心跳是正确的；
    真正"IDA 忙/在保存"仍由 savebase 钩子兜住（mark_save → idle=False + 静默窗口）。
    """
    global _last_heartbeat
    _last_heartbeat = time.monotonic()


def _heartbeat_age() -> float:
    """距上一次主线程心跳的秒数（从未心跳过返回 inf）。"""
    if _last_heartbeat <= 0.0:
        return float("inf")
    return max(0.0, time.monotonic() - _last_heartbeat)


def _gate_ready(handle: _DaemonHandle) -> bool:
    """派发前的最终门控：空闲 + 静默窗口 + **主线程心跳新鲜**。

    为什么需要心跳：空闲标志是"上一次采样"的结果。主线程正卡在长任务里
    （保存 IDB、自动分析、模态对话框）时采样会停止，标志停留在过期的 True；
    守护线程据此派发 `MFF_READ` 就会把请求排进队列，与长任务形成循环等待
    （实测：写操作密集后保存 IDB，IDA 全线程 Wait、CPU 冻结、界面无响应）。

    没有插件定时器时（无 IDA 的纯 Python 环境 / 单测 / 无头 idalib）**从未有过心跳**，
    此时退化为纯门控，不受心跳约束；一旦有心跳（插件定时器跑过），就必须保持新鲜。
    """
    if not handle.idle_state.is_ready():
        return False
    if handle.idle_state.ticks == 0 or _last_heartbeat <= 0.0:
        return True
    return _heartbeat_age() <= HEARTBEAT_STALE_SEC


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

    本函数**只等待、不派发**（派发才是卡死根因）。空闲状态由插件在 `init()` 里注册的
    定时器通过 `refresh_idle_states()` 刷新（`idle_state.ticks` 会递增）；只有在没有任何
    外部刷新时（无 IDA 的纯 Python 环境 / 单测）才退化为 `MFF_FAST` 兜底探测。
    stop_event 置位时返回 False。
    """
    while not handle.stop_event.is_set():
        if handle.idle_timer_id < 0 and handle.idle_state.ticks == 0:
            _probe_idle_once(handle)
        if handle.idle_state.is_ready():
            return True
        handle.stop_event.wait(IDLE_WATCH_POLL_SEC)
    return False


def _not_ready_backoff_delay(streak: int) -> float:
    """连续第 `streak` 轮被门控放弃时的退避时长（指数增长、封顶）。"""
    if streak <= 0:
        return IDLE_POLL_SEC
    return min(NOT_READY_BACKOFF_MAX_SEC, IDLE_POLL_SEC * (2 ** min(streak - 1, 5)))


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
        f"idle_gate=plugin-timer)",
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

    not_ready_streak = 0

    while not handle.stop_event.is_set():
        triggered = handle.force_event.wait(REFRESH_INTERVAL_SEC)
        if handle.stop_event.is_set():
            break
        handle.force_event.clear()
        forced = handle.force_now
        handle.force_now = False

        if not triggered and not forced:
            # 30 分钟兜底：IDB 没有任何变化就别跑（尤其别白跑 O(条目数) 的指纹 pass）
            if _idb_unchanged(handle, config):
                print(
                    f"[MCP][cache] IDB 未变化，跳过重建: {handle.idb_path}",
                    file=sys.stderr,
                )
                continue

        if not forced:
            # 保存触发的重建做**合并**：大库上每按一次 Ctrl+S 就跑一遍指纹 pass
            # （百万级条目要几十秒到几分钟主线程工作量）是不可接受的。
            remaining = _coalesce_wait(handle, config.rebuild_min_interval_sec)
            if remaining > 0:
                print(
                    f"[MCP][cache] 合并保存触发：等 {remaining:.1f}s 后再重建",
                    file=sys.stderr,
                )
                if handle.stop_event.wait(remaining):
                    break
                if handle.force_now:
                    handle.force_now = False
                elif _idb_unchanged(handle, config):
                    print(
                        "[MCP][cache] 合并窗口内 IDB 无净变化，跳过重建",
                        file=sys.stderr,
                    )
                    continue

        if not _wait_for_idle(handle):
            break
        if _build():
            # 门控未放行（IDA 忙/刚保存）：等待后重新排队，避免空转到 30 分钟兜底。
            # 连续失败必须**指数退避**：否则一旦每轮都在同一个位置被门控拦下
            # （历史缺陷：指纹整表一次抽完 → 单块 12s → 心跳过期 → 放弃 → 立刻重试），
            # 就变成"每十几秒占用主线程一次"的死循环，IDA 长期无响应。
            not_ready_streak += 1
            delay = _not_ready_backoff_delay(not_ready_streak)
            if not_ready_streak >= 3:
                print(
                    f"[MCP][cache] 连续 {not_ready_streak} 轮因门控未放行而放弃，"
                    f"退避 {delay:.1f}s 后重试",
                    file=sys.stderr,
                )
            handle.stop_event.wait(delay)
            handle.force_event.set()
        else:
            not_ready_streak = 0


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
        # 空闲状态由插件在 init() 里注册的定时器统一刷新（见 refresh_idle_states）。
        # **这里绝不能注册定时器**：本函数可能从定时器回调/IDB 钩子里被调用，
        # 在那些上下文里 register_timer 会锁死 IDA 主线程（实测）。
        try:
            handle.idle_backend = _backend_factory()
        except Exception as exc:  # noqa: BLE001
            print(f"[MCP][cache] 后端创建失败（改用兜底探测）: {exc}", file=sys.stderr)
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
    """唤醒指定 IDB 对应的守护线程立即进行一次刷新。

    标记 `force_now`：显式请求**不受**保存合并窗口限制（用户/工具要的是立刻刷新）。
    """
    with _daemons_lock:
        handle = _daemons.get(idb_path)
    if handle is None:
        return False
    handle.force_now = True
    handle.force_event.set()
    return True


def _drop_idb_hook(handle: _DaemonHandle) -> None:
    """注销保存钩子（必须在 IDA 主线程调用，插件定时器路径满足）。

    为什么必须注销：钩子闭包持有 `handle`（以及线程对象）。不注销的话，每次
    IDB 切换/插件重载都会在 IDA 里**残留一个仍然会在 `savebase` 时回调的钩子** ——
    旧钩子会持续对已停止的句柄 `mark_save()`，且钩子对象永不释放（实测切换 A→B
    后两个钩子同时存活）。这里先清引用再注销：即使 `unhook()` 抛异常也不会重试成
    二次注销。
    """
    hook = handle.idb_hook
    handle.idb_hook = None
    if hook is None:
        return
    try:
        hook.unhook()
    except Exception as exc:  # noqa: BLE001 - 注销失败不应影响停止流程
        print(f"[MCP][cache] IDB_Hooks 注销失败: {exc}", file=sys.stderr)


def stop_cache_daemon(idb_path: str, *, timeout: float = 5.0) -> None:
    """停止指定守护线程并清理状态（幂等）。"""
    with _daemons_lock:
        handle = _daemons.pop(idb_path, None)
    if handle is None:
        return
    handle.stop_event.set()
    handle.force_event.set()  # 唤醒等待
    thread = handle.thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=timeout)
    _drop_idb_hook(handle)


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
