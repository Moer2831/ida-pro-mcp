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
) -> tuple[Optional[str], int]:
    """只读 pass：分块哈希指定提取器覆盖的数据，返回 (digest, 块数)。"""
    from .cache_backend import run_on_ida_main

    fingerprint = Fingerprint()
    cursor = 0
    chunks = 0
    while True:
        if should_stop():
            return (None, chunks)
        started = time.perf_counter()
        result = run_on_ida_main(
            lambda: extractor.chunk(
                cursor, chunker.next_size(), collect=False, fingerprint=fingerprint
            )
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if result is None:
            return (None, chunks)
        chunker.observe(max(1, result.items), elapsed_ms)
        chunks += 1
        cursor = result.cursor
        if result.done:
            break
    return (fingerprint.digest(), chunks)


def build_cache(
    db_path: str,
    backend: Any,
    config: Optional[CacheConfig] = None,
    *,
    writer_factory: Callable[[str, CacheConfig], CacheWriter] = CacheWriter,
    chunker: Optional[AdaptiveChunker] = None,
    should_stop: Optional[Callable[[], bool]] = None,
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
        rss_limit_mb: 覆盖配置里的 RSS 上限（单测用）。
    """
    cfg = config or load_cache_config()
    stop = should_stop or (lambda: False)
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
                    extractor, chunker, should_stop=stop
                )
                stats.chunks += fp_chunks
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

            while True:
                if stop():
                    reasons.append("stopped")
                    stats.partial = True
                    break
                started = time.perf_counter()
                result = _next_chunk(extractor, cursor, chunker)
                elapsed_ms = (time.perf_counter() - started) * 1000.0
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

            if limit_hit or rss_hit or dispatch_failed:
                if dispatch_failed:
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
                reasons.append(detail)
                if rss_hit or dispatch_failed:
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
IDLE_POLL_SEC = 2.0  # 未就绪时的快速探测节奏


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
        idb_mtime=_ida_idb_mtime(handle.idb_path),
    )
    handle.last_stats = stats
    handle.builds += 1
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


def _wait_for_idle(handle: _DaemonHandle, backend: Any) -> bool:
    """等待 IDA 空闲；stop_event 置位时返回 False。

    无头（idalib）环境直接放行：那里没有交互式分析要避让，而且**从后台线程调用
    IDAPython 未必可用**（实测 idalib 下守护线程拿不到空闲判定），继续等只会永远
    建不出缓存。GUI 下仍然按 IDLE_POLL_SEC 轮询等待。
    """
    from .cache_backend import is_headless, run_on_ida_main

    if is_headless():
        return True

    while not handle.stop_event.is_set():
        idle = run_on_ida_main(backend.is_idle)
        if idle:
            return True
        handle.stop_event.wait(IDLE_POLL_SEC)
    return False


def _daemon_loop(handle: _DaemonHandle) -> None:
    """守护线程主循环。

    1. 首次：等 IDA 空闲后做一轮构建。
    2. 之后：等待 force_event（IDB 保存 / refresh_cache 工具）或 30 分钟兜底；
       IDB mtime 未变化时跳过重建（除非是被 force 唤醒）。
    """
    config = load_cache_config()
    if config.disabled:
        print(
            "[MCP][cache] IDA_MCP_DISABLE_CACHE=1，缓存守护线程未启动。",
            file=sys.stderr,
        )
        return

    backend = _backend_factory()
    print(
        f"[MCP][cache] 守护线程启动，目标数据库: {handle.db_path} "
        f"(scope={config.scope}, chunk={config.chunk_rows}, "
        f"incremental={int(config.incremental)}, fp={config.fingerprint})",
        file=sys.stderr,
    )

    if _wait_for_idle(handle, backend):
        try:
            _run_build_once(handle, backend, config)
        except Exception as exc:  # noqa: BLE001
            handle.last_error = str(exc)
            print(f"[MCP][cache] 构建失败: {exc}", file=sys.stderr)

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
        if not _wait_for_idle(handle, backend):
            break
        try:
            _run_build_once(handle, backend, config)
        except Exception as exc:  # noqa: BLE001
            handle.last_error = str(exc)
            print(f"[MCP][cache] 构建失败: {exc}", file=sys.stderr)


def _make_idb_save_hook(handle: _DaemonHandle) -> Any:
    """在 IDA 主线程中创建并注册 IDB_Hooks 子类实例（保存 IDB 即触发刷新）。"""
    import ida_idp  # type: ignore

    class _Hook(ida_idp.IDB_Hooks):
        def savebase(self) -> int:
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
        "last_error": handle.last_error,
        "last_stats": handle.last_stats.as_dict() if handle.last_stats else None,
        "progress": handle.progress.as_meta(),
    }
