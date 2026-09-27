"""SQLite 缓存的分块写入器：峰值内存 O(块)、影子表原子切换、表级指纹跳过。

为什么不用"一个事务 DELETE 全表 + 全量 executemany"（历史实现）：

1. 峰值内存 O(全库)：调用方必须先把整库物化成 Python 对象。实测每行约
   244 B（tracemalloc，百万行 ≈ 233 MB），千万级交叉引用即数 GB。
2. 读者会看到"空表窗口"：`DELETE FROM` 之后、`INSERT` 之前表是空的，
   任何并发只读查询都会拿到空结果。
3. WAL 膨胀：单事务全量重写会让 `-wal` 涨到与全库同量级。

本模块的实现方式：

- **分块写入**：调用方按块喂 rows，逐块 `executemany`，按 `commit_rows`
  定期提交，峰值内存 ≈ 单块大小。
- **影子表 + 原子切换**：新数据写进 `<table>__new`，最后一次事务内
  `DROP TABLE <table>` → `ALTER TABLE <table>__new RENAME TO <table>` →
  `CREATE INDEX`。切换前读者看到的始终是上一个 good snapshot。
- **索引后建**：影子表先无索引批量插入，切换后再建索引（bulk load 最快路径）。
- **失败安全**：任何一层失败只丢弃影子表，旧快照保持可读。

所有 meta 写入都是字符串键值对，读侧（`sqlite_query.cache_status`）无需 join。
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence

from .cache_config import CacheConfig, load_cache_config
from .cache_rss import current_rss_mb

SCHEMA_VERSION = 2

# ---------------------------------------------------------------------------
# 表结构定义
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TableSpec:
    """一张业务表的列定义与索引定义。"""

    name: str
    columns: tuple[str, ...]
    ddl_body: str
    indexes: tuple[tuple[str, str], ...]  # (索引名, 列清单)

    def create_sql(self, table: str) -> str:
        return f"CREATE TABLE IF NOT EXISTS {table} ({self.ddl_body})"

    def insert_sql(self, table: str) -> str:
        cols = ", ".join(self.columns)
        placeholders = ", ".join("?" for _ in self.columns)
        return f"INSERT OR REPLACE INTO {table}({cols}) VALUES ({placeholders})"

    def index_sql(self, table: str, index_name: str, columns: str) -> str:
        return f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({columns})"


TABLE_SPECS: dict[str, TableSpec] = {
    "strings": TableSpec(
        name="strings",
        columns=("addr", "ea", "text", "length", "segment"),
        ddl_body=(
            "addr TEXT PRIMARY KEY, ea INTEGER NOT NULL, text TEXT NOT NULL, "
            "length INTEGER NOT NULL, segment TEXT"
        ),
        indexes=(
            ("idx_strings_text", "text"),
            ("idx_strings_segment", "segment"),
            ("idx_strings_ea", "ea"),
        ),
    ),
    "string_xrefs": TableSpec(
        name="string_xrefs",
        columns=("str_addr", "xref_addr", "xref_ea", "type"),
        ddl_body=(
            "str_addr TEXT NOT NULL, xref_addr TEXT NOT NULL, xref_ea INTEGER NOT NULL, "
            "type TEXT NOT NULL, PRIMARY KEY (str_addr, xref_addr)"
        ),
        indexes=(("idx_string_xrefs_str", "str_addr"),),
    ),
    "functions": TableSpec(
        name="functions",
        columns=("addr", "ea", "name", "size", "segment", "has_type"),
        ddl_body=(
            "addr TEXT PRIMARY KEY, ea INTEGER NOT NULL, name TEXT NOT NULL, "
            "size INTEGER NOT NULL, segment TEXT, has_type INTEGER NOT NULL DEFAULT 0"
        ),
        indexes=(
            ("idx_functions_name", "name"),
            ("idx_functions_segment", "segment"),
            ("idx_functions_ea", "ea"),
        ),
    ),
    "function_xrefs": TableSpec(
        name="function_xrefs",
        columns=("func_addr", "xref_addr", "xref_ea", "direction", "type"),
        ddl_body=(
            "func_addr TEXT NOT NULL, xref_addr TEXT NOT NULL, xref_ea INTEGER NOT NULL, "
            "direction TEXT NOT NULL, type TEXT NOT NULL, "
            "PRIMARY KEY (func_addr, xref_addr, direction)"
        ),
        indexes=(
            ("idx_function_xrefs_func", "func_addr"),
            ("idx_function_xrefs_func_dir", "func_addr, direction"),
        ),
    ),
    "globals": TableSpec(
        name="globals",
        columns=("addr", "ea", "name", "size", "segment"),
        ddl_body=(
            "addr TEXT PRIMARY KEY, ea INTEGER NOT NULL, name TEXT NOT NULL, "
            "size INTEGER, segment TEXT"
        ),
        indexes=(
            ("idx_globals_name", "name"),
            ("idx_globals_segment", "segment"),
            ("idx_globals_ea", "ea"),
        ),
    ),
    "imports": TableSpec(
        name="imports",
        columns=("addr", "ea", "name", "module"),
        ddl_body=(
            "addr TEXT PRIMARY KEY, ea INTEGER NOT NULL, name TEXT NOT NULL, module TEXT"
        ),
        indexes=(
            ("idx_imports_name", "name"),
            ("idx_imports_module", "module"),
            ("idx_imports_ea", "ea"),
        ),
    ),
}

SHADOW_SUFFIX = "__new"

# meta 键
META_STATUS = "status"
META_SCHEMA_VERSION = "schema_version"
META_LAST_UPDATED = "last_updated"
META_LAST_ERROR = "last_error"
META_PARTIAL = "partial"
META_DEGRADED_REASON = "degraded_reason"
META_TABLES_SKIPPED = "tables_skipped"
META_BUILD_ID = "build_id"
META_IDB_MTIME = "idb_mtime"
META_REFRESHING = "refreshing"
META_SCOPE = "scope"
META_CONFIG = "config"
META_ELAPSED_MS = "elapsed_ms"
META_PEAK_RSS_MB = "peak_rss_mb"
META_PROGRESS_TABLE = "progress_table"
META_PROGRESS_PHASE = "progress_phase"
META_PROGRESS_ROWS = "progress_rows"
META_PROGRESS_TOTAL = "progress_total"

STATUS_READY = "ready"
STATUS_BUILDING = "building"
STATUS_DEGRADED = "degraded"
STATUS_PARTIAL = "partial"
STATUS_ERROR = "error"

META_TABLE_DDL = "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"


def count_key(table: str) -> str:
    return f"count_{table}"


def fingerprint_key(table: str) -> str:
    return f"fp_{table}"


# ---------------------------------------------------------------------------
# 写入器
# ---------------------------------------------------------------------------


@dataclass
class TableProgress:
    table: str = ""
    phase: str = ""
    rows: int = 0
    total: int = 0
    elapsed_ms: float = 0.0
    peak_rss_mb: float = 0.0

    def as_meta(self) -> dict[str, str]:
        return {
            META_PROGRESS_TABLE: self.table,
            META_PROGRESS_PHASE: self.phase,
            META_PROGRESS_ROWS: str(int(self.rows)),
            META_PROGRESS_TOTAL: str(int(self.total)),
            META_ELAPSED_MS: f"{self.elapsed_ms:.0f}",
            META_PEAK_RSS_MB: f"{self.peak_rss_mb:.1f}",
        }


@dataclass
class _TableState:
    rows_written: int = 0
    rows_since_commit: int = 0
    chunk_index: int = 0


class CacheWriter:
    """分块写入器。只应由缓存守护线程单线程使用。"""

    def __init__(
        self,
        db_path: str,
        config: Optional[CacheConfig] = None,
        *,
        commit_rows: int = 100_000,
        rss_probe: Callable[[], float] = current_rss_mb,
        clock: Callable[[], float] = time.monotonic,
        progress_interval_s: float = 0.5,
    ) -> None:
        self.db_path = db_path
        self.config = config or load_cache_config()
        self.commit_rows = max(1, int(commit_rows))
        self._rss_probe = rss_probe
        self._clock = clock
        self._progress_interval_s = max(0.0, float(progress_interval_s))

        self._conn: Optional[sqlite3.Connection] = None
        self._tables: dict[str, _TableState] = {}
        self._active: dict[str, str] = {}  # table -> shadow 名
        self._started_at = 0.0
        self._last_progress_at = 0.0
        self._peak_rss_mb = 0.0
        self._had_snapshot = False
        self._progress = TableProgress()
        self._lock = threading.Lock()
        self._closed = False

    # -- 生命周期 ---------------------------------------------------------

    def open(self) -> None:
        """连接数据库、应用 PRAGMA、按需迁移 schema、清理残留影子表。

        文件损坏（被写成垃圾 / 截断 / 半个磁盘镜像）时**隔离重建**而不是抛错：
        缓存是可随时重建的派生物，若在这里抛错，守护线程会永久失败（每 30 分钟
        重试一次、每次都失败），必须手工删文件才能恢复 —— 实测就是这种表现。
        """
        if self._conn is not None:
            return
        conn = self._open_usable()
        self._conn = conn
        self._started_at = self._clock()
        self._apply_pragmas()
        conn.execute(META_TABLE_DDL)
        self._migrate_if_needed()
        self._drop_stale_shadows()
        self._ensure_snapshot_status()

    def _open_usable(self) -> sqlite3.Connection:
        """返回一个**可用的**连接：文件损坏时先隔离（改名）再新建。"""
        conn = sqlite3.connect(self.db_path, timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA schema_version").fetchone()
            return conn
        except sqlite3.DatabaseError as exc:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            quarantined = self._quarantine(exc)
            print(
                f"[MCP][cache] 缓存文件不可用（{exc}），已隔离为 {quarantined}，将重建。",
                file=sys.stderr,
            )
        conn = sqlite3.connect(self.db_path, timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _quarantine(self, exc: sqlite3.Error) -> str:
        """把损坏的缓存文件改名保留（便于事后取证），返回新路径。"""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = f"{self.db_path}.corrupt-{stamp}"
        for suffix in ("", "-wal", "-shm", "-journal"):
            src = f"{self.db_path}{suffix}"
            if not os.path.exists(src):
                continue
            dst = f"{target}{suffix}"
            try:
                if suffix == "":
                    os.replace(src, dst)
                else:
                    os.remove(src)  # WAL/SHM 属于坏库，直接丢
            except OSError as rename_exc:
                print(
                    f"[MCP][cache] 隔离缓存文件失败（{rename_exc}），尝试原地删除。",
                    file=sys.stderr,
                )
                try:
                    os.remove(src)
                except OSError:
                    pass
        return target

    def _apply_pragmas(self) -> None:
        """写侧 PRAGMA。

        - WAL：单写多读，构建期间读者不被阻塞。
        - temp_store=FILE：历史实现用 MEMORY，大表排序/临时 B-tree 会吃内存，
          这里改成文件，把排序代价放到磁盘上。
        - cache_size=-8192：页缓存上限 8 MiB，避免 SQLite 自己把内存吃大。
        - journal_size_limit / wal_autocheckpoint：限制 WAL 增长。
        - mmap_size=0：不映射大文件，避免地址空间与工作集虚高。
        """
        conn = self._require_conn()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=FILE")
        conn.execute("PRAGMA cache_size=-8192")
        conn.execute("PRAGMA journal_size_limit=67108864")
        conn.execute("PRAGMA wal_autocheckpoint=1000")
        conn.execute("PRAGMA mmap_size=0")
        conn.execute("PRAGMA busy_timeout=15000")

    def _migrate_if_needed(self) -> None:
        """schema 版本不一致时丢弃旧表（缓存可随时重建），补齐规范表。"""
        conn = self._require_conn()
        current = self.get_meta(META_SCHEMA_VERSION)
        if current and current != str(SCHEMA_VERSION):
            for table in TABLE_SPECS:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
                conn.execute(f"DROP TABLE IF EXISTS {table}{SHADOW_SUFFIX}")
            self.set_meta(META_SCHEMA_VERSION, str(SCHEMA_VERSION))
            self.set_meta(META_STATUS, STATUS_BUILDING)
        elif not current:
            self.set_meta(META_SCHEMA_VERSION, str(SCHEMA_VERSION))
        for spec in TABLE_SPECS.values():
            conn.execute(spec.create_sql(spec.name))
            for index_name, columns in spec.indexes:
                conn.execute(spec.index_sql(spec.name, index_name, columns))

    def _drop_stale_shadows(self) -> None:
        conn = self._require_conn()
        for table in TABLE_SPECS:
            conn.execute(f"DROP TABLE IF EXISTS {table}{SHADOW_SUFFIX}")

    def _ensure_snapshot_status(self) -> None:
        """已有可用快照时保持 status=ready（读者继续读旧快照），否则标记 building。"""
        status = self.get_meta(META_STATUS)
        self._had_snapshot = status == STATUS_READY
        if not self._had_snapshot:
            self.set_meta(META_STATUS, STATUS_BUILDING)
        self.set_meta(META_REFRESHING, "1")
        self.set_meta(META_BUILD_ID, str(int(time.time())))
        self.set_meta(META_SCOPE, self.config.scope)
        self.set_meta(
            META_CONFIG,
            f"scope={self.config.scope};chunk={self.config.chunk_rows};"
            f"incremental={int(self.config.incremental)};fp={self.config.fingerprint}",
        )

    def finish(
        self,
        *,
        status: str = STATUS_READY,
        error: str = "",
        partial: bool = False,
        degraded_reason: str = "",
        skipped: Sequence[str] = (),
    ) -> None:
        """收尾：写 meta、checkpoint WAL、optimize。不提交任何未完成的事务。"""
        conn = self._require_conn()
        self._drop_stale_shadows()
        self.set_meta(META_REFRESHING, "0")
        self.set_meta(META_STATUS, status)
        self.set_meta(META_LAST_UPDATED, str(int(time.time())))
        self.set_meta(META_PARTIAL, "1" if partial else "0")
        self.set_meta(META_TABLES_SKIPPED, ",".join(skipped))
        self.set_meta(META_LAST_ERROR, error)
        self.set_meta(META_DEGRADED_REASON, degraded_reason)
        # 收尾时必须把进度推进到终态：否则读者会看到"status=ready 但 phase=building"
        # 这种自相矛盾的组合，AI 侧可能据此以为还在构建而不敢用缓存。
        # 保留最后处理的表名/行数（诊断"卡在哪张表"时有用），只改 phase。
        self._progress = TableProgress(
            table=self._progress.table,
            phase="done",
            rows=self._progress.rows,
            total=self._progress.total,
            elapsed_ms=(self._clock() - self._started_at) * 1000.0 if self._started_at else 0.0,
            peak_rss_mb=self._peak_rss_mb,
        )
        self._flush_progress(force=True)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        try:
            conn.execute("PRAGMA optimize")
        except sqlite3.Error:
            pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    # -- 表级操作 ---------------------------------------------------------

    def begin_table(self, table: str) -> None:
        """创建影子表（先不建索引，批量插入更快）。"""
        spec = self._spec(table)
        conn = self._require_conn()
        shadow = self.shadow_name(table)
        conn.execute(f"DROP TABLE IF EXISTS {shadow}")
        conn.execute(spec.create_sql(shadow))
        self._active[table] = shadow
        self._tables[table] = _TableState()
        self.set_progress(phase="building", table=table, rows=0, total=0, force=True)

    def write_chunk(self, table: str, rows: Iterable[Sequence[object]]) -> int:
        """写入一块数据，返回实际写入行数。空块是合法的 no-op。"""
        spec = self._spec(table)
        shadow = self._active.get(table)
        if shadow is None:
            raise ValueError(f"write_chunk 前必须先 begin_table({table!r})")
        materialized = list(rows)
        if not materialized:
            return 0
        conn = self._require_conn()
        state = self._tables.setdefault(table, _TableState())
        conn.execute("BEGIN")
        try:
            conn.executemany(spec.insert_sql(shadow), materialized)
            state.rows_written += len(materialized)
            state.rows_since_commit += len(materialized)
            state.chunk_index += 1
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        self.set_progress(phase="building", table=table, rows=state.rows_written)
        return len(materialized)

    def commit_table(
        self,
        table: str,
        *,
        fingerprint: Optional[str] = None,
        count: Optional[int] = None,
    ) -> int:
        """原子切换：DROP 旧表 → RENAME 影子表 → 建索引；返回最终行数。"""
        spec = self._spec(table)
        conn = self._require_conn()
        shadow = self._active.pop(table, None)
        state = self._tables.get(table, _TableState())
        if shadow is None:
            raise ValueError(f"commit_table({table!r}) 前必须先 begin_table({table!r})")
        rows = state.rows_written if count is None else int(count)
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.execute(f"ALTER TABLE {shadow} RENAME TO {table}")
            for index_name, columns in spec.indexes:
                conn.execute(spec.index_sql(table, index_name, columns))
            self._set_meta_locked(conn, count_key(table), str(rows))
            if fingerprint is not None:
                self._set_meta_locked(conn, fingerprint_key(table), fingerprint)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return rows

    def skip_table(
        self,
        table: str,
        *,
        fingerprint: Optional[str] = None,
        reason: str = "fingerprint-unchanged",
    ) -> None:
        """指纹未变：不写库，仅刷新指纹与说明。"""
        conn = self._require_conn()
        if fingerprint is not None:
            self.set_meta(fingerprint_key(table), fingerprint)
        self.set_meta(f"skipped_{table}", reason)
        self.set_progress(phase="skipped", table=table, rows=0, total=0, force=True)

    def abort_table(self, table: str, *, error: str = "") -> None:
        """放弃该表本轮刷新：丢弃影子表，旧快照保持可读。"""
        conn = self._require_conn()
        shadow = self._active.pop(table, None)
        if shadow is not None:
            conn.execute(f"DROP TABLE IF EXISTS {shadow}")
        if error:
            self.set_meta(f"error_{table}", error)
        self.set_progress(phase="aborted", table=table, rows=0, total=0, force=True)

    def clear_table(self, table: str, *, reason: str = "out-of-scope") -> None:
        """清空某张表（scope 收窄时用）。

        同时清掉 `count_<table>` 与 `fp_<table>`：否则下次 scope 变回 full 时，
        指纹可能仍然"未变化"而被跳过，导致表被清空后永远补不回来。
        """
        conn = self._require_conn()
        if not self.table_exists(table):
            return
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DELETE FROM {table}")
            self._set_meta_locked(conn, count_key(table), "0")
            conn.execute("DELETE FROM meta WHERE key=?", (fingerprint_key(table),))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        self.set_meta(f"cleared_{table}", reason)

    def has_active_table(self, table: str) -> bool:
        return table in self._active

    # -- 元信息 -----------------------------------------------------------

    def get_meta(self, key: str, default: str = "") -> str:
        conn = self._require_conn()
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else default

    def set_meta(self, key: str, value: str) -> None:
        self._set_meta_locked(self._require_conn(), key, value)

    @staticmethod
    def _set_meta_locked(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            (key, str(value)),
        )

    def stored_fingerprint(self, table: str) -> str:
        return self.get_meta(fingerprint_key(table), "")

    def stored_count(self, table: str) -> int:
        raw = self.get_meta(count_key(table), "")
        try:
            return int(raw)
        except ValueError:
            return -1

    def table_exists(self, table: str) -> bool:
        conn = self._require_conn()
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        return row is not None

    # -- 进度 / 内存护栏 --------------------------------------------------

    def set_progress(
        self,
        *,
        phase: str,
        table: str = "",
        rows: int = 0,
        total: int = 0,
        force: bool = False,
    ) -> None:
        """更新内存中的进度并按节流写库（读者通过 meta 观察）。"""
        self._progress = TableProgress(
            table=table,
            phase=phase,
            rows=rows,
            total=total,
            elapsed_ms=(self._clock() - self._started_at) * 1000.0 if self._started_at else 0.0,
            peak_rss_mb=self._peak_rss_mb,
        )
        self._flush_progress(force=force)

    def _flush_progress(self, *, force: bool = False) -> None:
        now = self._clock()
        if not force and (now - self._last_progress_at) < self._progress_interval_s:
            return
        self._last_progress_at = now
        conn = self._require_conn()
        for key, value in self._progress.as_meta().items():
            self._set_meta_locked(conn, key, value)

    def sample_rss(self) -> float:
        """采样 RSS 并记录峰值；返回当前值（未知时为 0.0）。"""
        rss = float(self._rss_probe() or 0.0)
        if rss > self._peak_rss_mb:
            self._peak_rss_mb = rss
        return rss

    @property
    def peak_rss_mb(self) -> float:
        return self._peak_rss_mb

    @property
    def had_snapshot(self) -> bool:
        """open() 时是否已存在可用的 ready 快照（决定失败时能否保持 ready）。"""
        return self._had_snapshot

    @property
    def progress(self) -> TableProgress:
        return self._progress

    # -- 内部工具 ---------------------------------------------------------

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("CacheWriter 尚未 open()")
        return self._conn

    @staticmethod
    def _spec(table: str) -> TableSpec:
        spec = TABLE_SPECS.get(table)
        if spec is None:
            raise KeyError(f"未知缓存表: {table!r}")
        return spec

    @staticmethod
    def shadow_name(table: str) -> str:
        return f"{table}{SHADOW_SUFFIX}"


def read_meta(db_path: str) -> dict[str, str]:
    """只读读取 meta（测试与诊断用；文件不存在返回空 dict）。"""
    import os

    if not os.path.exists(db_path):
        return {}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute("SELECT key, value FROM meta").fetchall()
        except sqlite3.Error:
            return {}
        return {str(r["key"]): str(r["value"]) for r in rows}
    finally:
        conn.close()
