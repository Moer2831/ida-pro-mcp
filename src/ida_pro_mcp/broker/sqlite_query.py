"""SQLite 缓存只读查询层（强类型）

所有公开函数直接返回 `broker.cache_types` 中声明的 TypedDict，
禁止返回弱类型字典或内部 dataclass。

IDA 插件进程在 `ida_mcp.py` 的拦截层中调用本模块；Broker 进程永远
不应 import 本模块。
"""

from __future__ import annotations

import os
import re
import sqlite3
from typing import Optional

from .cache_types import (
    CacheStatusResult,
    EntityItem,
    EntityKind,
    EntityQueryResult,
    FindRegexResult,
    FunctionItem,
    GlobalItem,
    ImportItem,
    ListFuncsResult,
    ListGlobalsResult,
    ListImportsResult,
    StringItem,
    XrefItem,
    XrefType,
)
from .sqlite_cache import resolve_cache_path


CACHE_STATUS_READY = "ready"
CACHE_STATUS_BUILDING = "building"


class CacheNotReadyError(RuntimeError):
    """缓存还没写好 / 数据库文件不存在 / status != ready。"""


# ---------------------------------------------------------------------------
# sqlite3 连接 / REGEXP 扩展
# ---------------------------------------------------------------------------


def _regexp(expr: str, item: Optional[str]) -> int:
    """SQLite 的 REGEXP 运算符实现 (大小写敏感，Python re)。"""
    if item is None:
        return 0
    try:
        return 1 if re.search(expr, item) else 0
    except re.error:
        return 0


def _open_readonly(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        raise CacheNotReadyError(
            f"IDA 本地 SQLite 缓存数据库尚未创建 ({db_path})，"
            f"请等待插件完成首次分析或调用 refresh_cache 后重试。"
        )
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.create_function("REGEXP", 2, _regexp, deterministic=True)
    return conn


def _read_status(conn: sqlite3.Connection) -> str:
    cur = conn.execute("SELECT value FROM meta WHERE key='status'")
    row = cur.fetchone()
    return str(row[0]) if row else ""


def ensure_ready(db_path: str) -> sqlite3.Connection:
    """打开连接并确保 status=ready，否则抛 CacheNotReadyError。"""
    conn = _open_readonly(db_path)
    status = _read_status(conn)
    if status != CACHE_STATUS_READY:
        conn.close()
        raise CacheNotReadyError(
            f"IDA 本地 SQLite 缓存数据库正在初始化或仍在自动分析 (status={status!r})，"
            f"请大模型稍后重试，或调用 refresh_cache 手动触发一次刷新。"
        )
    return conn


def get_cache_path_for_binary(idb_path: Optional[str]) -> Optional[str]:
    """把 IDB 路径映射为缓存数据库路径。"""
    return resolve_cache_path(idb_path) if idb_path else None


# ---------------------------------------------------------------------------
# Row -> TypedDict 显式装配 (不用 dict(row) 弱兜底)
# ---------------------------------------------------------------------------


def _row_to_xref(row: sqlite3.Row) -> XrefItem:
    type_str = str(row["type"])
    xtype: XrefType = "code" if type_str == "code" else "data"
    return {"addr": str(row["xref_addr"]), "type": xtype}


def _xrefs_for_string(conn: sqlite3.Connection, addr: str) -> list[XrefItem]:
    cur = conn.execute(
        "SELECT xref_addr, type FROM string_xrefs WHERE str_addr=? ORDER BY xref_addr",
        (addr,),
    )
    return [_row_to_xref(r) for r in cur.fetchall()]


def _xrefs_for_function_to(conn: sqlite3.Connection, addr: str) -> list[XrefItem]:
    cur = conn.execute(
        "SELECT xref_addr, type FROM function_xrefs "
        "WHERE func_addr=? AND direction='to' ORDER BY xref_addr",
        (addr,),
    )
    return [_row_to_xref(r) for r in cur.fetchall()]


def _row_to_string_item(row: sqlite3.Row) -> StringItem:
    return {
        "addr": str(row["addr"]),
        "text": str(row["text"]),
        "length": int(row["length"]),
        "segment": str(row["segment"] or ""),
    }


def _row_to_function_item(row: sqlite3.Row) -> FunctionItem:
    return {
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "size": int(row["size"]),
        "segment": str(row["segment"] or ""),
        "has_type": bool(row["has_type"]),
    }


def _row_to_global_item(row: sqlite3.Row) -> GlobalItem:
    return {
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "size": int(row["size"] or 0),
        "segment": str(row["segment"] or ""),
    }


def _row_to_import_item(row: sqlite3.Row) -> ImportItem:
    return {
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "module": str(row["module"] or ""),
    }


def _count(conn: sqlite3.Connection, sql: str, params: tuple) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# 过滤条件编译：尽量避开逐行 Python UDF
# ---------------------------------------------------------------------------

_REGEX_METACHARS = frozenset("\\.^$*+?{}[]|()")


def _literal_text(pattern: str) -> Optional[str]:
    """pattern 不含正则元字符时返回其字面量，否则 None。"""
    if not pattern or any(ch in _REGEX_METACHARS for ch in pattern):
        return None
    return pattern


def _prefix_text(pattern: str) -> Optional[str]:
    """识别 `^字面量` 形式并返回字面量部分。"""
    if not pattern.startswith("^"):
        return None
    return _literal_text(pattern[1:])


def _prefix_bounds(prefix: str) -> Optional[tuple[str, str]]:
    """把前缀转成 BINARY 区间 [lo, hi)；无法构造时返回 None。"""
    if not prefix:
        return None
    last = ord(prefix[-1])
    if last >= 0x10FFFF:
        return None
    return (prefix, prefix[:-1] + chr(last + 1))


def _text_clause(column: str, pattern: str) -> tuple[str, tuple]:
    """把正则 pattern 编译成 SQL 条件，优先走 SQLite 原生实现。

    - 纯字面量   → `instr(col, ?) > 0`：C 实现、大小写敏感，与 `re.search` 等价
    - `^字面量`  → `col >= ? AND col < ?`：BINARY 区间，可用索引，避免全表排序
    - 其它       → `col REGEXP ?`：保留 Python UDF，语义完整但逐行回调最慢
    """
    literal = _literal_text(pattern)
    if literal is not None:
        return (f"instr({column}, ?) > 0", (literal,))
    prefix = _prefix_text(pattern)
    if prefix:
        bounds = _prefix_bounds(prefix)
        if bounds is not None:
            return (f"{column} >= ? AND {column} < ?", bounds)
    return (f"{column} REGEXP ?", (pattern,))


# ---------------------------------------------------------------------------
# 查询函数 (公开接口)
# ---------------------------------------------------------------------------


def find_regex(
    db_path: str,
    pattern: str,
    *,
    limit: int = 100,
    offset: int = 0,
    include_xrefs: bool = True,
) -> FindRegexResult:
    conn = ensure_ready(db_path)
    try:
        clause, params = _text_clause("text", pattern)
        page_limit = max(0, int(limit))
        page_offset = max(0, int(offset))
        # 窗口函数在一次扫描里同时给出 total，省掉历史实现里额外的 COUNT(*) 全表扫
        rows = conn.execute(
            "SELECT addr, text, length, segment, COUNT(*) OVER () AS total "
            f"FROM strings WHERE {clause} ORDER BY ea LIMIT ? OFFSET ?",
            params + (page_limit, page_offset),
        ).fetchall()
        total = (
            int(rows[0]["total"])
            if rows
            else _count(conn, f"SELECT COUNT(*) FROM strings WHERE {clause}", params)
        )
        items: list[StringItem] = []
        for row in rows:
            item = _row_to_string_item(row)
            if include_xrefs:
                item["xrefs"] = _xrefs_for_string(conn, item["addr"])
            items.append(item)
        return {
            "items": items,
            "total": total,
            "offset": page_offset,
            "limit": page_limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def list_funcs(
    db_path: str,
    *,
    name_pattern: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    include_xrefs: bool = False,
) -> ListFuncsResult:
    conn = ensure_ready(db_path)
    try:
        where = ""
        params: tuple = ()
        if name_pattern:
            clause, clause_params = _text_clause("name", name_pattern)
            where = f" WHERE {clause}"
            params = clause_params

        page_limit = max(0, int(limit))
        page_offset = max(0, int(offset))
        rows = conn.execute(
            f"SELECT addr, name, size, segment, has_type, COUNT(*) OVER () AS total "
            f"FROM functions{where} ORDER BY ea LIMIT ? OFFSET ?",
            params + (page_limit, page_offset),
        ).fetchall()
        total = (
            int(rows[0]["total"])
            if rows
            else _count(conn, f"SELECT COUNT(*) FROM functions{where}", params)
        )
        items: list[FunctionItem] = []
        for row in rows:
            item = _row_to_function_item(row)
            if include_xrefs:
                item["xrefs_to"] = _xrefs_for_function_to(conn, item["addr"])
            items.append(item)
        return {
            "items": items,
            "total": total,
            "offset": page_offset,
            "limit": page_limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def list_globals(
    db_path: str,
    *,
    name_pattern: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> ListGlobalsResult:
    conn = ensure_ready(db_path)
    try:
        where = ""
        params: tuple = ()
        if name_pattern:
            clause, clause_params = _text_clause("name", name_pattern)
            where = f" WHERE {clause}"
            params = clause_params

        page_limit = max(0, int(limit))
        page_offset = max(0, int(offset))
        rows = conn.execute(
            f"SELECT addr, name, size, segment, COUNT(*) OVER () AS total "
            f"FROM globals{where} ORDER BY ea LIMIT ? OFFSET ?",
            params + (page_limit, page_offset),
        ).fetchall()
        total = (
            int(rows[0]["total"])
            if rows
            else _count(conn, f"SELECT COUNT(*) FROM globals{where}", params)
        )
        items = [_row_to_global_item(r) for r in rows]
        return {
            "items": items,
            "total": total,
            "offset": page_offset,
            "limit": page_limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def list_imports(
    db_path: str,
    *,
    name_pattern: Optional[str] = None,
    module_pattern: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> ListImportsResult:
    conn = ensure_ready(db_path)
    try:
        clauses: list[str] = []
        params_list: list[str] = []
        if name_pattern:
            clause, clause_params = _text_clause("name", name_pattern)
            clauses.append(clause)
            params_list.extend(clause_params)
        if module_pattern:
            clause, clause_params = _text_clause("module", module_pattern)
            clauses.append(clause)
            params_list.extend(clause_params)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params = tuple(params_list)

        page_limit = max(0, int(limit))
        page_offset = max(0, int(offset))
        rows = conn.execute(
            f"SELECT addr, name, module, COUNT(*) OVER () AS total "
            f"FROM imports{where} ORDER BY ea LIMIT ? OFFSET ?",
            params + (page_limit, page_offset),
        ).fetchall()
        total = (
            int(rows[0]["total"])
            if rows
            else _count(conn, f"SELECT COUNT(*) FROM imports{where}", params)
        )
        items = [_row_to_import_item(r) for r in rows]
        return {
            "items": items,
            "total": total,
            "offset": page_offset,
            "limit": page_limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def entity_query(
    db_path: str,
    kind: EntityKind,
    *,
    name_pattern: Optional[str] = None,
    segment: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    include_xrefs: bool = True,
) -> EntityQueryResult:
    if kind == "strings":
        conn = ensure_ready(db_path)
        try:
            clauses: list[str] = []
            params_list: list[str] = []
            if name_pattern:
                clause, clause_params = _text_clause("text", name_pattern)
                clauses.append(clause)
                params_list.extend(clause_params)
            if segment:
                clauses.append("segment = ?")
                params_list.append(segment)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            params = tuple(params_list)
            page_limit = max(0, int(limit))
            page_offset = max(0, int(offset))
            rows = conn.execute(
                f"SELECT addr, text, length, segment, COUNT(*) OVER () AS total "
                f"FROM strings{where} ORDER BY ea LIMIT ? OFFSET ?",
                params + (page_limit, page_offset),
            ).fetchall()
            total = (
                int(rows[0]["total"])
                if rows
                else _count(conn, f"SELECT COUNT(*) FROM strings{where}", params)
            )
            str_items: list[EntityItem] = []
            for row in rows:
                item = _row_to_string_item(row)
                if include_xrefs:
                    item["xrefs"] = _xrefs_for_string(conn, item["addr"])
                str_items.append(item)
            return {
                "kind": "strings",
                "items": str_items,
                "total": total,
                "offset": page_offset,
                "limit": page_limit,
                "source": "sqlite_cache",
            }
        finally:
            conn.close()

    if kind == "functions":
        sub = list_funcs(
            db_path,
            name_pattern=name_pattern,
            limit=limit,
            offset=offset,
            include_xrefs=include_xrefs,
        )
        fn_items: list[EntityItem] = list(sub["items"])
        return {
            "kind": "functions",
            "items": fn_items,
            "total": sub["total"],
            "offset": sub["offset"],
            "limit": sub["limit"],
            "source": "sqlite_cache",
        }

    if kind == "globals":
        gsub = list_globals(
            db_path, name_pattern=name_pattern, limit=limit, offset=offset
        )
        g_items: list[EntityItem] = list(gsub["items"])
        return {
            "kind": "globals",
            "items": g_items,
            "total": gsub["total"],
            "offset": gsub["offset"],
            "limit": gsub["limit"],
            "source": "sqlite_cache",
        }

    if kind == "imports":
        isub = list_imports(db_path, name_pattern=name_pattern, limit=limit, offset=offset)
        i_items: list[EntityItem] = list(isub["items"])
        return {
            "kind": "imports",
            "items": i_items,
            "total": isub["total"],
            "offset": isub["offset"],
            "limit": isub["limit"],
            "source": "sqlite_cache",
        }

    raise ValueError(
        f"未知的 entity kind={kind!r}，支持: strings / functions / globals / imports"
    )


def _unreadable_status(db_path: str, exc: sqlite3.Error) -> CacheStatusResult:
    """缓存文件存在但不可读时的诊断结果（**不抛错**）。"""
    return {
        "exists": True,
        "db_path": db_path,
        "status": "error",
        "meta": {},
        "strings": 0,
        "string_xrefs": 0,
        "functions": 0,
        "function_xrefs": 0,
        "globals": 0,
        "imports": 0,
        "partial": False,
        "counts_source": "meta",
        "last_error": f"{type(exc).__name__}: {exc}",
        "degraded_reason": "cache-unreadable",
        "tables_skipped": [],
        "progress": {},
    }


def cache_status(db_path: str) -> CacheStatusResult:
    """查询缓存元信息；**任何情况下都不抛错**（诊断工具必须能给出回答）。

    - 文件不存在 → `status='missing'`；
    - 文件存在但不可读（垃圾字节 / 被截断 / 半个磁盘镜像）→ `status='error'`，
      原因放在 `last_error` / `degraded_reason` 里。守护线程随后会把这个文件
      隔离改名并重建（见 `cache_writer.CacheWriter._quarantine`），所以这是
      自愈过程中的一个瞬时状态，不该让 MCP 工具调用直接失败。
    - 正常 → 行数优先读 meta 里的 `count_<table>`（O(1)），只有老缓存缺少该键时
      才回退到 `COUNT(*)`（大库上 6 张表各一次全表扫代价很高，而本工具会被频繁调用）。
    """
    if not os.path.exists(db_path):
        return {
            "exists": False,
            "db_path": db_path,
            "status": "missing",
            "meta": {},
            "strings": 0,
            "string_xrefs": 0,
            "functions": 0,
            "function_xrefs": 0,
            "globals": 0,
            "imports": 0,
            "partial": False,
            "counts_source": "meta",
            "progress": {},
        }
    try:
        result = _cache_status_from_db(db_path)
    except sqlite3.Error as exc:
        return _unreadable_status(db_path, exc)
    if not result.get("status") and not result.get("meta"):
        # 文件在、但没有 meta 也没有数据：属于"还没建过缓存"，不是错误。
        result["status"] = "empty"
        result["degraded_reason"] = result.get("degraded_reason") or "not-built"
    return result


def _cache_status_from_db(db_path: str) -> CacheStatusResult:
    """从存在的缓存文件读取状态（读取失败向上抛 `sqlite3.Error`）。"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        try:
            meta_rows = conn.execute("SELECT key, value FROM meta").fetchall()
        except sqlite3.Error:
            meta_rows = []
        meta = {str(r["key"]): str(r["value"]) for r in meta_rows}

        counts_source = "meta"

        def _tbl_count(tbl: str) -> int:
            nonlocal counts_source
            raw = meta.get(f"count_{tbl}", "")
            if raw:
                try:
                    return int(raw)
                except ValueError:
                    pass
            counts_source = "count"
            try:
                row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
            except sqlite3.OperationalError as exc:
                # 表不存在 = 这份缓存还没建过（或正在建），不是"损坏"：按 0 报。
                # 其余 OperationalError（锁、IO）照旧上抛。
                if "no such table" not in str(exc).lower():
                    raise
                counts_source = "none"
                return 0
            return int(row[0]) if row else 0

        def _meta_int(key: str, default: int = 0) -> int:
            try:
                return int(float(meta.get(key, "") or default))
            except ValueError:
                return default

        skipped_raw = meta.get("tables_skipped", "")
        progress = {
            "phase": meta.get("progress_phase", ""),
            "table": meta.get("progress_table", ""),
            "rows": _meta_int("progress_rows"),
            "total": _meta_int("progress_total"),
            "elapsed_ms": _meta_int("elapsed_ms"),
            "peak_rss_mb": _meta_int("peak_rss_mb"),
            "refreshing": meta.get("refreshing", "0") == "1",
            "build_id": _meta_int("build_id"),
        }

        result: CacheStatusResult = {
            "exists": True,
            "db_path": db_path,
            "status": meta.get("status", ""),
            "meta": meta,
            "strings": _tbl_count("strings"),
            "string_xrefs": _tbl_count("string_xrefs"),
            "functions": _tbl_count("functions"),
            "function_xrefs": _tbl_count("function_xrefs"),
            "globals": _tbl_count("globals"),
            "imports": _tbl_count("imports"),
            "schema_version": _meta_int("schema_version"),
            "partial": meta.get("partial", "0") == "1",
            "last_error": meta.get("last_error", ""),
            "degraded_reason": meta.get("degraded_reason", ""),
            "tables_skipped": [t for t in skipped_raw.split(",") if t],
            "counts_source": counts_source,
            "progress": progress,
        }
        return result
    finally:
        conn.close()
