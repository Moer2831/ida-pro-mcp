"""IDA 插件进程的"客户端 MCP 接管层"

当 Broker 把 `tools/call` 请求转发到 IDA 后，这一层在 ida_mcp 正常
`MCP_SERVER.registry.dispatch` 之前做拦截：

- 如果目标工具在 `CACHE_TOOL_NAMES` 集合里，改由本模块直接读本地
  `.mcp.sqlite` 缓存并构造响应 (完全不占用 IDA 主线程)。
- 未就绪 / 数据库缺失时直接返回 JSON-RPC error，不 fallback。

所有签名都是严格类型化的，返回 `JsonRpcResponse`。
"""

from __future__ import annotations

import json
from typing import Any, Mapping, cast

from . import sqlite_cache as _cache
from . import sqlite_query as _query
from .cache_types import (
    CacheStatusArgs,
    CacheStatusResult,
    EntityKind,
    EntityQueryArgs,
    EntityQueryResult,
    FindRegexArgs,
    FindRegexResult,
    ImportsArgs,
    JsonRpcError,
    JsonRpcId,
    JsonRpcRequest,
    JsonRpcResponse,
    ListFuncsArgs,
    ListFuncsResult,
    ListGlobalsArgs,
    ListGlobalsResult,
    ListImportsResult,
    McpTextContent,
    McpToolCallResult,
    RefreshCacheArgs,
    RefreshCacheResult,
)


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

CACHE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "find_regex",
        "entity_query",
        "list_funcs",
        "list_globals",
        "imports",
        "refresh_cache",
        "cache_status",
    }
)

_VALID_ENTITY_KINDS: frozenset[str] = frozenset(
    {"strings", "functions", "globals", "imports"}
)

# 缓存答不了的 entity_query 字段：出现任意一个就把请求**转给 IDA**（而不是静默忽略）
# 实测教训：工具 schema 声明的是插件的嵌套形态
# (`{"queries": {"filter": ..., "count": ...}}`)，而缓存层只读扁平键
# (`name_pattern` / `limit`)，于是过滤与分页被静默丢掉 —— 要 8 条返回 200 条、
# 要过滤返回全量、要 kind=names 直接报 -32602。
_ENTITY_PASSTHROUGH_KEYS: frozenset[str] = frozenset(
    {
        "regex",
        "fields",
        "sort_by",
        "descending",
        "min_addr",
        "max_addr",
        "include_fn",
        "dedup",
        "module",
    }
)


def _first_query(args: Mapping[str, Any]) -> Mapping[str, Any]:
    """取出第一个查询对象：兼容 `queries` 为 dict / list / 字符串简写三种形态。"""
    raw = args.get("queries")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    return raw if isinstance(raw, dict) else {}


def _pick(args: Mapping[str, Any], query: Mapping[str, Any], *keys: str) -> Any:
    """按 keys 顺序先查嵌套查询对象、再查扁平参数；返回第一个非空值。"""
    for src in (query, args):
        for key in keys:
            value = src.get(key)
            if value is not None and value != "":
                return value
    return None


def _entity_kind(args: Mapping[str, Any]) -> str:
    """解析 entity_query 的 kind（嵌套/扁平都认），缺省与插件一致为 functions。"""
    query = _first_query(args)
    value = _pick(args, query, "kind", "type")
    return str(value).lower() if value is not None else "functions"


def _entity_can_use_cache(args: Mapping[str, Any]) -> bool:
    """该 entity_query 请求是否完全落在缓存能力范围内。"""
    if _entity_kind(args) not in _VALID_ENTITY_KINDS:
        return False  # 例如 names：缓存没有这张表，交给 IDA
    query = _first_query(args)
    for key in _ENTITY_PASSTHROUGH_KEYS:
        value = _pick(args, query, key)
        if value not in (None, False, "", []):
            return False
    return True


# ---------------------------------------------------------------------------
# JSON-RPC 封装
# ---------------------------------------------------------------------------


def _wrap_ok(req_id: JsonRpcId, payload: Mapping[str, Any]) -> JsonRpcResponse:
    text_content: McpTextContent = {
        "type": "text",
        "text": json.dumps(payload, ensure_ascii=False, default=str),
    }
    result: McpToolCallResult = {"content": [text_content], "isError": False}
    return {"jsonrpc": "2.0", "result": result, "id": req_id}


def _wrap_err(req_id: JsonRpcId, code: int, message: str) -> JsonRpcResponse:
    err: JsonRpcError = {"code": code, "message": message}
    return {"jsonrpc": "2.0", "error": err, "id": req_id}


# ---------------------------------------------------------------------------
# 参数解析工具
# ---------------------------------------------------------------------------


def _get_args(req: JsonRpcRequest) -> dict[str, Any]:
    params = req.get("params")
    if not isinstance(params, dict):
        return {}
    args = params.get("arguments")
    return args if isinstance(args, dict) else {}


def _get_tool_name(req: JsonRpcRequest) -> str:
    params = req.get("params")
    if not isinstance(params, dict):
        return ""
    name = params.get("name", "")
    return name if isinstance(name, str) else ""


def _opt_str(args: Mapping[str, Any], key: str) -> str | None:
    v = args.get(key)
    return v if isinstance(v, str) and v else None


def _int_or(args: Mapping[str, Any], key: str, default: int) -> int:
    v = args.get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _bool_or(args: Mapping[str, Any], key: str, default: bool) -> bool:
    v = args.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.lower() in {"1", "true", "yes", "y", "on"}
    return default


# ---------------------------------------------------------------------------
# 各工具 handler (强类型)
# ---------------------------------------------------------------------------


def _do_find_regex(args: FindRegexArgs, db_path: str) -> FindRegexResult:
    return _query.find_regex(
        db_path,
        pattern=args["pattern"],
        limit=_int_or(args, "limit", 100),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", True),
    )


def _do_entity_query(args: EntityQueryArgs, db_path: str) -> EntityQueryResult:
    return _query.entity_query(
        db_path,
        kind=args["kind"],
        name_pattern=_opt_str(args, "name_pattern"),
        segment=_opt_str(args, "segment"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", True),
    )


def _do_list_funcs(args: ListFuncsArgs, db_path: str) -> ListFuncsResult:
    return _query.list_funcs(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", False),
    )


def _do_list_globals(args: ListGlobalsArgs, db_path: str) -> ListGlobalsResult:
    return _query.list_globals(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
    )


def _do_imports(args: ImportsArgs, db_path: str) -> ListImportsResult:
    return _query.list_imports(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        module_pattern=_opt_str(args, "module_pattern"),
        limit=_int_or(args, "limit", 500),
        offset=_int_or(args, "offset", 0),
    )


def _do_refresh_cache(_args: RefreshCacheArgs, idb_path: str) -> RefreshCacheResult:
    triggered = _cache.request_refresh(idb_path) if idb_path else False
    return {"triggered": bool(triggered), "idb_path": idb_path}


def _do_cache_status(_args: CacheStatusArgs, db_path: str) -> CacheStatusResult:
    return _query.cache_status(db_path)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def handle_cache_tool_locally(req: JsonRpcRequest, idb_path: str) -> JsonRpcResponse:
    """在 IDA 插件进程内部，直接用 SQLite 响应缓存类工具。

    调用前请先用 `is_cache_tool()` / `CACHE_TOOL_NAMES` 判断。
    """
    req_id: JsonRpcId = req.get("id")
    tool_name = _get_tool_name(req)
    raw_args = _get_args(req)

    if not idb_path:
        return _wrap_err(
            req_id,
            -32000,
            "当前 IDA 实例未提供 idb_path，无法定位本地 SQLite 缓存。",
        )

    db_path = _query.get_cache_path_for_binary(idb_path)
    if not db_path:
        return _wrap_err(req_id, -32000, "无法根据 idb_path 推导缓存数据库路径。")

    try:
        if tool_name == "find_regex":
            pattern = raw_args.get("pattern") or raw_args.get("regex")
            if not isinstance(pattern, str) or not pattern:
                return _wrap_err(req_id, -32602, "find_regex 需要 pattern 参数 (str)。")
            fr_args: FindRegexArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
                "pattern": pattern,
            }
            if "limit" in raw_args:
                fr_args["limit"] = _int_or(raw_args, "limit", 100)
            if "offset" in raw_args:
                fr_args["offset"] = _int_or(raw_args, "offset", 0)
            if "include_xrefs" in raw_args:
                fr_args["include_xrefs"] = _bool_or(raw_args, "include_xrefs", True)
            return _wrap_ok(req_id, _do_find_regex(fr_args, db_path))

        if tool_name == "entity_query":
            kind = _entity_kind(raw_args)
            if kind not in _VALID_ENTITY_KINDS:
                return _wrap_err(
                    req_id,
                    -32602,
                    "entity_query 的 kind 必须是 "
                    f"{'/'.join(sorted(_VALID_ENTITY_KINDS))} 之一（收到 {kind!r}）。"
                    "names / 正则 / 排序等超出缓存能力的查询会直接转发给 IDA，"
                    "通常不应看到此错误。",
                )
            query = _first_query(raw_args)
            eq_args: EntityQueryArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
                "kind": cast(EntityKind, kind),
            }
            name_pat = _pick(raw_args, query, "name_pattern", "filter", "pattern")
            if name_pat is not None:
                eq_args["name_pattern"] = str(name_pat)
            seg = _pick(raw_args, query, "segment")
            if seg is not None:
                eq_args["segment"] = str(seg)
            limit = _pick(raw_args, query, "limit", "count")
            if limit is not None:
                eq_args["limit"] = _int_or({"v": limit}, "v", 200)
            offset = _pick(raw_args, query, "offset")
            if offset is not None:
                eq_args["offset"] = _int_or({"v": offset}, "v", 0)
            xrefs = _pick(raw_args, query, "include_xrefs")
            if xrefs is not None:
                eq_args["include_xrefs"] = _bool_or({"v": xrefs}, "v", True)
            return _wrap_ok(req_id, _do_entity_query(eq_args, db_path))

        if tool_name == "list_funcs":
            query = _first_query(raw_args)
            lf_args: ListFuncsArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            name_pat = _pick(raw_args, query, "name_pattern", "filter", "pattern")
            if name_pat is not None:
                lf_args["name_pattern"] = str(name_pat)
            limit = _pick(raw_args, query, "limit", "count")
            if limit is not None:
                lf_args["limit"] = _int_or({"v": limit}, "v", 200)
            offset = _pick(raw_args, query, "offset")
            if offset is not None:
                lf_args["offset"] = _int_or({"v": offset}, "v", 0)
            xrefs = _pick(raw_args, query, "include_xrefs")
            if xrefs is not None:
                lf_args["include_xrefs"] = _bool_or({"v": xrefs}, "v", False)
            return _wrap_ok(req_id, _do_list_funcs(lf_args, db_path))

        if tool_name == "list_globals":
            query = _first_query(raw_args)
            lg_args: ListGlobalsArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            name_pat = _pick(raw_args, query, "name_pattern", "filter", "pattern")
            if name_pat is not None:
                lg_args["name_pattern"] = str(name_pat)
            limit = _pick(raw_args, query, "limit", "count")
            if limit is not None:
                lg_args["limit"] = _int_or({"v": limit}, "v", 200)
            offset = _pick(raw_args, query, "offset")
            if offset is not None:
                lg_args["offset"] = _int_or({"v": offset}, "v", 0)
            return _wrap_ok(req_id, _do_list_globals(lg_args, db_path))

        if tool_name == "imports":
            query = _first_query(raw_args)
            im_args: ImportsArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            name_pat = _pick(raw_args, query, "name_pattern", "filter", "pattern")
            if name_pat is not None:
                im_args["name_pattern"] = str(name_pat)
            mod_pat = _pick(raw_args, query, "module_pattern", "module_filter", "module")
            if mod_pat is not None:
                im_args["module_pattern"] = str(mod_pat)
            limit = _pick(raw_args, query, "limit", "count")
            if limit is not None:
                im_args["limit"] = _int_or({"v": limit}, "v", 500)
            offset = _pick(raw_args, query, "offset")
            if offset is not None:
                im_args["offset"] = _int_or({"v": offset}, "v", 0)
            return _wrap_ok(req_id, _do_imports(im_args, db_path))

        if tool_name == "refresh_cache":
            rc_args: RefreshCacheArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            return _wrap_ok(req_id, _do_refresh_cache(rc_args, idb_path))

        if tool_name == "cache_status":
            cs_args: CacheStatusArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            return _wrap_ok(req_id, _do_cache_status(cs_args, db_path))

    except _query.CacheNotReadyError as e:
        return _wrap_err(req_id, -32001, str(e))
    except Exception as e:  # noqa: BLE001
        return _wrap_err(req_id, -32603, f"SQLite 缓存查询失败: {e}")

    return _wrap_err(req_id, -32601, f"未知缓存工具: {tool_name!r}")


def is_cache_tool(req: JsonRpcRequest) -> bool:
    """请求是否命中缓存拦截名单（缓存答不了的请求放行给 IDA）。

    对 `entity_query` 会多看一眼参数：`kind=names`、正则/排序/地址范围等缓存
    没有的能力一律**不拦截**，由 Broker 转发给 IDA 正常执行 —— 而不是回一个
    "kind 不支持"的错误（实测踩到：工具 schema 明写支持 names，缓存却报 -32602）。
    """
    if req.get("method") != "tools/call":
        return False
    name = _get_tool_name(req)
    if name not in CACHE_TOOL_NAMES:
        return False
    if name == "entity_query":
        return _entity_can_use_cache(_get_args(req))
    return True
