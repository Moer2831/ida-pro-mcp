"""缓存拦截规则：**能答的才拦，答不了的一律转给 IDA，绝不静默忽略参数**。

背景（实测踩到的两个真实缺陷）：

1. 工具 schema 声明的是插件的**嵌套**形态 ——
   `list_globals(queries={"filter": "g_", "count": 8})`、`entity_query(queries=[{...}])`；
   而缓存层历史上只读**扁平**键（`name_pattern` / `limit`）。结果：过滤条件与分页被
   静默丢掉 —— 要 8 条返回 200 条、要过滤返回全量。**静默返回错数据比报错更危险**。
2. `entity_query(kind="names")` 被缓存直接拒掉（-32602），而插件本身支持 `names`
   （`idautils.Names()`）—— 工具文档说能用、实际报错。

现在的规则：缓存只服务它确实有数据的 4 种 kind 且不含它不支持的能力
（正则 / 排序 / 地址范围 / 投影 / module …），其余请求 `is_cache_tool()` 返回 False，
由 Broker 正常转发给 IDA。
"""

from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _cache_fakes import build_test_db, make_backend  # noqa: E402

from ida_pro_mcp.broker import cache_config, cache_handlers as ch, sqlite_cache  # noqa: E402


def _call(tool: str, args: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {"name": tool, "arguments": args},
    }


class InterceptionRuleTests(unittest.TestCase):
    """哪些请求可以走缓存、哪些必须交给 IDA。"""

    def test_names_kind_is_passed_through_to_ida(self) -> None:
        self.assertFalse(
            ch.is_cache_tool(_call("entity_query", {"queries": [{"kind": "names"}]})),
            "缓存没有 names 表，必须转给 IDA（而不是报 kind 不支持）",
        )

    def test_cacheable_kinds_are_intercepted(self) -> None:
        for kind in ("functions", "globals", "strings", "imports"):
            with self.subTest(kind=kind):
                self.assertTrue(
                    ch.is_cache_tool(_call("entity_query", {"queries": [{"kind": kind}]}))
                )

    def test_unsupported_features_pass_through(self) -> None:
        for key, value in (
            ("regex", "^sub_"),
            ("sort_by", "size"),
            ("descending", True),
            ("min_addr", "0x401000"),
            ("max_addr", "0x500000"),
            ("fields", ["addr", "name"]),
            ("include_fn", True),
            ("dedup", True),
            ("module", "KERNEL32"),
        ):
            with self.subTest(key=key):
                self.assertFalse(
                    ch.is_cache_tool(_call("entity_query", {"queries": [{"kind": "functions", key: value}]})),
                    f"缓存不支持 {key}，应转给 IDA",
                )

    def test_kind_defaults_to_functions_like_the_plugin(self) -> None:
        self.assertEqual(ch._entity_kind({"queries": [{"filter": "x"}]}), "functions")  # noqa: SLF001
        self.assertEqual(ch._entity_kind({"queries": [{"kind": "STRINGS"}]}), "strings")  # noqa: SLF001

    def test_other_cache_tools_always_intercepted(self) -> None:
        for tool in ("list_funcs", "list_globals", "imports", "find_regex", "cache_status", "refresh_cache"):
            with self.subTest(tool=tool):
                self.assertTrue(ch.is_cache_tool(_call(tool, {})))

    def test_non_cache_tool_and_non_call_are_not_intercepted(self) -> None:
        self.assertFalse(ch.is_cache_tool(_call("decompile", {"addr": "0x401000"})))
        self.assertFalse(
            ch.is_cache_tool({"jsonrpc": "2.0", "method": "tools/list", "id": 1, "params": {}})
        )


class ArgumentNormalizationTests(unittest.TestCase):
    """嵌套（工具 schema）与扁平（缓存历史）两种参数形态都要认。"""

    def test_nested_query_object_wins(self) -> None:
        args = {"queries": [{"filter": "sub_40", "count": 8, "offset": 4}]}
        query = ch._first_query(args)  # noqa: SLF001
        self.assertEqual(ch._pick(args, query, "name_pattern", "filter", "pattern"), "sub_40")  # noqa: SLF001
        self.assertEqual(ch._pick(args, query, "limit", "count"), 8)  # noqa: SLF001
        self.assertEqual(ch._pick(args, query, "offset"), 4)  # noqa: SLF001

    def test_flat_args_still_work(self) -> None:
        args = {"name_pattern": "g_", "limit": 5}
        query = ch._first_query(args)  # noqa: SLF001
        self.assertEqual(ch._pick(args, query, "name_pattern", "filter"), "g_")  # noqa: SLF001
        self.assertEqual(ch._pick(args, query, "limit", "count"), 5)  # noqa: SLF001

    def test_string_shorthand_does_not_crash(self) -> None:
        args = {"queries": "0:50"}
        self.assertEqual(ch._first_query(args), {})  # noqa: SLF001

    def test_empty_values_are_ignored(self) -> None:
        args = {"queries": [{"filter": "", "count": None}]}
        query = ch._first_query(args)  # noqa: SLF001
        self.assertIsNone(ch._pick(args, query, "name_pattern", "filter"))  # noqa: SLF001


class CacheServedQueryTests(unittest.TestCase):
    """真正打到缓存上：过滤、分页必须生效（曾经被静默忽略）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-intercept-")
        self.db = build_test_db(self.tmp)
        self.idb = self.db[: -len(".mcp.sqlite")]
        cache_config_ = cache_config.CacheConfig(chunk_rows=4, incremental=False)
        sqlite_cache.build_cache(self.db, make_backend(n_functions=40), cache_config_)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _payload(self, response: dict) -> dict:
        result = response.get("result") or {}
        content = result.get("content") or [{}]
        return json.loads(content[0].get("text", "{}"))

    def test_nested_filter_and_count_are_applied(self) -> None:
        response = ch.handle_cache_tool_locally(
            _call(
                "list_funcs",
                {
                    "instance_id": "x",
                    "queries": [{"filter": "sub_1", "count": 3}],
                },
            ),
            self.idb,
        )
        payload = self._payload(response)
        items = payload.get("items") or payload.get("data") or []
        self.assertTrue(items, f"过滤后不应为空: {payload}")
        self.assertLessEqual(len(items), 3, "count 必须生效（曾经被忽略成默认 200）")
        for item in items:
            self.assertIn("sub_1", str(item.get("name", "")))

    def test_flat_filter_still_applied(self) -> None:
        response = ch.handle_cache_tool_locally(
            _call("list_funcs", {"instance_id": "x", "name_pattern": "sub_2", "limit": 2}),
            self.idb,
        )
        items = self._payload(response).get("items") or []
        self.assertLessEqual(len(items), 2)
        for item in items:
            self.assertIn("sub_2", str(item.get("name", "")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
