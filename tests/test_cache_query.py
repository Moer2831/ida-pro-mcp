"""SQLite 缓存只读查询层单测：过滤条件编译、窗口函数 total、分页、状态观测。

重点验证两点：
1. **语义等价**：`_text_clause` 的字面量/前缀快路径必须与历史实现的
   `col REGEXP ?`（Python `re.search`）给出完全相同的结果集。
2. **状态可观测**：`cache_status` 走 meta 读行数（不再 6 次全表 COUNT），
   并把进度/降级/错误等新字段暴露出来。
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _cache_fakes import FakeBackend, build_test_db, make_backend  # noqa: E402

from ida_pro_mcp.broker import cache_config, cache_writer, sqlite_cache, sqlite_query  # noqa: E402


class TextClauseTests(unittest.TestCase):
    """过滤条件编译的纯逻辑边界。"""

    def test_literal_uses_instr(self) -> None:
        clause, params = sqlite_query._text_clause("name", "sub_12")  # noqa: SLF001
        self.assertEqual(clause, "instr(name, ?) > 0")
        self.assertEqual(params, ("sub_12",))

    def test_prefix_uses_binary_range(self) -> None:
        clause, params = sqlite_query._text_clause("name", "^sub_")  # noqa: SLF001
        self.assertEqual(clause, "name >= ? AND name < ?")
        self.assertEqual(params, ("sub_", "sub`"))

    def test_regex_falls_back_to_udf(self) -> None:
        for pattern in (r"sub_\d+", "a.c", "^sub_\\d", "a|b", "[abc]"):
            clause, params = sqlite_query._text_clause("name", pattern)  # noqa: SLF001
            self.assertEqual(clause, "name REGEXP ?", pattern)
            self.assertEqual(params, (pattern,))

    def test_empty_pattern_is_not_a_literal(self) -> None:
        clause, _params = sqlite_query._text_clause("name", "")  # noqa: SLF001
        self.assertEqual(clause, "name REGEXP ?")

    def test_prefix_with_multi_byte_tail(self) -> None:
        clause, params = sqlite_query._text_clause("text", "^日本")  # noqa: SLF001
        self.assertEqual(clause, "text >= ? AND text < ?")
        self.assertEqual(params[0], "日本")
        self.assertEqual(params[1], "日" + chr(ord("本") + 1))

    def test_uncraftable_prefix_falls_back(self) -> None:
        self.assertIsNone(sqlite_query._prefix_bounds("\U0010ffff"))  # noqa: SLF001
        self.assertIsNone(sqlite_query._prefix_bounds(""))  # noqa: SLF001


class QuerySemanticsTests(unittest.TestCase):
    """用假后端建库，再逐条比对查询结果与 Python re 的期望值。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="ida-mcp-query-")
        cls.db = build_test_db(cls.tmp)
        cls.backend = FakeBackend(
            functions=[
                (0x1000, "sub_10", 16, True),
                (0x1010, "sub_20", 32, False),
                (0x1020, "main", 64, True),
                (0x1030, "helper_日本語", 16, False),
            ],
            strings=[
                (0x2000, "hello world"),
                (0x2010, "HELLO"),
                (0x2020, "hello\x00embedded"),
                (0x2030, ""),
            ],
            names=[
                (0x3000, "g_counter"),
                (0x3010, "g_buffer"),
            ],
            imports=[
                ("kernel32.dll", [(0x4000, "CreateFileW", 0), (0x4008, "ReadFile", 1)]),
                ("user32.dll", [(0x4010, "MessageBoxA", 0)]),
            ],
            xrefs={
                0x1000: [(0x9000, True), (0x9010, False)],
                0x2000: [(0x9100, True)],
            },
            segments={
                0x1000: ".text",
                0x1010: ".text",
                0x1020: ".text",
                0x1030: ".text",
                0x2000: ".rodata",
                0x2010: ".rodata",
                0x2020: ".rodata",
                0x2030: ".rodata",
                0x3000: ".data",
                0x3010: ".data",
            },
        )
        sqlite_cache.build_cache(
            cls.db, cls.backend, cache_config.CacheConfig(chunk_rows=2)
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _fresh_copy(self) -> str:
        """返回类级 DB 的独立副本（需要改 meta 的测试用它，避免污染其它用例）。"""
        target_dir = tempfile.mkdtemp(prefix="ida-mcp-query-copy-")
        self.addCleanup(shutil.rmtree, target_dir, ignore_errors=True)
        target = os.path.join(target_dir, "copy.mcp.sqlite")
        shutil.copyfile(self.db, target)
        return target

    # -- find_regex -------------------------------------------------------

    def test_find_regex_matches_python_re_for_every_pattern_shape(self) -> None:
        texts = [text for _ea, text in self.backend._strings]  # noqa: SLF001
        patterns = ["hello", "HELLO", "^hello", "^HE", r"h.llo", "world$", "nomatch", r"\d"]
        for pattern in patterns:
            expected = sorted(t for t in texts if re.search(pattern, t))
            with self.subTest(pattern=pattern):
                result = sqlite_query.find_regex(
                    self.db, pattern, limit=50, include_xrefs=False
                )
                self.assertEqual(sorted(item["text"] for item in result["items"]), expected)
                self.assertEqual(result["total"], len(expected))

    def test_find_regex_paging_and_totals(self) -> None:
        page1 = sqlite_query.find_regex(self.db, "hello", limit=1, offset=0, include_xrefs=False)
        page2 = sqlite_query.find_regex(self.db, "hello", limit=1, offset=1, include_xrefs=False)
        page3 = sqlite_query.find_regex(self.db, "hello", limit=1, offset=2, include_xrefs=False)
        self.assertEqual(page1["total"], page2["total"])
        self.assertEqual(page1["total"], 2)  # "HELLO" 大小写不同，不命中
        self.assertEqual(page3["items"], [])
        self.assertEqual(page3["total"], 2, "越界分页仍要回报正确 total")
        self.assertNotEqual(page1["items"][0]["addr"], page2["items"][0]["addr"])

    def test_find_regex_zero_limit_still_reports_total(self) -> None:
        result = sqlite_query.find_regex(self.db, "hello", limit=0, include_xrefs=False)
        self.assertEqual(result["items"], [])
        self.assertEqual(result["total"], 2)

    def test_find_regex_no_match(self) -> None:
        result = sqlite_query.find_regex(self.db, "zzz-not-there", include_xrefs=False)
        self.assertEqual(result, {
            "items": [],
            "total": 0,
            "offset": 0,
            "limit": 100,
            "source": "sqlite_cache",
        })

    def test_find_regex_include_xrefs(self) -> None:
        with_xrefs = sqlite_query.find_regex(self.db, "^hello world", include_xrefs=True)
        without = sqlite_query.find_regex(self.db, "^hello world", include_xrefs=False)
        self.assertEqual(with_xrefs["items"][0]["xrefs"], [{"addr": "0x9100", "type": "code"}])
        self.assertNotIn("xrefs", without["items"][0])

    def test_find_regex_prefix_boundary_is_case_sensitive(self) -> None:
        result = sqlite_query.find_regex(self.db, "^HELLO", include_xrefs=False)
        self.assertEqual([i["text"] for i in result["items"]], ["HELLO"])

    # -- list_funcs / list_globals / list_imports -------------------------

    def test_list_funcs_patterns_and_xrefs(self) -> None:
        literal = sqlite_query.list_funcs(self.db, name_pattern="sub_", limit=10)
        regex = sqlite_query.list_funcs(self.db, name_pattern=r"sub_\d0", limit=10)
        expected_literal = [n for _e, n, _s, _t in self.backend._functions if "sub_" in n]  # noqa: SLF001
        expected_regex = [n for _e, n, _s, _t in self.backend._functions if re.search(r"sub_\d0", n)]  # noqa: SLF001
        self.assertEqual(sorted(i["name"] for i in literal["items"]), sorted(expected_literal))
        self.assertEqual(sorted(i["name"] for i in regex["items"]), sorted(expected_regex))
        self.assertEqual(literal["total"], len(expected_literal))

        with_xrefs = sqlite_query.list_funcs(self.db, name_pattern="^sub_10", include_xrefs=True)
        self.assertEqual(with_xrefs["items"][0]["xrefs_to"], [
            {"addr": "0x9000", "type": "code"},
            {"addr": "0x9010", "type": "data"},
        ])

    def test_list_funcs_unicode_and_has_type(self) -> None:
        result = sqlite_query.list_funcs(self.db, name_pattern="日本語", limit=5)
        self.assertEqual(len(result["items"]), 1)
        item = result["items"][0]
        self.assertTrue(item["has_type"] or not item["has_type"])  # 字段存在即可
        self.assertIn("has_type", item)

    def test_list_globals_and_imports(self) -> None:
        globals_result = sqlite_query.list_globals(self.db, name_pattern="^g_", limit=10)
        self.assertEqual([i["name"] for i in globals_result["items"]], ["g_counter", "g_buffer"])

        all_imports = sqlite_query.list_imports(self.db, limit=10)
        self.assertEqual(all_imports["total"], 3)
        by_module = sqlite_query.list_imports(self.db, module_pattern="^kernel32", limit=10)
        self.assertEqual(by_module["total"], 2)
        by_name = sqlite_query.list_imports(self.db, name_pattern="File", limit=10)
        self.assertEqual(sorted(i["name"] for i in by_name["items"]), ["CreateFileW", "ReadFile"])

    def test_entity_query_all_kinds(self) -> None:
        strings = sqlite_query.entity_query(self.db, "strings", name_pattern="hello", limit=10)
        self.assertEqual(strings["kind"], "strings")
        self.assertEqual(strings["total"], 2)
        functions = sqlite_query.entity_query(self.db, "functions", limit=10)
        self.assertEqual(functions["kind"], "functions")
        self.assertEqual(functions["total"], 4)
        globals_result = sqlite_query.entity_query(self.db, "globals", limit=10)
        self.assertEqual(globals_result["total"], 2)
        imports = sqlite_query.entity_query(self.db, "imports", limit=10)
        self.assertEqual(imports["total"], 3)

    def test_entity_query_segment_filter(self) -> None:
        result = sqlite_query.entity_query(self.db, "strings", segment=".rodata", limit=10)
        self.assertEqual(result["total"], len(self.backend._strings))  # noqa: SLF001
        empty = sqlite_query.entity_query(self.db, "strings", segment=".nope", limit=10)
        self.assertEqual(empty["total"], 0)

    def test_entity_query_unknown_kind_raises(self) -> None:
        with self.assertRaises(ValueError):
            sqlite_query.entity_query(self.db, "nonsense")  # type: ignore[arg-type]

    # -- status / readiness ----------------------------------------------

    def test_cache_status_reads_counts_from_meta(self) -> None:
        status = sqlite_query.cache_status(self.db)
        self.assertTrue(status["exists"])
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["counts_source"], "meta")
        self.assertEqual(status["schema_version"], cache_writer.SCHEMA_VERSION)
        self.assertEqual(status["functions"], 4)
        self.assertFalse(status["partial"])
        self.assertEqual(status["tables_skipped"], [])
        self.assertIn("progress", status)
        self.assertIn("phase", status["progress"])

    def test_cache_status_missing_file(self) -> None:
        status = sqlite_query.cache_status(self.db + ".missing")
        self.assertFalse(status["exists"])
        self.assertEqual(status["status"], "missing")
        self.assertEqual(status["functions"], 0)
        self.assertEqual(status["counts_source"], "meta")

    def test_cache_status_falls_back_to_count_without_meta_keys(self) -> None:
        db = self._fresh_copy()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM meta WHERE key LIKE 'count_%'")
        conn.commit()
        conn.close()
        status = sqlite_query.cache_status(db)
        self.assertEqual(status["counts_source"], "count")
        self.assertEqual(status["functions"], 4)

    def test_cache_status_reports_partial_and_reason(self) -> None:
        db = self._fresh_copy()
        conn = sqlite3.connect(db)
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('partial', '1')")
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('degraded_reason', 'rss>64MB')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('tables_skipped', 'strings,globals')"
        )
        conn.commit()
        conn.close()
        status = sqlite_query.cache_status(db)
        self.assertTrue(status["partial"])
        self.assertEqual(status["degraded_reason"], "rss>64MB")
        self.assertEqual(status["tables_skipped"], ["strings", "globals"])

    def test_ensure_ready_rejects_non_ready_status(self) -> None:
        tmp = tempfile.mkdtemp(prefix="ida-mcp-query-ready-")
        try:
            db = build_test_db(tmp)
            cache_writer.CacheWriter(db, cache_config.CacheConfig()).open()  # 停在 building
            with self.assertRaises(sqlite_query.CacheNotReadyError):
                sqlite_query.ensure_ready(db)
            with self.assertRaises(sqlite_query.CacheNotReadyError):
                sqlite_query.find_regex(db, "x")
            with self.assertRaises(sqlite_query.CacheNotReadyError):
                sqlite_query.ensure_ready(db + ".nope")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_get_cache_path_for_binary(self) -> None:
        self.assertEqual(
            sqlite_query.get_cache_path_for_binary(r"C:\x\a.i64"), r"C:\x\a.i64.mcp.sqlite"
        )
        self.assertIsNone(sqlite_query.get_cache_path_for_binary(None))
        self.assertIsNone(sqlite_query.get_cache_path_for_binary(""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
