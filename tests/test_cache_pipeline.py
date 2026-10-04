"""T1 缓存层单测：配置 / 自适应分块 / 分块提取 / 影子表写入 / 构建编排。

全部使用假后端（`_cache_fakes.FakeBackend`），不依赖 IDA，因此可在 CI 里跑。
覆盖的边界：空库、单条巨行、重复地址、unicode/NUL、越界索引、注入异常、
schema 迁移、指纹命中与失效、max_rows / RSS 护栏、取消、旧快照保活。
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _cache_fakes import FakeBackend, build_test_db, make_backend  # noqa: E402

from ida_pro_mcp.broker import cache_config, cache_extract, cache_writer, sqlite_cache  # noqa: E402
from ida_pro_mcp.broker.cache_writer import STATUS_PARTIAL, STATUS_READY  # noqa: E402


def _count_rows(db_path: str, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _rows(db_path: str, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def sqlite_query_text_is_empty(db_path: str) -> bool:
    """string_xrefs 表是否为空（scope 收窄后不应残留过期交叉引用）。"""
    return _count_rows(db_path, "string_xrefs") == 0


class CacheConfigTests(unittest.TestCase):
    def test_defaults_keep_legacy_behaviour(self) -> None:
        cfg = cache_config.load_cache_config({})
        self.assertFalse(cfg.disabled)
        self.assertEqual(cfg.scope, cache_config.SCOPE_FULL)
        self.assertEqual(cfg.chunk_rows, cache_config.DEFAULT_CHUNK_ROWS)
        self.assertTrue(cfg.incremental)
        self.assertEqual(cfg.fingerprint, cache_config.FINGERPRINT_SHAPE)
        self.assertEqual(cfg.max_rows, 0)
        self.assertEqual(cfg.max_rss_mb, 0)
        self.assertEqual(len(cfg.tables()), 6)

    def test_disable_and_scope(self) -> None:
        self.assertTrue(cache_config.load_cache_config({"IDA_MCP_DISABLE_CACHE": "1"}).disabled)
        self.assertTrue(cache_config.load_cache_config({"IDA_MCP_DISABLE_CACHE": "yes"}).disabled)
        self.assertFalse(cache_config.load_cache_config({"IDA_MCP_DISABLE_CACHE": "off"}).disabled)
        minimal = cache_config.load_cache_config({"IDA_MCP_CACHE_SCOPE": "MINIMAL"})
        self.assertEqual(minimal.scope, cache_config.SCOPE_MINIMAL)
        self.assertFalse(minimal.wants_xrefs)
        self.assertFalse(minimal.wants_globals)
        self.assertNotIn("string_xrefs", minimal.tables())
        self.assertIn("imports", minimal.tables())

    def test_invalid_values_fall_back(self) -> None:
        cfg = cache_config.load_cache_config(
            {
                "IDA_MCP_CACHE_SCOPE": "nonsense",
                "IDA_MCP_CACHE_CHUNK_ROWS": "abc",
                "IDA_MCP_CACHE_TARGET_CHUNK_MS": "",
                "IDA_MCP_CACHE_FINGERPRINT": "weird",
                "IDA_MCP_CACHE_MAX_ROWS": "-5",
                "IDA_MCP_CACHE_MAX_RSS_MB": "xyz",
            }
        )
        self.assertEqual(cfg.scope, cache_config.SCOPE_FULL)
        self.assertEqual(cfg.chunk_rows, cache_config.DEFAULT_CHUNK_ROWS)
        self.assertEqual(cfg.fingerprint, cache_config.FINGERPRINT_SHAPE)
        self.assertEqual(cfg.max_rows, 0)
        self.assertEqual(cfg.max_rss_mb, 0)

    def test_clamping(self) -> None:
        low = cache_config.load_cache_config({"IDA_MCP_CACHE_CHUNK_ROWS": "1"})
        self.assertEqual(low.chunk_rows, cache_config.MIN_CHUNK_ROWS)
        high = cache_config.load_cache_config({"IDA_MCP_CACHE_CHUNK_ROWS": "99999999"})
        self.assertEqual(high.chunk_rows, cache_config.MAX_CHUNK_ROWS)
        ms = cache_config.load_cache_config({"IDA_MCP_CACHE_TARGET_CHUNK_MS": "1"})
        self.assertEqual(ms.target_chunk_ms, cache_config.MIN_TARGET_CHUNK_MS)

    def test_fingerprint_full_flag(self) -> None:
        cfg = cache_config.load_cache_config({"IDA_MCP_CACHE_FINGERPRINT": "full"})
        self.assertTrue(cfg.fingerprint_full)


class AdaptiveChunkerTests(unittest.TestCase):
    def test_shrink_and_grow(self) -> None:
        chunker = cache_config.AdaptiveChunker(chunk_rows=10_000, target_ms=100)
        self.assertEqual(chunker.next_size(), 10_000)
        chunker.observe(10_000, 1_000.0)  # 慢 10 倍 → 显著收缩
        self.assertLess(chunker.next_size(), 10_000)
        slow_size = chunker.next_size()
        chunker.observe(slow_size, 10.0)  # 快 10 倍 → 扩张
        self.assertGreater(chunker.next_size(), slow_size)

    def test_clamped_to_bounds(self) -> None:
        chunker = cache_config.AdaptiveChunker(
            chunk_rows=1000, target_ms=100, min_rows=10, max_rows=2000
        )
        for _ in range(20):
            chunker.observe(1000, 10_000.0)
            self.assertGreaterEqual(chunker.next_size(), 10)
        for _ in range(20):
            chunker.observe(1000, 0.001)
            self.assertLessEqual(chunker.next_size(), 2000)

    def test_in_band_keeps_size(self) -> None:
        chunker = cache_config.AdaptiveChunker(chunk_rows=500, target_ms=100)
        chunker.observe(500, 120.0)
        self.assertEqual(chunker.next_size(), 500)

    def test_degenerate_inputs(self) -> None:
        chunker = cache_config.AdaptiveChunker(chunk_rows=500, target_ms=100)
        chunker.observe(0, 0.0)
        self.assertEqual(chunker.next_size(), 500)
        zero_target = cache_config.AdaptiveChunker(chunk_rows=500, target_ms=0)
        self.assertGreater(zero_target.next_size(), 0)


class ExtractorTests(unittest.TestCase):
    def test_functions_chunk_covers_everything_once(self) -> None:
        backend = make_backend(n_functions=7, n_strings=0, n_names=0, n_imports=0, xrefs_per_item=2)
        extractor = cache_extract.FunctionsExtractor(backend, want_xrefs=True, full_fp=False)
        cursor, seen, xrefs, chunks = 0, 0, 0, 0
        while True:
            result = extractor.chunk(cursor, 3, collect=True)
            chunks += 1
            seen += len(result.rows_for("functions"))
            xrefs += len(result.rows_for("function_xrefs"))
            cursor = result.cursor
            if result.done:
                break
            self.assertLess(chunks, 100)
        self.assertEqual(seen, 7)
        self.assertEqual(xrefs, 14)
        self.assertGreater(chunks, 1, "预算 3 行时不应一次吃完整库")

    def test_budget_bounds_rows_per_chunk(self) -> None:
        backend = make_backend(n_functions=50, n_strings=0, n_names=0, n_imports=0, xrefs_per_item=1)
        extractor = cache_extract.FunctionsExtractor(backend, want_xrefs=True, full_fp=False)
        result = extractor.chunk(0, 5, collect=True)
        # 单条目的 xref 可能让块略微超出预算，但不允许无界放大
        self.assertLessEqual(result.row_count, 5 + 2)
        self.assertGreater(result.row_count, 0)

    def test_want_xrefs_false_skips_xref_rows(self) -> None:
        backend = make_backend(n_functions=4, n_strings=0, n_names=0, n_imports=0, xrefs_per_item=3)
        extractor = cache_extract.FunctionsExtractor(backend, want_xrefs=False, full_fp=False)
        result = extractor.chunk(0, 100, collect=True)
        self.assertEqual(result.rows_for("function_xrefs"), [])
        self.assertEqual(len(result.rows_for("functions")), 4)

    def test_empty_backend_is_done_immediately(self) -> None:
        backend = FakeBackend()
        for extractor in cache_extract.build_extractors(
            backend, want_xrefs=True, want_globals=True, full_fp=False
        ):
            result = extractor.chunk(0, 10, collect=True)
            self.assertTrue(result.done)
            self.assertEqual(result.row_count, 0)

    def test_none_items_are_skipped_without_stalling(self) -> None:
        class FlakyStrings(FakeBackend):
            def str_at(self, index):  # type: ignore[override]
                if index % 2 == 0:
                    return None
                return super().str_at(index)

        backend = FlakyStrings(strings=[(0x2000 + i * 0x10, f"s{i}") for i in range(6)])
        extractor = cache_extract.StringsExtractor(backend, want_xrefs=False, full_fp=False)
        result = extractor.chunk(0, 100, collect=True)
        self.assertTrue(result.done)
        self.assertEqual(len(result.rows_for("strings")), 3)

    def test_globals_skip_function_addresses(self) -> None:
        backend = FakeBackend(
            functions=[(0x1000, "sub_0", 16, False)],
            names=[(0x1000, "sub_0"), (0x3000, "gvar")],
        )
        extractor = cache_extract.GlobalsExtractor(backend)
        result = extractor.chunk(0, 100, collect=True)
        self.assertEqual([r[2] for r in result.rows_for("globals")], ["gvar"])

    def test_imports_without_symbol_use_ordinal(self) -> None:
        backend = FakeBackend(imports=[("m.dll", [(0x4000, "", 7), (0x4008, "named", None)])])
        extractor = cache_extract.ImportsExtractor(backend)
        result = extractor.chunk(0, 100, collect=True)
        names = [r[2] for r in result.rows_for("imports")]
        self.assertEqual(names, ["#7", "named"])

    def test_fingerprint_is_deterministic(self) -> None:
        first = make_backend()
        second = make_backend()
        digests = []
        for backend in (first, second):
            extractor = cache_extract.FunctionsExtractor(backend, want_xrefs=True, full_fp=False)
            fp = cache_extract.Fingerprint()
            cursor = 0
            while True:
                result = extractor.chunk(cursor, 2, collect=False, fingerprint=fp)
                cursor = result.cursor
                if result.done:
                    break
            digests.append(fp.digest())
        self.assertEqual(digests[0], digests[1])

    def test_shape_fingerprint_ignores_text_but_full_does_not(self) -> None:
        base = [(0x2000, "AAAA"), (0x2010, "BBBB")]
        changed = [(0x2000, "ZZZZ"), (0x2010, "BBBB")]

        def digest(strings, full):
            backend = FakeBackend(strings=strings)
            extractor = cache_extract.StringsExtractor(backend, want_xrefs=False, full_fp=full)
            fp = cache_extract.Fingerprint()
            extractor.chunk(0, 100, collect=False, fingerprint=fp)
            return fp.digest()

        self.assertEqual(digest(base, False), digest(changed, False))
        self.assertNotEqual(digest(base, True), digest(changed, True))

    def test_shape_fingerprint_tracks_rename_size_and_xrefs(self) -> None:
        def digest(functions, xrefs, want_xrefs=True):
            backend = FakeBackend(functions=functions, xrefs=xrefs)
            extractor = cache_extract.FunctionsExtractor(
                backend, want_xrefs=want_xrefs, full_fp=False
            )
            fp = cache_extract.Fingerprint()
            extractor.chunk(0, 100, collect=False, fingerprint=fp)
            return fp.digest()

        original = [(0x1000, "sub_0", 16, False)]
        renamed = [(0x1000, "sub_renamed", 16, False)]
        resized = [(0x1000, "sub_0", 32, False)]
        self.assertNotEqual(digest(original, {}), digest(renamed, {}))
        self.assertNotEqual(digest(original, {}), digest(resized, {}))
        self.assertNotEqual(
            digest(original, {0x1000: [(0x9000, True)]}),
            digest(original, {0x1000: [(0x9000, True), (0x9010, False)]}),
        )
        # scope 变化（是否采集 xref）必须让指纹改变，从而强制重建
        self.assertNotEqual(
            digest(original, {0x1000: [(0x9000, True)]}, want_xrefs=True),
            digest(original, {0x1000: [(0x9000, True)]}, want_xrefs=False),
        )


class WriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-writer-")
        self.db = os.path.join(self.tmp, "x.i64.mcp.sqlite")
        self.cfg = cache_config.CacheConfig()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_open_creates_schema_indexes_and_pragmas(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        try:
            conn = sqlite3.connect(self.db)
            tables = {
                r[0]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            indexes = {
                r[0]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
            }
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            # temp_store 是"每连接"设置，必须从写入器自己的连接上验证
            temp_store = writer._conn.execute("PRAGMA temp_store").fetchone()[0]  # noqa: SLF001
            synchronous = writer._conn.execute("PRAGMA synchronous").fetchone()[0]  # noqa: SLF001
        finally:
            writer.close()
        for table in cache_writer.TABLE_SPECS:
            self.assertIn(table, tables)
        self.assertIn("idx_strings_ea", indexes)
        self.assertIn("idx_functions_ea", indexes)
        self.assertIn("idx_imports_ea", indexes)
        self.assertEqual(journal.lower(), "wal")
        self.assertEqual(temp_store, 1)  # 1 = FILE（历史实现是 MEMORY）
        self.assertEqual(synchronous, 1)  # 1 = NORMAL

    def test_write_chunk_requires_begin_table(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        try:
            with self.assertRaises(ValueError):
                writer.write_chunk("strings", [("0x1", 1, "a", 1, ".rodata")])
        finally:
            writer.close()

    def test_commit_table_makes_rows_visible_and_records_counts(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        try:
            writer.begin_table("strings")
            self.assertEqual(
                writer.write_chunk("strings", [("0x1", 1, "hello", 5, ".rodata")]), 1
            )
            self.assertEqual(writer.write_chunk("strings", []), 0)
            writer.commit_table("strings", fingerprint="deadbeef")
            self.assertEqual(writer.stored_count("strings"), 1)
            self.assertEqual(writer.stored_fingerprint("strings"), "deadbeef")
        finally:
            writer.finish()
            writer.close()
        self.assertEqual(_count_rows(self.db, "strings"), 1)
        self.assertEqual(_rows(self.db, "SELECT text FROM strings"), [("hello",)])

    def test_readers_see_old_snapshot_until_swap(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        writer.begin_table("strings")
        writer.write_chunk("strings", [("0x1", 1, "old", 3, ".rodata")])
        writer.commit_table("strings")

        # 第二轮：写进影子表但还没 commit
        writer.begin_table("strings")
        writer.write_chunk("strings", [("0x1", 1, "new", 3, ".rodata")])
        mid_flight = _rows(self.db, "SELECT text FROM strings")
        self.assertEqual(mid_flight, [("old",)], "影子表写入期间读者必须仍看到旧快照")
        writer.commit_table("strings")
        self.assertEqual(_rows(self.db, "SELECT text FROM strings"), [("new",)])
        writer.finish()
        writer.close()

    def test_abort_table_keeps_old_data_and_drops_shadow(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        writer.begin_table("functions")
        writer.write_chunk("functions", [("0x10", 0x10, "sub", 4, ".text", 0)])
        writer.commit_table("functions")

        writer.begin_table("functions")
        writer.write_chunk("functions", [("0x20", 0x20, "other", 4, ".text", 0)])
        writer.abort_table("functions", error="boom")
        writer.finish(status=STATUS_READY, partial=True)
        writer.close()

        self.assertEqual(_rows(self.db, "SELECT name FROM functions"), [("sub",)])
        conn = sqlite3.connect(self.db)
        shadows = conn.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE '%__new'"
        ).fetchall()
        conn.close()
        self.assertEqual(shadows, [])

    def test_duplicate_addresses_are_replaced(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        writer.begin_table("imports")
        writer.write_chunk(
            "imports",
            [("0x1", 1, "first", "m.dll"), ("0x1", 1, "second", "m.dll")],
        )
        writer.commit_table("imports")
        writer.finish()
        writer.close()
        self.assertEqual(_rows(self.db, "SELECT name FROM imports"), [("second",)])

    def test_unicode_and_embedded_nul_round_trip(self) -> None:
        payload = "日本語テキスト\x00with-nul-🎯"
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        writer.begin_table("strings")
        writer.write_chunk("strings", [("0x1", 1, payload, len(payload), ".rodata")])
        writer.commit_table("strings")
        writer.finish()
        writer.close()
        self.assertEqual(_rows(self.db, "SELECT text FROM strings"), [(payload,)])

    def test_large_single_row(self) -> None:
        huge = "A" * (1 << 20)
        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        writer.begin_table("strings")
        writer.write_chunk("strings", [("0x1", 1, huge, len(huge), ".rodata")])
        writer.commit_table("strings")
        writer.finish()
        writer.close()
        self.assertEqual(
            len(_rows(self.db, "SELECT text FROM strings")[0][0]), 1 << 20
        )

    def test_many_chunks_spanning_forced_commits(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg, commit_rows=7)
        writer.open()
        writer.begin_table("globals")
        for i in range(50):
            writer.write_chunk("globals", [(hex(i), i, f"g{i}", 4, ".data")])
        writer.commit_table("globals")
        writer.finish()
        writer.close()
        self.assertEqual(_count_rows(self.db, "globals"), 50)

    def test_schema_migration_drops_legacy_tables(self) -> None:
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO meta VALUES ('schema_version', '1')")
        conn.execute("INSERT INTO meta VALUES ('status', 'ready')")
        conn.execute(
            "CREATE TABLE strings (addr TEXT PRIMARY KEY, ea INTEGER NOT NULL, "
            "text TEXT NOT NULL, length INTEGER NOT NULL, segment TEXT)"
        )
        conn.execute("INSERT INTO strings VALUES ('0x1', 1, 'legacy', 6, '.rodata')")
        conn.commit()
        conn.close()

        writer = cache_writer.CacheWriter(self.db, self.cfg)
        writer.open()
        try:
            self.assertEqual(writer.get_meta("schema_version"), str(cache_writer.SCHEMA_VERSION))
            self.assertEqual(writer.stored_count("strings"), -1)
            self.assertFalse(writer.had_snapshot, "旧 schema 不能被当作可用快照")
            self.assertEqual(writer.get_meta("status"), cache_writer.STATUS_BUILDING)
        finally:
            writer.finish(status=STATUS_PARTIAL, partial=True)
            writer.close()
        self.assertEqual(_count_rows(self.db, "strings"), 0)

    def test_ready_snapshot_detection(self) -> None:
        first = cache_writer.CacheWriter(self.db, self.cfg)
        first.open()
        first.begin_table("imports")
        first.write_chunk("imports", [("0x1", 1, "f", "m")])
        first.commit_table("imports")
        first.finish()
        first.close()

        second = cache_writer.CacheWriter(self.db, self.cfg)
        second.open()
        try:
            self.assertTrue(second.had_snapshot)
            self.assertEqual(second.get_meta("status"), STATUS_READY)
            self.assertEqual(second.get_meta("refreshing"), "1")
        finally:
            second.finish()
            second.close()

    def test_read_meta_on_missing_file(self) -> None:
        self.assertEqual(cache_writer.read_meta(os.path.join(self.tmp, "nope.sqlite")), {})

    def test_progress_is_persisted(self) -> None:
        writer = cache_writer.CacheWriter(self.db, self.cfg, progress_interval_s=0.0)
        writer.open()
        writer.begin_table("strings")
        writer.write_chunk("strings", [("0x1", 1, "a", 1, ".rodata")])
        writer.finish()
        writer.close()
        meta = cache_writer.read_meta(self.db)
        self.assertEqual(meta.get("progress_table"), "strings")
        self.assertIn("progress_phase", meta)
        self.assertIn("peak_rss_mb", meta)


class BuildCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-build-")
        self.db = build_test_db(self.tmp)
        self.cfg = cache_config.CacheConfig(chunk_rows=4)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_build_populates_all_tables(self) -> None:
        backend = make_backend(n_functions=6, n_strings=4, n_names=5, n_imports=2, xrefs_per_item=2)
        stats = sqlite_cache.build_cache(self.db, backend, self.cfg)
        self.assertEqual(stats.status, STATUS_READY)
        self.assertEqual(stats.functions, 6)
        self.assertEqual(stats.function_xrefs, 12)
        self.assertEqual(stats.strings, 4)
        self.assertEqual(stats.string_xrefs, 8)
        self.assertEqual(stats.globals_, 5)  # make_backend 的 name 地址不与 function 重叠
        self.assertEqual(stats.imports, 4)
        self.assertEqual(_count_rows(self.db, "functions"), 6)
        self.assertEqual(_count_rows(self.db, "string_xrefs"), 8)
        self.assertFalse(stats.partial)
        self.assertEqual(stats.tables_skipped, ())

    def test_incremental_skips_unchanged_tables(self) -> None:
        backend = make_backend()
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        stats = sqlite_cache.build_cache(self.db, backend, self.cfg)
        self.assertEqual(stats.status, STATUS_READY)
        self.assertEqual(
            set(stats.tables_skipped),
            {"functions", "function_xrefs", "strings", "string_xrefs", "globals", "imports"},
        )
        self.assertFalse(stats.partial)

    def test_incremental_disabled_rebuilds(self) -> None:
        backend = make_backend()
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        cfg = cache_config.CacheConfig(chunk_rows=4, incremental=False)
        stats = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertEqual(stats.tables_skipped, ())

    def test_changed_function_name_rebuilds_only_functions_group(self) -> None:
        backend = make_backend()
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        backend._functions[0] = (backend._functions[0][0], "renamed", 32, True)  # type: ignore[index]
        stats = sqlite_cache.build_cache(self.db, backend, self.cfg)
        self.assertEqual(set(stats.tables_skipped), {"strings", "string_xrefs", "globals", "imports"})
        self.assertEqual(stats.functions, 5)

    def test_minimal_scope_leaves_xref_tables_empty(self) -> None:
        backend = make_backend()
        cfg = cache_config.CacheConfig(chunk_rows=4, scope=cache_config.SCOPE_MINIMAL)
        stats = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertGreater(stats.functions, 0)
        self.assertEqual(stats.string_xrefs, 0)
        self.assertEqual(stats.function_xrefs, 0)
        self.assertEqual(stats.globals_, 0)
        self.assertEqual(_count_rows(self.db, "globals"), 0)

    def test_scope_switch_clears_out_of_scope_tables(self) -> None:
        backend = make_backend()
        full = sqlite_cache.build_cache(self.db, backend, self.cfg)
        self.assertGreater(full.string_xrefs, 0)

        minimal_cfg = cache_config.CacheConfig(
            chunk_rows=4, scope=cache_config.SCOPE_MINIMAL
        )
        minimal = sqlite_cache.build_cache(self.db, backend, minimal_cfg)
        self.assertEqual(
            minimal.tables_cleared, ("string_xrefs", "function_xrefs", "globals")
        )
        self.assertEqual(minimal.string_xrefs, 0)
        self.assertEqual(_count_rows(self.db, "string_xrefs"), 0)
        self.assertEqual(_count_rows(self.db, "globals"), 0)
        self.assertEqual(
            sqlite_query_text_is_empty(self.db), True, "清空后不应再返回过期交叉引用"
        )

        # 切回 full 必须重新填充：清表时连指纹一起删了，不能被"指纹未变"卡死
        again = sqlite_cache.build_cache(self.db, backend, self.cfg)
        self.assertEqual(again.string_xrefs, full.string_xrefs)
        self.assertEqual(again.globals_, full.globals_)
        self.assertEqual(_count_rows(self.db, "string_xrefs"), full.string_xrefs)

    def test_max_rows_aborts_table_and_keeps_previous_snapshot(self) -> None:
        backend = make_backend(n_functions=10)
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        before = _count_rows(self.db, "functions")

        cfg = cache_config.CacheConfig(chunk_rows=2, incremental=False, max_rows=3)
        stats = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertTrue(stats.partial)
        self.assertIn("functions", stats.tables_aborted)
        self.assertEqual(stats.status, STATUS_READY, "已有快照时应继续对外可用")
        self.assertEqual(_count_rows(self.db, "functions"), before)
        self.assertIn("MAX_ROWS", stats.reason)

    def test_rss_guard_degrades_and_keeps_snapshot(self) -> None:
        backend = make_backend()
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        before = _count_rows(self.db, "functions")

        cfg = cache_config.CacheConfig(chunk_rows=2, incremental=False)
        stats = sqlite_cache.build_cache(self.db, backend, cfg, rss_limit_mb=1)
        self.assertTrue(stats.partial)
        self.assertIn("rss", stats.reason)
        self.assertEqual(stats.status, "degraded")
        self.assertEqual(_count_rows(self.db, "functions"), before)

    def test_cancel_before_first_chunk_keeps_old_snapshot(self) -> None:
        backend = make_backend()
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        before = _count_rows(self.db, "functions")

        cfg = cache_config.CacheConfig(chunk_rows=2, incremental=False)
        stats = sqlite_cache.build_cache(self.db, backend, cfg, should_stop=lambda: True)
        self.assertTrue(stats.partial)
        self.assertEqual(stats.status, STATUS_READY)
        self.assertEqual(_count_rows(self.db, "functions"), before)

    def test_first_build_cancel_never_reports_ready(self) -> None:
        backend = make_backend()
        stats = sqlite_cache.build_cache(
            self.db, backend, self.cfg, should_stop=lambda: True
        )
        self.assertEqual(stats.status, STATUS_PARTIAL)
        self.assertEqual(_count_rows(self.db, "functions"), 0)

    def test_backend_failure_records_error_and_keeps_snapshot(self) -> None:
        backend = make_backend()
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        before = _count_rows(self.db, "functions")

        broken = make_backend()
        broken.fail_on_chunk = "functions"
        cfg = cache_config.CacheConfig(chunk_rows=2, incremental=False)
        stats = sqlite_cache.build_cache(self.db, broken, cfg)
        self.assertTrue(stats.partial)
        self.assertIn("injected failure", stats.reason)
        # 有可用快照时构建异常不能让缓存下线：状态保持 ready，仅记录错误
        self.assertEqual(stats.status, STATUS_READY)
        self.assertEqual(cache_writer.read_meta(self.db).get("status"), STATUS_READY)
        self.assertIn("injected failure", cache_writer.read_meta(self.db).get("last_error", ""))
        self.assertEqual(_count_rows(self.db, "functions"), before)

    def test_first_build_failure_is_reported_as_error(self) -> None:
        broken = make_backend()
        broken.fail_on_chunk = "functions"
        cfg = cache_config.CacheConfig(chunk_rows=2, incremental=False)
        stats = sqlite_cache.build_cache(self.db, broken, cfg)
        self.assertEqual(stats.status, "error")
        self.assertEqual(cache_writer.read_meta(self.db).get("status"), "error")

    def test_empty_idb_builds_cleanly(self) -> None:
        stats = sqlite_cache.build_cache(self.db, FakeBackend(), self.cfg)
        self.assertEqual(stats.status, STATUS_READY)
        self.assertEqual(stats.functions, 0)
        self.assertEqual(stats.strings, 0)
        self.assertEqual(_count_rows(self.db, "functions"), 0)

    def test_chunk_budget_is_respected_across_groups(self) -> None:
        observed: list[int] = []

        class RecordingBackend(FakeBackend):
            def func_at(self, index):  # type: ignore[override]
                value = super().func_at(index)
                if value is not None:
                    observed.append(index)
                return value

        backend = RecordingBackend(
            functions=[(0x1000 + i * 0x10, f"f{i}", 16, False) for i in range(40)],
            xrefs={0x1000 + i * 0x10: [(0x9000 + i, True)] for i in range(40)},
        )
        cfg = cache_config.CacheConfig(chunk_rows=5, incremental=False)
        stats = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertEqual(stats.functions, 40)
        self.assertEqual(len(observed), 40, "关闭增量后每个函数只应被访问一次")

    def test_rebuild_overwrites_changed_rows(self) -> None:
        backend = make_backend(n_functions=3, n_strings=0, n_names=0, n_imports=0)
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        first = _rows(self.db, "SELECT name FROM functions ORDER BY ea")
        backend._functions[0] = (backend._functions[0][0], "changed", 99, False)  # type: ignore[index]
        sqlite_cache.build_cache(self.db, backend, self.cfg)
        second = _rows(self.db, "SELECT name FROM functions ORDER BY ea")
        self.assertNotEqual(first, second)
        self.assertIn(("changed",), second)


class DaemonLoopTests(unittest.TestCase):
    """守护线程主循环的可执行路径（历史上这里漏改过变量名，只有真跑才会炸）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-daemon-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _handle(self) -> sqlite_cache._DaemonHandle:  # noqa: SLF001
        return sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path=os.path.join(self.tmp, "x.i64"),
            db_path=os.path.join(self.tmp, "x.i64.mcp.sqlite"),
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
        )

    def test_disabled_config_returns_without_building(self) -> None:
        with mock.patch.dict(os.environ, {"IDA_MCP_DISABLE_CACHE": "1"}):
            handle = self._handle()
            sqlite_cache._daemon_loop(handle)  # noqa: SLF001
            self.assertIsNone(handle.last_stats)
            self.assertFalse(handle.stop_event.is_set())

    def test_start_cache_daemon_respects_disable_switch(self) -> None:
        with mock.patch.dict(os.environ, {"IDA_MCP_DISABLE_CACHE": "1"}):
            self.assertIsNone(sqlite_cache.start_cache_daemon(os.path.join(self.tmp, "y.i64")))
        snapshot = sqlite_cache.daemon_snapshot(os.path.join(self.tmp, "y.i64"))
        self.assertFalse(snapshot["running"])


    def test_daemon_loop_end_to_end_with_fake_backend(self) -> None:
        """跑完整主循环：启动 → 构建 → 等待 force → 退出（用假后端，秒级完成）。

        注意：这里刻意不用真 IDA —— 守护线程会从后台线程调用 IDA API，而 idalib 下
        这些调用未必可用（实测拿不到空闲判定）；生产环境里守护线程只在 GUI 插件里跑，
        走的是 `execute_sync` 派发到主线程。
        """
        backend = make_backend()
        original_factory = sqlite_cache._backend_factory  # noqa: SLF001
        sqlite_cache._backend_factory = lambda: backend  # noqa: SLF001
        # 本用例模拟"无 IDA / 无头"进程；其它测试模块可能已 import 过 idapro，
        # 于是这里显式钉住 headless 判定，保证测试与环境无关。
        patcher = mock.patch(
            "ida_pro_mcp.broker.cache_backend.dispatch_available", lambda: False
        )
        patcher.start()
        # 关掉"保存合并窗口"：本用例测的是主循环机制，不是合并策略（否则要等 20s）
        env_patcher = mock.patch.dict(
            os.environ, {"IDA_MCP_REBUILD_MIN_INTERVAL_SEC": "0"}
        )
        env_patcher.start()
        try:
            handle = self._handle()
            worker = threading.Thread(
                target=sqlite_cache._daemon_loop,  # noqa: SLF001
                args=(handle,),
                daemon=True,
            )
            worker.start()
            deadline = time.time() + 30
            while time.time() < deadline and handle.last_stats is None and worker.is_alive():
                time.sleep(0.05)

            self.assertIsNotNone(
                handle.last_stats,
                f"守护线程应完成一轮构建（last_error={handle.last_error!r}）",
            )
            assert handle.last_stats is not None
            self.assertEqual(handle.last_stats.status, STATUS_READY, handle.last_stats.reason)
            self.assertGreater(handle.last_stats.functions, 0)
            self.assertEqual(handle.builds, 1)

            # 第二次触发（IDB 保存 / refresh_cache）：mtime 未变 + force 唤醒 → 仍会重建一轮
            handle.force_event.set()
            deadline = time.time() + 30
            while time.time() < deadline and handle.builds < 2 and worker.is_alive():
                time.sleep(0.05)
            self.assertEqual(handle.builds, 2)

            handle.stop_event.set()
            handle.force_event.set()
            worker.join(timeout=15)
            self.assertFalse(worker.is_alive(), "stop_event 置位后守护线程应退出")
        finally:
            sqlite_cache._backend_factory = original_factory  # noqa: SLF001
            patcher.stop()
            env_patcher.stop()


class DispatchTests(unittest.TestCase):
    """主线程派发判定（历史上用 is_idaq() 误判过，导致后台线程直接碰 IDAPython）。"""

    def _fake_kernwin(self, calls: list) -> object:
        import types

        fake = types.ModuleType("ida_kernwin")
        fake.MFF_READ = 1  # type: ignore[attr-defined]

        def execute_sync(fn, flags):  # noqa: ANN001
            calls.append(("execute_sync", flags))
            return fn()

        fake.execute_sync = execute_sync  # type: ignore[attr-defined]
        # 故意让 is_idaq() 返回 False：它表示"是否由 IDAQ 承载"，在装载早期不可靠，
        # 代码不能依赖它来决定是否派发。
        fake.is_idaq = lambda: False  # type: ignore[attr-defined]
        return fake

    def test_execute_sync_is_used_whenever_ida_is_present(self) -> None:
        import sys

        from ida_pro_mcp.broker import cache_backend

        calls: list = []
        with mock.patch.dict(sys.modules, {"ida_kernwin": self._fake_kernwin(calls)}):
            self.assertTrue(cache_backend.dispatch_available())
            self.assertEqual(cache_backend.run_on_ida_main(lambda: 42), 42)
        self.assertEqual(calls, [("execute_sync", 1)])

    def test_direct_call_without_ida(self) -> None:
        import sys

        from ida_pro_mcp.broker import cache_backend

        with mock.patch.dict(sys.modules, {"ida_kernwin": None}):
            self.assertFalse(cache_backend.dispatch_available())
            self.assertEqual(cache_backend.run_on_ida_main(lambda: "direct"), "direct")

    def test_callback_exception_propagates(self) -> None:
        import sys

        from ida_pro_mcp.broker import cache_backend

        calls: list = []
        with mock.patch.dict(sys.modules, {"ida_kernwin": self._fake_kernwin(calls)}):
            with self.assertRaises(RuntimeError):
                cache_backend.run_on_ida_main(lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    def test_dispatch_failure_returns_none(self) -> None:
        import sys
        import types

        from ida_pro_mcp.broker import cache_backend

        fake = types.ModuleType("ida_kernwin")
        fake.MFF_READ = 1  # type: ignore[attr-defined]

        def boom(fn, flags):  # noqa: ANN001
            raise RuntimeError("main thread unreachable")

        fake.execute_sync = boom  # type: ignore[attr-defined]
        with mock.patch.dict(sys.modules, {"ida_kernwin": fake}):
            self.assertIsNone(cache_backend.run_on_ida_main(lambda: 1))

    def test_wait_for_idle_is_pure_waiting(self) -> None:
        """空闲等待不再 fail-open、也不再派发（保存期间卡死 IDA 的根因）。

        新契约：只有"空闲 + 过了保存静默窗口"才返回 True；stop_event 置位返回 False。
        完整的门控回归见 tests/test_cache_save_safety.py。
        """
        handle = sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path="x.i64",
            db_path="x.i64.mcp.sqlite",
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
        )
        handle.idle_backend = make_backend()
        # 假装主线程定时器已安装：此时等待期间不应有任何兜底探测
        handle.idle_timer_id = 42
        with mock.patch.object(sqlite_cache, "IDLE_WATCH_POLL_SEC", 0.01):
            timer = threading.Timer(0.1, handle.stop_event.set)
            timer.start()
            try:
                started = time.time()
                self.assertFalse(sqlite_cache._wait_for_idle(handle))  # noqa: SLF001
                self.assertLess(time.time() - started, 5.0)
            finally:
                timer.cancel()


class SnapshotTests(unittest.TestCase):
    def test_daemon_snapshot_shape(self) -> None:
        snapshot = sqlite_cache.daemon_snapshot(r"C:\nope\a.i64")
        self.assertIn("running", snapshot)
        self.assertFalse(snapshot["running"])
        self.assertEqual(snapshot["idb_path"], r"C:\nope\a.i64")


if __name__ == "__main__":
    unittest.main(verbosity=2)
