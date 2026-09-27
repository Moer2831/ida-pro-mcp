"""真 IDA 端到端集成测试（需要 IDADIR 指向 IDA 安装目录，否则整体跳过）。

与 `test_cache_pipeline.py` 的假后端不同，这里用 **idalib 真开一个数据库**，
验证 T1 的完整链路：真实后端适配器 → 分块提取 → 影子表写入 → 只读查询层。

运行方式::

    set IDADIR=D:\\IDA
    .venv\\Scripts\\python.exe -m unittest test_cache_idalib -v
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ida_pro_mcp.broker import cache_config, sqlite_cache, sqlite_query  # noqa: E402
from ida_pro_mcp.broker.cache_backend import IdaCacheBackend  # noqa: E402

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_BINARY = _REPO_ROOT / "tests" / "crackme03.elf"


@unittest.skipUnless(
    os.environ.get("IDADIR") and _BINARY.exists(),
    "需要 IDADIR 指向 IDA 安装目录（idalib）",
)
class RealIdalibCacheTests(unittest.TestCase):
    """真 IDA + 真 SQLite 的端到端验证。"""

    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("IDADIR", os.environ.get("IDADIR", ""))
        import idapro  # type: ignore

        idapro.enable_console_messages(False)
        rc = idapro.open_database(str(_BINARY), run_auto_analysis=True)
        if rc != 0:
            raise unittest.SkipTest(f"idalib 打开数据库失败 rc={rc}")
        import ida_auto  # type: ignore

        ida_auto.auto_wait()
        cls.tmp = tempfile.mkdtemp(prefix="ida-mcp-idalib-")
        cls.db = os.path.join(cls.tmp, "crackme03.elf.mcp.sqlite")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            import idapro  # type: ignore

            idapro.close_database()
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def test_backend_matches_ida_api_counts(self) -> None:
        backend = IdaCacheBackend()
        self.assertGreater(backend.func_count(), 0)
        self.assertGreater(backend.str_count(), 0)
        self.assertGreater(backend.name_count(), 0)
        self.assertGreaterEqual(backend.import_module_count(), 0)
        first = backend.func_at(0)
        assert first is not None
        ea, name, size, has_type = first
        self.assertIsInstance(ea, int)
        self.assertIsInstance(name, str)
        self.assertGreaterEqual(size, 0)
        self.assertIsInstance(has_type, bool)

    def test_full_build_and_query_round_trip(self) -> None:
        backend = IdaCacheBackend()
        expected_functions = backend.func_count()
        expected_strings = backend.str_count()

        cfg = cache_config.CacheConfig(chunk_rows=8)  # 故意用小块，确保分块路径被走到
        stats = sqlite_cache.build_cache(
            self.db, backend, cfg, idb_mtime=os.path.getmtime(_BINARY)
        )

        self.assertEqual(stats.status, "ready", stats.reason)
        self.assertEqual(stats.functions, expected_functions)
        self.assertEqual(stats.strings, expected_strings)
        self.assertGreater(stats.chunks, 1, "小块配置下应当发生多次分块提取")
        self.assertGreater(stats.peak_rss_mb, 0.0, "RSS 护栏读数应当可用")
        self.assertFalse(stats.partial, stats.reason)

        # 只读查询层能读到刚建好的数据
        status = sqlite_query.cache_status(self.db)
        self.assertTrue(status["exists"])
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["functions"], expected_functions)
        self.assertEqual(status["counts_source"], "meta")
        self.assertGreaterEqual(status["progress"]["peak_rss_mb"], 0.0)

        funcs = sqlite_query.list_funcs(self.db, limit=5)
        self.assertEqual(funcs["total"], expected_functions)
        self.assertLessEqual(len(funcs["items"]), 5)

        # 真正的正则 / 字面量 / 前缀三种过滤都要能用
        literal = sqlite_query.find_regex(self.db, "lib", limit=5, include_xrefs=True)
        prefixed = sqlite_query.find_regex(self.db, "^lib", limit=5, include_xrefs=False)
        regex = sqlite_query.find_regex(self.db, r"^lib.*\.so", limit=5, include_xrefs=False)
        for result in (literal, prefixed, regex):
            self.assertIn("total", result)
            self.assertIsInstance(result["total"], int)
        self.assertLessEqual(prefixed["total"], literal["total"])

        # ea 索引确实建好了（历史实现缺这三个索引，导致 ORDER BY ea 全表排序）
        conn = sqlite3.connect(self.db)
        indexes = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        conn.close()
        for expected in ("idx_strings_ea", "idx_functions_ea", "idx_globals_ea", "idx_imports_ea"):
            self.assertIn(expected, indexes)

    def test_incremental_second_build_skips_everything(self) -> None:
        backend = IdaCacheBackend()
        cfg = cache_config.CacheConfig(chunk_rows=16)
        first = sqlite_cache.build_cache(self.db, backend, cfg)
        second = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertEqual(first.functions, second.functions)
        self.assertEqual(
            set(second.tables_skipped),
            {"functions", "function_xrefs", "strings", "string_xrefs", "globals", "imports"},
            f"指纹未变时应整表跳过；reason={second.reason}",
        )
        self.assertEqual(second.status, "ready")

    def test_scope_minimal_skips_xref_tables(self) -> None:
        backend = IdaCacheBackend()
        cfg = cache_config.CacheConfig(chunk_rows=64, scope=cache_config.SCOPE_MINIMAL)
        stats = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertEqual(stats.status, "ready")
        self.assertEqual(stats.string_xrefs, 0)
        self.assertEqual(stats.function_xrefs, 0)
        self.assertGreater(stats.functions, 0)
        self.assertGreater(stats.strings, 0)

    def test_max_rows_guard_aborts_without_losing_snapshot(self) -> None:
        backend = IdaCacheBackend()
        sqlite_cache.build_cache(self.db, backend, cache_config.CacheConfig(chunk_rows=64))
        before = sqlite_query.cache_status(self.db)["functions"]

        cfg = cache_config.CacheConfig(chunk_rows=2, incremental=False, max_rows=1)
        stats = sqlite_cache.build_cache(self.db, backend, cfg)
        self.assertTrue(stats.partial)
        self.assertTrue(stats.tables_aborted)
        self.assertEqual(stats.status, "ready", "已有快照时必须继续可用")
        self.assertEqual(sqlite_query.cache_status(self.db)["functions"], before)


class DaemonApiTests(unittest.TestCase):
    """守护线程 API 的无 IDA 行为（禁用开关 / 幂等 / 诊断快照）。"""

    def test_disabled_cache_never_starts_daemon(self) -> None:
        previous = os.environ.get("IDA_MCP_DISABLE_CACHE")
        os.environ["IDA_MCP_DISABLE_CACHE"] = "1"
        try:
            self.assertIsNone(sqlite_cache.start_cache_daemon(r"C:\nonexistent\x.i64"))
        finally:
            if previous is None:
                os.environ.pop("IDA_MCP_DISABLE_CACHE", None)
            else:
                os.environ["IDA_MCP_DISABLE_CACHE"] = previous

    def test_snapshot_for_unknown_idb(self) -> None:
        snapshot = sqlite_cache.daemon_snapshot(r"C:\nonexistent\y.i64")
        self.assertFalse(snapshot["running"])

    def test_refresh_for_unknown_idb_returns_false(self) -> None:
        self.assertFalse(sqlite_cache.request_refresh(r"C:\nonexistent\z.i64"))

    def test_stop_unknown_daemon_is_noop(self) -> None:
        sqlite_cache.stop_cache_daemon(r"C:\nonexistent\w.i64")  # 不应抛异常

    def test_resolve_cache_path(self) -> None:
        self.assertEqual(
            sqlite_cache.resolve_cache_path(r"C:\a\b.i64"), r"C:\a\b.i64.mcp.sqlite"
        )
        self.assertIsNone(sqlite_cache.resolve_cache_path(""))


class PluginLifecycleTests(unittest.TestCase):
    """插件入口的缓存生命周期接线（需要 IDA：`ida_mcp.py` 顶层 import idaapi）。"""

    @classmethod
    def setUpClass(cls) -> None:
        if not os.environ.get("IDADIR"):
            raise unittest.SkipTest("需要 IDADIR")
        # idalib 必须先加载：它才会把 IDA 自带的 python 目录接进 sys.path，
        # 否则 `import idaapi`（插件入口的顶层依赖）会失败。
        try:
            import idapro  # type: ignore  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f"idalib 不可用: {exc}")

        import importlib.util

        plugin_path = _REPO_ROOT / "src" / "ida_pro_mcp" / "ida_mcp.py"
        spec = importlib.util.spec_from_file_location("_ida_mcp_plugin_under_test", plugin_path)
        if spec is None or spec.loader is None:
            raise unittest.SkipTest("无法加载插件入口模块")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.plugin_module = module

    def test_plugin_exposes_cache_lifecycle_hooks(self) -> None:
        plugin_cls = self.plugin_module.MCP
        for attr in ("_ensure_cache_daemon", "_stop_cache_daemon", "_install_idb_hooks"):
            self.assertTrue(hasattr(plugin_cls, attr), f"插件缺少 {attr}")

    def test_idb_hooks_can_be_installed_and_removed(self) -> None:
        import ida_idp

        events: list[str] = []

        class _Hook(ida_idp.IDB_Hooks):
            def loaded(self, *_args):
                events.append("loaded")
                return 0

            def closebase(self):
                events.append("closebase")
                return 0

        hook = _Hook()
        hook.hook()
        try:
            self.assertIsNotNone(hook)
        finally:
            hook.unhook()


if __name__ == "__main__":
    unittest.main(verbosity=2)
