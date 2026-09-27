"""恶劣环境边界：缓存文件损坏、并发换表、配置与内存护栏边界、IDB 切换。

这些用例对应的都是"线上会真的发生、而且一旦发生就很难查"的场景：

- 磁盘写满 / 断电 / 杀进程 → 缓存库被写成垃圾或被截断（**曾经会永久砖掉**：
  守护线程每次重试都抛 `file is not a database`，必须手工删文件才能恢复）。
- AI 侧频繁调 `cache_status` 的同时守护线程在重建 → 换表瞬间绝不能出现
  "no such table" 或空结果窗口。
- 用户乱设环境变量（0 / 负数 / 天文数字 / 全角字符 / 空格）→ 配置必须被钳制到
  安全区间，绝不能出现 0 行分块（死循环）或负的上限。
- 一个 IDA 里切换 IDB → 旧守护线程必须停干净，且不得再往新库写。
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

from ida_pro_mcp.broker import (  # noqa: E402
    cache_config,
    cache_rss,
    cache_writer,
    sqlite_cache,
    sqlite_query,
)


def _count_rows(db_path: str, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


class ConfigGarbageTests(unittest.TestCase):
    """环境变量是"用户可写、格式不可信"的输入：必须钳制，不能信。"""

    INT_KEYS = (
        "IDA_MCP_CACHE_CHUNK_ROWS",
        "IDA_MCP_CACHE_TARGET_CHUNK_MS",
        "IDA_MCP_CACHE_MAX_ROWS",
        "IDA_MCP_CACHE_MAX_RSS_MB",
        "IDA_MCP_CACHE_SLICE_SPAN",
    )

    def test_zero_and_negative_values_are_clamped_up(self) -> None:
        cfg = cache_config.load_cache_config(
            {
                "IDA_MCP_CACHE_CHUNK_ROWS": "0",
                "IDA_MCP_CACHE_TARGET_CHUNK_MS": "-100",
                "IDA_MCP_CACHE_MAX_ROWS": "-1",
                "IDA_MCP_CACHE_MAX_RSS_MB": "-5",
                "IDA_MCP_CACHE_SLICE_SPAN": "0",
            }
        )
        self.assertGreaterEqual(cfg.chunk_rows, cache_config.MIN_CHUNK_ROWS)
        self.assertGreaterEqual(cfg.target_chunk_ms, cache_config.MIN_TARGET_CHUNK_MS)
        self.assertGreaterEqual(cfg.max_rows, 0)
        self.assertGreaterEqual(cfg.max_rss_mb, 0)
        self.assertGreater(cfg.slice_span, 0)

    def test_absurdly_large_values_are_clamped_down(self) -> None:
        cfg = cache_config.load_cache_config(
            {
                "IDA_MCP_CACHE_CHUNK_ROWS": "9" * 30,
                "IDA_MCP_CACHE_TARGET_CHUNK_MS": "9" * 30,
            }
        )
        self.assertLessEqual(cfg.chunk_rows, cache_config.MAX_CHUNK_ROWS)
        self.assertLessEqual(cfg.target_chunk_ms, cache_config.MAX_TARGET_CHUNK_MS)

    def test_unparsable_values_fall_back_to_defaults(self) -> None:
        cases = ["", "   ", "abc", "1e9", "0x10", "NaN", "inf", "12.5", "1,000", "+", "-"]
        for raw in cases:
            with self.subTest(raw=raw):
                cfg = cache_config.load_cache_config({"IDA_MCP_CACHE_CHUNK_ROWS": raw})
                self.assertEqual(cfg.chunk_rows, cache_config.DEFAULT_CHUNK_ROWS)

    def test_unicode_digits_parse_but_stay_in_range(self) -> None:
        """全角数字会被 Python 的 `int()` 接受（语言语义，不是漏洞）。

        重要的是结果**仍被钳制在安全区间**：`１２３` → 123（≥ MIN），`０` → MIN，
        绝不会出现 0 行分块导致死循环。
        """
        cfg = cache_config.load_cache_config({"IDA_MCP_CACHE_CHUNK_ROWS": "１２３"})
        self.assertEqual(cfg.chunk_rows, 123)
        self.assertGreaterEqual(cfg.chunk_rows, cache_config.MIN_CHUNK_ROWS)
        zero = cache_config.load_cache_config({"IDA_MCP_CACHE_CHUNK_ROWS": "０"})
        self.assertGreaterEqual(zero.chunk_rows, cache_config.MIN_CHUNK_ROWS)

    def test_every_int_key_survives_hostile_input(self) -> None:
        """所有整型键一起灌垃圾，配置仍然落在安全区间内。"""
        for raw in ("0", "-999", "abc", "9" * 40, "  ", "１２３"):
            with self.subTest(raw=raw):
                cfg = cache_config.load_cache_config({key: raw for key in self.INT_KEYS})
                self.assertGreaterEqual(cfg.chunk_rows, cache_config.MIN_CHUNK_ROWS)
                self.assertLessEqual(cfg.chunk_rows, cache_config.MAX_CHUNK_ROWS)
                self.assertGreater(cfg.target_chunk_ms, 0)
                self.assertGreaterEqual(cfg.max_rows, 0)
                self.assertGreaterEqual(cfg.max_rss_mb, 0)
                self.assertGreater(cfg.slice_span, 0)
                self.assertTrue(cfg.tables(), "表集合不得为空")

    def test_bool_and_choice_garbage_fall_back(self) -> None:
        cfg = cache_config.load_cache_config(
            {
                "IDA_MCP_DISABLE_CACHE": "maybe",
                "IDA_MCP_CACHE_INCREMENTAL": "sort-of",
                "IDA_MCP_CACHE_SCOPE": "everything",
                "IDA_MCP_CACHE_FINGERPRINT": "md5",
            }
        )
        self.assertFalse(cfg.disabled)
        self.assertTrue(cfg.incremental)
        self.assertEqual(cfg.scope, cache_config.SCOPE_FULL)
        self.assertEqual(cfg.fingerprint, cache_config.FINGERPRINT_SHAPE)

    def test_chunker_stays_sane_under_clamped_config(self) -> None:
        cfg = cache_config.load_cache_config({"IDA_MCP_CACHE_CHUNK_ROWS": "0"})
        chunker = cache_config.AdaptiveChunker(
            chunk_rows=cfg.chunk_rows, target_ms=cfg.target_chunk_ms
        )
        self.assertGreaterEqual(chunker.next_size(), 1)
        # 极端观测值不得把分块算成 0 或负数（那会死循环）
        chunker.observe(chunker.next_size(), 0.0)
        self.assertGreaterEqual(chunker.next_size(), 1)
        chunker.observe(chunker.next_size(), 10**9)
        self.assertGreaterEqual(chunker.next_size(), 1)
        chunker.observe(0, 5.0)
        self.assertGreaterEqual(chunker.next_size(), 1)


class RssGuardBoundaryTests(unittest.TestCase):
    """内存护栏的边界：宁可漏报也不能误报成"永远超限"或"永远不超限"。"""

    def test_limit_zero_or_negative_never_trips(self) -> None:
        self.assertFalse(cache_rss.exceeds_rss_limit(0, 10_000.0))
        self.assertFalse(cache_rss.exceeds_rss_limit(-1, 10_000.0))

    def test_exactly_at_limit_is_not_exceeded(self) -> None:
        self.assertFalse(cache_rss.exceeds_rss_limit(100, 100.0))
        self.assertTrue(cache_rss.exceeds_rss_limit(100, 100.1))

    def test_unknown_reading_never_trips(self) -> None:
        """读数未知（0.0）时不得因为"测不到"就把构建判死。"""
        self.assertFalse(cache_rss.exceeds_rss_limit(100, 0.0))
        self.assertFalse(cache_rss.exceeds_rss_limit(100, -1.0))
        with mock.patch.object(cache_rss, "current_rss_mb", lambda: 0.0):
            self.assertFalse(cache_rss.exceeds_rss_limit(100))

    def test_uses_live_reading_when_not_supplied(self) -> None:
        with mock.patch.object(cache_rss, "current_rss_mb", lambda: 512.0):
            self.assertTrue(cache_rss.exceeds_rss_limit(100))
            self.assertFalse(cache_rss.exceeds_rss_limit(1024))

    def test_current_rss_never_raises_and_is_non_negative(self) -> None:
        value = cache_rss.current_rss_mb()
        self.assertIsInstance(value, float)
        self.assertGreaterEqual(value, 0.0)

    def test_probe_failure_degrades_to_zero(self) -> None:
        saved = cache_rss._windows_probe  # noqa: SLF001
        try:
            cache_rss._windows_probe = None  # noqa: SLF001 - 强制重建探测
            with mock.patch.object(cache_rss, "_build_windows_probe", lambda: None):
                self.assertGreaterEqual(cache_rss.current_rss_mb(), 0.0)
        finally:
            cache_rss._windows_probe = saved  # noqa: SLF001


class CorruptCacheFileTests(unittest.TestCase):
    """缓存库被写坏时的自愈：隔离重建 + 诊断工具永不抛错。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-hostile-")
        self.cfg = cache_config.CacheConfig(chunk_rows=4, incremental=False)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _path(self, name: str) -> str:
        return os.path.join(self.tmp, f"{name}.mcp.sqlite")

    def _quarantined(self) -> list[str]:
        return sorted(f for f in os.listdir(self.tmp) if ".corrupt-" in f)

    def test_garbage_file_is_quarantined_and_rebuilt(self) -> None:
        path = self._path("garbage")
        pathlib.Path(path).write_bytes(b"this is definitely not a sqlite database" * 64)
        status = sqlite_query.cache_status(path)  # 诊断工具不得抛错
        self.assertEqual(status["status"], "error")
        self.assertEqual(status["degraded_reason"], "cache-unreadable")
        self.assertTrue(status["last_error"])

        stats = sqlite_cache.build_cache(path, make_backend(), self.cfg)
        self.assertEqual(stats.status, "ready")
        self.assertGreater(_count_rows(path, "functions"), 0)
        self.assertEqual(len(self._quarantined()), 1, "损坏文件应当被隔离保留取证")
        self.assertEqual(sqlite_query.cache_status(path)["status"], "ready")

    def test_truncated_file_is_rebuilt(self) -> None:
        path = self._path("truncated")
        sqlite_cache.build_cache(path, make_backend(), self.cfg)
        with open(path, "r+b") as fh:
            fh.truncate(4096)  # 合法头 + 断裂的页
        self.assertEqual(sqlite_query.cache_status(path)["status"], "error")
        stats = sqlite_cache.build_cache(path, make_backend(), self.cfg)
        self.assertEqual(stats.status, "ready")
        self.assertEqual(len(self._quarantined()), 1)

    def test_zero_byte_file_is_reported_as_empty_then_built(self) -> None:
        path = self._path("empty")
        pathlib.Path(path).touch()
        status = sqlite_query.cache_status(path)
        self.assertEqual(status["status"], "empty", "还没建过缓存 ≠ 损坏")
        self.assertEqual(status["degraded_reason"], "not-built")
        stats = sqlite_cache.build_cache(path, make_backend(), self.cfg)
        self.assertEqual(stats.status, "ready")
        self.assertEqual(self._quarantined(), [], "空文件是合法的新库，不应被隔离")

    def test_future_schema_version_is_rebuilt(self) -> None:
        path = self._path("future")
        sqlite_cache.build_cache(path, make_backend(), self.cfg)
        conn = sqlite3.connect(path)
        try:
            conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
            conn.commit()
        finally:
            conn.close()
        stats = sqlite_cache.build_cache(path, make_backend(), self.cfg)
        self.assertEqual(stats.status, "ready")
        self.assertEqual(
            cache_writer.read_meta(path).get("schema_version"),
            str(cache_writer.SCHEMA_VERSION),
        )

    def test_quarantine_failure_still_recovers(self) -> None:
        """隔离改名失败（例如被占用）时必须退化为删除重建，而不是放弃。"""
        path = self._path("locked")
        pathlib.Path(path).write_bytes(b"garbage" * 512)
        with mock.patch("os.replace", side_effect=OSError("locked by another process")):
            stats = sqlite_cache.build_cache(path, make_backend(), self.cfg)
        self.assertEqual(stats.status, "ready")
        self.assertGreater(_count_rows(path, "functions"), 0)

    def test_cache_status_survives_deleted_file(self) -> None:
        path = self._path("gone")
        sqlite_cache.build_cache(path, make_backend(), self.cfg)
        os.remove(path)
        status = sqlite_query.cache_status(path)
        self.assertFalse(status["exists"])
        self.assertEqual(status["status"], "missing")


class ConcurrentSwapTests(unittest.TestCase):
    """换表期间的并发读者：绝不能看到"空表窗口"或"no such table"。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-swap-")
        self.db = build_test_db(self.tmp)
        self.cfg = cache_config.CacheConfig(chunk_rows=4, incremental=False)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_readers_never_see_empty_or_missing_tables(self) -> None:
        sqlite_cache.build_cache(self.db, make_backend(), self.cfg)
        baseline = _count_rows(self.db, "functions")
        self.assertGreater(baseline, 0)

        errors: list[str] = []
        observed: list[int] = []
        stop = threading.Event()

        def _reader() -> None:
            while not stop.is_set():
                try:
                    count = _count_rows(self.db, "functions")
                    observed.append(count)
                    status = sqlite_query.cache_status(self.db)
                    if status["status"] not in ("ready", "building", "partial", "empty"):
                        errors.append(f"意外状态: {status['status']}")
                except Exception as exc:  # noqa: BLE001 - 就是要抓异常
                    errors.append(f"{type(exc).__name__}: {exc}")
                    return

        threads = [threading.Thread(target=_reader, daemon=True) for _ in range(3)]
        for thread in threads:
            thread.start()
        try:
            for _ in range(6):
                sqlite_cache.build_cache(self.db, make_backend(), self.cfg)
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=10)

        self.assertEqual(errors, [], f"并发读者报错: {errors[:3]}")
        self.assertTrue(observed, "读者没有采到任何样本")
        self.assertNotIn(
            0,
            observed,
            "换表期间读者看到了空表（影子表+原子切换被破坏）",
        )

    def test_status_tool_is_safe_while_building(self) -> None:
        """门控中途关闸（IDB 开始保存）时，状态工具仍要给出可用答案。"""
        sqlite_cache.build_cache(self.db, make_backend(), self.cfg)
        state = {"checks": 0}

        def _gate() -> bool:
            state["checks"] += 1
            return state["checks"] <= 1  # 放行第一块，之后关闸

        stats = sqlite_cache.build_cache(
            self.db, make_backend(), self.cfg, wait_ready=_gate
        )
        status = sqlite_query.cache_status(self.db)
        self.assertTrue(stats.partial)
        self.assertIn(status["status"], ("ready", "partial", "building"))
        self.assertGreater(_count_rows(self.db, "functions"), 0, "旧快照必须仍然可读")


class StatusTruthfulnessTests(unittest.TestCase):
    """`status` 与 `progress` 不得自相矛盾 —— AI 会据此判断"能不能用缓存"。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-status-")
        self.db = build_test_db(self.tmp)
        self.cfg = cache_config.CacheConfig(chunk_rows=4, incremental=False)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_finished_build_reports_terminal_phase(self) -> None:
        sqlite_cache.build_cache(self.db, make_backend(), self.cfg)
        status = sqlite_query.cache_status(self.db)
        self.assertEqual(status["status"], "ready")
        self.assertEqual(
            status["progress"]["phase"],
            "done",
            "构建结束后 phase 必须离开 building，否则读者会以为还在建",
        )

    def test_aborted_build_also_leaves_terminal_phase(self) -> None:
        sqlite_cache.build_cache(self.db, make_backend(), self.cfg)
        state = {"checks": 0}

        def _gate() -> bool:
            state["checks"] += 1
            return state["checks"] <= 1

        stats = sqlite_cache.build_cache(
            self.db, make_backend(), self.cfg, wait_ready=_gate
        )
        self.assertTrue(stats.partial)
        status = sqlite_query.cache_status(self.db)
        self.assertNotEqual(status["progress"]["phase"], "building")
        self.assertIn(status["status"], ("ready", "partial", "building"))


class IdbSwitchTests(unittest.TestCase):
    """一个 IDA 进程里切换 IDB：旧线程停干净，且不得串写新库。"""

    def setUp(self) -> None:
        from ida_pro_mcp.broker import cache_autostart

        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-switch-")
        self.idb_a = os.path.join(self.tmp, "a.i64")
        self.idb_b = os.path.join(self.tmp, "b.i64")
        for path in (self.idb_a, self.idb_b):
            pathlib.Path(path).write_bytes(b"idb")
        self.supervisor = cache_autostart.CacheDaemonSupervisor()

    def tearDown(self) -> None:
        self.supervisor.stop()
        # 兜底：任何仍注册着的守护线程都要停掉，否则线程会活过测试进程（泄漏）
        with sqlite_cache._daemons_lock:  # noqa: SLF001
            pending = list(sqlite_cache._daemons)  # noqa: SLF001
        for key in pending:
            sqlite_cache.stop_cache_daemon(key, timeout=10)
        with sqlite_cache._daemons_lock:  # noqa: SLF001
            sqlite_cache._daemons.clear()  # noqa: SLF001
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_switch_stops_previous_daemon_and_does_not_cross_write(self) -> None:
        backend = make_backend()
        original = sqlite_cache._backend_factory  # noqa: SLF001
        sqlite_cache._backend_factory = lambda: backend  # noqa: SLF001
        try:
            supervisor = self.supervisor
            db_a = self.idb_a + ".mcp.sqlite"
            db_b = self.idb_b + ".mcp.sqlite"
            supervisor.ensure(self.idb_a)
            self.assertTrue(_wait_for(lambda: os.path.exists(db_a)))
            supervisor.ensure(self.idb_b)
            self.assertTrue(_wait_for(lambda: os.path.exists(db_b)))
            self.assertFalse(
                sqlite_cache.daemon_snapshot(self.idb_a)["running"],
                "切换 IDB 后旧守护线程必须已停止",
            )
            stamp_a = os.path.getmtime(db_a)
            time.sleep(0.4)
            self.assertEqual(
                os.path.getmtime(db_a), stamp_a, "旧库不得再被写入（跨库串写）"
            )
        finally:
            sqlite_cache._backend_factory = original  # noqa: SLF001

    def test_switch_to_empty_path_stops_everything(self) -> None:
        supervisor = self.supervisor
        supervisor.ensure(self.idb_a)
        self.assertTrue(supervisor.current_idb)
        supervisor.sync_to_idb("")
        self.assertFalse(supervisor.current_idb)
        self.assertFalse(sqlite_cache.daemon_snapshot(self.idb_a)["running"])


def _wait_for(predicate, timeout: float = 20.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


if __name__ == "__main__":
    unittest.main(verbosity=2)
