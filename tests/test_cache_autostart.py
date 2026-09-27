"""缓存守护线程"零操作自启"单测（不需要 IDA）。

覆盖 `broker/cache_autostart.py` 的 `CacheDaemonSupervisor`：路径绑定、
IDB 切换、禁用开关、异常容忍、幂等停止，以及默认接线是否指向
`sqlite_cache.start_cache_daemon` / `stop_cache_daemon`。
"""

from __future__ import annotations

import os
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ida_pro_mcp.broker import sqlite_cache  # noqa: E402
from ida_pro_mcp.broker.cache_autostart import CacheDaemonSupervisor  # noqa: E402


class SupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.disabled = False
        self.start_error: Exception | None = None
        self.stop_error: Exception | None = None

        def _start(path: str) -> str:
            if self.start_error is not None:
                raise self.start_error
            self.started.append(path)
            return path + ".mcp.sqlite"

        def _stop(path: str) -> None:
            if self.stop_error is not None:
                raise self.stop_error
            self.stopped.append(path)

        self.supervisor = CacheDaemonSupervisor(
            start=_start,
            stop=_stop,
            disabled_probe=lambda: self.disabled,
        )

    def test_empty_path_is_ignored(self) -> None:
        for value in (None, "", "   "):
            self.assertIsNone(self.supervisor.ensure(value))
        self.assertEqual(self.started, [])
        self.assertEqual(self.supervisor.current_idb, "")

    def test_ensure_starts_and_returns_cache_path(self) -> None:
        result = self.supervisor.ensure(r"C:\bin\a.i64")
        self.assertEqual(result, r"C:\bin\a.i64.mcp.sqlite")
        self.assertEqual(self.started, [r"C:\bin\a.i64"])
        self.assertEqual(self.supervisor.current_idb, r"C:\bin\a.i64")
        self.assertEqual(self.stopped, [])

    def test_ensure_is_idempotent_without_stopping(self) -> None:
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.assertEqual(self.started, [r"C:\bin\a.i64"] * 2)
        self.assertEqual(self.stopped, [], "重复 ensure 不应停掉正在运行的守护线程")

    def test_ensure_without_argument_reuses_current(self) -> None:
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.assertEqual(self.supervisor.ensure(), r"C:\bin\a.i64.mcp.sqlite")
        self.assertEqual(self.stopped, [])

    def test_switching_idb_stops_previous(self) -> None:
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.supervisor.ensure(r"C:\bin\b.i64")
        self.assertEqual(self.stopped, [r"C:\bin\a.i64"])
        self.assertEqual(self.started, [r"C:\bin\a.i64", r"C:\bin\b.i64"])
        self.assertEqual(self.supervisor.current_idb, r"C:\bin\b.i64")

    def test_disabled_switch_prevents_start_but_records_path(self) -> None:
        self.disabled = True
        self.assertIsNone(self.supervisor.ensure(r"C:\bin\a.i64"))
        self.assertEqual(self.started, [])
        self.assertEqual(
            self.supervisor.current_idb,
            r"C:\bin\a.i64",
            "即使缓存被禁用也要记住路径，拦截层才能给出准确的 -32001 报错",
        )

    def test_enabling_after_disabled_starts_without_stop(self) -> None:
        self.disabled = True
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.disabled = False
        self.assertEqual(self.supervisor.ensure(r"C:\bin\a.i64"), r"C:\bin\a.i64.mcp.sqlite")
        self.assertEqual(self.stopped, [])
        self.assertEqual(self.started, [r"C:\bin\a.i64"])

    def test_stop_is_idempotent_and_clears_state(self) -> None:
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.supervisor.stop()
        self.supervisor.stop()
        self.assertEqual(self.stopped, [r"C:\bin\a.i64"])
        self.assertEqual(self.supervisor.current_idb, "")

    def test_start_exception_is_swallowed(self) -> None:
        self.start_error = RuntimeError("boom")
        self.assertIsNone(self.supervisor.ensure(r"C:\bin\a.i64"))
        self.assertEqual(self.supervisor.current_idb, r"C:\bin\a.i64")

    def test_stop_exception_is_swallowed(self) -> None:
        self.supervisor.ensure(r"C:\bin\a.i64")
        self.stop_error = RuntimeError("boom")
        self.supervisor.stop()  # 不应抛异常
        self.assertEqual(self.supervisor.current_idb, "")

    def test_snapshot_reports_state(self) -> None:
        empty = self.supervisor.snapshot()
        self.assertEqual(empty["idb_path"], "")
        self.assertIsNone(empty["cache_db_path"])
        self.assertFalse(empty["disabled"])

        self.supervisor.ensure(r"C:\bin\a.i64")
        snap = self.supervisor.snapshot()
        self.assertEqual(snap["idb_path"], r"C:\bin\a.i64")
        self.assertEqual(snap["cache_db_path"], r"C:\bin\a.i64.mcp.sqlite")
        self.assertFalse(snap["disabled"])

    def test_disabled_probe_exception_defaults_to_enabled(self) -> None:
        def _boom() -> bool:
            raise RuntimeError("env read failed")

        supervisor = CacheDaemonSupervisor(
            start=lambda p: p, stop=lambda p: None, disabled_probe=_boom
        )
        self.assertFalse(supervisor.disabled)
        self.assertEqual(supervisor.ensure(r"C:\bin\a.i64"), r"C:\bin\a.i64")


class DefaultWiringTests(unittest.TestCase):
    def test_default_start_stop_use_sqlite_cache(self) -> None:
        with mock.patch.object(
            sqlite_cache, "start_cache_daemon", return_value="/x.mcp.sqlite"
        ) as start_mock, mock.patch.object(sqlite_cache, "stop_cache_daemon") as stop_mock:
            supervisor = CacheDaemonSupervisor(disabled_probe=lambda: False)
            self.assertEqual(supervisor.ensure(r"C:\bin\a.i64"), "/x.mcp.sqlite")
            start_mock.assert_called_once_with(r"C:\bin\a.i64")
            supervisor.stop()
            stop_mock.assert_called_once_with(r"C:\bin\a.i64")

    def test_default_disabled_probe_reads_env(self) -> None:
        supervisor = CacheDaemonSupervisor(start=lambda p: p, stop=lambda p: None)
        with mock.patch.dict(os.environ, {"IDA_MCP_DISABLE_CACHE": "1"}, clear=False):
            self.assertTrue(supervisor.disabled)
        with mock.patch.dict(os.environ, {"IDA_MCP_DISABLE_CACHE": "0"}, clear=False):
            self.assertFalse(supervisor.disabled)


if __name__ == "__main__":
    unittest.main(verbosity=2)
