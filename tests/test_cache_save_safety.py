"""保存期间的"空闲门控"回归测试 —— 针对实测把 IDA 卡死的那条路径。

背景（实测事故）
----------------
`MFF_READ` 的官方语义是"**只在 IDA 空闲且可安全查询数据库时**才执行"。旧实现用
`execute_sync(..., MFF_READ)` 去询问"IDA 是否空闲"，于是：

    IDB 保存中 → IDA 不是 idle → 请求排队（不执行）
                → 排队中的请求让 IDA 一直不算 idle → 循环等待 → IDA 卡死

现象：`idb_save` 完成后（`.i64` 已写盘）守护线程仍拿不到结果，缓存库再无任何写入，
IDA 界面长时间无响应。

修复后的不变量（本文件逐条钉住）：
1. 空闲判定只由**主线程定时器**写、守护线程只读，等待期间**零派发**；
2. 只有"空闲 且 距上次保存信号超过静默窗口"才允许派发；
3. 派发前逐块复查门控；门控不放行则中止本轮（保留旧快照）并稍后重试；
4. 状态探测若必须派发，只能 `db_read=False`（MFF_FAST），绝不能用 MFF_READ。
"""

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _cache_fakes import build_test_db, make_backend  # noqa: E402

from ida_pro_mcp.broker import cache_config, sqlite_cache  # noqa: E402
from ida_pro_mcp.broker.cache_writer import STATUS_READY  # noqa: E402


def _count_rows(db_path: str, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


class IdaIdleStateTests(unittest.TestCase):
    """门控状态机（纯逻辑，无 IDA、无线程）。"""

    def test_fresh_state_is_not_ready(self) -> None:
        state = sqlite_cache.IdaIdleState(quiet_sec=5.0)
        self.assertFalse(state.is_ready(now=100.0))

    def test_idle_without_save_is_ready(self) -> None:
        state = sqlite_cache.IdaIdleState()
        state.set_idle(True, now=100.0)
        self.assertTrue(state.is_ready(now=100.0))

    def test_save_marks_not_idle_and_blocks_quiet_window(self) -> None:
        state = sqlite_cache.IdaIdleState(quiet_sec=5.0)
        state.set_idle(True, now=100.0)
        state.mark_save(now=100.0)
        self.assertFalse(state.idle, "保存信号必须立刻把 idle 置否")
        self.assertFalse(state.is_ready(now=103.0), "静默窗口内不得派发")
        state.set_idle(True, now=104.0)
        self.assertFalse(state.is_ready(now=104.9), "还差 0.1s 也不行")
        self.assertTrue(state.is_ready(now=105.0), "满静默窗口后放行")

    def test_busy_state_is_never_ready(self) -> None:
        state = sqlite_cache.IdaIdleState(quiet_sec=1.0)
        state.mark_save(now=0.0)
        state.set_idle(False, now=10.0)
        self.assertFalse(state.is_ready(now=100.0))

    def test_snapshot_reports_fields(self) -> None:
        state = sqlite_cache.IdaIdleState()
        state.set_idle(True, now=1.0)
        snap = state.snapshot()
        self.assertTrue(snap["idle"])
        self.assertEqual(snap["ticks"], 1)
        self.assertIn("quiet_sec", snap)


class WaitForIdleTests(unittest.TestCase):
    """等待期间必须零派发 —— 这是卡死的直接原因。"""

    def _handle(self) -> sqlite_cache._DaemonHandle:  # noqa: SLF001
        return sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path="x.i64",
            db_path="x.i64.mcp.sqlite",
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
        )

    def test_no_dispatch_while_waiting_with_timer(self) -> None:
        handle = self._handle()
        handle.idle_timer_id = 42  # 假装主线程定时器已安装
        dispatched: list = []

        def _spy(fn, **kwargs):  # noqa: ANN001
            dispatched.append(kwargs)
            return None

        with mock.patch(
            "ida_pro_mcp.broker.cache_backend.run_on_ida_main", _spy
        ), mock.patch.object(sqlite_cache, "IDLE_WATCH_POLL_SEC", 0.01):
            thread = threading.Thread(
                target=lambda: (time.sleep(0.15), handle.idle_state.set_idle(True)),
                daemon=True,
            )
            thread.start()
            self.assertTrue(sqlite_cache._wait_for_idle(handle))  # noqa: SLF001
            thread.join(timeout=5)

        self.assertEqual(dispatched, [], "有主线程定时器时，等待期间不得派发任何请求")

    def test_stop_event_exits_waiting(self) -> None:
        handle = self._handle()
        handle.idle_timer_id = 42
        timer = threading.Timer(0.1, handle.stop_event.set)
        timer.start()
        try:
            started = time.time()
            self.assertFalse(sqlite_cache._wait_for_idle(handle))  # noqa: SLF001
            self.assertLess(time.time() - started, 5.0)
        finally:
            timer.cancel()

    def test_fallback_probe_uses_fast_flag_only(self) -> None:
        """无定时器时的兜底探测必须 db_read=False（MFF_FAST），永远不能是 MFF_READ。"""
        handle = self._handle()
        handle.idle_backend = make_backend()
        calls: list[dict] = []

        def _spy(fn, **kwargs):  # noqa: ANN001
            calls.append(kwargs)
            return True  # 探测结果：空闲

        with mock.patch(
            "ida_pro_mcp.broker.cache_backend.run_on_ida_main", _spy
        ), mock.patch.object(sqlite_cache, "IDLE_WATCH_POLL_SEC", 0.01):
            self.assertTrue(sqlite_cache._wait_for_idle(handle))  # noqa: SLF001

        self.assertTrue(calls, "兜底探测应当至少调用一次")
        self.assertTrue(
            all(call.get("db_read") is False for call in calls),
            f"兜底探测必须使用 MFF_FAST: {calls}",
        )


class BuildGatingTests(unittest.TestCase):
    """构建过程中的门控：不放行就不派发、不写库、保留旧快照。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-gate-")
        self.db = build_test_db(self.tmp)
        self.cfg = cache_config.CacheConfig(chunk_rows=4, incremental=False)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_not_ready_aborts_without_any_dispatch(self) -> None:
        dispatched: list = []

        def _spy(fn, **kwargs):  # noqa: ANN001
            dispatched.append(kwargs)
            raise AssertionError("门控未放行时不应派发到 IDA")

        with mock.patch("ida_pro_mcp.broker.cache_backend.run_on_ida_main", _spy):
            stats = sqlite_cache.build_cache(
                self.db,
                make_backend(),
                self.cfg,
                wait_ready=lambda: False,
            )

        self.assertEqual(dispatched, [], "门控未放行 → 零派发")
        self.assertTrue(stats.partial)
        self.assertIn(sqlite_cache.NOT_READY_REASON, stats.reason)
        self.assertEqual(stats.chunks, 0)
        self.assertEqual(_count_rows(self.db, "functions"), 0)
        # 首次构建被门控拦下时不能对外宣称 ready
        self.assertEqual(stats.status, "partial")

    def test_gate_closing_midway_keeps_previous_snapshot(self) -> None:
        sqlite_cache.build_cache(self.db, make_backend(), self.cfg)
        before = _count_rows(self.db, "functions")
        self.assertGreater(before, 0)

        checks = {"n": 0}

        def _ready() -> bool:
            checks["n"] += 1
            return checks["n"] <= 1  # 放行第一次，之后门控关闭（模拟保存开始）

        stats = sqlite_cache.build_cache(
            self.db,
            make_backend(),
            self.cfg,
            wait_ready=_ready,
        )
        self.assertTrue(stats.partial)
        self.assertIn(sqlite_cache.NOT_READY_REASON, stats.reason)
        self.assertEqual(
            _count_rows(self.db, "functions"), before, "门控中止不得破坏旧快照"
        )

    def test_ready_path_still_builds(self) -> None:
        stats = sqlite_cache.build_cache(
            self.db, make_backend(), self.cfg, wait_ready=lambda: True
        )
        self.assertEqual(stats.status, STATUS_READY)
        self.assertGreater(_count_rows(self.db, "functions"), 0)
        self.assertNotIn(sqlite_cache.NOT_READY_REASON, stats.reason)


class DaemonRetryTests(unittest.TestCase):
    """守护线程：门控未放行时不能干等 30 分钟，应重新排队重试。"""

    def test_daemon_retries_after_gate_blocks(self) -> None:
        tmp = tempfile.mkdtemp(prefix="ida-mcp-gate-daemon-")
        try:
            backend = make_backend()
            original_factory = sqlite_cache._backend_factory  # noqa: SLF001
            sqlite_cache._backend_factory = lambda: backend  # noqa: SLF001
            patcher = mock.patch(
                "ida_pro_mcp.broker.cache_backend.dispatch_available", lambda: False
            )
            patcher.start()
            try:
                handle = sqlite_cache._DaemonHandle(  # noqa: SLF001
                    idb_path=os.path.join(tmp, "x.i64"),
                    db_path=os.path.join(tmp, "x.i64.mcp.sqlite"),
                    thread=None,
                    stop_event=threading.Event(),
                    force_event=threading.Event(),
                )
                # 门控先关闭 0.6s，再放行
                handle.idle_state.set_idle(False)
                worker = threading.Thread(
                    target=sqlite_cache._daemon_loop,  # noqa: SLF001
                    args=(handle,),
                    daemon=True,
                )
                worker.start()
                threading.Timer(0.6, lambda: handle.idle_state.set_idle(True)).start()

                deadline = time.time() + 30
                while time.time() < deadline and handle.last_stats is None:
                    time.sleep(0.05)

                handle.stop_event.set()
                handle.force_event.set()
                worker.join(timeout=15)
                self.assertIsNotNone(handle.last_stats, "门控放行后应当完成构建")
                self.assertFalse(worker.is_alive())
            finally:
                patcher.stop()
                sqlite_cache._backend_factory = original_factory  # noqa: SLF001
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class DispatchFlagTests(unittest.TestCase):
    """`run_on_ida_main` 的标志选择（MFF_FAST vs MFF_READ）。"""

    def _fake_kernwin(self, recorded: list) -> object:
        fake = types.ModuleType("ida_kernwin")
        fake.MFF_READ = 1  # type: ignore[attr-defined]
        fake.MFF_FAST = 2  # type: ignore[attr-defined]

        def execute_sync(fn, flags):  # noqa: ANN001
            recorded.append(flags)
            return fn()

        fake.execute_sync = execute_sync  # type: ignore[attr-defined]
        return fake

    def test_db_read_true_uses_mff_read(self) -> None:
        from ida_pro_mcp.broker import cache_backend

        recorded: list = []
        with mock.patch.dict(sys.modules, {"ida_kernwin": self._fake_kernwin(recorded)}):
            self.assertEqual(cache_backend.run_on_ida_main(lambda: 7), 7)
            self.assertEqual(cache_backend.run_on_ida_main(lambda: 7, db_read=False), 7)
        self.assertEqual(recorded, [1, 2], "读库用 MFF_READ，仅探测状态用 MFF_FAST")

    def test_slow_dispatch_is_logged(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            warned = sqlite_cache._warn_if_slow_dispatch(  # noqa: SLF001
                "functions", sqlite_cache.DISPATCH_WARN_SEC * 1000.0 + 1
            )
        self.assertTrue(warned)
        self.assertIn("派发耗时", buffer.getvalue())

    def test_fast_dispatch_is_silent(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            warned = sqlite_cache._warn_if_slow_dispatch("functions", 10.0)  # noqa: SLF001
        self.assertFalse(warned)
        self.assertEqual(buffer.getvalue(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
