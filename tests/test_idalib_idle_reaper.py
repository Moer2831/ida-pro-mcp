"""idalib session manager 空闲回收 (T2) 单元测试。

全部不需要 IDA：`idapro` / `ida_auto` 通过 sys.modules 注入假模块，
时钟与 close_database 均可注入。
"""

import gc
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from ida_pro_mcp import idalib_session_manager as sm


class _FakeClock:
    """可推进的假时钟（返回 datetime，与 manager._now 契约一致）。"""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime(2024, 1, 1, 12, 0, 0)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)


class _FakeIDAPro:
    """idapro 替身，只实现 session manager 用到的接口。"""

    def __init__(self, *, fail_close: bool = False):
        self.opened: list[tuple[str, bool]] = []
        self.close_calls = 0
        self.fail_close = fail_close

    def open_database(self, path, run_auto_analysis=True):
        self.opened.append((str(path), bool(run_auto_analysis)))
        return 0

    def close_database(self):
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError("close_database failed")
        return 0


class _FakeIdaAuto:
    def __init__(self):
        self.waits = 0

    def auto_wait(self):
        self.waits += 1


class _FakeIdaModules:
    """把假 idapro / ida_auto 注入 sys.modules（走 _resolve_ida_module 的 sys.modules 分支）。"""

    def __init__(self, *, fail_close: bool = False):
        self.idapro = _FakeIDAPro(fail_close=fail_close)
        self.ida_auto = _FakeIdaAuto()
        self._saved: dict[str, object | None] = {}

    def __enter__(self) -> "_FakeIdaModules":
        for name, module in (("idapro", self.idapro), ("ida_auto", self.ida_auto)):
            self._saved[name] = sys.modules.get(name)
            sys.modules[name] = module  # type: ignore[assignment]
        return self

    def __exit__(self, *exc_info) -> None:
        for name, old in self._saved.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old  # type: ignore[assignment]


class IdleReaperTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.closed_calls: list[float] = []
        self.fake_modules = _FakeIdaModules()
        self.fake_modules.__enter__()
        self.addCleanup(lambda: self.fake_modules.__exit__(None, None, None))

    def make_manager(
        self,
        *,
        idle_ttl_sec: float,
        idle_sweep_sec: float = 30.0,
        close_database=None,
        inject_closer: bool = True,
    ) -> sm.IDASessionManager:
        closer = close_database
        if closer is None and inject_closer:
            def closer() -> None:  # type: ignore[misc]
                self.closed_calls.append(1.0)

        manager = sm.IDASessionManager(
            idle_ttl_sec=idle_ttl_sec,
            idle_sweep_sec=idle_sweep_sec,
            clock=self.clock,
            close_database=closer,
        )
        self.addCleanup(manager.stop_reaper)
        return manager

    def add_session(
        self,
        manager: sm.IDASessionManager,
        session_id: str,
        *,
        last_accessed: datetime | None = None,
        bind: str | None = None,
        activate: bool = False,
        active: bool = False,
        is_analyzing: bool = False,
    ) -> sm.IDASession:
        accessed = last_accessed or self.clock()
        session = sm.IDASession(
            session_id=session_id,
            input_path=Path(f"{session_id}.bin"),
            created_at=accessed,
            last_accessed=accessed,
            is_analyzing=is_analyzing,
        )
        with manager._lock:
            manager._sessions[session_id] = session
            if active:
                manager._active_session_id = session_id
        if bind is not None:
            manager.bind_context(bind, session_id, activate=activate)
        elif activate:
            with manager._lock:
                manager._active_session_id = session_id
        return session


class IdleTtlDisabledTests(IdleReaperTestBase):
    def test_ttl_zero_never_closes_anything(self):
        manager = self.make_manager(idle_ttl_sec=0)
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        self.clock.advance(10_000)

        self.assertEqual(manager.reap_idle_sessions(), [])
        self.assertIn("idle", manager._sessions)
        self.assertEqual(self.closed_calls, [])
        self.assertEqual(manager.reaper_stats()["reaped_sessions"], 0)

    def test_ttl_zero_does_not_start_background_thread(self):
        manager = self.make_manager(idle_ttl_sec=0, idle_sweep_sec=0.01)
        self.assertFalse(manager.start_reaper())
        self.assertFalse(manager.is_reaper_running())
        time.sleep(0.05)
        self.assertFalse(manager.is_reaper_running())

    def test_default_ttl_from_env_is_zero(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(sm.IDLE_TTL_ENV, None)
            manager = sm.IDASessionManager()
        self.assertEqual(manager.idle_ttl_sec, 0.0)
        self.assertEqual(manager.idle_sweep_sec, sm.DEFAULT_IDLE_SWEEP_SEC)


class IdleTtlReapTests(IdleReaperTestBase):
    def test_idle_session_is_reaped(self):
        manager = self.make_manager(idle_ttl_sec=10)
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        self.clock.advance(10.5)

        self.assertEqual(manager.reap_idle_sessions(), ["idle"])
        self.assertEqual(self.closed_calls, [1.0])
        self.assertNotIn("idle", manager._sessions)
        self.assertIsNone(manager._active_session_id)

    def test_recently_used_session_survives(self):
        manager = self.make_manager(idle_ttl_sec=10)
        self.add_session(manager, "fresh", last_accessed=self.clock(), active=True)
        self.clock.advance(9.999)

        self.assertEqual(manager.reap_idle_sessions(), [])
        self.assertIn("fresh", manager._sessions)
        self.assertEqual(self.closed_calls, [])
        self.assertEqual(manager._active_session_id, "fresh")

    def test_bound_session_survives_even_when_idle_forever(self):
        manager = self.make_manager(idle_ttl_sec=5)
        self.add_session(manager, "bound", last_accessed=self.clock(), bind="ctx", activate=True)
        self.clock.advance(10_000)

        self.assertEqual(manager.reap_idle_sessions(), [])
        self.assertIn("bound", manager._sessions)
        self.assertEqual(manager.get_context_session_id("ctx"), "bound")
        self.assertEqual(self.closed_calls, [])
        stats = manager.reaper_stats()
        self.assertGreaterEqual(stats["skipped_bound"], 1)

    def test_unbound_idle_session_reaped_while_bound_session_survives(self):
        manager = self.make_manager(idle_ttl_sec=5)
        self.add_session(manager, "bound", last_accessed=self.clock())
        manager.bind_context("ctx", "bound")
        self.add_session(manager, "free", last_accessed=self.clock(), active=True)
        self.clock.advance(6)

        self.assertEqual(manager.reap_idle_sessions(), ["free"])
        self.assertEqual(sorted(manager._sessions), ["bound"])
        # 只有"当前激活"的会话会真正调用 close_database
        self.assertEqual(self.closed_calls, [1.0])

    def test_reaping_non_active_session_does_not_touch_ida_database(self):
        manager = self.make_manager(idle_ttl_sec=5, inject_closer=False)
        self.add_session(manager, "idle", last_accessed=self.clock())  # 未激活
        self.clock.advance(6)

        self.assertEqual(manager.reap_idle_sessions(), ["idle"])
        self.assertEqual(self.fake_modules.idapro.close_calls, 0)

    def test_session_closed_exactly_at_ttl_boundary(self):
        manager = self.make_manager(idle_ttl_sec=10)
        self.add_session(manager, "edge", last_accessed=self.clock(), active=True)
        self.clock.advance(10)  # 空闲 == TTL：视为过期
        self.assertEqual(manager.reap_idle_sessions(), ["edge"])
        self.assertEqual(len(self.closed_calls), 1)

        manager2 = self.make_manager(idle_ttl_sec=10)
        self.add_session(manager2, "inside", last_accessed=self.clock())
        self.clock.advance(9.999)
        self.assertEqual(manager2.reap_idle_sessions(), [])
        self.assertIn("inside", manager2._sessions)

    def test_reap_is_idempotent(self):
        manager = self.make_manager(idle_ttl_sec=1)
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        self.clock.advance(2)

        self.assertEqual(manager.reap_idle_sessions(), ["idle"])
        self.assertEqual(manager.reap_idle_sessions(), [])
        self.assertEqual(manager.reap_idle_sessions(), [])
        self.assertEqual(self.closed_calls, [1.0])
        self.assertEqual(manager.reaper_stats()["reaped_sessions"], 1)

    def test_reap_reuses_close_session_bookkeeping(self):
        manager = self.make_manager(idle_ttl_sec=1)
        self.add_session(manager, "shared", last_accessed=self.clock(), active=True)
        manager.bind_context("ctx-a", "shared")
        manager.bind_context("ctx-b", "shared")
        # 先解绑 ctx-a，仅留 ctx-b（仍被绑定 -> 不会回收）
        self.assertTrue(manager.unbind_context("ctx-a"))
        self.clock.advance(2)
        self.assertEqual(manager.reap_idle_sessions(), [])

        # 解绑后变为可回收，close_session 必须清理激活状态与全部绑定
        self.assertTrue(manager.unbind_context("ctx-b"))
        self.assertEqual(manager.reap_idle_sessions(), ["shared"])
        self.assertIsNone(manager._active_session_id)
        self.assertEqual(manager._context_bindings, {})
        self.assertEqual(manager.list_sessions(), [])
        self.assertEqual(self.closed_calls, [1.0])

    def test_analyzing_session_is_skipped(self):
        manager = self.make_manager(idle_ttl_sec=1)
        self.add_session(manager, "busy", last_accessed=self.clock(), is_analyzing=True)
        self.clock.advance(5)

        self.assertEqual(manager.reap_idle_sessions(), [])
        self.assertIn("busy", manager._sessions)
        self.assertEqual(manager.reaper_stats()["skipped_analyzing"], 1)

    def test_close_database_error_is_recorded_not_swallowed(self):
        manager = self.make_manager(idle_ttl_sec=1, close_database=_FailingCloser())
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        self.clock.advance(2)

        with self.assertRaises(RuntimeError):
            manager.reap_idle_sessions()

        # 异常被保留在状态里，且会话不会被半关闭
        stats = manager.reaper_stats()
        self.assertEqual(stats["errors"], 1)
        self.assertIn("close_database failed", stats["last_error"] or "")
        self.assertIn("idle", manager._sessions)

    def test_open_binary_then_reap_then_reopen(self):
        # 不注入 closer：验证惰性解析走 sys.modules 里的假 idapro
        manager = self.make_manager(idle_ttl_sec=2, inject_closer=False)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
            binary = Path(handle.name)
        self.addCleanup(lambda: binary.unlink(missing_ok=True))

        session_id = manager.open_binary(binary, run_auto_analysis=True)
        self.assertEqual(self.fake_modules.idapro.opened, [(str(binary), True)])
        self.assertEqual(self.fake_modules.ida_auto.waits, 1)
        self.assertIsNotNone(manager.get_session(session_id))
        session = manager.get_session(session_id)
        self.assertEqual(session.last_accessed, self.clock())

        self.clock.advance(3)
        self.assertEqual(manager.reap_idle_sessions(), [session_id])
        self.assertEqual(self.fake_modules.idapro.close_calls, 1)

        # 回收后可以重新打开同一个文件，且走完整的 open 路径
        again = manager.open_binary(binary, run_auto_analysis=False)
        self.assertNotEqual(again, session_id)
        self.assertEqual(len(self.fake_modules.idapro.opened), 2)


class _FailingCloser:
    def __call__(self):
        raise RuntimeError("close_database failed")


class IdleReaperThreadTests(IdleReaperTestBase):
    def _wait_until(self, predicate, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    def test_background_reaper_closes_idle_session(self):
        manager = self.make_manager(idle_ttl_sec=50)
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        manager._idle_ttl_sec = 0.05  # 测试用毫秒级 TTL
        manager._idle_sweep_sec = 0.02
        self.assertTrue(manager.start_reaper())
        self.assertTrue(manager.is_reaper_running())

        # 假时钟不前进：会话不会过期
        time.sleep(0.1)
        self.assertIn("idle", manager._sessions)

        self.clock.advance(1)
        self.assertTrue(self._wait_until(lambda: "idle" not in manager._sessions))
        self.assertEqual(self.closed_calls, [1.0])

    def test_shutdown_stops_reaper_and_is_idempotent(self):
        manager = self.make_manager(idle_ttl_sec=0.05, idle_sweep_sec=0.02)
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        self.assertTrue(manager.start_reaper())

        manager.shutdown()  # 关闭会话 + 停止线程
        self.assertFalse(manager.is_reaper_running())
        self.assertEqual(self.closed_calls, [1.0])
        self.assertEqual(manager._sessions, {})

        # 幂等：重复调用不抛异常
        manager.shutdown()
        manager.shutdown(close_sessions=False)
        self.assertFalse(manager.is_reaper_running())

        # 停止后不会再有新的回收动作
        self.add_session(manager, "late", last_accessed=self.clock())
        self.clock.advance(1000)
        time.sleep(0.1)
        self.assertIn("late", manager._sessions)

    def test_start_reaper_is_idempotent(self):
        manager = self.make_manager(idle_ttl_sec=30, idle_sweep_sec=0.05)
        self.assertTrue(manager.start_reaper())
        first = manager._reaper_thread
        self.assertFalse(manager.start_reaper())
        self.assertIs(manager._reaper_thread, first)
        self.assertTrue(manager.stop_reaper())

    def test_reaper_stops_when_manager_is_collected(self):
        manager = sm.IDASessionManager(
            idle_ttl_sec=30,
            idle_sweep_sec=0.05,
            clock=self.clock,
            close_database=lambda: None,
        )
        self.assertTrue(manager.start_reaper())
        thread = manager._reaper_thread
        self.assertIsNotNone(thread)

        del manager
        gc.collect()

        self.assertTrue(
            self._wait_until(lambda: not thread.is_alive(), timeout=2.0),
            "回收线程应在 manager 被 GC 后退出",
        )

    def test_ttl_shorter_than_sweep_interval(self):
        # sweep=30s，TTL=1s：会话在 TTL 到期后应由"下一轮扫描"回收，
        # 而不是被 TTL 直接触发；手动扫描同样立刻生效。
        manager = self.make_manager(idle_ttl_sec=1, idle_sweep_sec=30)
        self.add_session(manager, "idle", last_accessed=self.clock(), active=True)
        self.clock.advance(1.5)
        self.assertEqual(manager.reap_idle_sessions(), ["idle"])
        self.assertEqual(self.closed_calls, [1.0])

        # 后台线程：TTL 远小于 sweep 时，第一次扫描（sweep 之后）才回收
        manager2 = self.make_manager(idle_ttl_sec=0.05, idle_sweep_sec=0.2)
        self.add_session(manager2, "idle2", last_accessed=self.clock(), active=True)
        manager2.start_reaper()
        self.clock.advance(1)
        time.sleep(0.05)
        self.assertIn("idle2", manager2._sessions)  # 还没到第一次扫描
        self.assertTrue(self._wait_until(lambda: "idle2" not in manager2._sessions, timeout=3.0))

    def test_reaper_racing_with_concurrent_bind_context(self):
        manager = self.make_manager(idle_ttl_sec=0.05, idle_sweep_sec=0.01)
        self.add_session(manager, "racy", last_accessed=self.clock(), active=True)
        self.clock.advance(1)  # 已过期

        errors: list[BaseException] = []
        stop = threading.Event()

        def binder() -> None:
            index = 0
            while not stop.is_set():
                index += 1
                try:
                    manager.bind_context(f"ctx-{index}", "racy")
                except ValueError as exc:
                    # 竞态下 reaper 先关闭会话是允许的，但错误必须是 "not found"
                    if "Session not found" not in str(exc):
                        errors.append(exc)
                except BaseException as exc:  # pragma: no cover - 失败时暴露问题
                    errors.append(exc)

        def reaper() -> None:
            while not stop.is_set():
                try:
                    manager.reap_idle_sessions()
                except BaseException as exc:  # pragma: no cover
                    errors.append(exc)

        threads = [threading.Thread(target=binder), threading.Thread(target=reaper)]
        for thread in threads:
            thread.start()
        time.sleep(0.4)
        stop.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(errors, [])
        with manager._lock:
            sessions = set(manager._sessions)
            bindings = set(manager._context_bindings.values())
            active = manager._active_session_id
        if "racy" in sessions:
            # bind 赢：会话仍在，且绑定/激活状态一致
            self.assertIn("racy", bindings)
            self.assertEqual(active, "racy")
        else:
            # reap 赢：bookkeeping 必须完全清理
            self.assertNotIn("racy", bindings)
            self.assertIsNone(active)
            self.assertEqual(self.closed_calls, [1.0])

        # 重复关闭不会发生：close_database 最多调用一次
        self.assertLessEqual(len(self.closed_calls), 1)


class IdleConfigTests(IdleReaperTestBase):
    def test_env_configures_ttl_and_sweep(self):
        with mock.patch.dict(
            os.environ,
            {sm.IDLE_TTL_ENV: "600", sm.IDLE_SWEEP_ENV: "45"},
            clear=False,
        ):
            manager = sm.IDASessionManager()
        self.assertEqual(manager.idle_ttl_sec, 600.0)
        self.assertEqual(manager.idle_sweep_sec, 45.0)

    def test_env_sweep_is_clamped_to_minimum(self):
        with mock.patch.dict(os.environ, {sm.IDLE_SWEEP_ENV: "0.001"}, clear=False):
            manager = sm.IDASessionManager()
        self.assertEqual(manager.idle_sweep_sec, sm.MIN_IDLE_SWEEP_SEC)

    def test_env_invalid_values_fall_back_to_defaults(self):
        with mock.patch.dict(
            os.environ,
            {sm.IDLE_TTL_ENV: "abc", sm.IDLE_SWEEP_ENV: "-5"},
            clear=False,
        ):
            manager = sm.IDASessionManager()
        self.assertEqual(manager.idle_ttl_sec, 0.0)
        self.assertEqual(manager.idle_sweep_sec, sm.MIN_IDLE_SWEEP_SEC)

    def test_negative_ttl_is_treated_as_disabled(self):
        manager = sm.IDASessionManager(idle_ttl_sec=-1)
        self.assertEqual(manager.idle_ttl_sec, 0.0)

    def test_get_session_manager_starts_reaper_only_when_ttl_set(self):
        saved = sm._session_manager
        try:
            sm._session_manager = None
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(sm.IDLE_TTL_ENV, None)
                manager = sm.get_session_manager()
            self.assertFalse(manager.is_reaper_running())

            sm._session_manager = None
            with mock.patch.dict(os.environ, {sm.IDLE_TTL_ENV: "300"}, clear=False):
                sm._session_manager = None
                manager = sm.get_session_manager()
            self.assertTrue(manager.is_reaper_running())
            self.assertEqual(manager.idle_ttl_sec, 300.0)
        finally:
            if sm._session_manager is not None:
                sm._session_manager.shutdown(close_sessions=False)
            sm._session_manager = saved


@unittest.skipUnless(os.environ.get("IDADIR"), "idalib 不可用：需要设置 IDADIR")
class RealIdalibReaperTests(unittest.TestCase):
    """真实 idalib 端到端回收测试（设置 IDADIR 后才会执行）。

    为了避免在 IDA 安装目录里留下 .i64，先把目标二进制复制到临时目录再打开。
    """

    @classmethod
    def setUpClass(cls) -> None:
        idadir = Path(os.environ["IDADIR"])
        python_dir = idadir / "idalib" / "python"
        if python_dir.is_dir() and str(python_dir) not in sys.path:
            sys.path.insert(0, str(python_dir))
        try:
            import idapro  # noqa: F401
        except ImportError as exc:  # pragma: no cover - 环境相关
            raise unittest.SkipTest(f"无法 import idapro: {exc}")
        cls.idadir = idadir

    def test_reap_closes_real_database_and_allows_reopen(self):
        candidates = ["idalib.dll", "libidalib.so", "libidalib.dylib"]
        source = next(
            (self.idadir / name for name in candidates if (self.idadir / name).exists()),
            None,
        )
        if source is None:  # pragma: no cover - 环境相关
            self.skipTest(f"在 {self.idadir} 找不到可用的测试二进制")

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            target = Path(tmp) / source.name
            target.write_bytes(source.read_bytes())

            clock = _FakeClock()
            manager = sm.IDASessionManager(
                idle_ttl_sec=10, idle_sweep_sec=1, clock=clock
            )
            try:
                session_id = manager.open_binary(target, run_auto_analysis=False)
                self.assertIn(session_id, manager._sessions)
                self.assertEqual(manager._active_session_id, session_id)

                clock.advance(11)
                self.assertEqual(manager.reap_idle_sessions(), [session_id])
                self.assertEqual(manager._sessions, {})
                self.assertEqual(manager._context_bindings, {})
                self.assertIsNone(manager._active_session_id)

                # 能再次打开说明 close_database 真正释放了当前数据库
                again = manager.open_binary(target, run_auto_analysis=False)
                self.assertNotEqual(again, session_id)
                self.assertIn(again, manager._sessions)
            finally:
                # 先释放 IDA 持有的 .id0/.i64 句柄，再删除临时目录
                manager.shutdown()


if __name__ == "__main__":
    unittest.main()
