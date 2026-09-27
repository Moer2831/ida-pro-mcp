"""生产事故回归：把三次真实事故的"形状"锁成可执行断言。

事故档案（都发生在真实 IDA 上，不是理论风险）

1. **保存即卡死**（2.1.1）：用 `execute_sync(MFF_READ)` 去"询问 IDA 是否空闲"。
   MFF_READ 的语义是"只在 IDA 空闲且可安全查询数据库时才执行"，于是请求排队等空闲、
   排队的请求又让 IDA 一直不算空闲 —— 循环等待，IDA 主线程锁死。
2. **启动即卡死**（2.1.1）：在 `IDB_Hooks.loaded()`（**数据库加载序列内部**被调用）
   里注册 UI 定时器，主线程锁死：启动即无响应、CPU 零增长。
3. **启动即卡死**（2.1.2）：在**定时器回调内部**调用 `register_timer()`，同样锁死。

三次事故的共同形状只有两类：

- **在错误的上下文里碰内核/主线程注册表**（定时器、钩子）→ 这类调用只允许发生在
  插件 `init()` 这一条路径上；守护线程的启动路径必须零副作用。
- **把"等 IDA 空闲"实现成对 IDA 的同步派发** → 等待路径只能睡眠 + 发 MFF_FAST
  状态探测，绝不能发 MFF_READ。

本文件用一个假 IDA 内核把这些 API 全部记录下来，于是上面三类事故在没有 IDA 的
CI 里也能被复现与拦截（真实环境另用 `ida.exe -L` 日志 + `Responding`/CPU 采样验证）。
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _cache_fakes import FakeBackend  # noqa: E402

from ida_pro_mcp.broker import cache_autostart, cache_config, sqlite_cache  # noqa: E402

# 会被装进 sys.modules 的假 IDA 模块
_IDA_MODULES = (
    "ida_kernwin",
    "ida_idp",
    "ida_auto",
    "idaapi",
    "ida_funcs",
    "ida_name",
    "ida_nalt",
    "ida_typeinf",
    "ida_bytes",
    "ida_segment",
    "ida_idaapi",
    "idautils",
)

# 只需要"存在但一用就炸"的模块（这些 API 在真实代码里都被 try/except 包住）
_DEFAULT_HOSTILE = ("ida_bytes", "ida_segment", "ida_typeinf")


class _Func:
    def __init__(self, start_ea: int, end_ea: int) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea


class _StringItem:
    def __init__(self, ea: int, text: str) -> None:
        self.ea = ea
        self._text = text

    def __str__(self) -> str:
        return self._text


class _Strings:
    """假的 `idautils.Strings`。"""

    def __init__(self) -> None:
        self._items = [_StringItem(0x408000, "hello")]

    @property
    def size(self) -> int:
        return len(self._items)

    def __getitem__(self, index: int) -> _StringItem:
        return self._items[index]


class FakeIda:
    """假 IDA 内核：记录一切"会影响主线程/内核注册表"的调用。

    - `register_timer` / `unregister_timer`：事故 2、3 的根源，启动路径必须恒为 0；
    - `IDB_Hooks` 子类的 `hook()` / `unhook()`：钩子纪律（多一个都是泄漏）；
    - `execute_sync` 的 flags：派发纪律（等待期间绝不能出现 MFF_READ）。

    `hostile_modules` 里的模块**一个属性都不提供**，访问即抛异常 —— 用来验证
    "IDA API 大面积失败时守护线程仍然活着、仍然能被停掉、钩子仍然被注销"。
    `ida_kernwin` / `ida_idp` 永远可用（它们负责记录，不参与注入）。
    """

    MFF_READ = 1
    MFF_FAST = 2
    MFF_WRITE = 4

    def __init__(
        self,
        *,
        idle: bool = True,
        hostile_modules: tuple[str, ...] = _DEFAULT_HOSTILE,
    ) -> None:
        self.idle = idle
        self.hostile_modules = set(hostile_modules)
        self.timer_registrations: list[tuple[int, object]] = []
        self.timer_unregistrations: list[int] = []
        self.hook_events: list[str] = []
        self.live_hooks = 0
        self.exec_flags: list[int] = []
        self._saved: dict[str, object] = {}
        self._installed = False

    # -- 上下文管理 -------------------------------------------------------

    def __enter__(self) -> FakeIda:
        self.install()
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.uninstall()
        return False

    def install(self) -> None:
        if self._installed:
            return
        self._installed = True
        for name in _IDA_MODULES:
            self._saved[name] = sys.modules.get(name)  # type: ignore[assignment]
            sys.modules[name] = self._build_module(name)

    def uninstall(self) -> None:
        if not self._installed:
            return
        self._installed = False
        for name, previous in self._saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous  # type: ignore[assignment]
        self._saved.clear()

    def fast_probes(self) -> int:
        return sum(1 for flag in self.exec_flags if flag == self.MFF_FAST)

    def db_reads(self) -> int:
        return sum(1 for flag in self.exec_flags if flag == self.MFF_READ)

    # -- 模块构造 ---------------------------------------------------------

    def _module(self, name: str, **attrs: object) -> types.ModuleType:
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        if name in self.hostile_modules:
            def _hostile(attr: str, _name: str = name) -> object:
                raise RuntimeError(f"{_name}.{attr} 不可用（注入的恶意环境）")

            module.__getattr__ = _hostile  # type: ignore[attr-defined]
        return module

    def _build_module(self, name: str) -> types.ModuleType:
        rec = self

        if name == "ida_kernwin":

            def execute_sync(callback, flags):  # noqa: ANN001
                rec.exec_flags.append(int(flags))
                callback()  # 主线程语义：立即执行
                return 1

            def register_timer(interval, callback):  # noqa: ANN001
                rec.timer_registrations.append((int(interval), callback))
                return len(rec.timer_registrations)

            def unregister_timer(timer_id):  # noqa: ANN001
                rec.timer_unregistrations.append(int(timer_id))
                return 1

            return self._module(
                name,
                MFF_READ=self.MFF_READ,
                MFF_FAST=self.MFF_FAST,
                MFF_WRITE=self.MFF_WRITE,
                execute_sync=execute_sync,
                register_timer=register_timer,
                unregister_timer=unregister_timer,
                is_idaq=lambda: False,
                msg=lambda *a, **k: None,
                UI_Hooks=type("UI_Hooks", (), {}),
            )

        if name == "ida_idp":

            class IDB_Hooks:  # noqa: N801 - 刻意与 IDAPython 同名
                def hook(self) -> int:
                    rec.hook_events.append("hook")
                    rec.live_hooks += 1
                    return 1

                def unhook(self) -> None:
                    rec.hook_events.append("unhook")
                    rec.live_hooks -= 1

            return self._module(name, IDB_Hooks=IDB_Hooks)

        # 恶意模块：只有 __getattr__（访问任何属性都炸）
        if name in self.hostile_modules:
            return self._module(name)

        if name == "ida_auto":
            return self._module(name, auto_is_ok=lambda: rec.idle, auto_wait=lambda: True)

        if name == "ida_funcs":
            funcs = {
                0x401000: _Func(0x401000, 0x401020),
                0x402000: _Func(0x402000, 0x402030),
            }
            order = list(funcs.values())
            return self._module(
                name,
                get_func_qty=lambda: len(order),
                getn_func=lambda i: order[i] if 0 <= i < len(order) else None,
                get_func_name=lambda ea: f"sub_{ea:X}",
                get_func=lambda ea: funcs.get(ea),
            )

        if name == "ida_name":
            names = [(0x403000, "g_counter")]
            return self._module(
                name,
                get_nlist_size=lambda: len(names),
                get_nlist_ea=lambda i: names[i][0],
                get_nlist_name=lambda i: names[i][1],
            )

        if name == "ida_nalt":
            return self._module(
                name,
                get_tinfo=lambda *a, **k: False,
                get_import_module_qty=lambda: 1,
                get_import_module_name=lambda i: "KERNEL32",
                enum_import_names=lambda i, cb: (cb(0x404000, "Sleep", 0), None)[1],
            )

        if name == "idautils":
            return self._module(name, Strings=_Strings, XrefsTo=lambda ea, flags: [])

        if name in ("idaapi", "ida_idaapi"):
            return self._module(
                name,
                get_func=lambda ea: None,
                get_item_size=lambda ea: 4,
                getseg=lambda ea: None,
                get_segm_name=lambda seg: "",
                get_inf_attr=lambda attr: 0,
            )

        return self._module(name)


def _wait_until(predicate, timeout: float = 15.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


class _FakeIdaTestBase(unittest.TestCase):
    """给需要真守护线程的用例准备临时目录、异常钩子与清理。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ida-mcp-incident-")
        self.idb = os.path.join(self.tmp, "target.i64")
        pathlib.Path(self.idb).write_bytes(b"fake idb payload")
        self._started: list[str] = []
        self._thread_errors: list[BaseException] = []
        self._previous_excepthook = threading.excepthook
        threading.excepthook = self._record_thread_exception

    def tearDown(self) -> None:
        for idb in self._started:
            try:
                sqlite_cache.stop_cache_daemon(idb, timeout=15)
            except Exception:  # noqa: BLE001 - 清理失败不应掩盖断言
                pass
        with sqlite_cache._daemons_lock:  # noqa: SLF001
            leaked = list(sqlite_cache._daemons)  # noqa: SLF001
            sqlite_cache._daemons.clear()  # noqa: SLF001
        threading.excepthook = self._previous_excepthook
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.assertEqual(leaked, [], f"守护线程句柄泄漏: {leaked}")
        self.assertEqual(
            [repr(e) for e in self._thread_errors],
            [],
            "守护线程不得有未捕获异常逃逸（会静默杀死缓存）",
        )

    def _record_thread_exception(self, args) -> None:  # noqa: ANN001
        self._thread_errors.append(args.exc_value)

    def track(self, idb_path: str) -> str:
        self._started.append(idb_path)
        return idb_path

    def start(self, idb_path: str | None = None) -> str | None:
        idb_path = idb_path or self.idb
        self._started.append(idb_path)
        return sqlite_cache.start_cache_daemon(idb_path)

    def cache_db(self, idb_path: str | None = None) -> str:
        return (idb_path or self.idb) + ".mcp.sqlite"


class MainThreadHeartbeatTests(unittest.TestCase):
    """主线程心跳闸：主线程被长任务占住时，一律不许派发。

    实测事故（2.1.3 复现）：密集写操作之后保存 IDB，守护线程正好在保存开始前后
    派发了 `MFF_READ`，请求排进 IDA 队列，而 `save_database()` 内部的等待又在等
    队列排空 —— IDA 全 16 个线程停在 Wait、CPU 冻结在 100.6s、界面无响应。
    根因是"空闲标志是过期采样"：主线程卡住时定时器不再刷新，标志停在 True。
    """

    def _handle(self, *, ticks: int) -> sqlite_cache._DaemonHandle:  # noqa: SLF001
        handle = sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path="x.i64",
            db_path="x.i64.mcp.sqlite",
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
            idle_backend=FakeBackend(idle=True),
        )
        # 直接置位，避免 set_idle() 顺带把 ticks 加一（ticks==0 表示"无插件定时器"）
        handle.idle_state.idle = True
        handle.idle_state.ticks = ticks
        return handle

    def test_fresh_heartbeat_allows_dispatch(self) -> None:
        handle = self._handle(ticks=1)
        sqlite_cache.refresh_idle_states()  # 主线程刚心跳过
        self.assertTrue(sqlite_cache._gate_ready(handle))  # noqa: SLF001

    def test_stale_heartbeat_blocks_dispatch(self) -> None:
        handle = self._handle(ticks=1)  # 有插件定时器（ticks>0）
        with mock.patch.object(sqlite_cache, "_heartbeat_age", lambda: 30.0):
            self.assertFalse(
                sqlite_cache._gate_ready(handle),  # noqa: SLF001
                "主线程心跳过期（=卡在长任务里）时绝不能派发 MFF_READ",
            )

    def test_never_heartbeat_falls_back_to_plain_gate(self) -> None:
        """从未有过心跳（无头/单测）时不受心跳约束，否则会把无 IDA 场景永久挡住。"""
        handle = self._handle(ticks=1)
        with mock.patch.object(sqlite_cache, "_last_heartbeat", 0.0):
            self.assertTrue(sqlite_cache._gate_ready(handle))  # noqa: SLF001

    def test_stale_heartbeat_after_first_tick_blocks(self) -> None:
        """一旦有过心跳（插件定时器跑过），停跳就必须挡住派发。"""
        handle = self._handle(ticks=1)
        with mock.patch.object(sqlite_cache, "_last_heartbeat", time.monotonic()):
            self.assertTrue(sqlite_cache._gate_ready(handle))  # noqa: SLF001
            with mock.patch.object(sqlite_cache, "_heartbeat_age", lambda: 99.0):
                self.assertFalse(sqlite_cache._gate_ready(handle))  # noqa: SLF001

    def test_fallback_mode_ignores_heartbeat(self) -> None:
        """没有插件定时器（无 IDA / 单测）时退化为纯门控，不能被心跳卡住。"""
        handle = self._handle(ticks=0)
        with mock.patch.object(sqlite_cache, "_last_heartbeat", 0.0):
            self.assertTrue(sqlite_cache._gate_ready(handle))  # noqa: SLF001

    def test_closed_gate_still_wins(self) -> None:
        handle = self._handle(ticks=1)
        sqlite_cache.refresh_idle_states()
        handle.idle_state.set_idle(False)  # 门控本身关闭
        self.assertFalse(sqlite_cache._gate_ready(handle))  # noqa: SLF001

    def test_refresh_updates_heartbeat(self) -> None:
        with mock.patch.object(sqlite_cache, "_last_heartbeat", 0.0):
            sqlite_cache.refresh_idle_states()
            self.assertLessEqual(sqlite_cache._heartbeat_age(), 1.0)  # noqa: SLF001

    def test_build_cache_receives_gated_wait_ready(self) -> None:
        """`_run_build_once` 必须把门控（而非裸的 is_ready）交给 build_cache。"""
        handle = self._handle(ticks=1)
        seen: list[object] = []

        def _fake_build(db_path, backend, config, **kwargs):  # noqa: ANN001
            seen.append(kwargs.get("wait_ready"))
            return sqlite_cache.CacheStats()

        with mock.patch.object(sqlite_cache, "build_cache", _fake_build):
            sqlite_cache._run_build_once(handle, FakeBackend(), cache_config.load_cache_config({}))  # noqa: SLF001
        self.assertEqual(len(seen), 1)
        gate = seen[0]
        self.assertIsNotNone(gate, "构建必须收到门控回调")
        with mock.patch.object(sqlite_cache, "_heartbeat_age", lambda: 30.0):
            self.assertFalse(gate(), "交给构建的门控必须包含心跳检查")  # type: ignore[operator]


class StartupDisciplineTests(_FakeIdaTestBase):
    """事故 2/3 的运行时回归：启动路径零内核副作用。"""

    def test_daemon_start_registers_no_ui_timer(self) -> None:
        with FakeIda() as fake:
            self.assertIsNotNone(self.start())
            self.assertTrue(
                _wait_until(lambda: os.path.exists(self.cache_db())),
                "守护线程没有产出缓存库",
            )
            self.assertEqual(
                fake.timer_registrations,
                [],
                "守护线程启动路径不得注册 UI 定时器（事故 2/3：启动即锁死主线程）",
            )
            self.assertEqual(fake.timer_unregistrations, [])

    def test_daemon_start_registers_exactly_one_idb_hook(self) -> None:
        with FakeIda() as fake:
            self.start()
            self.assertEqual(
                fake.hook_events,
                ["hook"],
                f"启动只应注册一个 IDB 保存钩子，实际 {fake.hook_events}",
            )
            self.assertEqual(fake.live_hooks, 1)

    def test_stop_unhooks_the_idb_hook(self) -> None:
        with FakeIda() as fake:
            self.start()
            sqlite_cache.stop_cache_daemon(self.idb, timeout=15)
            self.assertEqual(fake.live_hooks, 0, "停止守护线程必须注销 IDB 钩子（否则泄漏）")
            sqlite_cache.stop_cache_daemon(self.idb, timeout=15)  # 幂等
            self.assertEqual(fake.hook_events, ["hook", "unhook"])

    def test_switch_idb_never_leaves_two_live_hooks(self) -> None:
        other = self.track(os.path.join(self.tmp, "other.i64"))
        pathlib.Path(other).write_bytes(b"fake idb payload")
        with FakeIda() as fake, mock.patch.dict(
            os.environ, {"IDA_MCP_DISABLE_CACHE": "0"}, clear=False
        ):
            supervisor = cache_autostart.CacheDaemonSupervisor()
            self.track(self.idb)
            supervisor.ensure(self.idb)
            supervisor.ensure(other)  # 切库
            self.assertEqual(
                fake.live_hooks,
                1,
                f"切换 IDB 后必须只剩一个钩子，实际 {fake.hook_events}",
            )
            supervisor.stop()
            self.assertEqual(fake.live_hooks, 0, f"停止后不得残留钩子: {fake.hook_events}")

    def test_disabled_cache_starts_nothing(self) -> None:
        with FakeIda() as fake, mock.patch.dict(
            os.environ, {"IDA_MCP_DISABLE_CACHE": "1"}, clear=False
        ):
            self.assertIsNone(self.start())
            self.assertEqual(fake.hook_events, [])
            self.assertEqual(fake.timer_registrations, [])
            self.assertFalse(os.path.exists(self.cache_db()))


class DispatchDisciplineTests(_FakeIdaTestBase):
    """事故 1 的运行时回归：等待 IDA 空闲时绝不派发 MFF_READ。"""

    def test_no_db_read_dispatch_while_ida_is_busy(self) -> None:
        with FakeIda(idle=False) as fake:
            self.start()
            time.sleep(0.6)
            self.assertEqual(
                fake.db_reads(),
                0,
                "IDA 正忙时不得派发 MFF_READ（会排成循环等待、锁死主线程）",
            )
            self.assertGreater(
                fake.fast_probes(),
                0,
                "等待期间应由 MFF_FAST 兜底探测空闲状态",
            )

    def test_db_read_dispatch_appears_only_after_idle(self) -> None:
        with FakeIda(idle=False) as fake:
            self.start()
            time.sleep(0.4)
            self.assertEqual(fake.db_reads(), 0)
            fake.idle = True  # 模拟 IDA 结束分析 / 保存完成
            sqlite_cache.refresh_idle_states()
            self.assertTrue(
                _wait_until(lambda: fake.db_reads() > 0, timeout=10),
                "空闲放行后应当开始正常提取（MFF_READ）",
            )

    def test_plugin_timer_refresh_drives_the_gate(self) -> None:
        """插件定时器（refresh_idle_states）是门控的唯一驱动源。"""
        with FakeIda(idle=False) as fake:
            self.start()
            time.sleep(0.4)
            snapshot = sqlite_cache.daemon_snapshot(self.idb)
            self.assertGreaterEqual(snapshot["builds"], 0)
            fake.idle = True
            refreshed = sqlite_cache.refresh_idle_states()
            self.assertEqual(refreshed, 1, "应当只刷新一个守护线程")
            self.assertTrue(
                _wait_until(
                    lambda: (sqlite_cache.daemon_snapshot(self.idb).get("builds") or 0) >= 1,
                    timeout=10,
                ),
                "插件定时器刷新后应当完成一轮构建",
            )
            self.assertIsNotNone(sqlite_cache.daemon_snapshot(self.idb)["last_stats"])

    def test_wait_for_idle_probe_rate_is_bounded(self) -> None:
        """兜底探测必须是"慢轮询"，不能忙等烧 CPU。"""
        handle = sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path="x.i64",
            db_path="x.i64.mcp.sqlite",
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
            idle_backend=FakeBackend(idle=False),
        )
        calls: list[dict] = []

        def _spy(fn, **kwargs):  # noqa: ANN001
            calls.append(kwargs)
            return False  # 永远"不空闲"

        with mock.patch(
            "ida_pro_mcp.broker.cache_backend.run_on_ida_main", _spy
        ), mock.patch.object(sqlite_cache, "IDLE_WATCH_POLL_SEC", 0.05):
            timer = threading.Timer(0.5, handle.stop_event.set)
            timer.start()
            try:
                self.assertFalse(sqlite_cache._wait_for_idle(handle))  # noqa: SLF001
            finally:
                timer.cancel()
        self.assertLessEqual(
            len(calls), 30, f"0.5s 内探测 {len(calls)} 次 —— 疑似忙等（应为 ~10 次）"
        )
        self.assertTrue(
            all(call.get("db_read") is False for call in calls),
            "探测必须用 MFF_FAST",
        )


class LifecycleBoundaryTests(_FakeIdaTestBase):
    """停止 / 重启 / 恶意环境下的生命周期边界。"""

    def test_stop_is_bounded_when_ida_never_idle(self) -> None:
        with FakeIda(idle=False):
            self.start()
            time.sleep(0.3)
            started = time.time()
            sqlite_cache.stop_cache_daemon(self.idb, timeout=10)
            elapsed = time.time() - started
            self.assertLess(elapsed, 5.0, f"停止耗时 {elapsed:.2f}s —— 等待路径未能及时退出")
            self.assertFalse(sqlite_cache.daemon_snapshot(self.idb)["running"])

    def test_no_thread_leak_across_restarts(self) -> None:
        with FakeIda() as fake:
            for _ in range(5):
                self.start()
                sqlite_cache.stop_cache_daemon(self.idb, timeout=15)
            leaked = [
                t.name for t in threading.enumerate() if t.name.startswith("mcp-sqlite-cache:")
            ]
            self.assertEqual(leaked, [], f"守护线程泄漏: {leaked}")
            self.assertEqual(fake.live_hooks, 0, f"钩子泄漏: {fake.hook_events}")

    def test_hostile_ida_keeps_daemon_alive_and_stoppable(self) -> None:
        everything = tuple(m for m in _IDA_MODULES if m not in ("ida_kernwin", "ida_idp"))
        with FakeIda(hostile_modules=everything) as fake:
            self.start()
            time.sleep(0.6)
            self.assertIn("running", sqlite_cache.daemon_snapshot(self.idb))
            sqlite_cache.stop_cache_daemon(self.idb, timeout=10)
            self.assertFalse(sqlite_cache.daemon_snapshot(self.idb)["running"])
            self.assertEqual(fake.live_hooks, 0, "即使 IDA API 全炸也必须注销钩子")

    def test_extraction_failure_is_recorded_not_fatal(self) -> None:
        """门控放行但提取全失败：记录错误、线程不崩、仍可停止。"""
        broken = ("ida_funcs", "ida_name", "ida_nalt", "idautils")
        with FakeIda(idle=True, hostile_modules=broken) as fake:
            self.start()
            ok = _wait_until(
                lambda: (
                    sqlite_cache.daemon_snapshot(self.idb).get("last_error") is not None
                    or (
                        sqlite_cache.daemon_snapshot(self.idb).get("last_stats") or {}
                    ).get("status")
                    in ("error", "partial", "ready")
                ),
                timeout=15,
            )
            self.assertTrue(ok, "提取失败后应当有可观测的状态（last_error / last_stats）")
            self.assertFalse(
                self._thread_errors, f"提取失败不得杀死守护线程: {self._thread_errors}"
            )
            sqlite_cache.stop_cache_daemon(self.idb, timeout=10)
            self.assertEqual(fake.live_hooks, 0)

    def test_refresh_idle_states_tolerates_odd_handles(self) -> None:
        handles = {
            "no-backend": sqlite_cache._DaemonHandle(  # noqa: SLF001
                idb_path="a.i64",
                db_path="a.i64.mcp.sqlite",
                thread=None,
                stop_event=threading.Event(),
                force_event=threading.Event(),
            ),
            "with-backend": sqlite_cache._DaemonHandle(  # noqa: SLF001
                idb_path="b.i64",
                db_path="b.i64.mcp.sqlite",
                thread=None,
                stop_event=threading.Event(),
                force_event=threading.Event(),
                idle_backend=FakeBackend(idle=True),
            ),
        }

        class _Exploding:
            def is_idle(self) -> bool:
                raise RuntimeError("探测炸了")

        handles["exploding"] = sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path="c.i64",
            db_path="c.i64.mcp.sqlite",
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
            idle_backend=_Exploding(),
        )
        with sqlite_cache._daemons_lock:  # noqa: SLF001
            sqlite_cache._daemons.update(handles)  # noqa: SLF001
        try:
            refreshed = sqlite_cache.refresh_idle_states()
        finally:
            with sqlite_cache._daemons_lock:  # noqa: SLF001
                for key in handles:
                    sqlite_cache._daemons.pop(key, None)  # noqa: SLF001
        # 只有配了后端且探测不炸的那一个被刷新；其余被跳过而不是抛异常
        self.assertEqual(refreshed, 1)
        self.assertEqual(handles["with-backend"].idle_state.ticks, 1)
        self.assertEqual(handles["no-backend"].idle_state.ticks, 0)
        self.assertEqual(handles["exploding"].idle_state.ticks, 0)

    def test_refresh_idle_states_on_empty_registry(self) -> None:
        with sqlite_cache._daemons_lock:  # noqa: SLF001
            saved = dict(sqlite_cache._daemons)  # noqa: SLF001
            sqlite_cache._daemons.clear()  # noqa: SLF001
        try:
            self.assertEqual(sqlite_cache.refresh_idle_states(), 0)
        finally:
            with sqlite_cache._daemons_lock:  # noqa: SLF001
                sqlite_cache._daemons.update(saved)  # noqa: SLF001


if __name__ == "__main__":
    unittest.main(verbosity=2)
