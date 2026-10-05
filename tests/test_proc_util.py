"""父进程看门狗与进程存活判断的测试。

事故背景：`idalib-mcp` 的 supervisor 为每个库拉起独立 worker，worker 用 DEVNULL
完全脱离父进程。supervisor 被强杀（任务管理器 / TerminateProcess，不走 `shutdown()`）
后，worker 变成孤儿继续占着 IDB —— 之后启动无头服务时新 worker 打不开同一个库，
`initialize` 永远不返回（实测挂满 180s 超时，日志里只有一行 Spawning worker）。
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import threading
import time
import unittest

from ida_pro_mcp import proc_util


class PidAliveTests(unittest.TestCase):
    def test_own_pid_is_alive(self) -> None:
        self.assertTrue(proc_util.pid_alive(os.getpid()))

    def test_unused_pid_is_not_alive(self) -> None:
        self.assertFalse(proc_util.pid_alive(4_000_000))

    def test_nonpositive_pid_is_not_alive(self) -> None:
        for pid in (0, -1):
            with self.subTest(pid=pid):
                self.assertFalse(proc_util.pid_alive(pid))


class ParentWatchdogTests(unittest.TestCase):
    def test_disabled_for_zero_pid(self) -> None:
        called: list[int] = []
        thread = proc_util.start_parent_watchdog(0, lambda: called.append(1))
        self.assertIsNone(thread, "parent_pid=0 表示手工运行，不应起看门狗")
        time.sleep(0.15)
        self.assertEqual(called, [])

    def test_fires_immediately_when_parent_already_gone(self) -> None:
        done = threading.Event()
        proc_util.start_parent_watchdog(4_000_000, done.set, interval=0.05)
        self.assertTrue(done.wait(timeout=2.0), "父进程已不存在时应立刻回调")

    def test_fires_after_parent_disappears(self) -> None:
        """父进程先活着、后消失：看门狗必须在若干个周期内发现并回调。"""
        state = {"alive": True}
        original = proc_util.pid_alive
        proc_util.pid_alive = lambda pid: state["alive"]  # type: ignore[assignment]
        try:
            done = threading.Event()
            thread = proc_util.start_parent_watchdog(12345, done.set, interval=0.05)
            self.assertIsNotNone(thread)
            self.assertFalse(done.wait(timeout=0.2), "父进程还在时不应回调")
            state["alive"] = False
            self.assertTrue(done.wait(timeout=2.0), "父进程消失后应回调")
        finally:
            proc_util.pid_alive = original  # type: ignore[assignment]

    def test_does_not_fire_while_parent_alive(self) -> None:
        called: list[int] = []
        thread = proc_util.start_parent_watchdog(
            os.getpid(), lambda: called.append(1), interval=0.05
        )
        self.assertIsNotNone(thread)
        assert thread is not None
        self.assertTrue(thread.daemon, "看门狗必须是守护线程，不能拖住进程退出")
        time.sleep(0.3)
        self.assertEqual(called, [], "父进程活着时不能误触发")

    def test_callback_runs_at_most_once(self) -> None:
        calls: list[int] = []
        proc_util.start_parent_watchdog(
            4_000_000, lambda: calls.append(1), interval=0.05
        )
        time.sleep(0.3)
        self.assertEqual(len(calls), 1, "回调只允许执行一次")


class KillOnCloseJobTests(unittest.TestCase):
    """Job Object 是唯一不被句柄继承 / PID 复用破坏的父子通道。"""

    def test_job_can_be_created_and_closed(self) -> None:
        job = proc_util.create_kill_on_close_job()
        if sys.platform != "win32":
            self.assertIsNone(job)
            return
        self.assertTrue(job, "Windows 上必须能创建 Job")
        proc_util.close_job(job)

    @unittest.skipUnless(sys.platform == "win32", "Job Object 仅 Windows")
    def test_closing_job_kills_member_process(self) -> None:
        job = proc_util.create_kill_on_close_job()
        self.assertTrue(job)
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(
                proc_util.assign_pid_to_job(job, child.pid), "进程必须能加入 Job"
            )
            time.sleep(0.5)
            self.assertIsNone(child.poll(), "加入 Job 后不应立刻被杀")
            proc_util.close_job(job)  # 等价于 supervisor 进程消失（句柄被系统关闭）
            deadline = time.time() + 10
            while time.time() < deadline and child.poll() is None:
                time.sleep(0.1)
            self.assertIsNotNone(
                child.poll(), "关闭 Job 后成员进程必须被内核终止（孤儿 worker 的根治）"
            )
        finally:
            if child.poll() is None:
                child.kill()
            proc_util.close_job(job)

    def test_assign_failure_is_non_fatal(self) -> None:
        self.assertFalse(proc_util.assign_pid_to_job(None, os.getpid()))
        self.assertFalse(proc_util.assign_pid_to_job(0, os.getpid()))
        proc_util.close_job(None)  # 不应抛异常


class EofWatchdogTests(unittest.TestCase):
    """父进程存活通道必须是管道 EOF，而不是 PID 探活（PID 会被复用）。"""

    def test_fires_when_write_end_closes(self) -> None:
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb", buffering=0)
        done = threading.Event()
        try:
            thread = proc_util.start_eof_watchdog(stream, done.set)
            self.assertIsNotNone(thread)
            self.assertFalse(done.wait(timeout=0.2), "写端还开着时不应触发")
            os.close(write_fd)
            self.assertTrue(done.wait(timeout=3.0), "写端关闭（父进程死）后必须触发")
        finally:
            write_fd_open = True
            try:
                os.close(write_fd)
            except OSError:
                write_fd_open = False
            stream.close()

    def test_does_not_fire_while_write_end_open(self) -> None:
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb", buffering=0)
        calls: list[int] = []
        try:
            proc_util.start_eof_watchdog(stream, lambda: calls.append(1))
            time.sleep(0.4)
            self.assertEqual(calls, [])
        finally:
            os.close(write_fd)
            stream.close()

    def test_none_stream_is_disabled(self) -> None:
        calls: list[int] = []
        self.assertIsNone(proc_util.start_eof_watchdog(None, lambda: calls.append(1)))
        time.sleep(0.1)
        self.assertEqual(calls, [])

    def test_pid_alive_documents_reuse_hazard(self) -> None:
        """`pid_alive` 必须写明不能用于父子判定（PID 复用实测会骗过 OpenProcess）。"""
        doc = proc_util.pid_alive.__doc__ or ""
        self.assertIn("复用", doc)
        self.assertIn("start_eof_watchdog", doc)


class FdEofWatchdogTests(unittest.TestCase):
    """权威通道：直接读 fd 0（sys.stdin 在 worker 里可能不存在，实测导致看门狗未启动）。"""

    def test_fires_when_write_end_closes(self) -> None:
        read_fd, write_fd = os.pipe()
        done = threading.Event()
        try:
            thread = proc_util.start_fd_eof_watchdog(read_fd, done.set)
            self.assertIsNotNone(thread)
            self.assertFalse(done.wait(timeout=0.2), "写端还开着时不应触发")
            os.close(write_fd)
            self.assertTrue(done.wait(timeout=3.0), "写端关闭后必须触发")
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass
            try:
                os.close(read_fd)
            except OSError:
                pass

    def test_invalid_fd_is_disabled_and_does_not_fire(self) -> None:
        calls: list[int] = []
        self.assertIsNone(proc_util.start_fd_eof_watchdog(-1, lambda: calls.append(1)))
        closed_read, closed_write = os.pipe()
        os.close(closed_read)
        os.close(closed_write)
        self.assertIsNone(
            proc_util.start_fd_eof_watchdog(closed_read, lambda: calls.append(1))
        )
        time.sleep(0.1)
        self.assertEqual(calls, [], "通道不可用时绝不能误判父进程已死")

    def test_real_stdin_pipe_detects_parent_exit(self) -> None:
        """端到端：子进程通过 fd 0 感知父进程写端关闭。"""
        repo_src = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        script = (
            "import os,sys,time;"
            f"sys.path.insert(0, r'{repo_src}');"
            "from ida_pro_mcp.proc_util import start_fd_eof_watchdog;"
            "start_fd_eof_watchdog(0, lambda: os._exit(7));"
            "time.sleep(30)"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        self.assertIsNone(child.poll(), "父进程还在时子进程不应退出")
        assert child.stdin is not None
        child.stdin.close()  # 等价于父进程死亡（写端被关）
        try:
            code = child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            self.fail("写端关闭后子进程未退出（EOF 通道失效）")
        self.assertEqual(code, 7, "子进程应由 EOF 回调主动退出")


class HeadlessWiringTests(unittest.TestCase):
    """跨进程接线无法在单测里真跑，用源码形态守卫（正向断言：必须存在）。"""

    def _read(self, rel: str) -> str:
        return (
            pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / rel
        ).read_text(encoding="utf-8")

    def test_supervisor_tells_worker_its_parent(self) -> None:
        src = self._read("idalib_supervisor.py")
        self.assertIn('"--parent-pid"', src, "worker 必须知道自己属于哪个 supervisor")
        self.assertIn("os.getpid()", src)
        self.assertIn("--watch-stdin-eof", src)
        self.assertIn("stdin=subprocess.PIPE", src, "supervisor 必须持有写端，才能靠 EOF 通知 worker")

    def test_worker_installs_watchdog(self) -> None:
        src = self._read("idalib_server.py")
        self.assertIn("--parent-pid", src)
        self.assertIn("start_parent_watchdog", src)
        self.assertIn("start_fd_eof_watchdog", src, "worker 必须以 fd EOF 为主通道（sys.stdin 可能不存在）")
        self.assertIn("os._exit", src, "父进程消失后必须真的退出（否则继续占着 IDB）")

    def test_startup_open_is_bounded_with_actionable_error(self) -> None:
        src = self._read("idalib_supervisor.py")
        self.assertIn("--open-timeout", src, "开库必须有上界，不能无限挂住 initialize")
        self.assertIn("IDA_MCP_OPEN_TIMEOUT_SEC", src)
        self.assertIn("idalib_server", src, "报错要指出残留 worker 的排查方式")
        self.assertIn("被强杀", src, "报错要说清最可能的原因")


if __name__ == "__main__":
    unittest.main(verbosity=2)