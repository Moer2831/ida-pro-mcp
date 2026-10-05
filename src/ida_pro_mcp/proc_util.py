"""进程存活与父进程看门狗。

为什么需要：`idalib-mcp` 的 supervisor 会为每个库拉起独立的 worker 进程，worker 用
`DEVNULL` 完全脱离父进程。supervisor 若被强杀（任务管理器 / TerminateProcess，
不走 `shutdown()`），worker 就变成**孤儿**并继续占着 IDB —— 之后再启动无头服务时，
新 worker 打不开同一个库（IDA 侧阻塞），表现为 `initialize` 永远不返回。

修法有两层：
1. worker 侧：启动时带上 `--parent-pid`，由看门狗发现父进程消失后**自行退出**，
   操作系统随即释放库；
2. supervisor 侧：启动开库有上界（见 `idalib_supervisor.main`），超时给出可操作报错，
   绝不无限挂住。
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Callable, Optional

__all__ = [
    "pid_alive",
    "start_parent_watchdog",
    "start_eof_watchdog",
    "start_fd_eof_watchdog",
    "create_kill_on_close_job",
    "assign_pid_to_job",
    "close_job",
]


def pid_alive(pid: int) -> bool:
    """进程是否仍然存在。

    ⚠️ **不要用它判断"父进程是否还是原来那个"**：PID 会被复用。实测在 Windows 上，
    supervisor 被杀后它的 PID 立刻被另一个会话里的进程占用，于是
    `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` 成功、`GetLastError()==0`，
    看起来"父进程还活着" —— worker 因此永远不退出。可靠的父子通道是管道 EOF
    （见 `start_eof_watchdog`），本函数只适合"这个 pid 现在有没有东西"。
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        # 打不开也可能是权限不足：只要不是"进程不存在"就当作活着
        return ctypes.windll.kernel32.GetLastError() == 5  # ERROR_ACCESS_DENIED
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True
    except (ProcessLookupError, OSError):
        return False


def create_kill_on_close_job() -> Optional[int]:
    """创建"句柄一关就杀掉全部成员"的 Job Object（仅 Windows；其它平台返回 None）。

    为什么最终选它：supervisor 一死就没人能通知 worker 了 —— 管道 EOF 会被进程链里的
    re-exec 子进程继承句柄破坏，PID 探活会被 PID 复用骗过（两者都实测踩过）。Job Object
    由**操作系统**负责：supervisor 进程无论怎么消失，它的句柄被关闭，内核立刻终止所有
    成员进程（含 worker 及其后代），与句柄继承、PID 复用都无关。
    """
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = kernel32.SetInformationJobObject(
        wintypes.HANDLE(job),
        JobObjectExtendedLimitInformation,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        kernel32.CloseHandle(wintypes.HANDLE(job))
        return None
    return int(job)


def assign_pid_to_job(job: Optional[int], pid: int) -> bool:
    """把进程加入 Job（失败返回 False；调用方应能接受"没保护"的情况）。"""
    if not job or sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, int(pid))
    if not handle:
        return False
    try:
        return bool(
            kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(handle))
        )
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def close_job(job: Optional[int]) -> None:
    """关闭 Job 句柄（KILL_ON_JOB_CLOSE 语义下会让全部成员进程被终止）。"""
    if not job or sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(wintypes.HANDLE(job))


def start_fd_eof_watchdog(
    fd: int,
    on_dead: Callable[[], None],
) -> Optional[threading.Thread]:
    """父进程存活通道（推荐实现）：**直接读文件描述符**，读到 EOF 就认为父进程没了。

    为什么不用 `sys.stdin`：worker 进程里 `sys.stdin` 可能是 None 或被 IDA/idalib 换成
    不带 `buffer` 的对象 —— 实测这样看门狗根本不会启动，孤儿 worker 就留下来了。
    直接读 fd 0（`os.read`）不依赖任何 Python 层包装，与 PID 无关，因此也不受 PID 复用
    影响。

    fd 不可读（例如手工运行、标准输入被关了）时**不触发**回调并返回 None —— 宁可少杀
    自己一次，也不要误退。
    """
    if fd is None or fd < 0:
        return None
    try:
        os.fstat(fd)
    except OSError:
        return None

    def _watch() -> None:
        while True:
            try:
                chunk = os.read(fd, 1)
            except OSError:
                return  # 通道不可用：不当作父进程死亡
            if not chunk:
                break
        on_dead()

    thread = threading.Thread(target=_watch, name="fd-eof-watchdog", daemon=True)
    thread.start()
    return thread


def start_eof_watchdog(
    stream: object,
    on_dead: Callable[[], None],
) -> Optional[threading.Thread]:
    """父进程存活通道：读管道，读到 EOF 就认为父进程没了。

    为什么这是可靠的做法：supervisor 用 `stdin=PIPE` 拉起 worker 后**只持有写端**，
    进程无论怎么死（正常退出 / TerminateProcess / 崩溃）操作系统都会关闭它的句柄，
    worker 立刻读到 EOF。整个过程不依赖 PID，因此不受 PID 复用影响。

    `stream` 需要是有 `read()` 的二进制流（例如 `sys.stdin.buffer`）；为 None 时返回
    None（例如手工运行 worker，没有父进程通道）。
    """
    if stream is None:
        return None

    def _watch() -> None:
        try:
            while True:
                chunk = stream.read(1)  # type: ignore[attr-defined]
                if not chunk:
                    break
        except Exception:  # noqa: BLE001 - 管道被关/被抢都会走到这里
            pass
        on_dead()

    thread = threading.Thread(target=_watch, name="stdin-eof-watchdog", daemon=True)
    thread.start()
    return thread


def start_parent_watchdog(
    parent_pid: int,
    on_dead: Callable[[], None],
    *,
    interval: float = 2.0,
) -> Optional[threading.Thread]:
    """起一个守护线程：父进程消失时调用 `on_dead`（只调用一次）。

    `parent_pid <= 0` 时不做任何事并返回 None（允许手工直接运行 worker 调试）。
    """
    if parent_pid <= 0:
        return None
    if not pid_alive(parent_pid):
        on_dead()
        return None

    def _watch() -> None:
        while True:
            time.sleep(interval)
            if not pid_alive(parent_pid):
                try:
                    on_dead()
                finally:
                    return

    thread = threading.Thread(
        target=_watch, name="parent-watchdog", daemon=True
    )
    thread.start()
    return thread