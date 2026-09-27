"""进程 RSS 读取（零依赖）——用于缓存构建的内存护栏。

Windows 走 `GetProcessMemoryInfo`（psapi.dll，回退 kernel32 的
`K32GetProcessMemoryInfo`），POSIX 读 `/proc/self/statm`；两条路都失败时返回
0.0，调用方必须把 0.0 当作"未知"而不是"占用为 0"。

注意：Windows 上必须设置 `argtypes`/`restype`，否则 ctypes 会把
`GetCurrentProcess()` 的句柄按 `c_int` 截断、调用恒失败（实测踩过这个坑）。
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Any, Callable, Optional

__all__ = ["current_rss_mb", "exceeds_rss_limit"]

_windows_probe: Optional[Callable[[], float]] = None


def _build_windows_probe() -> Optional[Callable[[], float]]:
    """构造并缓存 Windows 探针；失败返回 None。"""
    from ctypes import wintypes

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    get_current = kernel32.GetCurrentProcess
    get_current.restype = wintypes.HANDLE
    get_current.argtypes = []

    candidates: list[Any] = []
    try:
        psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)  # type: ignore[attr-defined]
        candidates.append(psapi.GetProcessMemoryInfo)
    except OSError:
        pass
    k32_fn = getattr(kernel32, "K32GetProcessMemoryInfo", None)
    if k32_fn is not None:
        candidates.append(k32_fn)
    if not candidates:
        return None

    def _probe() -> float:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        handle = get_current()
        last_error = 0
        for fn in candidates:
            fn.restype = wintypes.BOOL
            fn.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            if fn(handle, ctypes.byref(counters), counters.cb):
                return float(counters.WorkingSetSize) / (1024.0 * 1024.0)
            last_error = ctypes.get_last_error()
        del last_error
        return 0.0

    # 预热一次：句柄与函数签名只解析一次，后续每块采样都很便宜
    try:
        _probe()
    except Exception:  # noqa: BLE001
        return None
    return _probe


def _rss_mb_posix() -> float:
    try:
        with open("/proc/self/statm", "r", encoding="ascii") as fh:
            fields = fh.read().split()
        pages = int(fields[1])
        return pages * (os.sysconf("SC_PAGE_SIZE") / (1024.0 * 1024.0))
    except (OSError, IndexError, ValueError):
        return 0.0


def current_rss_mb() -> float:
    """当前进程 RSS（MB）；无法读取时返回 0.0。"""
    global _windows_probe
    try:
        if sys.platform != "win32":
            return _rss_mb_posix()
        if _windows_probe is None:
            _windows_probe = _build_windows_probe()
        if _windows_probe is None:
            return 0.0
        return _windows_probe()
    except Exception:  # noqa: BLE001 - 护栏读数失败不应影响构建
        return 0.0


def exceeds_rss_limit(limit_mb: int, rss_mb: Optional[float] = None) -> bool:
    """RSS 是否超过上限；limit<=0 或读数未知（0.0）时恒为 False。"""
    if limit_mb <= 0:
        return False
    if rss_mb is None:
        rss_mb = current_rss_mb()
    if rss_mb <= 0:
        return False
    return rss_mb > float(limit_mb)
