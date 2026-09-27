"""把 SQLite 缓存守护线程的生命周期绑定到"当前 IDB"，与 Broker 连接解耦。

历史行为（容易踩坑）：守护线程只在插件**连上 Broker** 时启动、断开时停止。
于是"IDA 启动时没有开库 → 自动连接时 `idb_path` 为空 → 之后再打开库也不会建缓存"，
用户必须记得按一次 `Ctrl+Alt+M` 才会开始建缓存。

**当前实现（2.1.2 起）**：不再安装任何 IDB 钩子，生命周期完全由插件在 `init()`
里注册的**那一个主循环定时器**驱动 —— 定时器回调里调用 `sync_to_idb(当前 IDB)`，
它等价于"打开 IDB 就开始建缓存、关库/切库就停掉旧的"。手动 `Ctrl+Alt+M` 也走
同一个 `ensure()`（幂等）。

为什么不用 IDB 钩子：`IDB_Hooks.loaded()` 是在**数据库加载序列内部**被调用的，
在那里注册 UI 定时器会把 IDA 主线程锁死（实测：启动即无响应、CPU 零增长）。
"注册定时器/钩子"这类动作只允许发生在 `init()` 这一条路径上。

仍尊重 `IDA_MCP_DISABLE_CACHE=1`：禁用时 `ensure()` 不会启动任何线程，
但依然记住当前 IDB 路径，便于上层给出"缓存被禁用"的准确报错。
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from . import sqlite_cache as _cache
from .cache_config import load_cache_config

__all__ = ["CacheDaemonSupervisor"]


class CacheDaemonSupervisor:
    """记录当前 IDB，并负责起停它对应的缓存守护线程。"""

    def __init__(
        self,
        *,
        start: Optional[Callable[[str], Optional[str]]] = None,
        stop: Optional[Callable[[str], None]] = None,
        disabled_probe: Optional[Callable[[], bool]] = None,
    ) -> None:
        self._start = start or _cache.start_cache_daemon
        self._stop = stop or _cache.stop_cache_daemon
        self._disabled_probe = disabled_probe or (lambda: load_cache_config().disabled)
        self._current_idb = ""

    @property
    def current_idb(self) -> str:
        """当前绑定的 IDB 路径（可能为空）。"""
        return self._current_idb

    @property
    def disabled(self) -> bool:
        try:
            return bool(self._disabled_probe())
        except Exception:  # noqa: BLE001
            return False

    def ensure(self, idb_path: Optional[str] = None) -> Optional[str]:
        """确保 `idb_path`（缺省用已记录的路径）对应的守护线程在运行。

        返回缓存数据库路径；未启动（禁用 / 无路径 / 启动异常）时返回 None。
        切换到另一个 IDB 时会先停掉上一个。
        """
        path = (idb_path or self._current_idb or "").strip()
        if not path:
            return None
        if self._current_idb and self._current_idb != path:
            self.stop()
        self._current_idb = path
        if self.disabled:
            return None
        try:
            return self._start(path)
        except Exception:  # noqa: BLE001 - 启动失败不应影响插件连接
            return None

    def stop(self) -> None:
        """停掉当前 IDB 的守护线程（幂等）。"""
        if not self._current_idb:
            return
        path, self._current_idb = self._current_idb, ""
        try:
            self._stop(path)
        except Exception:  # noqa: BLE001
            pass

    def sync_to_idb(self, current_idb_path: Optional[str]) -> Optional[str]:
        """把守护线程同步到"当前打开的 IDB"（由主循环定时器调用，幂等）。

        - 路径为空（没有库）→ 停掉守护线程；
        - 路径与当前绑定不同 → `ensure` 内部先停旧的再起新的；
        - 路径相同 → 幂等，不重复起停。

        返回当前绑定的 IDB 路径（无库时为 None）。
        """
        path = (current_idb_path or "").strip()
        if not path:
            self.stop()
            return None
        self.ensure(path)
        return self._current_idb

    def snapshot(self) -> dict[str, Any]:
        """诊断快照（供日志/问题定位）。"""
        cache_db = _cache.resolve_cache_path(self._current_idb) if self._current_idb else None
        return {
            "idb_path": self._current_idb,
            "cache_db_path": cache_db,
            "disabled": self.disabled,
        }
