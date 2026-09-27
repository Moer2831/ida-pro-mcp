"""把 SQLite 缓存守护线程的生命周期绑定到"当前 IDB"，与 Broker 连接解耦。

历史行为（容易踩坑）：守护线程只在插件**连上 Broker** 时启动、断开时停止。
于是"IDA 启动时没有开库 → 自动连接时 `idb_path` 为空 → 之后再打开库也不会建缓存"，
用户必须记得按一次 `Ctrl+Alt+M` 才会开始建缓存。

现在由 `ida_mcp.py` 安装 IDB_Hooks：

- `loaded()`    → `ensure(当前 IDB)`
- `closebase()` → `stop()`

加上插件初始化定时器与手动 `Ctrl+Alt+M` 也会调用 `ensure()`（幂等），
"打开 IDB 就开始建缓存"变成零操作。

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

    def snapshot(self) -> dict[str, Any]:
        """诊断快照（供日志/问题定位）。"""
        cache_db = _cache.resolve_cache_path(self._current_idb) if self._current_idb else None
        return {
            "idb_path": self._current_idb,
            "cache_db_path": cache_db,
            "disabled": self.disabled,
        }
