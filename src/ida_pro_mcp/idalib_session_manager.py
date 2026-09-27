"""IDALib Session Manager - Multi-binary management for headless MCP server

This module provides session management for multiple IDA databases in idalib mode.
Each session represents an opened binary with its own IDA database instance.

T2: idle-TTL 回收。后台 reaper 周期性关闭空闲超过 TTL 的会话，避免
`--max-workers` 个 IDB 永久驻留内存。默认 TTL=0，即保持旧行为（不回收）。

配置（环境变量，均由 idalib worker 进程的 session manager 读取）:
- `IDA_MCP_IDLE_TTL_SEC`: 空闲回收阈值（秒），0 = 禁用，默认 0。
- `IDA_MCP_IDLE_SWEEP_SEC`: reaper 扫描周期（秒），最小 1，默认 30。

注意: `idapro` / `ida_auto` 改为按需解析（见 `_idapro()` / `_ida_auto()`），
这样没有 IDA 的环境也能 import 本模块做单元测试。
"""

import importlib
import logging
import os
import sys
import threading
import uuid
import weakref
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

IDLE_TTL_ENV = "IDA_MCP_IDLE_TTL_SEC"
IDLE_SWEEP_ENV = "IDA_MCP_IDLE_SWEEP_SEC"
DEFAULT_IDLE_TTL_SEC = 0.0
DEFAULT_IDLE_SWEEP_SEC = 30.0
# 环境变量路径下的最小扫描周期：避免配置成毫秒级导致 CPU 空转
MIN_IDLE_SWEEP_SEC = 1.0


def _resolve_ida_module(name: str) -> Any:
    """按需解析 IDA 模块（idapro / ida_auto）。

    优先复用 `sys.modules` 中已加载的模块（同时是单元测试注入假模块的入口），
    否则才真正 import，避免非 IDA 环境 import 本模块直接失败。
    """
    module = sys.modules.get(name)
    if module is not None:
        return module
    return importlib.import_module(name)


def _idapro() -> Any:
    """延迟获取 idapro 模块。"""
    return _resolve_ida_module("idapro")


def _ida_auto() -> Any:
    """延迟获取 ida_auto 模块。"""
    return _resolve_ida_module("ida_auto")


def _env_float(name: str, default: float) -> float:
    """读取浮点型环境变量，非法值回退默认值并告警。"""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("%s=%r 不是合法数字，回退默认值 %s", name, raw, default)
        return default


def _parse_idle_ttl_sec(raw: float) -> float:
    """解析 TTL：负数按 0（禁用）处理。"""
    if raw < 0:
        logger.warning("idle TTL 为负数 (%s)，按 0（禁用回收）处理", raw)
        return 0.0
    return float(raw)


def _parse_idle_sweep_sec(raw: float) -> float:
    """解析扫描周期：环境变量路径强制下限 MIN_IDLE_SWEEP_SEC。"""
    if raw < MIN_IDLE_SWEEP_SEC:
        logger.warning(
            "idle sweep %s 小于最小值 %s，已提升到最小值", raw, MIN_IDLE_SWEEP_SEC
        )
        return MIN_IDLE_SWEEP_SEC
    return float(raw)


@dataclass
class IDASession:
    """Represents a single IDA database session"""

    session_id: str
    input_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert session to dictionary format"""
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": self.metadata,
        }

    def idle_seconds(self, now: Optional[datetime] = None) -> float:
        """距上次访问的空闲秒数。"""
        return ((now or datetime.now()) - self.last_accessed).total_seconds()


@dataclass
class ReaperStats:
    """空闲回收线程的统计（异常一律记录，绝不静默吞掉）

    errors/last_error 同时记录 close_database 的异常（含显式 close_session 路径）。
    """

    sweeps: int = 0
    reaped_sessions: int = 0
    skipped_bound: int = 0
    skipped_active: int = 0
    skipped_analyzing: int = 0
    errors: int = 0
    last_reap_at: Optional[str] = None
    last_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "sweeps": self.sweeps,
            "reaped_sessions": self.reaped_sessions,
            "skipped_bound": self.skipped_bound,
            "skipped_active": self.skipped_active,
            "skipped_analyzing": self.skipped_analyzing,
            "errors": self.errors,
            "last_reap_at": self.last_reap_at,
            "last_error": self.last_error,
        }


class IDASessionManager:
    """Manages multiple IDA database sessions for idalib mode.

    Design:
    - `_sessions` stores all known session metadata.
    - `_active_session_id` tracks the database currently opened in the idalib process.
    - `_context_bindings` maps MCP transport context IDs to session IDs.
    - `start_reaper()` 启动空闲回收线程（TTL=0 时为空操作）；生产路径由
      `get_session_manager()` 自动调用。
    """

    def __init__(
        self,
        *,
        idle_ttl_sec: Optional[float] = None,
        idle_sweep_sec: Optional[float] = None,
        clock: Optional[Callable[[], datetime]] = None,
        close_database: Optional[Callable[[], Any]] = None,
    ) -> None:
        """创建 session manager。

        Args:
            idle_ttl_sec: 空闲回收阈值（秒），0 = 禁用；默认取环境变量
                `IDA_MCP_IDLE_TTL_SEC`（缺省 0）。
            idle_sweep_sec: reaper 扫描周期（秒）；默认取环境变量
                `IDA_MCP_IDLE_SWEEP_SEC`（缺省 30，且下限 MIN_IDLE_SWEEP_SEC）。
                显式传入的值不做下限钳制，便于单元测试使用毫秒级周期。
            clock: 可注入时钟（返回 datetime），默认 `datetime.now`。
            close_database: 可注入的关闭数据库回调，默认 `idapro.close_database`。
        """
        self._sessions: Dict[str, IDASession] = {}
        self._active_session_id: Optional[str] = None
        self._context_bindings: Dict[str, str] = {}
        self._lock = threading.RLock()

        if idle_ttl_sec is None:
            self._idle_ttl_sec = _parse_idle_ttl_sec(
                _env_float(IDLE_TTL_ENV, DEFAULT_IDLE_TTL_SEC)
            )
        else:
            self._idle_ttl_sec = _parse_idle_ttl_sec(float(idle_ttl_sec))

        if idle_sweep_sec is None:
            self._idle_sweep_sec = _parse_idle_sweep_sec(
                _env_float(IDLE_SWEEP_ENV, DEFAULT_IDLE_SWEEP_SEC)
            )
        else:
            self._idle_sweep_sec = float(idle_sweep_sec)
            if self._idle_sweep_sec <= 0:
                logger.warning("idle sweep 必须为正数，回退默认值 %s", DEFAULT_IDLE_SWEEP_SEC)
                self._idle_sweep_sec = DEFAULT_IDLE_SWEEP_SEC

        self._clock: Callable[[], datetime] = clock or datetime.now
        self._close_database_fn = close_database

        self._reaper_stop = threading.Event()
        self._reaper_stop.set()  # 未 start_reaper() 时视为已停止
        self._reaper_thread: Optional[threading.Thread] = None
        self._reaper_stats = ReaperStats()

        logger.info(
            "IDASessionManager initialized (idle_ttl=%ss, idle_sweep=%ss)",
            self._idle_ttl_sec,
            self._idle_sweep_sec,
        )

    # ------------------------------------------------------------------
    # 时钟 / 惰性 IDA 访问
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        """当前时间（可通过 clock 注入以做单元测试）。"""
        return self._clock()

    def _close_active_database_locked(self) -> None:
        """关闭当前激活的 IDB；异常先计入状态再抛出，避免静默吞掉。"""
        try:
            if self._close_database_fn is not None:
                self._close_database_fn()
            else:
                _idapro().close_database()
        except Exception as exc:
            self._reaper_stats.errors += 1
            self._reaper_stats.last_error = f"close_database failed: {exc}"
            logger.exception("close_database failed")
            raise

    def open_binary(
        self,
        input_path: Path | str,
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None,
    ) -> str:
        """Open a binary file and create a new session

        Args:
            input_path: Path to the binary file
            run_auto_analysis: Whether to run auto-analysis
            session_id: Optional custom session ID (auto-generated if not provided)

        Returns:
            Session ID for the opened binary

        Raises:
            FileNotFoundError: If the input file doesn't exist
            RuntimeError: If failed to open the database
        """
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            # Check if this file is already tracked
            for sid, session in self._sessions.items():
                if session.input_path.resolve() == input_path.resolve():
                    logger.info(f"Binary already open in session: {sid}")
                    session.last_accessed = self._now()
                    return sid

            # Generate session ID
            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            elif session_id in self._sessions:
                raise ValueError(f"Session already exists: {session_id}")

            # Open the database
            logger.info(f"Opening database: {input_path} (session: {session_id})")
            self._activate_database_path(str(input_path), run_auto_analysis)

            # Create session object
            session = IDASession(
                session_id=session_id,
                input_path=input_path,
                created_at=self._now(),
                last_accessed=self._now(),
                is_analyzing=run_auto_analysis,
            )

            self._sessions[session_id] = session
            self._active_session_id = session_id

            # Wait for analysis if requested
            if run_auto_analysis:
                logger.debug(
                    f"Waiting for auto-analysis to complete (session: {session_id})"
                )
                _ida_auto().auto_wait()
                session.is_analyzing = False
                logger.info(f"Auto-analysis completed (session: {session_id})")

            logger.info(f"Session created: {session_id} for {input_path.name}")
            return session_id

    def close_session(self, session_id: str) -> bool:
        """Close a specific session and its database

        Args:
            session_id: Session ID to close

        Returns:
            True if closed successfully, False if session not found
        """
        with self._lock:
            if session_id not in self._sessions:
                logger.warning(f"Session not found: {session_id}")
                return False

            session = self._sessions[session_id]
            logger.info(f"Closing session: {session_id} ({session.input_path.name})")

            # If this is the active in-process database, close it.
            if self._active_session_id == session_id:
                self._close_active_database_locked()
                self._active_session_id = None

            # Remove session
            del self._sessions[session_id]
            self._unbind_session_everywhere_locked(session_id)
            logger.info(f"Session closed: {session_id}")
            return True

    def bind_context(
        self, context_id: str, session_id: str, activate: bool = False
    ) -> IDASession:
        """Bind a transport context to a session.

        Args:
            context_id: Transport-specific context identifier.
            session_id: IDA session ID to bind.
            activate: Whether to activate the bound session immediately.

        Returns:
            The bound session object.
        """
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session not found: {session_id}")

            self._context_bindings[context_id] = session_id
            session = self._sessions[session_id]
            session.last_accessed = self._now()
            logger.info("Bound context %s -> session %s", context_id, session_id)

            if activate:
                self._activate_session_locked(session_id)
            return session

    def unbind_context(self, context_id: str) -> bool:
        """Remove an existing context binding."""
        with self._lock:
            removed = self._context_bindings.pop(context_id, None)
            if removed is None:
                return False
            logger.info("Unbound context %s from session %s", context_id, removed)
            return True

    def get_context_session_id(self, context_id: str) -> Optional[str]:
        """Return the session ID bound to a context."""
        with self._lock:
            return self._context_bindings.get(context_id)

    def get_context_session(self, context_id: str) -> Optional[IDASession]:
        """Get the session object bound to a context."""
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                return None
            return self._sessions.get(session_id)

    def activate_context(self, context_id: str) -> IDASession:
        """Activate the database bound to a context for the current request."""
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                raise RuntimeError(
                    "No session bound for this context. "
                    "Use idalib_switch(session_id) or idalib_open(...) first."
                )
            session = self._sessions.get(session_id)
            if session is None:
                self._context_bindings.pop(context_id, None)
                raise RuntimeError(
                    f"Context binding is stale (missing session: {session_id}). "
                    "Bind to a valid session again."
                )

            self._activate_session_locked(session_id)
            session.last_accessed = self._now()
            return session

    def list_sessions(self, context_id: Optional[str] = None) -> list[dict]:
        """List all open sessions with binding and activation metadata."""
        with self._lock:
            context_session_id = self._context_bindings.get(context_id, None)
            binding_counts: Dict[str, int] = {}
            for bound_session_id in self._context_bindings.values():
                binding_counts[bound_session_id] = (
                    binding_counts.get(bound_session_id, 0) + 1
                )

            return [
                {
                    **session.to_dict(),
                    "is_active": session.session_id == self._active_session_id,
                    "is_current_context": session.session_id == context_session_id,
                    "bound_contexts": binding_counts.get(session.session_id, 0),
                }
                for session in self._sessions.values()
            ]

    def get_session(self, session_id: str) -> Optional[IDASession]:
        """Get a specific session by ID

        Args:
            session_id: Session ID to retrieve

        Returns:
            Session object or None if not found
        """
        with self._lock:
            return self._sessions.get(session_id)

    def close_all_sessions(self):
        """Close all sessions and databases"""
        with self._lock:
            logger.info(f"Closing all {len(self._sessions)} sessions")

            if self._active_session_id is not None:
                self._close_active_database_locked()
                self._active_session_id = None

            self._sessions.clear()
            self._context_bindings.clear()
            logger.info("All sessions closed")

    # ------------------------------------------------------------------
    # 空闲回收 (idle-TTL reaper)
    # ------------------------------------------------------------------

    @property
    def idle_ttl_sec(self) -> float:
        """空闲回收阈值（秒），0 表示禁用。"""
        return self._idle_ttl_sec

    @property
    def idle_sweep_sec(self) -> float:
        """reaper 扫描周期（秒）。"""
        return self._idle_sweep_sec

    def is_reaper_running(self) -> bool:
        """回收线程是否在运行。"""
        with self._lock:
            return self._reaper_thread is not None and self._reaper_thread.is_alive()

    def reaper_stats(self) -> dict:
        """回收线程统计快照（含 TTL/sweep/运行状态）。"""
        with self._lock:
            stats = self._reaper_stats.to_dict()
            stats.update(
                {
                    "idle_ttl_sec": self._idle_ttl_sec,
                    "idle_sweep_sec": self._idle_sweep_sec,
                    "running": self._reaper_thread is not None
                    and self._reaper_thread.is_alive(),
                    "session_count": len(self._sessions),
                }
            )
            return stats

    def start_reaper(self) -> bool:
        """启动后台空闲回收线程。

        Returns:
            True 表示本次真的启动了线程；TTL=0 或线程已在运行时返回 False。

        线程只持有 manager 的弱引用，因此不会阻止 manager 被 GC。
        """
        with self._lock:
            if self._idle_ttl_sec <= 0:
                logger.info(
                    "idle TTL 未启用 (%s=%s)，不启动回收线程",
                    IDLE_TTL_ENV,
                    self._idle_ttl_sec,
                )
                return False
            if self._reaper_thread is not None and self._reaper_thread.is_alive():
                return False

            stop_event = self._reaper_stop
            stop_event.clear()
            sweep = self._idle_sweep_sec
            weak_self = weakref.ref(self)

            def _sweep_once() -> bool:
                # 局部变量在函数返回时释放，线程不会长期持有 manager 强引用
                target = weak_self()
                if target is None:
                    return False
                try:
                    target.reap_idle_sessions()
                except Exception as exc:
                    target._record_reaper_error(exc)
                return True

            def _reap_loop() -> None:
                while not stop_event.wait(sweep):
                    if not _sweep_once():
                        return

            self._reaper_thread = threading.Thread(
                target=_reap_loop, name="ida-session-reaper", daemon=True
            )
            self._reaper_thread.start()
            logger.info(
                "空闲回收线程已启动 (ttl=%ss, sweep=%ss)",
                self._idle_ttl_sec,
                self._idle_sweep_sec,
            )
            return True

    def stop_reaper(self, timeout: float = 5.0) -> bool:
        """停止回收线程（幂等，可从任意线程调用）。"""
        with self._lock:
            thread = self._reaper_thread
            self._reaper_stop.set()
        if thread is None:
            return False
        if thread is threading.current_thread():
            # 从回收线程内部调用时不 join 自己
            return True
        if thread.is_alive():
            thread.join(timeout)
        alive = thread.is_alive()
        if not alive:
            with self._lock:
                if self._reaper_thread is thread:
                    self._reaper_thread = None
        else:
            logger.warning("回收线程在 %ss 内未退出", timeout)
        return not alive

    def shutdown(self, *, close_sessions: bool = True) -> None:
        """关闭 manager：停止回收线程，并按需关闭所有会话（幂等）。"""
        self.stop_reaper()
        if close_sessions:
            self.close_all_sessions()

    def close(self) -> None:
        """`shutdown()` 的别名。"""
        self.shutdown()

    def __del__(self) -> None:
        # GC 兜底：只唤醒回收线程，不触碰可能已失效的 IDA 状态
        try:
            stop_event = getattr(self, "_reaper_stop", None)
            if stop_event is not None:
                stop_event.set()
        except Exception:
            pass

    def _record_reaper_error(self, exc: BaseException) -> None:
        """记录回收线程异常（绝不静默吞掉）。"""
        with self._lock:
            self._reaper_stats.errors += 1
            self._reaper_stats.last_error = f"{type(exc).__name__}: {exc}"
        logger.exception("空闲回收线程异常")

    def reap_idle_sessions(self) -> List[str]:
        """关闭所有空闲超过 TTL 的会话。

        规则：
        - TTL<=0 时不做任何事（返回空列表，保持旧行为）。
        - 空闲时间 `>= TTL` 即视为过期（TTL 边界上会被回收）。
        - 绑定在 `_context_bindings` 上的会话永不回收。
        - 当前激活会话在 TTL 内不回收；超过 TTL 且未被绑定时允许回收。
        - 自动分析进行中的会话跳过（避免打断分析）。

        Returns:
            本次被关闭的 session_id 列表（幂等：重复调用不会重复关闭）。
        """
        if self._idle_ttl_sec <= 0:
            return []

        closed: List[str] = []
        with self._lock:
            self._reaper_stats.sweeps += 1
            now = self._now()
            bound_session_ids = set(self._context_bindings.values())
            candidates: List[str] = []
            for session_id, session in self._sessions.items():
                if session_id in bound_session_ids:
                    self._reaper_stats.skipped_bound += 1
                    continue
                idle_seconds = session.idle_seconds(now)
                if idle_seconds < self._idle_ttl_sec:
                    if session_id == self._active_session_id:
                        self._reaper_stats.skipped_active += 1
                    continue
                if session.is_analyzing:
                    self._reaper_stats.skipped_analyzing += 1
                    continue
                candidates.append(session_id)

            for session_id in candidates:
                # 复用 close_session：上下文解绑 / _active_session_id 复位都在里面
                session = self._sessions.get(session_id)
                if session is None:
                    continue
                idle_seconds = session.idle_seconds(now)
                if self.close_session(session_id):
                    closed.append(session_id)
                    self._reaper_stats.reaped_sessions += 1
                    logger.info(
                        "回收空闲会话 %s (%s, 空闲 %.1fs >= TTL %.1fs)",
                        session_id,
                        session.input_path.name,
                        idle_seconds,
                        self._idle_ttl_sec,
                    )

            if closed:
                self._reaper_stats.last_reap_at = now.isoformat()
        return closed

    def _activate_session_locked(self, session_id: str) -> None:
        if self._active_session_id == session_id:
            return
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")
        self._activate_database_path(str(session.input_path), run_auto_analysis=False)
        self._active_session_id = session_id
        logger.info("Activated session %s (%s)", session_id, session.input_path.name)

    def _activate_database_path(self, input_path: str, run_auto_analysis: bool) -> None:
        if self._active_session_id is not None:
            logger.debug("Closing active database before opening %s", input_path)
            self._close_active_database_locked()
            self._active_session_id = None

        if _idapro().open_database(input_path, run_auto_analysis=run_auto_analysis):
            raise RuntimeError(f"Failed to open database: {input_path}")

    def _unbind_session_everywhere_locked(self, session_id: str) -> None:
        stale_contexts = [
            context_id
            for context_id, bound_session_id in self._context_bindings.items()
            if bound_session_id == session_id
        ]
        for context_id in stale_contexts:
            del self._context_bindings[context_id]


# Global session manager instance
_session_manager: Optional[IDASessionManager] = None


def get_session_manager() -> IDASessionManager:
    """Get the global session manager instance

    Side effect: 首次创建时按环境变量启动空闲回收线程（TTL=0 时不启动）。

    Returns:
        Global IDASessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        manager = IDASessionManager()
        manager.start_reaper()
        _session_manager = manager
    return _session_manager
