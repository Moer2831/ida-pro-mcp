"""IDA Pro MCP Plugin Loader（HTTP+SSE 版本）

通过 HTTP+SSE 与 MCP 服务器通信。
插件加载时自动连接，按 Ctrl+Alt+M 可手动重连。
"""

import os
import sys
import threading
import time
import idaapi
import idc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


_DEBUG_TRACE = bool(os.environ.get("IDA_MCP_DEBUG"))


def _trace(message: str) -> None:
    """启动路径追踪（设 `IDA_MCP_DEBUG=1` 才输出）。

    走 stdout：会进 IDA 的 Output 窗口，`ida.exe -L<log>` 也能读到 —— 专为诊断
    "IDA 启动即卡死 / 卡在某一步"这类问题准备（哪句是最后一条，就卡在那句之后）。
    """
    if not _DEBUG_TRACE:
        return
    try:
        print(f"[MCP] trace: {message}", flush=True)
    except Exception:  # noqa: BLE001 - 诊断输出绝不能影响插件
        pass


def _generate_instance_id() -> str:
    """生成实例 ID，基于进程 ID"""
    return f"ida-{os.getpid()}"


def _get_current_binary_path() -> str:
    """获取当前打开的二进制文件路径"""
    try:
        return idc.get_input_file_path() or ""
    except Exception:
        return ""


def _get_current_idb_path() -> str:
    """获取当前 IDB 数据库路径（.idb/.i64）。用于在旁路生成 SQLite 缓存文件。"""
    try:
        return idc.get_idb_path() or ""
    except Exception:
        return ""


def _get_current_binary_name() -> str:
    """获取当前打开的二进制文件名"""
    path = _get_current_binary_path()
    return os.path.basename(path) if path else ""


def _get_arch_info() -> dict:
    """获取当前二进制文件的架构信息"""
    try:
        import ida_ida
        
        proc_name = ida_ida.inf_get_procname() if hasattr(ida_ida, 'inf_get_procname') else ""
        is_64bit = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else False
        bitness = 64 if is_64bit else 32
        is_be = ida_ida.inf_is_be() if hasattr(ida_ida, 'inf_is_be') else False
        endian = "big" if is_be else "little"
        
        file_type = ida_ida.inf_get_filetype() if hasattr(ida_ida, 'inf_get_filetype') else 0
        file_type_names = {
            0: "unknown", 1: "EXE", 2: "COM", 3: "BIN", 4: "DRV", 5: "WIN",
            6: "HEX", 7: "MEX", 8: "LX", 9: "LE", 10: "NLM", 11: "COFF",
            12: "PE", 13: "OMF", 14: "SREC", 15: "ZIP", 16: "OMFLIB",
            17: "AR", 18: "LOADER", 19: "ELF", 20: "W32RUN", 21: "AOUT",
            22: "PRC", 23: "PILOT", 24: "MACHO", 25: "MACHO64",
        }
        file_type_str = file_type_names.get(file_type, f"type_{file_type}")
        base_addr = hex(idaapi.get_imagebase())
        
        return {
            "processor": proc_name,
            "bitness": bitness,
            "endian": endian,
            "file_type": file_type_str,
            "base_addr": base_addr,
        }
    except Exception as e:
        return {"error": str(e)}


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        # 一眼可辨"当前跑的是哪份代码"：代码目录 + 装载器 mtime（构建指纹）+ 缓存 schema
        # 注意：这里**故意不用 importlib.metadata** —— 它会扫描整个 sys.path
        # （IDA 的 site-packages 很大），拖慢插件初始化。
        try:
            import broker.cache_writer as _cache_writer

            _loader = os.path.abspath(__file__)
            try:
                _stamp = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(_loader))
                )
            except OSError:
                _stamp = "unknown"
            print(
                f"[MCP] 插件代码: {os.path.dirname(_loader)} "
                f"(装载器 {_stamp}, 缓存 schema v{_cache_writer.SCHEMA_VERSION})"
            )
        except Exception:
            pass

        self._connected = False
        self._connecting = False  # 正在连接中标志，防止重复连接
        self._mcp_server = None
        self._auto_connect_tried = False
        self._idb_path_for_cache = ""

        def auto_connect_timer():
            if not self._auto_connect_tried:
                self._auto_connect_tried = True
                _trace("自动连接定时器触发")
                self._try_connect(silent=True)
                _trace("自动连接定时器返回")
            return -1

        idaapi.register_timer(500, auto_connect_timer)
        _trace("init 完成（定时器已注册）")

        # 缓存守护线程的生命周期由**主循环定时器**轮询驱动（不在 IDB 钩子里做任何注册）：
        # 曾经在 IDB_Hooks.loaded() 里 register_timer，导致 IDA 启动即死锁 —— 加载序列
        # 内部不能碰 UI 定时器/钩子注册，这类动作只能在正常主循环上下文里做。
        try:
            from broker.cache_autostart import CacheDaemonSupervisor

            self._cache_supervisor = CacheDaemonSupervisor()
        except Exception as _e:  # noqa: BLE001
            self._cache_supervisor = None
            print(f"[MCP] 缓存监督器初始化失败: {_e}")

        def cache_supervisor_timer():
            try:
                before = self._idb_path_for_cache
                self._sync_cache_daemon()
                # 统一刷新"IDA 是否空闲"：定时器只在这里注册一次（init），
                # 守护线程启动路径绝不注册定时器（那会锁死主线程）
                try:
                    from broker import sqlite_cache as _cache_module

                    _cache_module.refresh_idle_states()
                except Exception:  # noqa: BLE001
                    pass
                if self._idb_path_for_cache != before:
                    _trace(
                        f"缓存监督定时器 -> idb={self._idb_path_for_cache or '(无)'}"
                    )
            except Exception:  # noqa: BLE001 - 定时器回调绝不能抛
                pass
            return 1000

        idaapi.register_timer(1000, cache_supervisor_timer)
        return idaapi.PLUGIN_KEEP

    def _sync_cache_daemon(self):
        """把缓存守护线程同步到"当前打开的 IDB"（在主循环定时器里调用）。

        - 没有库 → 停掉守护线程；
        - 换了库 → 先停旧的再起新的；
        - 同一个库 → 幂等（`ensure` 内部去重）。
        """
        supervisor = getattr(self, "_cache_supervisor", None)
        if supervisor is None:
            return
        supervisor.sync_to_idb(_get_current_idb_path())
        self._idb_path_for_cache = supervisor.current_idb

    def _ensure_cache_daemon(self, idb_path: str = ""):
        """确保当前 IDB 的缓存守护线程在跑（供连接路径 Ctrl+Alt+M 调用）。"""
        supervisor = getattr(self, "_cache_supervisor", None)
        if supervisor is None:
            return
        path = idb_path or _get_current_idb_path()
        if not path:
            return
        supervisor.ensure(path)
        # 无论缓存是否被禁用都记录路径：拦截层据此给出准确报错（-32001 而非"未提供 idb_path"）
        self._idb_path_for_cache = supervisor.current_idb

    def _stop_cache_daemon(self):
        supervisor = getattr(self, "_cache_supervisor", None)
        if supervisor is not None:
            supervisor.stop()
        self._idb_path_for_cache = ""

    def run(self, arg):
        """手动连接/重连（Ctrl+Alt+M）"""
        self._try_connect(silent=False)

    def _try_connect(self, silent: bool = False):
        """尝试连接到 MCP 服务器（后台线程执行，不阻塞 UI）"""
        _trace("_try_connect 开始")
        if self._connecting:
            if not silent:
                print("[MCP] 正在连接中，请稍候...")
            return
        
        if self._connected:
            self._disconnect()
        
        self._connecting = True
        
        # 在 UI 线程准备参数
        unload_package("ida_mcp")
        _trace("unload_package 完成")
        
        if TYPE_CHECKING:
            from .ida_mcp import (
                MCP_SERVER,
                connect_to_server,
                disconnect,
                is_connected,
                set_auto_reconnect,
            )
        else:
            from ida_mcp import (
                MCP_SERVER,
                connect_to_server,
                disconnect,
                is_connected,
                set_auto_reconnect,
            )

        _trace("ida_mcp 导入完成")
        set_auto_reconnect(True)
        self._mcp_server = MCP_SERVER

        instance_id = _generate_instance_id()
        binary_path = _get_current_binary_path()
        binary_name = _get_current_binary_name()
        idb_path = _get_current_idb_path()
        arch_info = _get_arch_info()
        # 将 idb_path 塞入 arch_info，注册到 Broker 后外部即可定位 .mcp.sqlite 缓存文件。
        if idb_path:
            arch_info["idb_path"] = idb_path

        # 启动 SQLite 静态缓存后台守护线程（与 Broker 连接解耦，打开 IDB 即开始构建）
        _trace(f"准备建立缓存监督 idb={idb_path or '(无)'}")
        self._ensure_cache_daemon(idb_path)
        _trace("缓存监督完成")

        def handle_mcp_request(request: dict) -> dict:
            """处理来自服务器的 MCP 请求。

            先拦截缓存类工具 (find_regex / entity_query / list_funcs /
            list_globals / imports / refresh_cache / cache_status)，
            直接用本地 SQLite 响应，不进入 ida_mcp 正常分发，不占 IDA 主线程。
            """
            from typing import cast as _cast
            if TYPE_CHECKING:
                from .broker import cache_handlers as _cache_handlers
                from .broker.cache_types import JsonRpcRequest as _JsonRpcRequest
            else:
                from broker import cache_handlers as _cache_handlers
                from broker.cache_types import JsonRpcRequest as _JsonRpcRequest

            typed_req = _cast(_JsonRpcRequest, request)
            if _cache_handlers.is_cache_tool(typed_req):
                idb_for_cache = self._idb_path_for_cache or _get_current_idb_path()
                return dict(_cache_handlers.handle_cache_tool_locally(typed_req, idb_for_cache))

            out = MCP_SERVER.registry.dispatch(request)
            if out is None:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Internal error"},
                    "id": request.get("id"),
                }
            return dict(out)

        if not silent:
            print("[MCP] 正在连接到 MCP 服务器...")

        def do_connect():
            """后台线程执行连接"""
            try:
                success = connect_to_server(
                    instance_id=instance_id,
                    instance_type="gui",
                    name=binary_name or f"IDA-{os.getpid()}",
                    binary_path=binary_path,
                    arch_info=arch_info,
                    on_mcp_request=handle_mcp_request,
                )

                def update_status():
                    self._connecting = False
                    if success:
                        self._connected = True
                        print(f"[MCP] 已连接 ({binary_name or 'IDA'})")
                    else:
                        if silent:
                            print("[MCP] 自动连接失败，按 Ctrl+Alt+M 手动重试")
                        else:
                            print("[MCP] 连接失败，请确保 Cursor 已启动")
                    return -1

                idaapi.execute_sync(lambda: update_status(), idaapi.MFF_WRITE)
            except Exception as e:
                def report_error():
                    self._connecting = False
                    print(f"[MCP] 连接异常: {e}")
                    return -1
                idaapi.execute_sync(lambda: report_error(), idaapi.MFF_WRITE)

        thread = threading.Thread(target=do_connect, daemon=True)
        thread.start()

    def _disconnect(self):
        """断开与服务器的连接。

        注意：缓存守护线程**不在这里停止** —— 它与 IDB 生命周期绑定
        （见 `closebase` / `term`），重连 Broker 不应该打断正在进行的缓存构建。
        """
        if not self._connected:
            return

        try:
            if TYPE_CHECKING:
                from .ida_mcp import disconnect
            else:
                from ida_mcp import disconnect

            disconnect()
            self._connected = False
        except Exception:
            pass

    def term(self):
        # 只停守护线程与连接；插件不再注册任何 IDB 钩子（见 init() 的说明）
        self._stop_cache_daemon()
        self._disconnect()


def PLUGIN_ENTRY():
    return MCP()


PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
