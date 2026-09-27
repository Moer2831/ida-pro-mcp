"""IDA 侧后端适配器：把 `CacheBackend` 协议落到真实的 IDAPython API 上。

约定
----
- 本模块顶层**不 import 任何 IDA 模块**，所有 IDA 调用都延迟到方法内部，
  这样无 IDA 环境也能 import（单测会用假后端替换）。
- 只读提取一律通过 `run_on_ida_main()` 派发：
    * GUI（`ida_kernwin.is_idaq()` 为真）→ `execute_sync(..., MFF_READ)`；
    * 无头 idalib → 直接调用（实测 `execute_sync` 在 idalib 下也可用，
      但直调少一层派发，语义更直白）。
- 每个方法都做了防御：IDA API 返回 None / 抛异常时返回空值，绝不让
  单条坏数据中断整轮缓存构建。
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Sequence, TypeVar

__all__ = ["run_on_ida_main", "is_headless", "IdaCacheBackend"]

T = TypeVar("T")


def is_headless() -> bool:
    """是否存在"需要派发"的 GUI 主线程。

    - 无 IDA 环境（单测）→ True（直接调用即可）
    - idalib 无头 → True（`is_idaq()` 为 False）
    - IDA GUI → False（必须走 `execute_sync`）
    """
    try:
        import ida_kernwin  # type: ignore
    except Exception:  # noqa: BLE001 - 没有 IDA 就是无头场景
        return True
    try:
        return not bool(ida_kernwin.is_idaq())
    except Exception:  # noqa: BLE001
        # 判定失败时按"无 GUI 可派发"处理：直接调用至少能让缓存建出来，
        # 而误判成 GUI 会让 execute_sync 拿不到主线程、守护线程永远空等。
        return True


def run_on_ida_main(fn: Callable[[], T]) -> Optional[T]:
    """把 `fn` 派发到 IDA 主线程执行并同步取回结果。

    GUI 下必须走 `execute_sync`（IDAPython 不是线程安全的）；无头/无 IDA 下
    直接调用。派发本身失败时返回 None（调用方按"本轮放弃"处理），但 `fn`
    内部抛出的异常会原样向上抛，方便定位真正的问题。
    """
    if is_headless():
        return fn()

    import ida_kernwin  # type: ignore

    box: list[Any] = [None]
    exc_box: list[BaseException] = []

    def runner() -> int:
        try:
            box[0] = fn()
        except BaseException as exc:  # noqa: BLE001 - 回传给调用线程再抛
            exc_box.append(exc)
        return 1

    try:
        ida_kernwin.execute_sync(runner, ida_kernwin.MFF_READ)
    except Exception:  # noqa: BLE001 - 派发失败（主线程不可达）
        return None
    if exc_box:
        raise exc_box[0]
    return box[0]  # type: ignore[no-any-return]


class IdaCacheBackend:
    """`cache_extract.CacheBackend` 的 IDAPython 实现（惰性、可缓存计数）。"""

    def __init__(self) -> None:
        self._strings: Any = None
        self._func_count: Optional[int] = None
        self._name_count: Optional[int] = None
        self._import_module_count: Optional[int] = None

    # -- 空闲判定 ---------------------------------------------------------

    def is_idle(self) -> bool:
        """自动分析队列清空即视为空闲，可以开始建缓存。

        历史实现还额外要求 Hex-Rays 就绪，但缓存只读 strings / functions / names /
        imports（`has_type` 走 `ida_nalt.get_tinfo`），**不依赖反编译器**；而在无头
        idalib 或未安装/未授权 Hex-Rays 的环境里 `init_hexrays_plugin()` 可能始终返回
        False，会导致守护线程一直空等、缓存永远建不出来（实测踩到）。
        """
        try:
            import ida_auto  # type: ignore

            return bool(ida_auto.auto_is_ok())
        except Exception:  # noqa: BLE001
            return False

    # -- functions --------------------------------------------------------

    def func_count(self) -> int:
        if self._func_count is None:
            import ida_funcs  # type: ignore

            self._func_count = int(ida_funcs.get_func_qty())
        return self._func_count

    def func_at(self, index: int) -> Optional[tuple[int, str, int, bool]]:
        try:
            import ida_funcs  # type: ignore

            fn = ida_funcs.getn_func(index)
            if fn is None:
                return None
            ea = int(fn.start_ea)
            name = ida_funcs.get_func_name(ea) or "<unnamed>"
            size = int(fn.end_ea) - ea
            return (ea, name, size, self.has_type(ea))
        except Exception:  # noqa: BLE001
            return None

    def func_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]:
        return self._xrefs_to(ea)

    def has_type(self, ea: int) -> bool:
        try:
            import ida_nalt  # type: ignore
            import ida_typeinf  # type: ignore

            return bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), ea))
        except Exception:  # noqa: BLE001
            return False

    # -- strings ----------------------------------------------------------

    def _string_list(self) -> Any:
        """惰性构造 `idautils.Strings`（沿用保存的 string 窗口选项）。"""
        if self._strings is None:
            import idautils  # type: ignore

            self._strings = idautils.Strings()
        return self._strings

    def str_count(self) -> int:
        try:
            return int(self._string_list().size)
        except Exception:  # noqa: BLE001
            return 0

    def str_at(self, index: int) -> Optional[tuple[int, str, int]]:
        try:
            item = self._string_list()[index]
            if item is None:
                return None
            text = str(item)
            return (int(item.ea), text, len(text))
        except Exception:  # noqa: BLE001 - 越界 / 解码失败都当作无此项
            return None

    def str_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]:
        return self._xrefs_to(ea)

    # -- globals ----------------------------------------------------------

    def name_count(self) -> int:
        if self._name_count is None:
            import ida_name  # type: ignore

            self._name_count = int(ida_name.get_nlist_size())
        return self._name_count

    def name_at(self, index: int) -> Optional[tuple[int, str]]:
        try:
            import ida_name  # type: ignore

            ea = int(ida_name.get_nlist_ea(index))
            name = ida_name.get_nlist_name(index)
            if not name:
                return None
            return (ea, name)
        except Exception:  # noqa: BLE001
            return None

    def is_function(self, ea: int) -> bool:
        try:
            import idaapi  # type: ignore

            return bool(idaapi.get_func(ea))
        except Exception:  # noqa: BLE001
            return False

    def item_size(self, ea: int) -> int:
        try:
            import idaapi  # type: ignore

            return int(idaapi.get_item_size(ea) or 0)
        except Exception:  # noqa: BLE001
            return 0

    # -- imports ----------------------------------------------------------

    def import_module_count(self) -> int:
        if self._import_module_count is None:
            try:
                import ida_nalt  # type: ignore

                self._import_module_count = int(ida_nalt.get_import_module_qty())
            except Exception:  # noqa: BLE001
                self._import_module_count = 0
        return self._import_module_count

    def import_module_name(self, index: int) -> str:
        try:
            import ida_nalt  # type: ignore

            return str(ida_nalt.get_import_module_name(index) or "<unnamed>")
        except Exception:  # noqa: BLE001
            return "<unnamed>"

    def import_names(self, index: int) -> Sequence[tuple[int, str, Optional[int]]]:
        acc: list[tuple[int, str, Optional[int]]] = []
        try:
            import ida_nalt  # type: ignore

            def _cb(ea: int, symbol: Optional[str], ordinal: Optional[int]) -> bool:
                acc.append((int(ea), symbol or "", ordinal))
                return True

            ida_nalt.enum_import_names(index, _cb)
        except Exception:  # noqa: BLE001
            return ()
        return acc

    # -- 公共工具 ---------------------------------------------------------

    def segment_name(self, ea: int) -> str:
        try:
            import idaapi  # type: ignore

            seg = idaapi.getseg(ea)
            if not seg:
                return ""
            return str(idaapi.get_segm_name(seg) or "")
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _xrefs_to(ea: int) -> Sequence[tuple[int, bool]]:
        try:
            import idautils  # type: ignore

            return [(int(x.frm), bool(x.iscode)) for x in idautils.XrefsTo(ea, 0)]
        except Exception:  # noqa: BLE001
            return ()
