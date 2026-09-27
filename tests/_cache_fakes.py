"""缓存层单测用的假后端与建库辅助（不含 IDA 依赖）。

`FakeBackend` 实现 `cache_extract.CacheBackend` 协议，行为刻意与 IDAPython
一一对应（索引式访问、可能返回 None、xref 可注入），这样提取器/写入器/守护
线程的全部逻辑都能在没有 IDA 的环境里被完整覆盖。
"""

from __future__ import annotations

import os
import tempfile
from typing import Iterable, Optional, Sequence

__all__ = ["FakeBackend", "build_test_db", "make_backend"]


class FakeBackend:
    """可编程的假后端。"""

    def __init__(
        self,
        *,
        functions: Iterable[tuple[int, str, int, bool]] = (),
        strings: Iterable[tuple[int, str]] = (),
        names: Iterable[tuple[int, str]] = (),
        imports: Iterable[tuple[str, Sequence[tuple[int, str, Optional[int]]]]] = (),
        segments: Optional[dict[int, str]] = None,
        xrefs: Optional[dict[int, Sequence[tuple[int, bool]]]] = None,
        idle: bool = True,
        item_size: int = 4,
        fail_on_chunk: Optional[str] = None,
        raise_after_chunks: Optional[int] = None,
    ) -> None:
        self._functions = list(functions)
        self._strings = list(strings)
        self._names = list(names)
        self._imports = list(imports)
        self._segments = dict(segments or {})
        self._xrefs = {k: list(v) for k, v in (xrefs or {}).items()}
        self._idle = idle
        self._item_size = item_size
        self.fail_on_chunk = fail_on_chunk
        self.raise_after_chunks = raise_after_chunks
        self.chunk_calls = 0

    # -- 计数 -------------------------------------------------------------

    def is_idle(self) -> bool:
        return self._idle

    def func_count(self) -> int:
        return len(self._functions)

    def str_count(self) -> int:
        return len(self._strings)

    def name_count(self) -> int:
        return len(self._names)

    def import_module_count(self) -> int:
        return len(self._imports)

    # -- 索引式访问 -------------------------------------------------------

    def func_at(self, index: int) -> Optional[tuple[int, str, int, bool]]:
        self._maybe_fail("functions")
        if 0 <= index < len(self._functions):
            return self._functions[index]
        return None

    def str_at(self, index: int) -> Optional[tuple[int, str, int]]:
        self._maybe_fail("strings")
        if 0 <= index < len(self._strings):
            ea, text = self._strings[index]
            return (ea, text, len(text))
        return None

    def name_at(self, index: int) -> Optional[tuple[int, str]]:
        if 0 <= index < len(self._names):
            return self._names[index]
        return None

    def import_module_name(self, index: int) -> str:
        if 0 <= index < len(self._imports):
            return self._imports[index][0]
        return "<unnamed>"

    def import_names(self, index: int) -> Sequence[tuple[int, str, Optional[int]]]:
        if 0 <= index < len(self._imports):
            return self._imports[index][1]
        return ()

    # -- 辅助能力 ---------------------------------------------------------

    def func_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]:
        return self._xrefs.get(ea, ())

    def str_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]:
        return self._xrefs.get(ea, ())

    def is_function(self, ea: int) -> bool:
        return any(fn[0] == ea for fn in self._functions)

    def item_size(self, ea: int) -> int:
        return self._item_size

    def segment_name(self, ea: int) -> str:
        return self._segments.get(ea, ".text")

    # -- 故障注入 ---------------------------------------------------------

    def _maybe_fail(self, group: str) -> None:
        self.chunk_calls += 1
        if self.fail_on_chunk == group:
            raise RuntimeError(f"injected failure in {group}")
        if self.raise_after_chunks is not None and self.chunk_calls > self.raise_after_chunks:
            raise RuntimeError("injected failure after N chunk calls")


def make_backend(
    *,
    n_functions: int = 5,
    n_strings: int = 4,
    n_names: int = 6,
    n_imports: int = 2,
    xrefs_per_item: int = 2,
    function_base: int = 0x1000,
    string_base: int = 0x2000,
    name_base: int = 0x3000,
    import_base: int = 0x4000,
) -> FakeBackend:
    """构造一个规模可控、xref 可预测的假后端。"""
    functions = [
        (function_base + i * 0x10, f"sub_{i:X}", 0x10 + i, i % 2 == 0)
        for i in range(n_functions)
    ]
    strings = [(string_base + i * 0x20, f"str_{i}") for i in range(n_strings)]
    names = [(name_base + i * 0x10, f"gvar_{i}") for i in range(n_names)]
    imports = [
        (f"mod{i}.dll", [(import_base + i * 0x10 + j * 8, f"imp_{i}_{j}", j) for j in range(2)])
        for i in range(n_imports)
    ]
    xrefs: dict[int, list[tuple[int, bool]]] = {}
    for ea, _name, _size, _has_type in functions:
        xrefs[ea] = [(ea + 0x1000 + k, k % 2 == 0) for k in range(xrefs_per_item)]
    for ea, _text in strings:
        xrefs[ea] = [(ea + 0x2000 + k, True) for k in range(xrefs_per_item)]
    segments = {ea: ".text" for ea, _n, _s, _t in functions}
    segments.update({ea: ".rodata" for ea, _t in strings})
    segments.update({ea: ".data" for ea, _n in names})
    return FakeBackend(
        functions=functions,
        strings=strings,
        names=names,
        imports=imports,
        segments=segments,
        xrefs=xrefs,
    )


def build_test_db(tmpdir: Optional[str] = None) -> str:
    """在临时目录里返回一个缓存库路径（不创建文件）。"""
    base = tmpdir or tempfile.mkdtemp(prefix="ida-mcp-cache-test-")
    return os.path.join(base, "fixture.i64.mcp.sqlite")
