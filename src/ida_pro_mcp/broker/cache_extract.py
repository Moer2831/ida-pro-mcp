"""分块提取层：把"整库物化"拆成"按游标切片 + 边切边哈希"。

设计要点
--------
- 每个表组（strings/functions/globals/imports）都是一个可续跑的游标：
  `chunk(cursor, budget_rows, ...)` 返回下一段数据与新的游标，因此主线程
  可以在两次 `execute_sync` 之间喘息，GUI 不再被整段提取占死。
- 同一套切片逻辑同时服务两种用途：
    * `collect=True`  → 产出要写库的行（块大小有上限，峰值内存 O(块)）；
    * `collect=False` → 只做哈希（表级指纹），不产生任何行对象。
  这样"指纹相同就跳过重建"不会引入第二份实现，避免两边逻辑漂移。
- 本模块**不 import 任何 IDA 模块**，只依赖 `CacheBackend` 协议，
  因此可以用假后端在无 IDA 环境下做完整单测。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol, Sequence

from .cache_config import (
    TABLE_FUNCTION_XREFS,
    TABLE_FUNCTIONS,
    TABLE_GLOBALS,
    TABLE_IMPORTS,
    TABLE_STRING_XREFS,
    TABLE_STRINGS,
)

# 行类型别名：写入器按 TABLE_SPECS 的列顺序消费
Row = tuple[Any, ...]


# ---------------------------------------------------------------------------
# 后端协议
# ---------------------------------------------------------------------------


class CacheBackend(Protocol):
    """提取器需要的最小 IDA 能力集合（由 IDA 适配器或测试假件实现）。"""

    def is_idle(self) -> bool: ...

    # functions
    def func_count(self) -> int: ...
    def func_at(self, index: int) -> Optional[tuple[int, str, int, bool]]: ...
    def func_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]: ...
    def segment_name(self, ea: int) -> str: ...
    def has_type(self, ea: int) -> bool: ...
    def item_size(self, ea: int) -> int: ...

    # strings
    def str_count(self) -> int: ...
    def str_at(self, index: int) -> Optional[tuple[int, str, int]]: ...
    def str_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]: ...

    # globals
    def name_count(self) -> int: ...
    def name_at(self, index: int) -> Optional[tuple[int, str]]: ...
    def is_function(self, ea: int) -> bool: ...

    # imports
    def import_module_count(self) -> int: ...
    def import_module_name(self, index: int) -> str: ...
    def import_names(self, index: int) -> Sequence[tuple[int, str, Optional[int]]]: ...


# ---------------------------------------------------------------------------
# 哈希工具
# ---------------------------------------------------------------------------


class Fingerprint:
    """增量哈希：长度前缀分帧，避免字段拼接歧义。"""

    __slots__ = ("_h", "_items")

    def __init__(self) -> None:
        self._h = hashlib.blake2b(digest_size=16)
        self._items = 0

    def add_int(self, value: int) -> None:
        self._h.update(int(value).to_bytes(8, "little", signed=True))

    def add_str(self, value: str) -> None:
        data = value.encode("utf-8", "replace")
        self._h.update(len(data).to_bytes(4, "little"))
        self._h.update(data)

    def add_bool(self, value: bool) -> None:
        self._h.update(b"\x01" if value else b"\x00")

    def add_item_marker(self) -> None:
        self._items += 1
        self._h.update(b"\x1e")  # record separator，区分条目边界

    @property
    def items(self) -> int:
        return self._items

    def digest(self) -> str:
        final = hashlib.blake2b(digest_size=16)
        final.update(self._h.digest())
        final.update(self._items.to_bytes(8, "little"))
        return final.hexdigest()


# ---------------------------------------------------------------------------
# 切片结果
# ---------------------------------------------------------------------------


@dataclass
class ChunkResult:
    """一次切片的结果（行按目标表分组，便于直接喂给写入器）。"""

    cursor: int
    done: bool
    items: int = 0
    rows_by_table: dict[str, list[Row]] = field(default_factory=dict)
    truncated_by_limit: bool = False  # 触达 max_rows 上限（该表本轮应放弃）

    def rows_for(self, table: str) -> list[Row]:
        return self.rows_by_table.get(table, [])

    @property
    def row_count(self) -> int:
        return sum(len(rows) for rows in self.rows_by_table.values())


def _append(rows_by_table: dict[str, list[Row]], table: str, row: Row) -> None:
    bucket = rows_by_table.get(table)
    if bucket is None:
        rows_by_table[table] = [row]
    else:
        bucket.append(row)


def _xref_type(is_code: bool) -> str:
    return "code" if is_code else "data"


# ---------------------------------------------------------------------------
# strings 组
# ---------------------------------------------------------------------------


class StringsExtractor:
    """strings + string_xrefs。"""

    name = TABLE_STRINGS
    tables: tuple[str, ...] = (TABLE_STRINGS, TABLE_STRING_XREFS)

    def __init__(self, backend: CacheBackend, *, want_xrefs: bool, full_fp: bool) -> None:
        self._backend = backend
        self._want_xrefs = want_xrefs
        self._full_fp = full_fp
        self._size: Optional[int] = None

    def total(self) -> int:
        if self._size is None:
            self._size = int(self._backend.str_count())
        return self._size

    def chunk(
        self,
        cursor: int,
        budget_rows: int,
        *,
        collect: bool,
        fingerprint: Optional[Fingerprint] = None,
    ) -> ChunkResult:
        total = self.total()
        rows_by_table: dict[str, list[Row]] = {}
        row_count = 0
        items = 0
        index = cursor

        # 分块预算必须**同时**约束 items 与 row_count：指纹模式（collect=False）不产生
        # 数据行，row_count 恒为 0，只按它判断会让整张表在一次派发里跑完 —— 实测在
        # 13.5 万函数的 GameAssembly 库上单次派发 12~13 秒，主线程长期无响应
        # （插件定时器跑不了 → 心跳过期 → 本轮被门控放弃 → 立刻重试 → 死循环）。
        while index < total and items < budget_rows and row_count < budget_rows:
            item = self._backend.str_at(index)
            index += 1
            if item is None:
                continue
            ea, text, length = item
            addr = hex(ea)
            xrefs = self._backend.str_xrefs_to(ea) if self._want_xrefs else ()

            if fingerprint is not None:
                fingerprint.add_item_marker()
                fingerprint.add_int(ea)
                fingerprint.add_int(length)
                if self._full_fp:
                    fingerprint.add_str(text)
                if self._want_xrefs:
                    fingerprint.add_int(len(xrefs))

            items += 1
            if not collect:
                continue

            _append(
                rows_by_table,
                TABLE_STRINGS,
                (addr, ea, text, length, self._backend.segment_name(ea)),
            )
            row_count += 1
            for frm, is_code in xrefs:
                _append(
                    rows_by_table,
                    TABLE_STRING_XREFS,
                    (addr, hex(frm), int(frm), _xref_type(is_code)),
                )
                row_count += 1

        return ChunkResult(
            cursor=index, done=index >= total, items=items, rows_by_table=rows_by_table
        )


# ---------------------------------------------------------------------------
# functions 组
# ---------------------------------------------------------------------------


class FunctionsExtractor:
    """functions + function_xrefs（direction='to'）。"""

    name = TABLE_FUNCTIONS
    tables: tuple[str, ...] = (TABLE_FUNCTIONS, TABLE_FUNCTION_XREFS)

    def __init__(self, backend: CacheBackend, *, want_xrefs: bool, full_fp: bool) -> None:
        self._backend = backend
        self._want_xrefs = want_xrefs
        self._full_fp = full_fp
        self._size: Optional[int] = None

    def total(self) -> int:
        if self._size is None:
            self._size = int(self._backend.func_count())
        return self._size

    def chunk(
        self,
        cursor: int,
        budget_rows: int,
        *,
        collect: bool,
        fingerprint: Optional[Fingerprint] = None,
    ) -> ChunkResult:
        total = self.total()
        rows_by_table: dict[str, list[Row]] = {}
        row_count = 0
        items = 0
        index = cursor

        while index < total and items < budget_rows and row_count < budget_rows:
            item = self._backend.func_at(index)
            index += 1
            if item is None:
                continue
            ea, name, size, has_type = item
            addr = hex(ea)
            xrefs = self._backend.func_xrefs_to(ea) if self._want_xrefs else ()

            if fingerprint is not None:
                fingerprint.add_item_marker()
                fingerprint.add_int(ea)
                fingerprint.add_int(size)
                fingerprint.add_str(name)
                fingerprint.add_bool(bool(has_type))
                if self._want_xrefs:
                    fingerprint.add_int(len(xrefs))

            items += 1
            if not collect:
                continue

            _append(
                rows_by_table,
                TABLE_FUNCTIONS,
                (addr, ea, name, size, self._backend.segment_name(ea), 1 if has_type else 0),
            )
            row_count += 1
            for frm, is_code in xrefs:
                _append(
                    rows_by_table,
                    TABLE_FUNCTION_XREFS,
                    (addr, hex(frm), int(frm), "to", _xref_type(is_code)),
                )
                row_count += 1

        return ChunkResult(
            cursor=index, done=index >= total, items=items, rows_by_table=rows_by_table
        )


# ---------------------------------------------------------------------------
# globals 组
# ---------------------------------------------------------------------------


class GlobalsExtractor:
    """globals（IDA 名字表里不是函数入口的那些）。"""

    name = TABLE_GLOBALS
    tables: tuple[str, ...] = (TABLE_GLOBALS,)

    def __init__(self, backend: CacheBackend, *, full_fp: bool = False) -> None:
        self._backend = backend
        self._full_fp = full_fp
        self._size: Optional[int] = None

    def total(self) -> int:
        if self._size is None:
            self._size = int(self._backend.name_count())
        return self._size

    def chunk(
        self,
        cursor: int,
        budget_rows: int,
        *,
        collect: bool,
        fingerprint: Optional[Fingerprint] = None,
    ) -> ChunkResult:
        total = self.total()
        rows_by_table: dict[str, list[Row]] = {}
        row_count = 0
        items = 0
        index = cursor

        while index < total and items < budget_rows and row_count < budget_rows:
            item = self._backend.name_at(index)
            index += 1
            if item is None:
                continue
            ea, name = item
            if self._backend.is_function(ea):
                continue
            size = self._backend.item_size(ea)

            if fingerprint is not None:
                fingerprint.add_item_marker()
                fingerprint.add_int(ea)
                fingerprint.add_str(name)
                fingerprint.add_int(size)

            items += 1
            if not collect:
                continue

            _append(
                rows_by_table,
                TABLE_GLOBALS,
                (hex(ea), ea, name, size, self._backend.segment_name(ea)),
            )
            row_count += 1

        return ChunkResult(
            cursor=index, done=index >= total, items=items, rows_by_table=rows_by_table
        )


# ---------------------------------------------------------------------------
# imports 组
# ---------------------------------------------------------------------------


class ImportsExtractor:
    """imports（按模块逐个枚举，模块数量天然很小）。"""

    name = TABLE_IMPORTS
    tables: tuple[str, ...] = (TABLE_IMPORTS,)

    def __init__(self, backend: CacheBackend, *, full_fp: bool = False) -> None:
        self._backend = backend
        self._full_fp = full_fp
        self._size: Optional[int] = None

    def total(self) -> int:
        if self._size is None:
            self._size = int(self._backend.import_module_count())
        return self._size

    def chunk(
        self,
        cursor: int,
        budget_rows: int,
        *,
        collect: bool,
        fingerprint: Optional[Fingerprint] = None,
    ) -> ChunkResult:
        total = self.total()
        rows_by_table: dict[str, list[Row]] = {}
        row_count = 0
        items = 0
        index = cursor

        while index < total and items < budget_rows and row_count < budget_rows:
            module = self._backend.import_module_name(index) or "<unnamed>"
            names = self._backend.import_names(index)
            index += 1

            for ea, symbol, ordinal in names:
                name = symbol or (f"#{ordinal}" if ordinal is not None else "<unnamed>")
                if fingerprint is not None:
                    fingerprint.add_item_marker()
                    fingerprint.add_int(ea)
                    fingerprint.add_str(name)
                    fingerprint.add_str(module)
                items += 1
                if collect:
                    _append(
                        rows_by_table, TABLE_IMPORTS, (hex(ea), ea, name, module)
                    )
                    row_count += 1

        return ChunkResult(
            cursor=index, done=index >= total, items=items, rows_by_table=rows_by_table
        )


# ---------------------------------------------------------------------------
# 组装
# ---------------------------------------------------------------------------


def build_extractors(
    backend: CacheBackend,
    *,
    want_xrefs: bool,
    want_globals: bool,
    full_fp: bool,
) -> list[Any]:
    """按范围返回本轮要处理的提取器（顺序即建库顺序）。"""
    extractors: list[Any] = [
        FunctionsExtractor(backend, want_xrefs=want_xrefs, full_fp=full_fp),
        StringsExtractor(backend, want_xrefs=want_xrefs, full_fp=full_fp),
    ]
    if want_globals:
        extractors.append(GlobalsExtractor(backend, full_fp=full_fp))
    extractors.append(ImportsExtractor(backend, full_fp=full_fp))
    return extractors


def tables_of(extractor: Any) -> Iterable[str]:
    return tuple(extractor.tables)
