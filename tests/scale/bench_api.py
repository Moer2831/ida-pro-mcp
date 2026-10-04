"""微基准：在合成大库上逐个测 IDA API 的单元成本，用来定位"慢在哪"。

为什么需要：规模测试只能告诉你"整体慢了"，定位必须靠单点测量。这里刻意把
**可能退化成 O(n) 的接口**单独拎出来（例如索引式取函数），并把几种等价实现
放在一起对比（例如 `idautils.XrefsTo` vs 低层 `ida_xref.xrefblk_t`）。

用法::

    set IDADIR=D:\\IDA
    python tests/scale/bench_api.py %TEMP%\\ida-mcp-scale\\synth-1.exe.i64

经验值（stage 1，2.1.8 实测）：`getn_func`/`get_func_ea_by_num` 均为 O(1)
（连续 2000 次约 1ms）；名字表 1 万次约 34ms；`idautils.Strings()` 构造约 0.7s；
交叉引用枚举差异见 `bench_xref.py`（低层快 7~17 倍）。
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scale_common import open_db, prepare_environment  # noqa: E402


def timed(label: str, fn, *args):  # noqa: ANN001, ANN201
    started = time.perf_counter()
    out = fn(*args)
    print(f"{label:<44} {(time.perf_counter() - started) * 1000:>10.1f} ms")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="IDA API 单元成本微基准")
    parser.add_argument("idb")
    parser.add_argument("--sample", type=int, default=400, help="找热门函数的抽样数")
    args = parser.parse_args()

    prepare_environment()
    open_db(args.idb, auto_analysis=False)

    import ida_funcs  # noqa: PLC0415
    import ida_name  # noqa: PLC0415
    import idautils  # noqa: PLC0415

    qty = timed("func_qty()", ida_funcs.get_func_qty)
    print(f"   函数总数 = {qty}")
    print(f"   名字总数 = {ida_name.get_nlist_size()}")

    for index in (0, 1000, qty // 2, qty - 1):
        timed(f"get_func_ea_by_num({index})", ida_funcs.get_func_ea_by_num, index)

    def sequential(start: int, count: int = 2000) -> int:
        got = 0
        for i in range(start, min(start + count, qty)):
            if ida_funcs.get_func_ea_by_num(i):
                got += 1
        return got

    timed("get_func_ea_by_num 连续 2000 次（中段）", sequential, qty // 2)
    timed("get_func_ea_by_num 连续 2000 次（尾部）", sequential, qty - 2000)

    def names(count: int = 10_000) -> int:
        seen = 0
        for i in range(min(count, ida_name.get_nlist_size())):
            ida_name.get_nlist_ea(i)
            ida_name.get_nlist_name(i)
            seen += 1
        return seen

    timed("nlist 连续 10000 次（ea+name）", names)

    strings = timed("idautils.Strings() 构造", idautils.Strings)
    print(f"   Strings.size = {strings.size}")

    def walk_strings(count: int = 2000) -> int:
        seen = 0
        for i in range(min(count, strings.size)):
            item = strings[i]
            if item is not None:
                str(item)
                seen += 1
        return seen

    timed("Strings 连续 2000 次（含 str()）", walk_strings)

    hot_ea, hot_n = 0, -1
    for i in range(min(qty, args.sample)):
        ea = int(ida_funcs.get_func_ea_by_num(i))
        count = len(list(idautils.XrefsTo(ea, 0)))
        if count > hot_n:
            hot_ea, hot_n = ea, count
    print(f"   抽样 {args.sample} 个函数，热门 0x{hot_ea:X} = {hot_n} 条 xref")

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
    from ida_pro_mcp.broker import cache_backend  # noqa: PLC0415

    backend = cache_backend.IdaCacheBackend()

    def backend_funcs(count: int = 2000) -> int:
        seen = 0
        for i in range(1000, 1000 + count):
            if backend.func_at(i):
                seen += 1
        return seen

    timed("backend.func_at 连续 2000 次", backend_funcs)
    timed("backend.func_xref_count(热门)", backend.func_xref_count, hot_ea)

    import idapro  # noqa: PLC0415

    idapro.close_database(save=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())