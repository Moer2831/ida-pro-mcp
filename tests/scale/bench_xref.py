"""微基准：交叉引用枚举的几种实现对比（决定"单条目爆炸"那次派发有多长）。

背景：一个被引用 20 万次的条目，IDA 侧的枚举成本无法切开 —— 这次派发的长度就由
枚举的常数因子决定。`idautils.XrefsTo` 会为每条 xref 造一个 Python 对象，低层
`ida_xref.xrefblk_t` 直接读结构体。2.1.8 起后端走低层实现（带高层回退）。

用法::

    set IDADIR=D:\\IDA
    python tests/scale/bench_xref.py %TEMP%\\ida-mcp-scale\\synth-1.exe.i64

stage 1 实测（20 万条 xref）：枚举 1915ms → 261ms（7.3×），只计数 1808ms → 105ms（17×）。
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scale_common import open_db, prepare_environment  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="xref 枚举实现对比")
    parser.add_argument("idb")
    parser.add_argument("--scan-all", action="store_true", help="全库扫描找最热条目（慢但准）")
    parser.add_argument("--sample", type=int, default=4000, help="不全库扫描时的抽样数")
    args = parser.parse_args()

    prepare_environment()
    open_db(args.idb, auto_analysis=False)

    import ida_funcs  # noqa: PLC0415
    import ida_xref  # noqa: PLC0415
    import idautils  # noqa: PLC0415

    qty = ida_funcs.get_func_qty()
    limit = qty if args.scan_all else min(qty, args.sample)
    started = time.perf_counter()
    hot_ea, hot_n = 0, -1
    for i in range(limit):
        ea = int(ida_funcs.get_func_ea_by_num(i))
        count = len(list(idautils.XrefsTo(ea, 0)))
        if count > hot_n:
            hot_ea, hot_n = ea, count
    print(
        f"扫描 {limit} 个函数求最大 xref 数: {time.perf_counter() - started:.1f}s  "
        f"热门 0x{hot_ea:X} = {hot_n} 条"
    )

    started = time.perf_counter()
    high = [(int(x.frm), bool(x.iscode)) for x in idautils.XrefsTo(hot_ea, 0)]
    high_sec = time.perf_counter() - started

    started = time.perf_counter()
    low: list[tuple[int, bool]] = []
    block = ida_xref.xrefblk_t()
    if block.first_to(hot_ea, 0):
        while True:
            low.append((int(block.frm), bool(block.iscode)))
            if not block.next_to():
                break
    low_sec = time.perf_counter() - started

    started = time.perf_counter()
    count_high = sum(1 for _ in idautils.XrefsTo(hot_ea, 0))
    count_high_sec = time.perf_counter() - started

    started = time.perf_counter()
    count_low = 0
    block2 = ida_xref.xrefblk_t()
    if block2.first_to(hot_ea, 0):
        while True:
            count_low += 1
            if not block2.next_to():
                break
    count_low_sec = time.perf_counter() - started

    print(f"A) idautils.XrefsTo : {len(high):>7} 条  {high_sec * 1000:>8.1f} ms")
    print(f"B) ida_xref 低层     : {len(low):>7} 条  {low_sec * 1000:>8.1f} ms")
    if low_sec > 0:
        print(f"   枚举加速比 A/B = {high_sec / low_sec:.2f}x")
    print(f"   枚举结果一致 = {sorted(high) == sorted(low)}")
    print(f"A) 迭代计数        : {count_high:>7} 条  {count_high_sec * 1000:>8.1f} ms")
    print(f"B) 低层计数        : {count_low:>7} 条  {count_low_sec * 1000:>8.1f} ms")
    if count_low_sec > 0:
        print(f"   计数加速比 A/B = {count_high_sec / count_low_sec:.2f}x")
    print(f"   计数结果一致 = {count_high == count_low}")

    import idapro  # noqa: PLC0415

    idapro.close_database(save=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())