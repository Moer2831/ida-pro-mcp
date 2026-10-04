"""生成合成大库（GB 级 IDB），用于规模回归测试。

为什么要造而不是找一个：要触发"单条目几万条交叉引用""百万条目"这类形状，
真实样本可遇不可求，而分析一个真实大程序要几小时。这里直接构造一个合法 PE64，
再用 IDAPython 把函数 / 交叉引用 / 名字 / 字符串**程序化写入**，几分钟即可得到
百万条目级的真实 `.i64`。

刻意包含的病态样本（都是"单条目成本极高"的形状）：

* 一个函数被大量 `call` 指向（默认 20 万条）—— 单条目 xref 数量爆炸
* 超长函数名（1000 字符）与非 ASCII 名字
* 大量"非函数"名字（globals 表）
* 稀疏区域（只定义少量条目的大段空间）

用法::

    set IDADIR=D:\\IDA
    python tests/scale/make_fixture.py --stage 1     # 30 万函数 / 300 万 xref
    python tests/scale/make_fixture.py --stage 2     # 100 万函数 / 1000 万 xref

产物默认落在 `%TEMP%\\ida-mcp-scale\\synth-<stage>.exe(.i64)`，
可用 `IDA_MCP_SCALE_DIR` 改到磁盘空间充足的位置（stage 2 约需数十 GB）。
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scale_common import WORK_DIR, open_db, prepare_environment  # noqa: E402

STAGES = {
    "self": dict(funcs=200, calls=500, hot=50, globals_=100, strings=50, hot_str=20),
    "1": dict(
        funcs=300_000,
        calls=3_000_000,
        hot=200_000,
        globals_=60_000,
        strings=20_000,
        hot_str=50_000,
    ),
    "2": dict(
        funcs=1_000_000,
        calls=10_000_000,
        hot=400_000,
        globals_=200_000,
        strings=60_000,
        hot_str=120_000,
    ),
}


def build_pe(path: str, text_size: int, rdata_size: int, data_size: int) -> dict:
    """写一个最小合法 PE64（三个节，无导入表/重定位）。"""
    FILE_ALIGN = 0x200
    SECT_ALIGN = 0x1000
    IMAGE_BASE = 0x140000000

    def align(value: int, boundary: int) -> int:
        return (value + boundary - 1) // boundary * boundary

    headers_raw = align(0x40 + 4 + 20 + 0xF0 + 40 * 3, FILE_ALIGN)
    text_raw = align(text_size, FILE_ALIGN)
    rdata_raw = align(rdata_size, FILE_ALIGN)
    data_raw = align(data_size, FILE_ALIGN)

    text_va = SECT_ALIGN
    rdata_va = text_va + align(text_size, SECT_ALIGN)
    data_va = rdata_va + align(rdata_size, SECT_ALIGN)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664, 3, 0, 0, 0, 0xF0, 0x0022)

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, 0x20B)  # PE32+
    opt[0x02] = 0x0A
    struct.pack_into("<I", opt, 0x04, text_raw)
    struct.pack_into("<I", opt, 0x10, text_va)  # entry point
    struct.pack_into("<Q", opt, 0x18, IMAGE_BASE)
    struct.pack_into("<I", opt, 0x20, SECT_ALIGN)
    struct.pack_into("<I", opt, 0x24, FILE_ALIGN)
    struct.pack_into("<H", opt, 0x28, 6)
    struct.pack_into("<H", opt, 0x30, 6)
    struct.pack_into("<I", opt, 0x38, data_va + align(data_size, SECT_ALIGN))
    struct.pack_into("<I", opt, 0x3C, headers_raw)
    struct.pack_into("<H", opt, 0x44, 3)  # console subsystem
    struct.pack_into("<I", opt, 0x6C, 16)  # NumberOfRvaAndSizes

    def section(name: str, vsize: int, va: int, raw: int, chars: int) -> bytes:
        return struct.pack(
            "<8sIIIIIIHHI",
            name.encode().ljust(8, b"\0"),
            vsize,
            va,
            raw,
            raw,
            0,
            0,
            0,
            0,
            chars,
        )

    sections = (
        section(".text", text_size, text_va, text_raw, 0x60000020)
        + section(".rdata", rdata_size, rdata_va, rdata_raw, 0x40000040)
        + section(".data", data_size, data_va, data_raw, 0xC0000040)
    )

    blob = bytearray()
    blob += dos + coff + bytes(opt) + sections
    blob += bytes(headers_raw - len(blob))
    blob += bytes(text_raw + rdata_raw + data_raw)
    with open(path, "wb") as fh:
        fh.write(blob)

    return {
        "image_base": IMAGE_BASE,
        "text_va": IMAGE_BASE + text_va,
        "rdata_va": IMAGE_BASE + rdata_va,
        "data_va": IMAGE_BASE + data_va,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="生成合成大库（GB 级 IDB）")
    parser.add_argument("--stage", default="self", choices=sorted(STAGES))
    parser.add_argument("--force", action="store_true", help="已存在时重新生成")
    args = parser.parse_args()
    cfg = STAGES[args.stage]

    prepare_environment()
    pe_path = str(WORK_DIR / f"synth-{args.stage}.exe")
    idb_path = pe_path + ".i64"
    if os.path.exists(idb_path) and not args.force:
        print(f"复用已有 IDB: {idb_path}")
        return 0

    func_slot, call_slot = 2, 5  # 每个函数 2 字节（ret;nop），每条 call 5 字节
    func_bytes = cfg["funcs"] * func_slot
    call_bytes = cfg["calls"] * call_slot
    text_size = func_bytes + call_bytes + 0x1000
    rdata_size = cfg["strings"] * 48 + 0x1000
    data_size = cfg["globals_"] * 8 + 0x1000

    print(
        f"[1/4] 生成 PE: text={text_size / 1e6:.1f}MB "
        f"rdata={rdata_size / 1e6:.2f}MB data={data_size / 1e6:.2f}MB"
    )
    layout = build_pe(pe_path, text_size, rdata_size, data_size)

    print(f"[2/4] idalib 打开（不跑自动分析）: {pe_path}")
    open_db(pe_path, auto_analysis=False)

    import ida_bytes  # noqa: PLC0415
    import ida_funcs  # noqa: PLC0415
    import ida_name  # noqa: PLC0415
    import ida_nalt  # noqa: PLC0415
    import ida_ua  # noqa: PLC0415

    def make_insn(ea: int) -> int:
        """创建指令（IDA 9 用 ida_ua.create_insn；旧版回退 idc）。"""
        fn = getattr(ida_ua, "create_insn", None)
        if fn is None:  # pragma: no cover - 兼容旧版本
            import idc  # noqa: PLC0415

            fn = idc.create_insn
        return int(fn(ea))

    started = time.time()
    text_start = layout["text_va"]
    rdata_start = layout["rdata_va"]
    data_start = layout["data_va"]

    func_eas: list[int] = []
    print(f"[3/4] 造 {cfg['funcs']} 个函数 …")
    for i in range(cfg["funcs"]):
        ea = text_start + i * func_slot
        ida_bytes.patch_bytes(ea, b"\xC3\x90")  # ret; nop
        make_insn(ea)
        ida_funcs.add_func(ea, ea + 1)
        func_eas.append(ea)
    print(f"     函数完成 {time.time() - started:.1f}s，func_qty={ida_funcs.get_func_qty()}")

    hot_ea = func_eas[len(func_eas) // 2]
    call_start = text_start + func_bytes + 0x800
    print(
        f"[4/4] 造 {cfg['calls']} 条 call"
        f"（其中 {cfg['hot']} 条指向同一热门函数 0x{hot_ea:X}）…"
    )
    tick = time.time()
    for j in range(cfg["calls"]):
        ea = call_start + j * call_slot
        target = hot_ea if j < cfg["hot"] else func_eas[(j * 7919) % len(func_eas)]
        rel = target - (ea + 5)
        if not (-0x80000000 <= rel < 0x80000000):  # 超出 rel32 就就近自指
            target, rel = ea + 5 + 0x10, 0x10
        ida_bytes.patch_bytes(ea, b"\xE8" + struct.pack("<i", rel))
        make_insn(ea)
    print(f"     call 完成 {time.time() - tick:.1f}s")

    for i in range(cfg["globals_"]):
        ida_name.set_name(data_start + i * 8, f"g_var_{i:x}", ida_name.SN_NOWARN)

    str_eas: list[int] = []
    for i in range(cfg["strings"]):
        ea = rdata_start + i * 48
        text = f"synth_string_{i}".encode()
        ida_bytes.patch_bytes(ea, text + b"\0")
        ida_bytes.create_strlit(ea, len(text), ida_nalt.STRTYPE_C)
        ida_name.set_name(ea, f"aStr{i:x}", ida_name.SN_NOWARN)
        str_eas.append(ea)

    if str_eas:  # 热门字符串：被大量引用
        hot_str = str_eas[0]
        base = call_start + cfg["calls"] * call_slot + 0x100
        for j in range(cfg["hot_str"]):
            ea = base + j * call_slot
            ida_bytes.patch_bytes(ea, b"\xE8" + struct.pack("<i", hot_str - (ea + 5)))
            make_insn(ea)

    long_name_ea = data_start + cfg["globals_"] * 8 + 0x100
    ida_bytes.patch_bytes(long_name_ea, b"\0" * 32)
    ida_name.set_name(long_name_ea, "L" + "o" * 998 + "ng", ida_name.SN_NOWARN)
    unicode_ea = long_name_ea + 0x10
    ida_name.set_name(unicode_ea, "中文变量_测试_Ω", ida_name.SN_NOWARN)

    print(f"造数据总耗时 {time.time() - started:.1f}s")
    print(
        f"统计: funcs={ida_funcs.get_func_qty()} strings={len(str_eas)} "
        f"globals={cfg['globals_']} calls={cfg['calls']}"
    )

    print("保存 IDB …")
    import idapro  # noqa: PLC0415

    idapro.close_database(save=True)
    size = os.path.getsize(idb_path) if os.path.exists(idb_path) else -1
    print(f"IDB: {idb_path}  {size / 1024 / 1024:.1f}MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())