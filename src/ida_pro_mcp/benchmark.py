"""缓存层基准：合成数据集，量化"峰值内存 / 构建耗时 / 查询延迟"。

用途
----
1. 给 T1 的分块流式改造留可回归的数字（CI 里用 `--assert-peak-mb` 做门禁，
   防止有人把"整库物化"的写法改回来）。
2. 本地快速对比不同 `IDA_MCP_CACHE_CHUNK_ROWS` / scope 配置的代价。

用法::

    python -m ida_pro_mcp.benchmark --rows 200000
    python -m ida_pro_mcp.benchmark --rows 200000 --assert-peak-mb 500
    python -m ida_pro_mcp.benchmark --rows 200000 --legacy      # 对照：历史全量物化写法
    python -m ida_pro_mcp.benchmark --rows 200000 --keep-db     # 保留生成的 sqlite 供检查

`--legacy` 分支是**对历史实现的等价模拟**（先把整库读成 Python list 再单事务写库），
用来在同一台机器上给出"改造前 vs 改造后"的峰值内存对照，不需要旧代码在场。
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from typing import Iterator, Optional, Sequence

from .broker import cache_config, sqlite_cache, sqlite_query
from .broker.cache_rss import current_rss_mb


# ---------------------------------------------------------------------------
# 合成后端：按索引即时生成，绝不预先物化（否则基准本身就会吃掉内存）
# ---------------------------------------------------------------------------


@dataclass
class SyntheticShape:
    """合成数据集的形状（行数分布）。"""

    functions: int
    function_xrefs: int
    strings: int
    string_xrefs: int
    names: int
    import_modules: int = 4
    imports_per_module: int = 8

    @classmethod
    def from_total_rows(cls, rows: int) -> "SyntheticShape":
        rows = max(1, int(rows))
        return cls(
            functions=max(1, rows // 8),
            function_xrefs=rows // 2,
            strings=max(1, rows // 16),
            string_xrefs=rows // 4,
            names=max(1, rows // 16),
        )


class SyntheticBackend:
    """实现 `cache_extract.CacheBackend` 的合成后端（内存恒定）。"""

    def __init__(self, shape: SyntheticShape) -> None:
        self.shape = shape
        self._xrefs_per_function = max(
            1, shape.function_xrefs // max(1, shape.functions)
        )
        self._xrefs_per_string = max(1, shape.string_xrefs // max(1, shape.strings))

    # -- 基础 -------------------------------------------------------------

    def is_idle(self) -> bool:
        return True

    def func_count(self) -> int:
        return self.shape.functions

    def str_count(self) -> int:
        return self.shape.strings

    def name_count(self) -> int:
        return self.shape.names

    def import_module_count(self) -> int:
        return self.shape.import_modules

    # -- 数据 -------------------------------------------------------------

    def func_at(self, index: int) -> Optional[tuple[int, str, int, bool]]:
        if not 0 <= index < self.shape.functions:
            return None
        ea = 0x1000 + index * 0x10
        return (ea, f"sub_{index:X}", 0x10 + (index % 64), index % 3 == 0)

    def str_at(self, index: int) -> Optional[tuple[int, str, int]]:
        if not 0 <= index < self.shape.strings:
            return None
        text = f"synthetic string #{index} with some payload {index * 7 % 9973}"
        return (0x100000 + index * 0x20, text, len(text))

    def name_at(self, index: int) -> Optional[tuple[int, str]]:
        if not 0 <= index < self.shape.names:
            return None
        return (0x200000 + index * 0x10, f"gvar_{index:X}")

    def import_module_name(self, index: int) -> str:
        return f"module{index}.dll"

    def import_names(self, index: int) -> Sequence[tuple[int, str, Optional[int]]]:
        if not 0 <= index < self.shape.import_modules:
            return ()
        base = 0x300000 + index * 0x100
        return [
            (base + j * 8, f"import_{index}_{j}", j)
            for j in range(self.shape.imports_per_module)
        ]

    # -- 关系 -------------------------------------------------------------

    def func_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]:
        index = (ea - 0x1000) // 0x10
        return [(0x400000 + index * 0x40 + k, k % 2 == 0) for k in range(self._xrefs_per_function)]

    def str_xrefs_to(self, ea: int) -> Sequence[tuple[int, bool]]:
        index = (ea - 0x100000) // 0x20
        return [(0x500000 + index * 0x40 + k, True) for k in range(self._xrefs_per_string)]

    def is_function(self, ea: int) -> bool:
        return 0x1000 <= ea < 0x1000 + self.shape.functions * 0x10

    def item_size(self, ea: int) -> int:
        return 8

    def segment_name(self, ea: int) -> str:
        if ea >= 0x200000:
            return ".data"
        if ea >= 0x100000:
            return ".rodata"
        return ".text"


# ---------------------------------------------------------------------------
# 历史实现模拟（用于对照峰值内存）
# ---------------------------------------------------------------------------


def _legacy_materialize(backend: SyntheticBackend) -> dict[str, list[tuple]]:
    """等价复刻历史 `_collect_all_data()`：把整库读成 6 个 list。"""
    out: dict[str, list[tuple]] = {
        "strings": [],
        "string_xrefs": [],
        "functions": [],
        "function_xrefs": [],
        "globals": [],
        "imports": [],
    }
    for i in range(backend.func_count()):
        item = backend.func_at(i)
        if item is None:
            continue
        ea, name, size, has_type = item
        addr = hex(ea)
        out["functions"].append((addr, ea, name, size, backend.segment_name(ea), int(has_type)))
        for frm, is_code in backend.func_xrefs_to(ea):
            out["function_xrefs"].append((addr, hex(frm), frm, "to", "code" if is_code else "data"))
    for i in range(backend.str_count()):
        item = backend.str_at(i)
        if item is None:
            continue
        ea, text, length = item
        addr = hex(ea)
        out["strings"].append((addr, ea, text, length, backend.segment_name(ea)))
        for frm, is_code in backend.str_xrefs_to(ea):
            out["string_xrefs"].append((addr, hex(frm), frm, "code" if is_code else "data"))
    for i in range(backend.name_count()):
        item = backend.name_at(i)
        if item is None:
            continue
        ea, name = item
        if backend.is_function(ea):
            continue
        out["globals"].append((hex(ea), ea, name, backend.item_size(ea), backend.segment_name(ea)))
    for i in range(backend.import_module_count()):
        module = backend.import_module_name(i)
        for ea, name, ordinal in backend.import_names(i):
            out["imports"].append((hex(ea), ea, name or f"#{ordinal}", module))
    return out


def _legacy_write(db_path: str, data: dict[str, list[tuple]]) -> None:
    """等价复刻历史 `_write_data_to_db()`：单事务 DELETE + 全量 executemany。

    历史实现的 `_connect()` 会在同一个脚本里建表**带索引**，插桩保持一致：
    索引在插入期间就被维护（这正是旧实现更慢/更吃内存的原因之一）。
    """
    import sqlite3

    from .broker.cache_writer import META_TABLE_DDL, TABLE_SPECS

    conn = sqlite3.connect(db_path, timeout=15.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")  # 历史实现就是 MEMORY
        conn.execute(META_TABLE_DDL)
        for spec in TABLE_SPECS.values():
            conn.execute(spec.create_sql(spec.name))
            for index_name, columns in spec.indexes:
                conn.execute(spec.index_sql(spec.name, index_name, columns))
        for table, spec in TABLE_SPECS.items():
            rows = data.get(table, [])
            conn.executemany(spec.insert_sql(table), rows)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 基准主体
# ---------------------------------------------------------------------------


@dataclass
class BenchResult:
    label: str
    rows: int
    seconds: float
    peak_py_mb: float
    rss_delta_mb: float
    db_mb: float

    def as_dict(self) -> dict[str, float | str | int]:
        return {
            "label": self.label,
            "rows": self.rows,
            "seconds": round(self.seconds, 3),
            "peak_tracemalloc_mb": round(self.peak_py_mb, 1),
            "rss_delta_mb": round(self.rss_delta_mb, 1),
            "db_mb": round(self.db_mb, 2),
        }


def _measure(label: str, rows: int, fn) -> BenchResult:
    rss_before = current_rss_mb()
    tracemalloc.start()
    started = time.perf_counter()
    fn()
    seconds = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = current_rss_mb()
    return BenchResult(
        label=label,
        rows=rows,
        seconds=seconds,
        peak_py_mb=peak / (1024 * 1024),
        rss_delta_mb=max(0.0, rss_after - rss_before),
        db_mb=0.0,
    )


def _db_size_mb(db_path: str) -> float:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.path.getsize(db_path + suffix)
        except OSError:
            continue
    return total / (1024 * 1024)


def _time_queries(db_path: str, rounds: int = 20) -> dict[str, float]:
    """查询延迟：字面量 / 正则 / 前缀 / 列表。"""
    timings: dict[str, list[float]] = {}
    probes = {
        "find_regex_literal": lambda: sqlite_query.find_regex(
            db_path, "payload", limit=50, include_xrefs=False
        ),
        "find_regex_prefix": lambda: sqlite_query.find_regex(
            db_path, "^synthetic string #1", limit=50, include_xrefs=False
        ),
        "find_regex_regex": lambda: sqlite_query.find_regex(
            db_path, r"payload \d{1,3}$", limit=50, include_xrefs=False
        ),
        "list_funcs": lambda: sqlite_query.list_funcs(db_path, limit=100),
        "entity_query_strings": lambda: sqlite_query.entity_query(
            db_path, "strings", limit=100, include_xrefs=False
        ),
        "cache_status": lambda: sqlite_query.cache_status(db_path),
    }
    for name, fn in probes.items():
        samples: list[float] = []
        for _ in range(rounds):
            started = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - started) * 1000.0)
        timings[name] = statistics.median(samples)
    return timings


def run_benchmark(
    rows: int,
    *,
    chunk_rows: int,
    legacy: bool,
    keep_db: bool,
    tmpdir: Optional[str] = None,
    query_rounds: int = 20,
) -> dict[str, object]:
    shape = SyntheticShape.from_total_rows(rows)
    backend = SyntheticBackend(shape)
    workdir = tmpdir or tempfile.mkdtemp(prefix="ida-mcp-bench-")
    db_path = os.path.join(workdir, "synthetic.i64.mcp.sqlite")

    results: list[BenchResult] = []

    # 先跑 legacy：它的峰值最高，先测才能让它的 RSS 增量从干净基线量起
    if legacy:
        legacy_db = os.path.join(workdir, "legacy.i64.mcp.sqlite")

        def _legacy() -> None:
            data = _legacy_materialize(backend)
            _legacy_write(legacy_db, data)

        legacy_result = _measure("legacy (monolithic)", rows, _legacy)
        legacy_result.db_mb = _db_size_mb(legacy_db)
        results.append(legacy_result)
        if not keep_db:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(legacy_db + suffix)
                except OSError:
                    pass

    def _chunked() -> None:
        cfg = cache_config.CacheConfig(chunk_rows=chunk_rows, incremental=False)
        sqlite_cache.build_cache(db_path, backend, cfg)

    chunked = _measure("chunked (T1)", rows, _chunked)
    chunked.db_mb = _db_size_mb(db_path)
    results.append(chunked)

    timings = _time_queries(db_path, rounds=query_rounds)

    if not keep_db:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_path + suffix)
            except OSError:
                pass
        try:
            os.rmdir(workdir)
        except OSError:
            pass

    return {
        "rows": rows,
        "shape": {
            "functions": shape.functions,
            "function_xrefs": shape.function_xrefs,
            "strings": shape.strings,
            "string_xrefs": shape.string_xrefs,
            "names": shape.names,
        },
        "chunk_rows": chunk_rows,
        "results": [r.as_dict() for r in results],
        "query_ms_median": {k: round(v, 3) for k, v in timings.items()},
        "peak_tracemalloc_mb": chunked.peak_py_mb,
    }


def _print_report(report: dict[str, object]) -> None:
    print("=" * 78)
    print("IDA Pro MCP — SQLite 缓存基准（合成数据集，不含 IDA）")
    print("=" * 78)
    print(f"总行数规模: {report['rows']:,}   分块行数: {report['chunk_rows']:,}")
    shape = report["shape"]
    assert isinstance(shape, dict)
    print(
        "形状: functions={functions:,} function_xrefs={function_xrefs:,} "
        "strings={strings:,} string_xrefs={string_xrefs:,} names={names:,}".format(**shape)
    )
    print()
    print(f"{'实现':<24}{'耗时(s)':>10}{'Python峰值(MB)':>16}{'RSS增量(MB)':>14}{'库大小(MB)':>12}")
    print("-" * 78)
    results = report["results"]
    assert isinstance(results, list)
    for row in results:
        assert isinstance(row, dict)
        print(
            f"{row['label']:<24}{row['seconds']:>10.2f}"
            f"{row['peak_tracemalloc_mb']:>16.1f}{row['rss_delta_mb']:>14.1f}"
            f"{row['db_mb']:>12.2f}"
        )
    print()
    print("查询延迟（中位数，ms）:")
    timings = report["query_ms_median"]
    assert isinstance(timings, dict)
    for name, value in timings.items():
        print(f"  {name:<24}{value:>8.2f}")
    if len(results) > 1:
        peaks = {str(r["label"]): float(r["peak_tracemalloc_mb"]) for r in results}  # type: ignore[arg-type]
        chunked_peak = peaks.get("chunked (T1)", 0.0)
        legacy_peak = peaks.get("legacy (monolithic)", 0.0)
        if legacy_peak > 0 and chunked_peak > 0:
            print()
            print(
                f"Python 峰值内存: legacy {legacy_peak:.0f} MB -> chunked {chunked_peak:.0f} MB "
                f"（{legacy_peak / chunked_peak:.1f}x）"
            )
            print(
                "说明: legacy 峰值 ≈ 行数 × ~180B 线性增长；chunked 峰值 ≈ 单块大小，"
                "与总行数无关（这是本次改造的核心目标）。"
            )
    print(
        "注: RSS 列是进程级读数且与执行顺序有关，权威指标是 tracemalloc 峰值；"
        "CI 门禁用 --assert-peak-mb 卡 tracemalloc 峰值。"
    )
    print("=" * 78)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-mcp-bench",
        description="SQLite 缓存层基准（峰值内存 / 耗时 / 查询延迟）",
    )
    parser.add_argument("--rows", type=int, default=200_000, help="合成数据集总行数量级")
    parser.add_argument(
        "--chunk-rows",
        type=int,
        default=cache_config.DEFAULT_CHUNK_ROWS,
        help="分块行数（默认 %(default)s）",
    )
    parser.add_argument("--legacy", action="store_true", help="同时跑历史全量物化实现做对照")
    parser.add_argument("--keep-db", action="store_true", help="保留生成的 sqlite 文件")
    parser.add_argument("--query-rounds", type=int, default=20, help="每个查询的采样次数")
    parser.add_argument(
        "--assert-peak-mb",
        type=float,
        default=0.0,
        help="Python 峰值内存上限（MB）；超出时以退出码 2 失败，用于 CI 门禁",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 输出（便于 CI 解析）")
    args = parser.parse_args(argv)

    report = run_benchmark(
        args.rows,
        chunk_rows=args.chunk_rows,
        legacy=args.legacy,
        keep_db=args.keep_db,
        query_rounds=args.query_rounds,
    )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_report(report)

    peak = float(report["peak_tracemalloc_mb"])  # type: ignore[arg-type]
    if args.assert_peak_mb > 0 and peak > args.assert_peak_mb:
        print(
            f"FAIL: Python 峰值内存 {peak:.0f} MB 超过上限 {args.assert_peak_mb:.0f} MB",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
