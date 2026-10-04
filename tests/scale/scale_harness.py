"""规模测试台：在 headless idalib 里用**真实 IDA 后端**跑缓存构建，精确测量每次派发。

GUI 里只能靠日志和肉眼判断"卡不卡"；这里能拿硬指标，并且能对病态样本直接断言：

* 每次派发的耗时分布（中位 / p95 / 最大）与 **>5s 慢派发次数**
* 每块处理的条目数与落盘行数（必须都在预算内）
* 指纹 pass 单独耗时、Python 峰值内存（tracemalloc）、缓存库大小

用法::

    set IDADIR=D:\\IDA
    python tests/scale/scale_harness.py %TEMP%\\ida-mcp-scale\\synth-1.exe.i64 --mode full
    python tests/scale/scale_harness.py <idb> --mode skip          # 增量：验证指纹跳过
    python tests/scale/scale_harness.py <idb> --mode fp-only       # 只跑指纹 pass
    python tests/scale/scale_harness.py <idb> --fail-on-slow-dispatch --assert-peak-mb 128

回归基线（stage 1：30 万函数 / 300 万 xref / 1.46GB IDB，2.1.8 实测）::

    全量重建  ≈ 71 s，chunks ≈ 400，最大单次派发 ≈ 1.3 s，>5s 次数 = 0
    Python 峰值内存 ≈ 23 MB，缓存库 ≈ 419 MB
    保存后增量（skip）≈ 3 s，全部表按指纹跳过
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scale_common import open_db, prepare_environment  # noqa: E402

SLOW_DISPATCH_MS = 5000.0


def main() -> int:
    parser = argparse.ArgumentParser(description="大库缓存构建的规模测试台")
    parser.add_argument("idb", help="目标 IDB（用 make_fixture.py 生成）")
    parser.add_argument("--chunk-rows", type=int, default=20_000)
    parser.add_argument("--scope", default="full", choices=("full", "minimal"))
    parser.add_argument(
        "--mode",
        default="full",
        choices=("full", "skip", "fp-only"),
        help="full=清库重建；skip=增量（验证指纹跳过）；fp-only=只跑指纹 pass",
    )
    parser.add_argument("--keep-db", action="store_true", help="不要先删掉已有缓存库")
    parser.add_argument("--sample-funcs", type=int, default=400, help="病态样本抽样函数数")
    parser.add_argument("--assert-peak-mb", type=float, default=0.0, help="峰值内存上限（超了退出码 2）")
    parser.add_argument(
        "--fail-on-slow-dispatch",
        action="store_true",
        help="出现 >5s 的单次派发就退出码 2（回归门禁）",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 输出指标")
    args = parser.parse_args()

    prepare_environment()

    from ida_pro_mcp.broker import cache_backend, cache_config, cache_extract, sqlite_cache

    idb = args.idb
    db = idb + ".mcp.sqlite"
    if args.mode == "full" and not args.keep_db:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db + suffix)
            except OSError:
                pass

    open_db(idb, auto_analysis=False)
    backend = cache_backend.IdaCacheBackend()

    # 病态样本：抽样找 xref 最多的函数（用于确认"单条目爆炸"形状确实存在）
    worst_ea, worst_n = 0, -1
    for i in range(min(backend.func_count(), args.sample_funcs)):
        item = backend.func_at(i)
        if not item:
            continue
        count = len(backend.func_xrefs_to(item[0]))
        if count > worst_n:
            worst_ea, worst_n = item[0], count

    dispatches: list[tuple[float, int, int]] = []
    original = cache_backend.run_on_ida_main

    def spy(fn, **kwargs):  # noqa: ANN001, ANN202
        started = time.perf_counter()
        out = original(fn, **kwargs)
        dispatches.append(
            (
                (time.perf_counter() - started) * 1000.0,
                int(getattr(out, "items", 0) or 0),
                int(getattr(out, "row_count", 0) or 0),
            )
        )
        return out

    # sqlite_cache 在调用点才取该属性，所以打补丁能生效
    cache_backend.run_on_ida_main = spy
    cfg = cache_config.CacheConfig(
        chunk_rows=args.chunk_rows,
        scope=args.scope,
        incremental=(args.mode != "full"),
    )

    metrics: dict = {
        "idb": idb,
        "idb_mb": round(os.path.getsize(idb) / 1e6, 1) if os.path.exists(idb) else -1,
        "funcs": backend.func_count(),
        "strings": backend.str_count(),
        "names": backend.name_count(),
        "worst_xref_ea": hex(worst_ea),
        "worst_xref_count": worst_n,
        "mode": args.mode,
    }

    if args.mode == "fp-only":
        extractor = cache_extract.FunctionsExtractor(backend, want_xrefs=True, full_fp=False)
        chunker = cache_config.AdaptiveChunker(
            chunk_rows=min(cfg.chunk_rows, sqlite_cache.INITIAL_CHUNK_ROWS),
            target_ms=cfg.target_chunk_ms,
            min_rows=100,
            max_rows=cfg.chunk_rows,
        )
        started = time.perf_counter()
        digest, chunks = sqlite_cache._fingerprint_extractor(
            extractor, chunker, should_stop=lambda: False, wait_ready=lambda: True
        )
        metrics.update(
            fingerprint_sec=round(time.perf_counter() - started, 2),
            fingerprint_chunks=chunks,
            fingerprint_digest=digest,
        )
    else:
        tracemalloc.start()
        started = time.perf_counter()
        stats = sqlite_cache.build_cache(db, backend, cfg)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        metrics.update(
            status=stats.status,
            partial=bool(stats.partial),
            reason=stats.reason or "",
            chunks=stats.chunks,
            elapsed_sec=round(elapsed, 2),
            functions=stats.functions,
            function_xrefs=stats.function_xrefs,
            strings=stats.strings,
            globals=stats.globals_,
            imports=stats.imports,
            skipped=list(stats.tables_skipped),
            cache_mb=round(os.path.getsize(db) / 1e6, 1) if os.path.exists(db) else -1,
            peak_mb=round(peak / 1024 / 1024, 1),
        )

    times = [d[0] for d in dispatches] or [0.0]
    metrics.update(
        dispatches=len(dispatches),
        dispatch_max_ms=round(max(times), 1),
        dispatch_median_ms=round(statistics.median(times), 1),
        dispatch_p95_ms=round(sorted(times)[max(0, int(len(times) * 0.95) - 1)], 1),
        slow_dispatches=sum(1 for t in times if t > SLOW_DISPATCH_MS),
        max_chunk_items=max((d[1] for d in dispatches), default=0),
        max_chunk_rows=max((d[2] for d in dispatches), default=0),
    )

    if args.json:
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
    else:
        print(f"[后端] funcs={metrics['funcs']} strings={metrics['strings']} names={metrics['names']}")
        print(
            f"[病态样本] 抽样 {args.sample_funcs} 个函数，xref 最多者 "
            f"{metrics['worst_xref_ea']} 有 {metrics['worst_xref_count']} 条"
        )
        if args.mode == "fp-only":
            print(
                f"[指纹 pass] chunks={metrics['fingerprint_chunks']} "
                f"elapsed={metrics['fingerprint_sec']}s"
            )
        else:
            print(
                f"[构建] mode={args.mode} status={metrics['status']} "
                f"partial={metrics['partial']} reason={metrics['reason'] or '-'} "
                f"chunks={metrics['chunks']} elapsed={metrics['elapsed_sec']}s"
            )
            print(
                f"[结果] functions={metrics['functions']} "
                f"function_xrefs={metrics['function_xrefs']} strings={metrics['strings']} "
                f"globals={metrics['globals']} imports={metrics['imports']} "
                f"skipped={metrics['skipped']}"
            )
            print(
                f"[容量] 缓存库={metrics['cache_mb']}MB "
                f"Python 峰值内存={metrics['peak_mb']}MB"
            )
        print(
            f"[派发] n={metrics['dispatches']} 最大={metrics['dispatch_max_ms']}ms "
            f"中位={metrics['dispatch_median_ms']}ms p95={metrics['dispatch_p95_ms']}ms "
            f">5s 次数={metrics['slow_dispatches']}"
        )
        print(
            f"[派发] 单块最大 items={metrics['max_chunk_items']} "
            f"rows={metrics['max_chunk_rows']}"
        )

    import idapro  # noqa: PLC0415

    idapro.close_database(save=False)

    failed = 0
    if args.fail_on_slow_dispatch and metrics["slow_dispatches"]:
        print(f"失败：出现 {metrics['slow_dispatches']} 次 >5s 的派发", file=sys.stderr)
        failed = 2
    if args.assert_peak_mb and metrics.get("peak_mb", 0.0) > args.assert_peak_mb:
        print(
            f"失败：Python 峰值内存 {metrics['peak_mb']}MB > {args.assert_peak_mb}MB",
            file=sys.stderr,
        )
        failed = 2
    return failed


if __name__ == "__main__":
    sys.exit(main())