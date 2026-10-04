"""分块预算与门控自激：这是"IDA 长期无响应"事故的回归测试。

事故经过（真实日志，GameAssembly.dll 806MB / 134,942 函数）：

    [MCP][cache] 清理旧表: …GameAssembly.dll.i64.mcp.sqlite
    [MCP][cache] 派发耗时 12296ms（>5s）: functions —— IDA 可能正忙…
    [MCP][cache] 构建完成 …: functions=134942, chunks=1, skipped=[], elapsed=12760ms, reason=not-ready
    （约每 13 秒重复一次，IDA 界面长期"未响应"）

根因链条：

1. `CacheExtractor.chunk()` 的循环用 `row_count < budget_rows` 约束工作量，但**指纹模式
   （`collect=False`）在 `row_count += 1` 之前就 `continue` 了** → `row_count` 恒为 0 →
   整张表在一次派发里跑完（13.5 万函数 = 12~13 秒）。
2. 这 12 秒里主线程跑不了插件定时器 → "主线程心跳"过期。
3. 派发结束后的门控复查读到过期心跳，判定"IDA 忙" → 整轮放弃（`not-ready`）。
4. 守护线程立刻重试 → 又抽一大块 → 又放弃 …… 死循环，每轮独占主线程十几秒。

本文件锁死：① 分块预算在两种模式下都生效（首次派发不得吞下整表）；② 我们自己派发完
必须刷新心跳，不让过期心跳判死本轮；③ 连续被门控放弃要指数退避而不是死循环重试。
"""

from __future__ import annotations

import pathlib
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _cache_fakes import FakeBackend, make_backend  # noqa: E402

from ida_pro_mcp.broker import cache_config, cache_extract, sqlite_cache  # noqa: E402


def _iter_chunks(extractor, budget: int, *, collect: bool, limit: int = 500):
    """反复调用 chunk() 直到 done，返回 [(items, rows)]。"""
    cursor = 0
    out: list[tuple[int, int]] = []
    for _ in range(limit):
        result = extractor.chunk(
            cursor,
            budget,
            collect=collect,
            fingerprint=None if collect else cache_extract.Fingerprint(),
        )
        out.append(
            (result.items, sum(len(v) for v in result.rows_by_table.values()))
        )
        cursor = result.cursor
        if result.done:
            return out
    raise AssertionError("chunk() 未能收敛（疑似预算失效导致死循环）")


class ChunkBudgetTests(unittest.TestCase):
    """分块预算：一次 `chunk()` 处理的项目数不得超过预算。"""

    def _extractors(self, backend: FakeBackend) -> dict:
        return {
            "strings": cache_extract.StringsExtractor(
                backend, want_xrefs=True, full_fp=False
            ),
            "functions": cache_extract.FunctionsExtractor(
                backend, want_xrefs=True, full_fp=False
            ),
            "globals": cache_extract.GlobalsExtractor(backend, full_fp=False),
        }

    def test_fingerprint_mode_respects_budget(self) -> None:
        """指纹模式不产生数据行 —— 必须按 items 约束，否则整表一次跑完（本次事故）。"""
        backend = make_backend(n_functions=50, n_strings=40, n_names=30, n_imports=6)
        budget = 7
        for label, extractor in self._extractors(backend).items():
            with self.subTest(extractor=label):
                chunks = _iter_chunks(extractor, budget, collect=False)
                per_chunk = [items for items, _ in chunks]
                self.assertGreater(
                    len(chunks), 1, f"{label}: 数据量大于预算却只用一块 = 预算没生效"
                )
                self.assertLessEqual(
                    max(per_chunk), budget, f"{label}: 单块 {max(per_chunk)} 项 > 预算 {budget}"
                )

    def test_first_dispatch_never_swallows_whole_table(self) -> None:
        """事故的直接形态：首次派发就把整表抽完。这里用远大于预算的表锁死它。"""
        backend = make_backend(n_functions=3000)
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=False, full_fp=False
        )
        first = extractor.chunk(0, 200, collect=False, fingerprint=cache_extract.Fingerprint())
        self.assertFalse(first.done, "首次派发不该直接跑到表尾")
        self.assertLessEqual(first.items, 200, "首次派发处理的项目数超过预算")

    def test_collect_mode_still_bounded(self) -> None:
        """采集模式按"行"收敛：预算检查在块首，最后一个 item 连带的 xref 行会让本块略超
        （超出量 ≤ 单个 item 的 xref 数），这是既有语义，改分块预算时不能把它改坏。"""
        backend = make_backend(n_functions=60, n_strings=50, n_names=40, n_imports=6)
        budget = 8
        xrefs_per_item = 2  # FakeBackend 默认每个 function/string 的 xref 数
        for label, extractor in self._extractors(backend).items():
            with self.subTest(extractor=label):
                chunks = _iter_chunks(extractor, budget, collect=True)
                rows = [r for _, r in chunks]
                self.assertLessEqual(
                    max(rows),
                    budget + xrefs_per_item,
                    f"{label}: 单块写入行数异常膨胀（超出预算 + 单项 xref 数）",
                )
                self.assertGreater(len(chunks), 1, f"{label}: 应分多块")

    def test_imports_split_by_module_without_loss(self) -> None:
        """imports 以"模块"为原子单位：允许模块内轻微超出预算，但不得漏项/重复。"""
        backend = make_backend(n_imports=5)  # 每模块 2 个符号
        extractor = cache_extract.ImportsExtractor(backend, full_fp=False)
        chunks = _iter_chunks(extractor, 3, collect=True)
        total_rows = sum(r for _, r in chunks)
        self.assertEqual(total_rows, 10, "imports 行数应等于所有模块的符号总数")
        self.assertGreater(len(chunks), 1, "预算 3 时应分多块（不得一次吞下整表）")
        self.assertLessEqual(
            max(r for _, r in chunks),
            3 + 4,
            "单块最多只允许超出一个模块的量级",
        )

    def test_both_modes_walk_the_same_cursor(self) -> None:
        """两种模式的游标终点一致（分段没漏项/重复）。"""
        backend = make_backend(n_functions=33, n_strings=21, n_names=17, n_imports=4)
        for label, extractor in self._extractors(backend).items():
            with self.subTest(extractor=label):
                fp_cursor = collect_cursor = 0
                for mode in ("fp", "collect"):
                    cursor = 0
                    for _ in range(300):
                        r = extractor.chunk(
                            cursor,
                            5,
                            collect=(mode == "collect"),
                            fingerprint=None if mode == "collect" else cache_extract.Fingerprint(),
                        )
                        cursor = r.cursor
                        if r.done:
                            break
                    if mode == "fp":
                        fp_cursor = cursor
                    else:
                        collect_cursor = cursor
                self.assertEqual(fp_cursor, collect_cursor, f"{label}: 两种模式游标不一致")


class FingerprintDispatchTests(unittest.TestCase):
    """`_fingerprint_extractor` 必须分多次小派发，且放行条件由心跳驱动。"""

    def test_pass_is_split_into_small_dispatches(self) -> None:
        backend = make_backend(n_functions=200)
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=False, full_fp=False
        )
        chunker = cache_config.AdaptiveChunker(chunk_rows=10, target_ms=150, min_rows=2)
        dispatched: list[tuple[int, int]] = []
        original = extractor.chunk

        def _spy(cursor, budget, **kwargs):  # noqa: ANN001
            result = original(cursor, budget, **kwargs)
            dispatched.append((budget, result.items))
            return result

        with mock.patch.object(extractor, "chunk", _spy):
            digest, chunks = sqlite_cache._fingerprint_extractor(  # noqa: SLF001
                extractor, chunker, should_stop=lambda: False, wait_ready=lambda: True
            )
        self.assertIsNotNone(digest)
        self.assertGreater(chunks, 1, "200 个函数、初始预算 10 却只派发一次 = 整表一次抽完")
        self.assertEqual(dispatched[0][0], 10, "首次派发必须用初始预算（不得一上来就放大）")
        for budget, items in dispatched:
            self.assertLessEqual(items, budget, f"单块处理 {items} 项 > 预算 {budget}")

    def test_own_dispatch_refreshes_heartbeat(self) -> None:
        """派发期间定时器跑不了 → 心跳变旧；我们自己派发完必须刷新，否则整轮被放弃。"""
        backend = make_backend(n_functions=120)
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=False, full_fp=False
        )
        chunker = cache_config.AdaptiveChunker(chunk_rows=5, target_ms=150, min_rows=2)
        handle = _handle_with_ticks()
        original = extractor.chunk

        def _spy(cursor, budget, **kwargs):  # noqa: ANN001
            result = original(cursor, budget, **kwargs)
            # 模拟：这次派发把主线程占住了，期间插件定时器没能刷新心跳
            sqlite_cache._last_heartbeat = 1.0  # noqa: SLF001
            return result

        with mock.patch.object(extractor, "chunk", _spy), mock.patch.object(
            sqlite_cache, "_last_heartbeat", 1.0
        ):
            sqlite_cache._touch_heartbeat()  # 起始时心跳是新鲜的  # noqa: SLF001
            digest, chunks = sqlite_cache._fingerprint_extractor(  # noqa: SLF001
                extractor,
                chunker,
                should_stop=lambda: False,
                wait_ready=lambda: sqlite_cache._gate_ready(handle),  # noqa: SLF001
            )
        self.assertIsNotNone(digest, "心跳被自己刷新后，pass 应能跑完而不是中途被放弃")
        self.assertGreater(chunks, 1)

    def test_without_heartbeat_touch_the_pass_aborts(self) -> None:
        """反向验证：把刷新心跳去掉，同场景必须中途放弃（证明上面的测试真的有效）。"""
        backend = make_backend(n_functions=120)
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=False, full_fp=False
        )
        chunker = cache_config.AdaptiveChunker(chunk_rows=5, target_ms=150, min_rows=2)
        handle = _handle_with_ticks()
        original = extractor.chunk

        def _spy(cursor, budget, **kwargs):  # noqa: ANN001
            result = original(cursor, budget, **kwargs)
            sqlite_cache._last_heartbeat = 1.0  # noqa: SLF001 - 心跳变旧
            return result

        with mock.patch.object(extractor, "chunk", _spy), mock.patch.object(
            sqlite_cache, "_touch_heartbeat", lambda: None
        ):
            digest, chunks = sqlite_cache._fingerprint_extractor(  # noqa: SLF001
                extractor,
                chunker,
                should_stop=lambda: False,
                wait_ready=lambda: sqlite_cache._gate_ready(handle),  # noqa: SLF001
            )
        self.assertIsNone(digest, "心跳过期且不刷新时，pass 必须放弃（不能假装没发生）")


def _handle_with_ticks() -> sqlite_cache._DaemonHandle:  # noqa: SLF001
    """构造一个"有插件定时器"的句柄（ticks>0 才会启用心跳判定）。"""
    handle = sqlite_cache._DaemonHandle(  # noqa: SLF001
        idb_path="x.i64",
        db_path="x.i64.mcp.sqlite",
        thread=None,
        stop_event=threading.Event(),
        force_event=threading.Event(),
        idle_backend=FakeBackend(idle=True),
    )
    handle.idle_state.idle = True
    handle.idle_state.ticks = 5
    return handle


class InitialChunkTests(unittest.TestCase):
    """首块要小：配置值 20000 起步在大库上单次派发 6.4 秒，界面会明显卡一下。"""

    def test_first_dispatch_is_capped_and_never_exceeds_config(self) -> None:
        import tempfile
        import shutil

        tmp = tempfile.mkdtemp(prefix="ida-mcp-firstchunk-")
        try:
            backend = make_backend(n_functions=50_000)
            extractor = cache_extract.FunctionsExtractor(
                backend, want_xrefs=False, full_fp=False
            )
            budgets: list[int] = []
            original = extractor.chunk

            def _spy(cursor, budget, **kwargs):  # noqa: ANN001
                budgets.append(budget)
                return original(cursor, budget, **kwargs)

            cfg = cache_config.CacheConfig(chunk_rows=20_000, incremental=False)
            with mock.patch.object(extractor, "chunk", _spy), mock.patch.object(
                sqlite_cache, "build_extractors", lambda *a, **k: [extractor]
            ):
                sqlite_cache.build_cache(
                    tmp + "/x.mcp.sqlite", backend, cfg, wait_ready=lambda: True
                )
            self.assertTrue(budgets, "没有观察到任何派发")
            self.assertLessEqual(
                budgets[0],
                sqlite_cache.INITIAL_CHUNK_ROWS,  # noqa: SLF001
                f"首块预算 {budgets[0]} 超过 INITIAL_CHUNK_ROWS，大库上会卡住主线程",
            )
            self.assertLessEqual(
                max(budgets),
                cfg.chunk_rows,
                f"自适应把单块放大到 {max(budgets)}，超过配置上限 {cfg.chunk_rows}",
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_small_config_is_not_inflated(self) -> None:
        """配置比 INITIAL_CHUNK_ROWS 小时以配置为准（单测常用 chunk_rows=4）。"""
        chunker = cache_config.AdaptiveChunker(
            chunk_rows=min(4, sqlite_cache.INITIAL_CHUNK_ROWS),  # noqa: SLF001
            target_ms=150,
            min_rows=max(1, min(4, cache_config.MIN_CHUNK_ROWS)),
            max_rows=4,
        )
        self.assertLessEqual(chunker.next_size(), 4)


class BackoffTests(unittest.TestCase):
    """连续被门控放弃必须退避，不能"放弃→立刻重试"地死循环。"""

    def test_delay_grows_and_is_capped(self) -> None:
        delays = [sqlite_cache._not_ready_backoff_delay(n) for n in range(1, 12)]  # noqa: SLF001
        self.assertGreaterEqual(delays[0], sqlite_cache.IDLE_POLL_SEC)
        self.assertTrue(
            all(b >= a for a, b in zip(delays, delays[1:])),
            f"退避不是单调不减: {delays}",
        )
        self.assertLessEqual(max(delays), sqlite_cache.NOT_READY_BACKOFF_MAX_SEC)
        self.assertGreater(
            max(delays),
            sqlite_cache.IDLE_POLL_SEC,
            "连续失败时退避必须真的变大（否则仍是每 2 秒一轮的死循环）",
        )

    def test_zero_or_negative_streak_is_base_delay(self) -> None:
        self.assertEqual(
            sqlite_cache._not_ready_backoff_delay(0), sqlite_cache.IDLE_POLL_SEC  # noqa: SLF001
        )
        self.assertEqual(
            sqlite_cache._not_ready_backoff_delay(-3), sqlite_cache.IDLE_POLL_SEC  # noqa: SLF001
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)