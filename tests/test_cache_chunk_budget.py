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

import os
import pathlib
import sys
import tempfile
import threading
import time
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


class HotItemResumeTests(unittest.TestCase):
    """单个条目派生上万行时的预算（续传游标）。

    真实形状：一个被调用几万次的函数（或一个被反复引用的字符串）。旧的实现里预算只
    在"条目之间"生效，这种条目会在**一次派发**里把全部 xref 落盘 —— 实测足以占住
    IDA 主线程数秒。现在预算在条目内部也生效，靠 `(条目下标, 已写条数)` 续传。
    """

    HOT_XREFS = 10_000

    def _hot_backend(self) -> FakeBackend:
        # 目标函数 0x1000 有 1 万条 xref；另一个函数 0x2000 只有 1 条
        return FakeBackend(
            functions=[(0x1000, "hot", 16, False), (0x2000, "cold", 16, False)],
            xrefs={
                0x1000: [(0x3000 + i, i % 2 == 0) for i in range(self.HOT_XREFS)],
                0x2000: [(0x9000, True)],
            },
        )

    def _walk(self, extractor, budget: int, table: str):
        """走完全部块，返回 (所有行, 每块行数, 是否出现过续传游标)。"""
        cursor: object = 0
        rows: list = []
        per_chunk: list[int] = []
        saw_tuple_cursor = False
        for _ in range(100_000):
            result = extractor.chunk(cursor, budget, collect=True)
            if isinstance(result.cursor, tuple):
                saw_tuple_cursor = True
            chunk_rows = 0
            for tbl, bucket in result.rows_by_table.items():
                chunk_rows += len(bucket)
                if tbl == table:
                    rows.extend(bucket)
            per_chunk.append(chunk_rows)
            cursor = result.cursor
            if result.done:
                return rows, per_chunk, saw_tuple_cursor
        raise AssertionError("未收敛")

    def test_hot_function_xrefs_are_split_and_complete(self) -> None:
        backend = self._hot_backend()
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        rows, per_chunk, saw_resume = self._walk(extractor, 100, "function_xrefs")

        self.assertEqual(
            len(rows), self.HOT_XREFS + 1, "xref 行数必须与后端一致（不能丢也不能重）"
        )
        self.assertTrue(saw_resume, "预算在条目中途用尽时必须产生续传游标")
        self.assertLessEqual(
            max(per_chunk), 100, f"单块行数 {max(per_chunk)} 超过预算（热门条目未被切分）"
        )
        # 顺序必须与后端枚举顺序一致
        addrs = [hex(r[2]) for r in rows if r[0] != hex(0x2000)]
        expected = [hex(0x3000 + i) for i in range(self.HOT_XREFS)]
        self.assertEqual(addrs[: self.HOT_XREFS], expected, "续传后行序被打乱")

    def test_hot_function_rows_are_not_duplicated(self) -> None:
        backend = self._hot_backend()
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        rows, _, _ = self._walk(extractor, 64, "function_xrefs")
        unique = set(rows)
        self.assertEqual(len(unique), len(rows), "续传导致重复行")

    def test_hot_string_xrefs_are_split_and_complete(self) -> None:
        backend = FakeBackend(
            strings=[(0x5000, "hot"), (0x5100, "cold")],
            xrefs={
                0x5000: [(0x7000 + i, True) for i in range(5_000)],
                0x5100: [(0x8000, True)],
            },
        )
        extractor = cache_extract.StringsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        rows, per_chunk, saw_resume = self._walk(extractor, 100, "string_xrefs")
        self.assertEqual(len(rows), 5_001, "字符串 xref 行数必须与后端一致")
        self.assertTrue(saw_resume, "热门字符串也必须能中途续传")
        self.assertLessEqual(max(per_chunk), 100, "单块行数超过预算")

    def test_resume_does_not_repeat_item_row(self) -> None:
        """续传只补 xref，不能把条目主行再写一次（否则表里会出现重复主键行）。"""
        backend = self._hot_backend()
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        cursor: object = 0
        main_rows = 0
        for _ in range(100_000):
            result = extractor.chunk(cursor, 32, collect=True)
            main_rows += len(result.rows_by_table.get("functions", []))
            cursor = result.cursor
            if result.done:
                break
        self.assertEqual(main_rows, 2, f"functions 主行被重复写入：{main_rows} 行（应为 2）")

    def test_fingerprint_mode_unaffected_by_resume(self) -> None:
        """指纹模式条目是原子的：不该受续传改动影响，且仍按预算分块。"""
        backend = self._hot_backend()
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        cursor: object = 0
        chunks = 0
        for _ in range(1000):
            result = extractor.chunk(
                cursor, 1, collect=False, fingerprint=cache_extract.Fingerprint()
            )
            self.assertNotIsInstance(result.cursor, tuple, "指纹模式不应产生续传游标")
            chunks += 1
            cursor = result.cursor
            if result.done:
                break
        self.assertEqual(chunks, 2, f"2 个条目、预算 1 应恰好 2 块，实际 {chunks}")


class InflightCacheTests(unittest.TestCase):
    """条目内续传时**不能重新枚举 xref**（否则是"预算缩小倍数 × 条目 xref 数"的二次放大）。

    实测事故：热门函数 20 万条 xref + 自适应把预算缩到 100 行 ⇒ 上千次重新枚举，
    一次构建从 1 分钟被拖到 10 分钟以上还没结束。
    """

    def _counting_backend(self, xrefs_of_hot: int = 5_000) -> tuple[FakeBackend, dict]:
        counts = {"func_xrefs_to": 0, "func_at": 0, "count_calls": 0}

        class CountingBackend(FakeBackend):
            def func_xrefs_to(self, ea):  # type: ignore[override]
                counts["func_xrefs_to"] += 1
                return super().func_xrefs_to(ea)

            def func_at(self, index):  # type: ignore[override]
                counts["func_at"] += 1
                return super().func_at(index)

            def func_xref_count(self, ea):  # type: ignore[override]
                counts["count_calls"] += 1
                return len(super().func_xrefs_to(ea))

        backend = CountingBackend(
            functions=[(0x1000, "hot", 16, False), (0x2000, "cold", 16, False)],
            xrefs={0x1000: [(0x4000 + i, True) for i in range(xrefs_of_hot)]},
        )
        return backend, counts

    def test_hot_item_xrefs_enumerated_once_despite_many_resumes(self) -> None:
        # 只放一个热门条目：这样"枚举次数"能直接和"块数"对比
        counts = {"func_xrefs_to": 0, "func_at": 0}

        class CountingBackend(FakeBackend):
            def func_xrefs_to(self, ea):  # type: ignore[override]
                counts["func_xrefs_to"] += 1
                return super().func_xrefs_to(ea)

            def func_at(self, index):  # type: ignore[override]
                counts["func_at"] += 1
                return super().func_at(index)

        backend = CountingBackend(
            functions=[(0x1000, "hot", 16, False)],
            xrefs={0x1000: [(0x4000 + i, True) for i in range(5_000)]},
        )
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        cursor: object = 0
        chunks = 0
        for _ in range(100_000):
            result = extractor.chunk(cursor, 50, collect=True)
            chunks += 1
            cursor = result.cursor
            if result.done:
                break
        self.assertGreater(chunks, 50, "热门条目应被切成很多块")
        self.assertEqual(
            counts["func_xrefs_to"], 1, f"{chunks} 块里 xref 只允许枚举一次（二次放大回归）"
        )
        self.assertEqual(counts["func_at"], 1, "条目元数据只允许访问一次")

    def test_repeated_builds_do_not_reuse_inflight_state(self) -> None:
        """in-flight 缓存不能跨构建泄漏（否则第二轮会读到上一轮的条目）。"""
        backend, counts = self._counting_backend(xrefs_of_hot=200)
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )

        def walk() -> int:
            cursor: object = 0
            rows = 0
            for _ in range(10_000):
                result = extractor.chunk(cursor, 25, collect=True)
                rows += result.row_count
                cursor = result.cursor
                if result.done:
                    return rows
            raise AssertionError("未收敛")

        first = walk()
        second = walk()
        self.assertEqual(first, second, "第二轮结果与第一轮不一致（in-flight 状态泄漏）")
        self.assertEqual(counts["func_xrefs_to"], 4, "每轮每个条目各枚举一次 xref")

    def test_fingerprint_mode_uses_count_only(self) -> None:
        """指纹模式只需要条数：应走"只数不建对象"的接口，不物化 xref 列表。"""
        counts = {"func_xrefs_to": 0, "count_calls": 0}

        class CountingBackend(FakeBackend):
            def func_xrefs_to(self, ea):  # type: ignore[override]
                counts["func_xrefs_to"] += 1
                return super().func_xrefs_to(ea)

            def func_xref_count(self, ea):  # type: ignore[override]
                counts["count_calls"] += 1
                return len(super().func_xrefs_to(ea))

        backend = CountingBackend(
            functions=[(0x1000, "hot", 16, False)],
            xrefs={0x1000: [(0x4000 + i, True) for i in range(1_000)]},
        )
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        cursor: object = 0
        for _ in range(100):
            result = extractor.chunk(
                cursor, 10, collect=False, fingerprint=cache_extract.Fingerprint()
            )
            cursor = result.cursor
            if result.done:
                break
        self.assertEqual(
            counts["func_xrefs_to"], 0, "指纹模式不应物化 xref（应为 0 次枚举）"
        )
        self.assertEqual(counts["count_calls"], 1, "指纹模式应调用一次计数接口")

    def test_fingerprint_falls_back_without_count_api(self) -> None:
        """后端没有计数接口时必须回退为枚举（兼容旧后端/第三方后端）。"""

        class NoCountBackend(FakeBackend):
            func_xref_count = None  # type: ignore[assignment]

        backend = NoCountBackend(
            functions=[(0x1000, "f", 16, False)],
            xrefs={0x1000: [(0x4000, True), (0x4001, True)]},
        )
        extractor = cache_extract.FunctionsExtractor(
            backend, want_xrefs=True, full_fp=False
        )
        fp = cache_extract.Fingerprint()
        result = extractor.chunk(0, 10, collect=False, fingerprint=fp)
        self.assertTrue(result.done)
        self.assertEqual(fp.items, 1)


class BackendApiHygieneTests(unittest.TestCase):
    """后端不得再使用 IDA 9.1 已弃用的 API（兼容 + 每次调用更少 = 更快）。

    只检查**代码形态**：注释/文档字符串里提到旧 API 名（解释"为什么换掉"）不算违规 ——
    这正是之前那次静态守卫翻车的地方（文本匹配把注释也算了）。
    """

    DEPRECATED = (
        "getn_func",
        "getseg",
        "get_segm_name",
        "get_func",
    )

    @staticmethod
    def _called_names(src: str) -> set[str]:
        import ast

        names: set[str] = set()
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Attribute):
                names.add(fn.attr)
            elif isinstance(fn, ast.Name):
                names.add(fn.id)
        return names

    def _source(self) -> str:
        return (
            pathlib.Path(__file__).resolve().parents[1]
            / "src"
            / "ida_pro_mcp"
            / "broker"
            / "cache_backend.py"
        ).read_text(encoding="utf-8")

    def test_backend_avoids_deprecated_apis(self) -> None:
        called = self._called_names(self._source())
        for bad in self.DEPRECATED:
            with self.subTest(api=bad):
                self.assertNotIn(bad, called, f"cache_backend.py 仍在调用已弃用 API: {bad}")

    def test_backend_uses_low_level_xref_enumeration(self) -> None:
        """xref 枚举必须走低层 xrefblk_t（实测快 7.3×、计数快 17×），且保留高层回退。"""
        called = self._called_names(self._source())
        self.assertIn("first_to", called, "应使用 ida_xref.xrefblk_t.first_to")
        self.assertIn("next_to", called)
        self.assertIn(
            "XrefsTo", called, "必须保留 idautils.XrefsTo 作为回退（兼容低层不可用环境）"
        )

    def test_backend_uses_single_call_segment_name(self) -> None:
        called = self._called_names(self._source())
        self.assertIn("get_segment_name", called, "段名应一次调用取到（get_segment_name）")
        self.assertIn("get_func_ea_by_num", called)
        self.assertIn("calc_func_size_ea", called)


class RebuildCoalescingTests(unittest.TestCase):
    """保存触发的重建要合并 + "什么都没变"要整轮跳过（大库上这是每分钟级的主线程开销）。"""

    def _handle(self, tmp: str) -> sqlite_cache._DaemonHandle:  # noqa: SLF001
        return sqlite_cache._DaemonHandle(  # noqa: SLF001
            idb_path=os.path.join(tmp, "x.i64"),
            db_path=os.path.join(tmp, "x.i64.mcp.sqlite"),
            thread=None,
            stop_event=threading.Event(),
            force_event=threading.Event(),
        )

    def test_coalesce_wait_shrinks_and_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = self._handle(tmp)
            handle.last_build_monotonic = time.monotonic() - 5.0
            wait = sqlite_cache._coalesce_wait(handle, 20.0)  # noqa: SLF001
            self.assertGreater(wait, 14.0)
            self.assertLessEqual(wait, 15.5)
            handle.last_build_monotonic = time.monotonic() - 100.0
            self.assertEqual(sqlite_cache._coalesce_wait(handle, 20.0), 0.0)  # noqa: SLF001
            self.assertEqual(sqlite_cache._coalesce_wait(handle, 0.0), 0.0)  # noqa: SLF001

    def test_coalesce_wait_zero_without_prior_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = self._handle(tmp)
            self.assertEqual(sqlite_cache._coalesce_wait(handle, 20.0), 0.0)  # noqa: SLF001

    def test_idb_unchanged_requires_valid_matching_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = self._handle(tmp)
            cfg = cache_config.CacheConfig()
            with open(handle.idb_path, "wb") as fh:
                fh.write(b"abc")
            handle.last_build_sig = sqlite_cache._idb_sig(handle.idb_path)  # noqa: SLF001
            handle.last_build_config = sqlite_cache._config_sig(cfg)  # noqa: SLF001
            handle.last_build_sig_valid = True
            self.assertTrue(sqlite_cache._idb_unchanged(handle, cfg))  # noqa: SLF001

            # 上一轮不完整（partial/not-ready）→ 不允许跳过
            handle.last_build_sig_valid = False
            self.assertFalse(sqlite_cache._idb_unchanged(handle, cfg))  # noqa: SLF001
            handle.last_build_sig_valid = True

            # 配置变了 → 不允许跳过（否则会拿旧配置的库当"没变"）
            other = cache_config.CacheConfig(scope="minimal")
            self.assertFalse(sqlite_cache._idb_unchanged(handle, other))  # noqa: SLF001

            # IDB 真变了（大小/mtime 变化）→ 不允许跳过
            time.sleep(1.1)
            with open(handle.idb_path, "wb") as fh:
                fh.write(b"abcd")
            self.assertFalse(sqlite_cache._idb_unchanged(handle, cfg))  # noqa: SLF001

    def test_request_refresh_marks_forced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = self._handle(tmp)
            sqlite_cache._daemons[handle.idb_path] = handle  # noqa: SLF001
            try:
                self.assertTrue(sqlite_cache.request_refresh(handle.idb_path))
                self.assertTrue(handle.force_now, "显式刷新必须绕过合并窗口")
                self.assertTrue(handle.force_event.is_set())
            finally:
                sqlite_cache._daemons.pop(handle.idb_path, None)  # noqa: SLF001
            self.assertFalse(sqlite_cache.request_refresh(r"C:\nope\x.i64"))


class DiskPreflightTests(unittest.TestCase):
    """磁盘预检：空间不够就拒绝构建，而不是写到一半把盘写满（10GB 级 IDB 上是真事故）。"""

    def test_refuses_when_free_space_below_need(self) -> None:
        usage = type("U", (), {"free": 100 * 1024 * 1024, "total": 0, "used": 0})()
        with mock.patch("shutil.disk_usage", return_value=usage):
            problem = sqlite_cache._disk_preflight(  # noqa: SLF001
                os.path.join(tempfile.gettempdir(), "x.mcp.sqlite"),
                expected_bytes=5_000_000_000,
                factor=2.0,
            )
        self.assertTrue(problem)
        self.assertIn("可用空间不足", problem)

    def test_allows_when_plenty(self) -> None:
        usage = type("U", (), {"free": 100 * 1024**3, "total": 0, "used": 0})()
        with mock.patch("shutil.disk_usage", return_value=usage):
            self.assertEqual(
                sqlite_cache._disk_preflight(  # noqa: SLF001
                    os.path.join(tempfile.gettempdir(), "x.mcp.sqlite"),
                    expected_bytes=5_000_000_000,
                    factor=2.0,
                ),
                "",
            )

    def test_floor_applies_even_with_zero_estimate(self) -> None:
        usage = type("U", (), {"free": 10 * 1024 * 1024, "total": 0, "used": 0})()
        with mock.patch("shutil.disk_usage", return_value=usage):
            problem = sqlite_cache._disk_preflight(  # noqa: SLF001
                os.path.join(tempfile.gettempdir(), "x.mcp.sqlite"),
                expected_bytes=0,
                factor=1.0,
            )
        self.assertTrue(problem, "即使估不出大小，低于下限也必须拒绝")

    def test_expected_bytes_uses_db_size_then_idb_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = sqlite_cache._DaemonHandle(  # noqa: SLF001
                idb_path=os.path.join(tmp, "x.i64"),
                db_path=os.path.join(tmp, "x.mcp.sqlite"),
                thread=None,
                stop_event=threading.Event(),
                force_event=threading.Event(),
            )
            with open(handle.idb_path, "wb") as fh:
                fh.write(b"x" * 1000)
            self.assertEqual(
                sqlite_cache._expected_cache_bytes(handle),  # noqa: SLF001
                int(1000 * sqlite_cache.CACHE_TO_IDB_RATIO),
            )
            with open(handle.db_path, "wb") as fh:
                fh.write(b"y" * 777)
            self.assertEqual(
                sqlite_cache._expected_cache_bytes(handle), 777  # noqa: SLF001
            )

    def test_build_cache_refuses_and_keeps_old_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "x.mcp.sqlite")
            cfg = cache_config.CacheConfig(chunk_rows=4, incremental=False)
            stats = sqlite_cache.build_cache(db, make_backend(n_functions=5), cfg)
            self.assertEqual(stats.status, "ready")
            before = _count_rows(db, "functions")

            usage = type("U", (), {"free": 1, "total": 0, "used": 0})()
            with mock.patch("shutil.disk_usage", return_value=usage):
                refused = sqlite_cache.build_cache(
                    db, make_backend(n_functions=5), cfg
                )
            self.assertEqual(refused.status, "error")
            self.assertEqual(refused.reason, sqlite_cache.DISK_RISK_REASON)  # noqa: SLF001
            self.assertEqual(_count_rows(db, "functions"), before, "拒绝构建不得改库")


def _count_rows(db: str, table: str) -> int:
    """统计行数。

    注意 `with sqlite3.connect(...)` **不会关闭连接**（只处理事务），Windows 上会一直
    占着文件导致临时目录删不掉 —— 必须显式 close。
    """
    import sqlite3

    conn = sqlite3.connect(db)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    finally:
        conn.close()

class SlowToolTimeoutTests(unittest.TestCase):
    """慢工具的超时与"已保存"短路。

    实测误报：806MB 的 IDB 上 `idb_save` 客户端报 -32001 超时，其实保存成功。
    Broker 这层不该比真实耗时更早放弃；插件侧则要让"超时后立刻重试"变得廉价且安全。
    """

    def test_default_timeout_for_unknown_and_non_tool_calls(self) -> None:
        from ida_pro_mcp.broker import manager

        self.assertEqual(
            manager._request_timeout({"method": "tools/list"}),  # noqa: SLF001
            manager.DEFAULT_REQUEST_TIMEOUT_SEC,
        )
        self.assertEqual(
            manager._request_timeout(  # noqa: SLF001
                {"method": "tools/call", "params": {"name": "no_such_tool"}}
            ),
            manager.DEFAULT_REQUEST_TIMEOUT_SEC,
        )

    def test_slow_tools_get_longer_timeout(self) -> None:
        from ida_pro_mcp.broker import manager

        for name in ("idb_save", "survey_binary", "analyze_batch", "export_funcs"):
            with self.subTest(tool=name):
                got = manager._request_timeout(  # noqa: SLF001
                    {"method": "tools/call", "params": {"name": name}}
                )
                self.assertGreater(got, manager.DEFAULT_REQUEST_TIMEOUT_SEC, name)

    def test_route_to_ida_forwards_timeout(self) -> None:
        from ida_pro_mcp.broker import manager

        seen: dict = {}

        class FakeBroker:
            def ping(self) -> bool:
                return True

            def has_instances(self) -> bool:
                return True

            def send_request(self, request, instance_id=None, timeout=60.0):  # noqa: ANN001
                seen["timeout"] = timeout
                seen["instance_id"] = instance_id
                return {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}

        with mock.patch.object(manager, "get_broker_client", lambda: FakeBroker()):
            out = manager.route_to_ida(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "idb_save", "arguments": {"instance_id": "ida-1"}},
                }
            )
        self.assertIsNotNone(out)
        self.assertEqual(seen["instance_id"], "ida-1")
        self.assertEqual(
            seen["timeout"], manager.SLOW_TOOL_TIMEOUTS["idb_save"], "慢工具要转发更长超时"
        )

    def test_plugin_idb_save_short_circuits_recent_save(self) -> None:
        """插件侧必须有"刚刚已保存过"短路（源码形态检查，IDA 外无法 import 该模块）。"""
        src = (
            pathlib.Path(__file__).resolve().parents[1]
            / "src"
            / "ida_pro_mcp"
            / "ida_mcp"
            / "api_core.py"
        ).read_text(encoding="utf-8")
        self.assertIn("RECENT_SAVE_WINDOW_SEC", src)
        self.assertIn("_LAST_SAVE_AT", src)
        self.assertIn("刚刚已保存过", src, "短路必须给出可读提示")
        self.assertIn("不要反复重试", src, "文档必须写明客户端超时的应对方式")
        self.assertIn("force", src, "必须保留强制保存开关（不能用时间窗口牺牲可用性）")


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