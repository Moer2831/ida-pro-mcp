# Changelog

本文件记录本仓库（[Moer2831/ida-pro-mcp](https://github.com/Moer2831/ida-pro-mcp)）的改动。
上游来源：[QiuChenly/ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement)
→ [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。

## 2.1.0

主题：**大 IDB 的内存与性能**。历史实现把整库静态信息一次性物化成 Python 对象
（实测约 244 B/行，千万级交叉引用即数 GB）再单事务全量重写，是"大 IDA 内存爆满 +
界面卡死"的根因。本次改造把这条链路整体换成分块流式 + 影子表原子切换。

### 内存与性能（T1）

- **分块流式提取**：新增 `broker/cache_extract.py`（游标式切片 + 增量指纹）与
  `broker/cache_backend.py`（IDAPython 适配器）。峰值内存从 O(全库) 降到 O(块)，
  块间经 `execute_sync` 让出 IDA 主线程，GUI 不再被整段提取占死。
- **自适应块大小**：按实测耗时（默认目标 150 ms/块）动态调整行数，
  配置项 `IDA_MCP_CACHE_TARGET_CHUNK_MS`。
- **影子表 + 原子切换**：`broker/cache_writer.py` 先写 `<table>__new`，最后一次
  事务内 DROP/RENAME/建索引。读者要么看到旧快照、要么看到新快照，
  **不再存在"表被清空"的窗口**；索引改为切换后一次性创建（bulk load 最快路径）。
- **表级指纹增量**：指纹未变的表整组跳过写库（`IDA_MCP_CACHE_INCREMENTAL=0` 可关闭）；
  `IDA_MCP_CACHE_FINGERPRINT=shape|full` 控制精度（shape 只哈希索引字段，full 连文本一起哈希）。
- **失败安全**：单表失败只丢弃影子表；有可用快照时构建异常**不会让缓存下线**，
  而是保持 `ready` 并把原因写进 `last_error` / `degraded_reason`。
- **SQLite 调优**：`temp_store=FILE`（历史实现是 MEMORY，大表排序吃内存）、
  `cache_size` 上限 8 MiB、`journal_size_limit`、`wal_autocheckpoint`、`mmap_size=0`，
  构建结束后 `wal_checkpoint(TRUNCATE)` + `PRAGMA optimize`。
- **补齐索引**：`strings/functions/globals/imports` 的 `ea` 列与
  `function_xrefs(func_addr, direction)`。历史 schema 缺 `ea` 索引，
  导致 `ORDER BY ea ... LIMIT` 每次都要全表扫描 + 排序。
- **查询提速**：`find_regex` / `list_funcs` / `list_globals` / `list_imports` /
  `entity_query` 改为窗口函数 `COUNT(*) OVER ()` 一次扫描同时取回 `total`（省掉
  历史实现里额外的 `COUNT(*)` 全表扫描）；纯字面量走 `instr()`、`^前缀` 走 BINARY
  区间（可用索引），只有真正的正则才回落到 Python UDF。
- **`cache_status` 变 O(1)**：行数改为读 `meta.count_<table>`，不再对 6 张表各做一次
  `COUNT(*)`。
- **护栏与开关**：`IDA_MCP_DISABLE_CACHE`、`IDA_MCP_CACHE_SCOPE=full|minimal`、
  `IDA_MCP_CACHE_CHUNK_ROWS`、`IDA_MCP_CACHE_MAX_ROWS`、`IDA_MCP_CACHE_MAX_RSS_MB`
  （RSS 读数零依赖实现，Windows 走 psapi / POSIX 走 `/proc/self/statm`）。
- **scope 收窄的正确性**：从 `full` 切到 `minimal` 会清空范围外的表（含指纹），
  避免继续返回上一轮的**过期**交叉引用；切回 `full` 时会重新填充。
- **零操作自启**：缓存守护线程的生命周期改为绑定"当前 IDB"
  （`IDB_Hooks.loaded` 起、`closebase` 停，实现在 `broker/cache_autostart.py`），
  不再依赖"是否连上 Broker"。历史行为是"IDA 启动时没开库 → 自动连接时 `idb_path`
  为空 → 之后打开库也不会建缓存"，必须手动按一次 `Ctrl+Alt+M`；现在打开 IDB 即开始构建，
  且重连 Broker 不会打断正在进行的构建。
- **观测性**：`cache_status` 新增 `progress`（阶段/表/已处理行/耗时/峰值 RSS/
  refreshing/build_id）、`partial`、`last_error`、`degraded_reason`、`tables_skipped`、
  `counts_source`、`schema_version`；schema 版本升到 2，旧缓存会被自动丢弃重建。

### 健壮性与易用性（T2）

- **idalib idle 回收**：`IDA_MCP_IDLE_TTL_SEC`（默认 0 = 关闭）+ `IDA_MCP_IDLE_SWEEP_SEC`
  （默认 30s），配套 `--idle-ttl` / `--idle-sweep` 命令行参数。此前 `last_accessed`
  只记录不使用，默认 4 个 worker 会把整份数据库长期驻留内存。
- **Broker 指标与泄漏修复**：`/status` 新增 `metrics`（routed / in-flight / completed /
  failed / timed-out / rejected、late & unknown response、pending 簿记、每实例
  `last_seen` / `queue_depth` 等），并保证 `routed == completed + failed + timed_out`；
  超时后的 `_pending` 一定会被清理，迟到响应被安全丢弃并计数。既有 JSON 键与错误码
  保持不变。

### 工程化（T3）

- 新增基准与门禁：`python -m ida_pro_mcp.benchmark`（`ida-mcp-bench`），
  合成数据集对比"分块（新）"与"全量物化（旧）"的峰值内存/耗时/查询延迟，
  支持 `--assert-peak-mb` 作为 CI 门禁，防止全量物化写法回潮。
- 新增 `.github/workflows/unit-tests.yml`：在 ubuntu/windows × Python 3.11/3.12 上跑
  **不需要 IDA** 的测试与基准（`idalib-tests.yml` 需要 Hex-Rays 私有镜像，fork 上不可用）。
- 新增 `.gitattributes`（`* text=auto eol=lf` + 二进制标记），消除 Windows 上的
  CRLF 假 diff。
- 版本号 2.0.0 → 2.1.0。

### 基准数字（合成数据集，本机实测，`python -m ida_pro_mcp.benchmark --legacy`）

| 规模 | 实现 | Python 峰值内存 | 耗时 |
|------|------|----------------|------|
| 12 万行 | legacy（全量物化） | 22.1 MB | 0.64 s |
| 12 万行 | chunked（本版） | 9.6 MB | 0.78 s |
| 120 万行 | legacy（全量物化） | **217.0 MB** | 6.45 s |
| 120 万行 | chunked（本版） | **8.2 MB** | 11.71 s |

结论：legacy 峰值约 **181 B/行线性增长**（1200 万行即 ≈2.2 GB），chunked 峰值与总行数**无关**，
只取决于单块大小。代价是纯 Python 吞吐下降约 1.8×（每块的事务/进度/采样开销）；
在真实 IDA 场景中提取耗时由 IDAPython 调用主导，该比例会显著缩小，
而且换来的是 **IDA 主线程不再被整段提取占死**（块间让出消息循环）。

### 测试

- 新增 `tests/test_cache_pipeline.py`（配置/分块/提取/写入/编排，含空库、单条巨行、
  重复地址、unicode 与内嵌 NUL、注入异常、schema 迁移、指纹命中与失效、
  max_rows / RSS 护栏、取消、旧快照保活）。
- 新增 `tests/test_cache_query.py`（过滤条件编译的边界 + 与 Python `re` 的结果等价性、
  分页与 total、状态观测）。
- 新增 `tests/test_cache_idalib.py`：真 IDA（idalib）端到端集成测试，
  无 `IDADIR` 时自动跳过。
- 新增 T2 测试：`tests/test_idalib_idle_reaper.py`、`tests/test_broker_metrics.py`、
  `tests/test_idalib_supervisor_idle.py`。
- 新增 `tests/_cache_fakes.py`：无 IDA 依赖的假后端，供上述单测复用。

### 已知问题（与本次改动无关，改动前即存在）

- 本机 `ida-mcp-test tests/crackme03.elf`（全量）会崩溃/挂起；`--category api_core`
  可跑完但其中 2 条断言失败（`value.name: expected str, got NoneType`）。
  疑似与具体 IDA 构建/被测二进制有关，需要单独排查。
