# Changelog

本文件记录本仓库（[Moer2831/ida-pro-mcp](https://github.com/Moer2831/ida-pro-mcp)）的改动。
上游来源：[QiuChenly/ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement)
→ [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。

## 2.1.7

主题：**修复"IDA 长期无响应"的真凶 —— 缓存分块预算在指纹模式下失效**（生产事故）。

### 事故现象

大库（GameAssembly.dll：806MB、134,942 函数）上，IDA 界面周期性"未响应"，Output 反复刷：

```
[MCP][cache] 派发耗时 12296ms（>5s）: functions —— IDA 可能正忙…
[MCP][cache] 构建完成 …: functions=134942, chunks=1, skipped=[], elapsed=12760ms, reason=not-ready
（约每 13 秒重复一次）
```

### 根因链条

1. `CacheExtractor.chunk()` 的循环用 `row_count < budget_rows` 约束单次派发的工作量，但
   **指纹模式（`collect=False`）在 `row_count += 1` 之前就 `continue`** —— `row_count` 恒为 0，
   于是整张表在一次派发里跑完（13.5 万函数 ⇒ 单次派发 12~13 秒）。
2. 这 12 秒里 IDA 主线程跑不了插件定时器 ⇒ 我们自己的"主线程心跳"过期。
3. 派发结束后的门控复查读到过期心跳 ⇒ 判定"IDA 忙" ⇒ **整轮放弃**（`not-ready`，什么都没建成）。
4. 守护线程立刻重试 ⇒ 又抽一大块 ⇒ 又放弃 …… 死循环，每轮独占主线程十几秒。

### 修复

- fix: **分块预算同时约束 `items` 与 `row_count`**（四个提取器全部修正）。指纹模式按 items
  受限，采集模式语义不变；首次派发不再可能吞下整表。
- fix: **每次派发成功后刷新主线程心跳**（`_touch_heartbeat`）。派发成功本身就证明主线程在
  执行我们的回调，用"派发期间的过期心跳"判死本轮是错的；真正的"IDA 忙/保存中"仍由
  `savebase` 钩子（`mark_save` → idle=False + 静默窗口）拦截。
- fix: **连续被门控放弃时指数退避**（2s→4s→…→封顶 30s，`_not_ready_backoff_delay`），
  并打印"连续 N 轮放弃"日志。避免任何原因导致的"放弃→立刻重试"再次演变成 CPU 死循环。
- fix: 慢派发日志不再一口咬定"IDA 正忙"，改为"单块偏大或 IDA 正忙"，指向正确的排查方向。

### 测试 399 → 409

新增 `tests/test_cache_chunk_budget.py`（10 项）：指纹模式/采集模式的分块预算、
"首次派发不得吞下整表"、imports 按模块原子分段且不漏项、两种模式游标一致、
`_fingerprint_extractor` 的实际派发序列（首块必须用初始预算、每块不超预算）、
**派发后刷新心跳**（含反向验证：去掉刷新就必须中途放弃）、退避单调且封顶。
## 2.1.6

主题：**工具名变更的兼容与可发现性**（多实例实测补测时暴露）。

- fix: **`list_instances` / `select_instance` 恢复可用**。这两个工具此前改名为
  `discover_local_instances` / `redirect_to_instance`，而 MCP 客户端只在会话开始时拉一次
  `tools/list` —— 已打开的会话用旧名调用会直接失败（实测 `Method 'list_instances' not found`）。
  现在旧名保留为**兼容别名**（文档标注 deprecated），并一起列入 `_LOCAL_TOOL_NAMES`，
  否则会被误当成远端工具转发出去。
- fix: **`-32601` 不再是一句干巴巴的 not found**。错误消息现在解释"客户端工具表可能已过期"，
  提示重新获取 `tools/list` 或改用当前名字，并附可用方法示例。
- fix: **`discover_local_instances` 不再误导性地返回空列表**。它扫描的是旧的文件注册表
  `~/.ida-pro-mcp/instances/instance_*.json`，而当前架构实例注册在 Broker 上，该目录通常为空；
  现在**始终把"当前正在处理本次调用的实例"放进结果**（`source: "current"`）。
  实现细节：不能以 `_LOCAL_PORT` 存在为兜底条件 —— Broker 架构下插件从不调用
  `set_local_instance()`，该值恒为 None，会导致兜底永不触发。
- docs: README 增补两条排障 Q&A（`Method not found`、`discover_local_instances` 返回空）。
- test: 新增 2 条静态守卫（改名工具必须保留别名且列入本地工具名单；`-32601` 必须带恢复提示），
  全量 397 → 399 项通过。
## 2.1.5

主题：**修复"保存 IDB 后卡死"的真正根因**（承接 2.1.4 的调查结论）。

- **根因**：`trace` 模块的 IDB 钩子在 `savebase()` 里调用 `backend.flush()` →
  `_netnode_flush_segment()` → **在数据库保存序列内部往 netnode 写数据**。
  这与保存流程形成循环等待：`.i64` 已写盘，但 IDA 主线程死等、CPU 冻结、
  全部线程 Wait、界面无响应，随后所有需要主线程的 MCP 工具（`idb_save` 等）全部超时。
- **修复**：`savebase()` 只置一个纯 Python 的"待 flush"标志（不碰 IDB）；
  真正的落盘改由插件已有的 **1s 主循环定时器** 调用 `flush_pending()` 在正常上下文完成。
  `closebase()` 行为保持不变（关闭时的最后落盘）。
- **验证**：修复后连续两轮"写操作（rename + set_type）→ `idb_save`"均返回 `ok`，
  保存后 IDA 持续 `Responding=True`、CPU 正常推进、缓存重建完成；
  修复前同一序列 **3/3 次复现卡死**。
- **防回归**：新增两条静态守卫 —— `IDB_Hooks.savebase()` 内不得出现任何写库动作；
  延迟 flush 必须由主循环定时器驱动（`ida_mcp.py` 调用 `trace.flush_pending()`）。

### 全量实测（在 2.1.5 最终代码上重跑）

写入矩阵在最终版本上逐项复验并逐项还原：`rename`（函数/全局/局部/栈/dry_run）、
`set_comments`/`append_comments`、`patch`/`put_int`、`declare_type`/`enum_upsert`/
`declare_stack`/`delete_stack`、`define_code`/`define_func`/`undefine`（往返后
**字节与原始基线完全一致**）、`set_type`/`type_apply_batch`/`infer_types`；
缓存层 `cache_status`/`refresh_cache`/`find_regex`/`entity_query`（4 种 kind + `names` 直通）/
`list_globals`（嵌套 filter+count 生效）/`imports`（count 精确）；两轮
"写操作 → `idb_save`" 均返回 `ok` 且 IDA 持续 `Responding=True`。

### 实测新发现：局部变量改名不落库

`ida_hexrays.rename_lvar()` 只改内存中的 cfunc（函数返回 True），名字**不写数据库** ——
改完当场能看到，下一次反编译就退回旧名。现在改为优先调用官方持久化 API
`modify_user_lvars()`（"Modify **saved** local variable settings"），失败再退回
`rename_lvar()`，最后**强制重建 cfunc 回读校验**；确实没落库时明确报错
（`改名未生效（Hex-Rays 未把 'x' 落库…）`），而不是像以前那样返回 ok。
实测还发现：某些目标名会被 Hex-Rays 拒收（把局部变量改成 `v3` 始终失败，
改成 `qa_v3` 成功），这属于 IDA 侧行为，工具现在如实回报。

## 2.1.4

主题：**写入类工具全面实测**（rename / patch / put_int / set_type / define / 注释 / 栈 / 类型 …）
暴露并修掉一批"静默返回错数据"和"误报失败"的问题，同时把一次**保存后卡死**查到根因。

### 卡死调查（结论：与本项目缓存层无关）

实测：密集写操作后保存 IDB，IDA 会卡死（`Responding=False`、CPU 冻结、全部线程 Wait、
`.i64` 已写盘）。做了三组对照实验：

1. `IDA_MCP_DISABLE_CACHE=1`（缓存守护线程完全不启动）→ **仍然卡死** ⇒ 排除缓存守护线程；
2. 禁用第三方原生插件 hrtng(`hrtng.dll`) → 仍然卡死 ⇒ 排除 hrtng 单方面原因；
3. 移出本插件（`ida_mcp.py` + `broker/` + `ida_mcp/`），用 IDA 自带 `-S` 脚本做
   "反编译 + 保存" → **`save_database` 立即返回 True，IDA 完全正常** ⇒ 卡死与本插件相关。

结合 1、3：嫌疑落在缓存守护线程以外的插件部分，首要嫌疑是 `trace` 模块的 IDB 钩子 ——
它在 `savebase()`（保存过程中）往 **netnode 写数据**，而"在保存过程中修改数据库"是经典死锁形状。
后续需要单独实验确认（把 flush 从 IDB 钩子移到已有的 1s 主循环定时器即可规避）。

### 稳定性：派发前增加"主线程心跳"闸

空闲标志是**上一次采样**的结果：主线程卡在长任务（保存/分析/模态）里时定时器不再刷新，
标志会停留在过期的 `True`，守护线程据此派发 `MFF_READ` 就可能与长任务形成循环等待。
`refresh_idle_states()` 现在同时打心跳，`_gate_ready()` 要求心跳新鲜（2s 内）才允许派发；
从未有过心跳的环境（单测 / 无头 idalib）退化为纯门控，不受影响。

### 缓存层：能答的才拦，答不了转给 IDA（不再静默忽略参数）

- **静默忽略参数**（最严重）：工具 schema 声明的是插件那套嵌套形态
  （`list_globals(queries={"filter": "g_", "count": 8})`、`entity_query(queries=[{...}])`），
  而缓存层只读扁平键（`name_pattern` / `limit`）—— 于是**过滤条件与分页被丢掉**：
  要 8 条返回 200 条、要过滤返回全量。现在两种形态都认（`filter`→`name_pattern`、
  `count`→`limit`、嵌套优先），实测 `list_globals` 过滤+分页、`imports(count=5)` 均精确生效。
- **`entity_query(kind="names")` 被硬拒**：插件本身支持 `names`（`idautils.Names()`），
  缓存没有这张表却回 `-32602`。现在 `is_cache_tool()` 会检查请求是否落在缓存能力内 ——
  `names`、正则、排序、地址范围、投影、module 等一律**放行给 IDA 正常执行**。
- `kind` 缺省与插件一致取 `functions`（不再报"需要 kind 参数"）。

### 插件侧：把"误报失败"和"改了却说没改"改成可判定

- `set_comments` 在非函数入口处会**部分成功**（反汇编注释已写、反编译器视图放不下），
  却返回 `error` —— AI 会以为整条注释没生效。现在返回 `applied: ["disasm"]` + 说明性错误。
- `rename` 局部变量增加**回读校验**：`ida_hexrays.rename_lvar()` 会返回成功但名字没落库
  （实测：形参改名回退报 ok，重启后仍是旧名；有时还顺带把形参改成 `xxx_1`），
  现在重新反编译确认新名字存在，否则明确报错。
- `type_apply_batch` 的 `Unknown kind: ...` 错误补上可用取值与"可省略 kind 自动识别"的提示。

### Broker 自愈

`ensure_local_broker()` 只在 MCP 服务端**启动时**调用一次；Broker 中途挂掉后，本会话
所有工具都会静默失败，`instance_list` 还会把"Broker 不可达"误报成"没有活动实例"。
现在新增 `BrokerClient.ping()` 与 `manager.ensure_broker_available()`：每次路由前探活，
不可达则按需后台拉起并重试；确实不可达时给出"Broker 未运行 + 日志路径 + 手动启动命令"。

### 实测记录（真实 IDB：11208 函数 / 74324 xrefs）

写入工具逐项验证并**逐项还原**：`rename`(函数/全局/局部/栈/批量+`dry_run`)、
`set_comments`/`append_comments`、`patch`/`patch_asm`/`put_int`、`define_code`/`define_func`/
`undefine`（往返后字节与原始基线完全一致）、`declare_type`/`enum_upsert`/`declare_stack`/
`delete_stack`/`set_type`/`type_apply_batch`/`infer_types`。
另确认 `py_eval`、`dbg_*` **未暴露**到 MCP 工具面（安全正面结论）。

### 测试 383 → 402

- `tests/test_cache_intercept.py`（12 项）：拦截规则（哪些请求必须转给 IDA）、
  嵌套/扁平参数归一化、以及"打真实缓存"的过滤+分页生效用例。
- `tests/test_incident_regressions.py` +13 项：主线程心跳闸的完整边界
  （新鲜/过期/从未心跳/门控本身关闭/构建回调确实拿到带心跳的门控）。

## 2.1.3

主题：**按"事故类别"补齐边界防护** —— 前三次卡死（保存卡死、启动卡死 ×2）都是生产事故，
这里不只修那一处，而是把同类形状全部找出来、修掉、并用可执行断言看住。

### 一并纳入上一轮未提交的卡死修复

- **第三次启动卡死的根因**：`start_cache_daemon()` 里调用 `register_timer()`，而它是在
  **定时器回调内部**被调用的（`auto_connect_timer` → `_try_connect` → 启动守护线程），
  在主循环回调里注册 UI 定时器同样锁死主线程。现在启动路径**零定时器注册**，
  空闲状态由 `init()` 注册的那一个定时器统一调 `refresh_idle_states()` 刷新。
- **新增 `IDA_MCP_DEBUG=1` 启动追踪**：`[MCP] trace: ...` 逐句打印启动路径
  （走 stdout，IDA Output 窗口与 `ida.exe -L<log>` 都能看到），定位"卡在哪一句之后"
  这类问题不再靠猜。默认关闭，零开销。

### 修掉的三类真实缺陷

- **IDB 钩子泄漏**（每次切换/重载累积一个）：`stop_cache_daemon()` 只停线程、**不注销**
  `savebase` 钩子。切库 A→B 后两个钩子同时存活，旧钩子持续对已停止的句柄
  `mark_save()`，钩子对象（连同句柄、线程引用）永不释放。现在统一走
  `_drop_idb_hook()`：先清引用再 `unhook()`，失败只告警不影响停止流程。
- **缓存库损坏 = 永久砖掉**：文件被写成垃圾或被截断后，`build_cache()` 每次重试都抛
  `file is not a database` / `database disk image is malformed`，守护线程每 30 分钟
  失败一次、永不恢复，必须手工删文件。现在 `CacheWriter.open()` 先用
  `PRAGMA schema_version` 探活，不可用则**改名隔离**（`<库名>.corrupt-<时间戳>`）后重建；
  连改名都失败（被占用）时退化为删除重建。
- **诊断工具会把异常抛给 AI**：`cache_status()` 在文件不可读时抛 SQLite 异常。
  现在它永不抛错：不可读 → `status=error` + `degraded_reason=cache-unreadable` +
  `last_error` 原因；文件在但没建过 → `status=empty`（`degraded_reason=not-built`）。
  （`_tbl_count` 仍只吞"no such table"，锁/IO 类错误照旧上抛，不掩盖真问题。）

### 顺带修正

- `refresh_idle_states()` 的返回值改为**成功刷新数**（探测抛异常的实例不再被计入），
  与文档一致。
- `cache_autostart` 模块文档更新为"定时器驱动"的现状（原文还写着 2.1.1 的 IDB 钩子方案）。
- README 更正："插件不再注册任何 IDB 钩子"是不准确的 —— 缓存与调用记录各有一个
  save/close 钩子，关键在于**注册动作只允许发生在 `init()` 路径**，且停止/关闭时必须注销。

### 新增 42 项测试（总数 331 → 373）

- `tests/test_incident_regressions.py`（15 项）：假 IDA 内核记录
  `register_timer` / `IDB_Hooks.hook/unhook` / `execute_sync(flags)`，
  于是三次事故的形状在没有 IDA 的 CI 里可复现 —— 启动路径零定时器、只注册一个钩子、
  停止必注销、切换 IDB 不残留、**IDA 忙时绝不发 `MFF_READ`**、等待路径是慢轮询而非忙等、
  IDA API 全炸时线程不崩且仍可停、5 次重启无线程/钩子泄漏。
- `tests/test_hostile_environment.py`（22 项）：垃圾/截断/零字节/未来 schema 版本的缓存库
  自愈与隔离、诊断工具永不抛错、3 读者 × 6 轮重建的并发换表不出现空表窗口、
  环境变量垃圾值（0/负数/天文数字/全角/空格/`1e9`）全部被钳制、
  RSS 护栏边界（恰好等于上限、0、未知读数不得误判超限）、切库不跨库串写。
- `tests/test_static_sanity.py`（+4 项，改为全树 `ast` 守卫）：`broker/` 不得模块级导入 IDA；
  `register_timer` 注册点白名单；`IDB_Hooks` 子类定义文件白名单（精确匹配）；
  **IDB 回调内禁止注册定时器/钩子**（事故 2/3 的精确形状）。

## 2.1.2

主题：**修复"IDA 一启动就卡死"**（2.1.1 引入的回归）。

- **根因**：2.1.1 把缓存守护线程的启动挂在 `IDB_Hooks.loaded()` 上，并在那里调用
  `ida_kernwin.register_timer()` 安装空闲监视器。而 `loaded()` 是在**数据库加载序列内部**
  被调用的 —— 在那时注册 UI 定时器会把主线程锁死，表现为"一启动就无响应"：
  CPU 零增长、`.i64` 已解包但界面不动、Broker 里看不到实例。
- **修复**：插件装载器**不再注册任何 IDB 钩子**（`ida_idp` 零导入）；缓存生命周期改由
  `init()` 里注册的**主循环定时器**（1000ms）轮询驱动 —— 没有库→停、换库→先停再起、
  同库→幂等，通过 `CacheDaemonSupervisor.sync_to_idb()` 完成。所有注册动作
  （空闲监视定时器、savebase 钩子、守护线程）都发生在正常主循环上下文里。
- **插件初始化不再扫描 `sys.path`**：版本横幅改用"装载器 mtime"作为构建指纹
  （`[MCP] 插件代码: <目录> (装载器 2026-09-28 02:10, 缓存 schema v2)`），
  避免 `importlib.metadata` 在 IDA 的大 site-packages 上拖慢启动。
- **测试**：新增 5 项 `sync_to_idb` 用例 + 3 项插件启动路径静态守卫
  （不得导入 `ida_idp`、不得注册钩子、不得用 `importlib.metadata`），全量 328 项通过。

## 2.1.1

主题：**修复"保存 IDB 时 IDA 卡死"**（实测事故），并消除两个 API 易用性坑。

### 卡死根因与修复

- **根因**：`MFF_READ` 的官方语义是"**只在 IDA 空闲且可安全查询数据库时才执行**"。
  旧实现却用 `execute_sync(..., MFF_READ)` 去询问"IDA 是否空闲"，形成循环等待：
  保存 IDB 期间 IDA 不是 idle → 请求排队 → 排队的请求又让 IDA 一直不算 idle →
  界面长时间无响应，且保存完成后守护线程仍拿不到结果（实测：`.i64` 已写盘，
  缓存库再无任何写入，只能强杀 IDA）。
- **修复**：空闲判定改由 **IDA 主线程定时器**维护（`ida_kernwin.register_timer`, 500ms），
  守护线程只读一个普通变量，**等待期间零派发**；`savebase` 钩子额外标记"刚保存过"，
  派发还需过 `SAVE_QUIET_SEC=5s` 静默窗口。
- **逐块复查门控**：每个分块派发前复查门控；不放行则中止本轮（`NOT_READY_REASON`）、
  **保留旧快照**，并在数秒后自动重新排队重试（不再干等 30 分钟兜底）。
- **只探测状态时使用 `MFF_FAST`**：`run_on_ida_main(..., db_read=False)` 用于状态探测
  （不查库、不要求 idle）；读库提取仍用 `MFF_READ`，但只在门控放行后发出。
- **卡顿可诊断**：单次派发超过 `DISPATCH_WARN_SEC=5s` 会在 Output 窗口打印警告（含表名），
  `daemon_snapshot` 也会给出 `pauses`、`slow_dispatches`、`idle_state`。
- **版本可见**：插件启动首行打印 `[MCP] 插件代码: <路径> (v2.1.1, 缓存 schema v2)`。

### API 易用性（消除命名陷阱与错误信息不足）

- `list_instances` → **`discover_local_instances`**、`select_instance` → **`redirect_to_instance`**：
  与 broker 侧**无需参数**的 `instance_list` 语义完全不同，旧名只差词序极易误用；
  description 现在写明两者区别与"需先取 `instance_id`"。
- `-32000 找不到目标实例: X` 附带"**当前可用实例: ida-27740(geek.exe)**"与
  "请先调用 instance_list（无需参数）"；`-32602 必须提供 instance_id` 同样附带实例清单。
- `rename` 的 tool description 补上参数示例：`dry_run` / `stop_on_error` / `allow_overwrite`
  写在 **`batch` 内部**（不是顶层参数），并给出分组格式。

### 测试

- 新增 `tests/test_cache_save_safety.py`（15 项）：门控状态机、**等待期间零派发**、
  兜底探测只允许 `MFF_FAST`、门控中途关闭保留旧快照、守护线程门控放行后重试成功、慢派发告警。
- 全量 320 项通过（原 305 + 15）。

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
