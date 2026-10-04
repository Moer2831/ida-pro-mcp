# 规模测试（GB 级 IDB）

CI 里的假后端（`tests/_cache_fakes.py`）只能验逻辑：条目太少，**验证不了"百万条目 /
千万交叉引用"下的实际行为**。这一组脚本用 [idalib](https://ida.readthedocs.io/en/latest/idalib.html)
**程序化生成**一个合法的大库（不分析任何真实样本），再用真实 IDA 后端跑缓存构建，
拿硬指标回归。

## 为什么必须有这一层

2.1.8 的两个真实缺陷都**只在 GB 级库上才暴露**：

| 缺陷 | 小库表现 | 大库表现 |
|------|----------|----------|
| 条目内续传反复重枚举 xref | 无感（条目 xref 只有几条） | 构建 10 分钟不结束、缓存库停止增长 |
| 单条目派生行数不受预算约束 | 无感 | 一次派发落盘 20 万行，界面卡住数秒 |

两次都是"先在小库上看不出来"。所以**改动缓存提取 / 分块 / 门控后，请跑一遍这里**。

## 用法

```bat
set IDADIR=D:\IDA
set IDA_MCP_SCALE_DIR=E:\ida-mcp-scale     :: 可选：产物目录（stage 2 需要几十 GB）

:: 1) 生成合成大库（stage 1 ≈ 2 分钟，产出约 1.5GB IDB）
python tests\scale\make_fixture.py --stage 1

:: 2) 全量重建：看耗时、每块规模、慢派发次数、峰值内存
python tests\scale\scale_harness.py %IDA_MCP_SCALE_DIR%\synth-1.exe.i64 --mode full

:: 3) 增量：验证"指纹未变则整表跳过"
python tests\scale\scale_harness.py %IDA_MCP_SCALE_DIR%\synth-1.exe.i64 --mode skip

:: 4) 回归门禁（出现 >5s 派发或内存超限即失败）
python tests\scale\scale_harness.py %IDA_MCP_SCALE_DIR%\synth-1.exe.i64 ^
    --mode full --fail-on-slow-dispatch --assert-peak-mb 128

:: 定位"慢在哪"时用微基准
python tests\scale\bench_api.py  %IDA_MCP_SCALE_DIR%\synth-1.exe.i64
python tests\scale\bench_xref.py %IDA_MCP_SCALE_DIR%\synth-1.exe.i64 --scan-all
```

生成的库包含刻意构造的病态样本：一个被调用 20 万次的函数（单条目 xref 爆炸）、
超长名与非 ASCII 名、大量非函数名、稀疏区域。

## 回归基线（stage 1：30 万函数 / 300 万 xref / 1.46GB IDB）

| 指标 | 2.1.8 实测 | 门禁 |
|------|-----------|------|
| 全量重建 | 71 s（chunks ≈ 400） | — |
| 单次派发最大耗时 | 1.29 s | `--fail-on-slow-dispatch`（>5s 失败） |
| 每块规模 | ≤ 13k 项 / ≤ 16.5k 行 | 预算内 |
| Python 峰值内存（3.4M 行） | 23 MB | `--assert-peak-mb 128` |
| 缓存库大小 | 419 MB（≈ IDB 的 0.29×） | — |
| 保存后增量 | 3 s，6 张表全部指纹跳过 | — |

## 说明

* 脚本会自动把 `IDAUSR` 指向工作目录下的空目录：否则 idalib 会加载本机
  `plugins/` 下的全部插件（包括本项目自己的 MCP 插件），给测量带来噪声。
* 这些脚本**不参与** `unittest discover`（文件名不是 `test_*.py`），也不会在
  CI 里自动跑 —— 它们需要 IDA 授权与数 GB 磁盘。
* 产物可整体删除：`rmdir /s /q %IDA_MCP_SCALE_DIR%`。