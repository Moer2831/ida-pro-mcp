"""大库规模测试的公共设置（路径解析、环境隔离）。

这一组脚本回答的问题是：**在 GB 级 IDB 上，缓存层还成立吗？**
CI 里的假后端只能验逻辑，验不了"百万条目 / 千万交叉引用"下的实际行为，
所以这里用 idalib **程序化生成**一个合法的大库（不分析任何真实样本），
再用真实 IDA 后端跑一遍，拿硬指标：每次派发的耗时分布、每块行数、峰值内存。

公共约定：

* `IDADIR`：IDA 安装目录（必需，例如 `D:\\IDA`）。
* `IDA_MCP_SCALE_DIR`：工作目录（可选，默认系统临时目录下的 `ida-mcp-scale`）。
  生成物（合成 PE / IDB / 缓存库）都放这里，方便整体删除。
* `IDAUSR` 被指向工作目录下的空目录：否则 idalib 会加载本机 `plugins/`
  里的全部插件（包括本项目自己的 MCP 插件），给生成与测量带来无关噪声。
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"

WORK_DIR = pathlib.Path(
    os.environ.get("IDA_MCP_SCALE_DIR")
    or os.path.join(tempfile.gettempdir(), "ida-mcp-scale")
)


def prepare_environment() -> None:
    """设置 idalib 需要的环境（必须在 `import idapro` 之前调用）。"""
    idadir = os.environ.get("IDADIR") or os.environ.get("IDA_DIR")
    if not idadir:
        raise SystemExit(
            "请先设置 IDADIR 指向 IDA 安装目录（例：set IDADIR=D:\\IDA）"
        )
    os.environ["IDADIR"] = idadir
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    idausr = WORK_DIR / "idausr"
    idausr.mkdir(parents=True, exist_ok=True)
    os.environ["IDAUSR"] = str(idausr)
    # 生成/测量期间不要启动缓存守护线程（否则合成库上会多出无关的构建）
    os.environ["IDA_MCP_DISABLE_CACHE"] = "1"
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))


def open_db(path: str, *, auto_analysis: bool = False) -> None:
    """用 idalib 打开库/样本；失败直接退出并给出可读原因。"""
    import idapro  # noqa: PLC0415

    rc = idapro.open_database(path, auto_analysis)
    if rc != 0:
        raise SystemExit(f"open_database 失败 rc={rc}: {path}")