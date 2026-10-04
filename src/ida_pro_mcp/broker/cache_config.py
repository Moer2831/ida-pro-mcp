"""SQLite 缓存构建的运行时配置与自适应分块参数（纯逻辑，可无 IDA 单测）。

所有开关都以环境变量形式提供，**默认值保持历史行为**（缓存开启、范围 full、
表级增量开启、无内存护栏），只有显式设置才改变行为，避免升级即变行为。

环境变量一览::

    IDA_MCP_DISABLE_CACHE=1        # 完全关闭缓存守护线程（7 个缓存工具将返回 -32001）
    IDA_MCP_CACHE_SCOPE=minimal    # full(默认) | minimal：minimal 只建 strings/functions/imports
    IDA_MCP_CACHE_CHUNK_ROWS=20000 # 每块行数上限（峰值内存 ≈ 块大小）
    IDA_MCP_CACHE_TARGET_CHUNK_MS=150  # 每块目标耗时，用于自适应调整块大小
    IDA_MCP_CACHE_MAX_ROWS=0       # 单表行数上限，0=不限；超限则该表放弃本轮刷新（保留旧快照）
    IDA_MCP_CACHE_MAX_RSS_MB=0     # 进程 RSS 上限，0=不限；超限则停止本轮刷新（保留旧快照）
    IDA_MCP_CACHE_INCREMENTAL=0    # 关闭表级指纹增量（强制全量重建）
    IDA_MCP_CACHE_FINGERPRINT=full # shape(默认) | full：shape 只哈希索引字段，full 连文本一起哈希
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

# ---------------------------------------------------------------------------
# 解析工具
# ---------------------------------------------------------------------------

_TRUE_VALUES = frozenset({"1", "true", "t", "yes", "y", "on"})
_FALSE_VALUES = frozenset({"0", "false", "f", "no", "n", "off", ""})

SCOPE_FULL = "full"
SCOPE_MINIMAL = "minimal"
VALID_SCOPES = (SCOPE_FULL, SCOPE_MINIMAL)

FINGERPRINT_SHAPE = "shape"
FINGERPRINT_FULL = "full"
VALID_FINGERPRINTS = (FINGERPRINT_SHAPE, FINGERPRINT_FULL)

DEFAULT_CHUNK_ROWS = 20_000
MIN_CHUNK_ROWS = 100
MAX_CHUNK_ROWS = 2_000_000

DEFAULT_TARGET_CHUNK_MS = 150
MIN_TARGET_CHUNK_MS = 10
MAX_TARGET_CHUNK_MS = 5_000

DEFAULT_REBUILD_MIN_INTERVAL_SEC = 20.0
MAX_REBUILD_MIN_INTERVAL_SEC = 3_600
DEFAULT_DISK_HEADROOM_FACTOR = 2.0

DEFAULT_SLICE_SPAN = 1 << 20  # 1 MiB：按 EA 区间切片时的默认跨度（预留给区间式后端）

# 表名常量（与 cache_writer.TABLE_SPECS 的 key 保持一致）
TABLE_STRINGS = "strings"
TABLE_STRING_XREFS = "string_xrefs"
TABLE_FUNCTIONS = "functions"
TABLE_FUNCTION_XREFS = "function_xrefs"
TABLE_GLOBALS = "globals"
TABLE_IMPORTS = "imports"

ALL_TABLES: tuple[str, ...] = (
    TABLE_STRINGS,
    TABLE_STRING_XREFS,
    TABLE_FUNCTIONS,
    TABLE_FUNCTION_XREFS,
    TABLE_GLOBALS,
    TABLE_IMPORTS,
)

MINIMAL_TABLES: tuple[str, ...] = (
    TABLE_STRINGS,
    TABLE_FUNCTIONS,
    TABLE_IMPORTS,
)


def env_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    """宽松解析布尔环境变量；无法识别时回退 default。"""
    raw = env.get(key)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    return default


def env_int(
    env: Mapping[str, str],
    key: str,
    default: int,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    """解析整数环境变量并做区间钳制；非法值回退 default（default 同样被钳制）。"""
    raw = env.get(key)
    value: Optional[int] = None
    if raw is not None and raw.strip():
        try:
            value = int(raw.strip(), 10)
        except ValueError:
            value = None
    if value is None:
        value = default
    if minimum is not None and value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


def env_float(
    env: Mapping[str, str],
    key: str,
    default: float,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    """解析浮点环境变量并做区间钳制；非法值/NaN 回退 default。"""
    raw = env.get(key)
    value: Optional[float] = None
    if raw is not None and raw.strip():
        try:
            value = float(raw.strip())
        except ValueError:
            value = None
    if value is None or value != value:  # NaN != NaN
        value = default
    if minimum is not None and value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return float(value)


def env_choice(env: Mapping[str, str], key: str, default: str, choices: tuple[str, ...]) -> str:
    """解析枚举环境变量（大小写不敏感）；非法值回退 default。"""
    raw = env.get(key)
    if raw is None:
        return default
    value = raw.strip().lower()
    return value if value in choices else default


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheConfig:
    """缓存构建配置（不可变，便于在线程间安全共享）。"""

    disabled: bool = False
    scope: str = SCOPE_FULL
    chunk_rows: int = DEFAULT_CHUNK_ROWS
    target_chunk_ms: int = DEFAULT_TARGET_CHUNK_MS
    max_rows: int = 0
    max_rss_mb: int = 0
    incremental: bool = True
    fingerprint: str = FINGERPRINT_SHAPE
    slice_span: int = DEFAULT_SLICE_SPAN
    # 保存触发的重建最小间隔（秒）：把"连续保存"合并成一轮，避免大库上每按一次
    # Ctrl+S 就跑一遍 O(条目数) 的指纹 pass。显式 refresh_cache 不受此限。
    rebuild_min_interval_sec: float = DEFAULT_REBUILD_MIN_INTERVAL_SEC
    # 磁盘预检：构建前按"现有缓存库大小 × 该倍率 + 影子表峰值"估算需求，
    # 可用空间不足则拒绝构建（而不是写到一半把盘写满）。
    disk_headroom_factor: float = DEFAULT_DISK_HEADROOM_FACTOR

    @property
    def wants_xrefs(self) -> bool:
        """minimal 范围不采集交叉引用（更快、更省内存，代价是 include_xrefs 返回空）。"""
        return self.scope == SCOPE_FULL

    @property
    def wants_globals(self) -> bool:
        return self.scope == SCOPE_FULL

    @property
    def fingerprint_full(self) -> bool:
        """full 指纹会连字符串文本一起哈希（更精确，但建立指纹的开销更高）。"""
        return self.fingerprint == FINGERPRINT_FULL

    def tables(self) -> tuple[str, ...]:
        """本轮需要维护的表集合。"""
        return ALL_TABLES if self.scope == SCOPE_FULL else MINIMAL_TABLES

    def table_enabled(self, table: str) -> bool:
        return table in self.tables()


def load_cache_config(env: Optional[Mapping[str, str]] = None) -> CacheConfig:
    """从环境变量装载配置；`env=None` 时读取 `os.environ`。"""
    source: Mapping[str, str] = os.environ if env is None else env
    return CacheConfig(
        disabled=env_bool(source, "IDA_MCP_DISABLE_CACHE", False),
        scope=env_choice(source, "IDA_MCP_CACHE_SCOPE", SCOPE_FULL, VALID_SCOPES),
        chunk_rows=env_int(
            source,
            "IDA_MCP_CACHE_CHUNK_ROWS",
            DEFAULT_CHUNK_ROWS,
            minimum=MIN_CHUNK_ROWS,
            maximum=MAX_CHUNK_ROWS,
        ),
        target_chunk_ms=env_int(
            source,
            "IDA_MCP_CACHE_TARGET_CHUNK_MS",
            DEFAULT_TARGET_CHUNK_MS,
            minimum=MIN_TARGET_CHUNK_MS,
            maximum=MAX_TARGET_CHUNK_MS,
        ),
        max_rows=env_int(source, "IDA_MCP_CACHE_MAX_ROWS", 0, minimum=0),
        max_rss_mb=env_int(source, "IDA_MCP_CACHE_MAX_RSS_MB", 0, minimum=0),
        incremental=env_bool(source, "IDA_MCP_CACHE_INCREMENTAL", True),
        fingerprint=env_choice(
            source,
            "IDA_MCP_CACHE_FINGERPRINT",
            FINGERPRINT_SHAPE,
            VALID_FINGERPRINTS,
        ),
        slice_span=env_int(source, "IDA_MCP_CACHE_SLICE_SPAN", DEFAULT_SLICE_SPAN, minimum=1 << 12),
        rebuild_min_interval_sec=env_float(
            source,
            "IDA_MCP_REBUILD_MIN_INTERVAL_SEC",
            DEFAULT_REBUILD_MIN_INTERVAL_SEC,
            minimum=0.0,
            maximum=MAX_REBUILD_MIN_INTERVAL_SEC,
        ),
        disk_headroom_factor=env_float(
            source,
            "IDA_MCP_DISK_HEADROOM_FACTOR",
            DEFAULT_DISK_HEADROOM_FACTOR,
            minimum=0.0,
            maximum=100.0,
        ),
    )


# ---------------------------------------------------------------------------
# 自适应分块
# ---------------------------------------------------------------------------


@dataclass
class AdaptiveChunker:
    """按实测耗时动态调整"每块行数"，把主线程占用切成 ~target_ms 的小片。

    纯逻辑，不触碰 IDA / SQLite，便于单测。调整策略：

    - 实测耗时 > target * 1.5 → 按 target/elapsed 比例收缩（最多缩到 1/4）；
    - 实测耗时 < target * 0.5 → 按 target/elapsed 比例扩张（最多扩到 4 倍）；
    - 始终钳制在 [min_rows, max_rows] 内，且 ≥ 1。
    """

    chunk_rows: int = DEFAULT_CHUNK_ROWS
    target_ms: float = DEFAULT_TARGET_CHUNK_MS
    min_rows: int = MIN_CHUNK_ROWS
    max_rows: int = MAX_CHUNK_ROWS

    def __post_init__(self) -> None:
        self.min_rows = max(1, int(self.min_rows))
        self.max_rows = max(self.min_rows, int(self.max_rows))
        self.target_ms = float(self.target_ms)
        if self.target_ms <= 0:
            self.target_ms = float(DEFAULT_TARGET_CHUNK_MS)

    def next_size(self) -> int:
        """返回当前块大小（至少 1 行）。"""
        return max(1, int(self.chunk_rows))

    def observe(self, rows: int, elapsed_ms: float) -> int:
        """喂入上一块的实测数据，返回调整后的块大小。"""
        self.chunk_rows = self._adjust(int(rows), float(elapsed_ms))
        return self.chunk_rows

    def _adjust(self, rows: int, elapsed_ms: float) -> int:
        if rows <= 0 or elapsed_ms <= 0:
            return max(self.min_rows, min(self.max_rows, int(self.chunk_rows)))

        ratio = self.target_ms / elapsed_ms
        if elapsed_ms > self.target_ms * 1.5:
            ratio = max(0.25, min(1.0, ratio))
        elif elapsed_ms < self.target_ms * 0.5:
            ratio = max(1.0, min(4.0, ratio))
        else:
            return max(self.min_rows, min(self.max_rows, int(self.chunk_rows)))

        proposed = int(round(rows * ratio))
        return max(self.min_rows, min(self.max_rows, proposed))
