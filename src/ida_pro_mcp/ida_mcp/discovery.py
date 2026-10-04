"""实例可达性探测（TCP）。

历史背景：早期版本让每个 IDA 插件把自身信息写成 JSON 文件到
`{IDAUSR}/mcp/instances/instance_*.json`，由 MCP 侧扫描这些文件来"发现实例"。
Broker 架构落地后，实例清单的唯一权威来源是 Broker（`instance_list`），**没有任何
生产代码再写这些文件** —— 于是"扫描文件注册表"变成了一段永远返回空列表的死代码
（表现为 `discover_local_instances` 恒为 `[]`，让人误以为没有实例）。

这里只保留仍然有用的 TCP 探测：判断某个 host:port 是否真的在监听。
"""

from __future__ import annotations

import socket


def probe_instance(host: str, port: int, timeout: float = 2.0) -> bool:
    """目标 host:port 是否可连接（用于判断实例是否真的在监听）。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False