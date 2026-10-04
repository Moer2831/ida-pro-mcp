"""实例可达性探测的测试。

历史：这里曾有一整套"文件注册表"测试（register/unregister/discover）。Broker 架构下
没有任何生产代码再写那些 JSON 文件，注册表扫描是死代码（表现为
`discover_local_instances` 恒为 `[]`），已删除；只保留仍然有用的 TCP 探测。
"""

from __future__ import annotations

import socket
import threading

from .. import discovery


def _listening_socket() -> tuple[socket.socket, int]:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def test_probe_instance_true_for_listening_port():
    srv, port = _listening_socket()
    try:
        assert discovery.probe_instance("127.0.0.1", port, timeout=1.0) is True
    finally:
        srv.close()


def test_probe_instance_false_for_closed_port():
    srv, port = _listening_socket()
    srv.close()
    assert discovery.probe_instance("127.0.0.1", port, timeout=0.5) is False


def test_probe_instance_false_on_unroutable_host():
    assert discovery.probe_instance("127.0.0.1", 1, timeout=0.5) is False


def test_registry_machinery_is_gone():
    """死代码必须真的删掉，不能只改调用点（否则以后又会被误用）。"""
    for name in (
        "register_instance",
        "unregister_instance",
        "discover_instances",
        "get_instances_dir",
        "is_pid_alive",
    ):
        assert not hasattr(discovery, name), f"discovery.{name} 应已删除"


def test_probe_handles_parallel_checks():
    """并行探测不应互相干扰（Broker 会为多个实例做健康检查）。"""
    srv, port = _listening_socket()
    results: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        ok = discovery.probe_instance("127.0.0.1", port, timeout=1.0)
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    srv.close()
    assert results and all(results), f"并行探测结果异常: {results}"