"""Broker 指标与泄漏修复 (T2) 单元测试，不需要 IDA。

覆盖：请求计数的终态一致性、超时/断开后的 _pending 清理、
迟到响应安全丢弃、/status 新增 metrics 键且保留旧键。
"""

import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime

from ida_pro_mcp.broker import server as broker_server

REGISTRY = broker_server.REGISTRY

# /status 中必须保留的历史键（前端/测试依赖）
PREEXISTING_INSTANCE_KEYS = (
    "client_id",
    "instance_id",
    "type",
    "name",
    "binary_path",
    "idb_path",
)


def _reset_registry() -> None:
    """把全局 REGISTRY 恢复到干净状态（测试之间互不干扰）。"""
    with REGISTRY._lock:
        REGISTRY._instances.clear()
        REGISTRY._sse_queues.clear()
        REGISTRY._pending.clear()
        REGISTRY._expired_pending.clear()
        REGISTRY._instance_stats.clear()
        REGISTRY._retired_instance_stats.clear()
        REGISTRY._metrics = broker_server.BrokerMetrics()
        REGISTRY._started_at = datetime.now()
        REGISTRY._started_monotonic = time.monotonic()


def _pick_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _request_payload(request_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": "ping"}


class RegistryMetricsTestBase(unittest.TestCase):
    def setUp(self) -> None:
        _reset_registry()

    def tearDown(self) -> None:
        _reset_registry()

    def register_instance(self, instance_id: str = "ida-1", **extra) -> broker_server.IDAInstance:
        payload = {"instance_id": instance_id, "name": instance_id, **extra}
        instance = REGISTRY.register(payload)
        assert instance is not None
        return instance

    def take_queued_request(self, client_id: str, timeout: float = 2.0) -> dict:
        sse_queue = REGISTRY.get_sse_queue(client_id)
        assert sse_queue is not None
        return sse_queue.get(timeout=timeout)

    def assert_terminal_invariant(self, metrics: dict) -> None:
        """终态桶必须与 routed 完全对齐（无泄漏的 in-flight 计数）。"""
        self.assertEqual(
            metrics["requests_routed"],
            metrics["requests_completed"]
            + metrics["requests_failed"]
            + metrics["requests_timed_out"],
            f"routed 与终态计数不一致: {metrics}",
        )
        self.assertGreaterEqual(metrics["requests_in_flight"], 0)
        self.assertEqual(metrics["requests_in_flight"], 0)


class SendRequestMetricsTests(RegistryMetricsTestBase):
    def test_timeout_metrics_stay_consistent(self):
        self.register_instance()

        response = REGISTRY.send_request(_request_payload(), timeout=0.05)

        self.assertIsNone(response)
        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["requests_routed"], 1)
        self.assertEqual(metrics["requests_timed_out"], 1)
        self.assertEqual(metrics["requests_completed"], 0)
        self.assertEqual(metrics["requests_failed"], 0)
        self.assertEqual(metrics["requests_in_flight"], 0)
        self.assertEqual(metrics["pending_requests"], 0)
        self.assertEqual(REGISTRY._pending, {})
        self.assertIn("超时", metrics["last_error"] or "")
        self.assert_terminal_invariant(metrics)

    def test_late_response_after_timeout_is_discarded(self):
        instance = self.register_instance()
        self.assertIsNone(REGISTRY.send_request(_request_payload(), timeout=0.05))
        item = self.take_queued_request(instance.client_id)

        REGISTRY.set_response(
            item["request_id"], {"jsonrpc": "2.0", "id": 1, "result": {"late": True}}
        )

        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["late_responses_discarded"], 1)
        self.assertEqual(metrics["responses_accepted"], 0)
        self.assertEqual(metrics["unknown_responses_discarded"], 0)
        self.assertEqual(metrics["requests_completed"], 0)
        self.assertEqual(metrics["requests_in_flight"], 0)
        self.assertEqual(metrics["pending_requests"], 0)
        self.assert_terminal_invariant(metrics)

    def test_unknown_response_is_discarded(self):
        REGISTRY.set_response("does-not-exist", {"jsonrpc": "2.0", "id": 1, "result": {}})

        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["unknown_responses_discarded"], 1)
        self.assertEqual(metrics["late_responses_discarded"], 0)
        self.assertEqual(metrics["requests_routed"], 0)
        self.assertEqual(REGISTRY._pending, {})

    def test_successful_response_completes_and_releases_in_flight(self):
        instance = self.register_instance()
        holder: dict = {}

        thread = threading.Thread(
            target=lambda: holder.update(
                response=REGISTRY.send_request(_request_payload(), timeout=5.0)
            )
        )
        thread.start()
        item = self.take_queued_request(instance.client_id)

        in_flight = REGISTRY.metrics_snapshot()
        self.assertEqual(in_flight["requests_in_flight"], 1)
        self.assertEqual(in_flight["pending_requests"], 1)

        upstream = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        REGISTRY.set_response(item["request_id"], upstream)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(holder["response"], upstream)

        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["requests_completed"], 1)
        self.assertEqual(metrics["responses_accepted"], 1)
        self.assertEqual(metrics["pending_requests"], 0)
        self.assert_terminal_invariant(metrics)

    def test_error_response_counts_as_failed(self):
        instance = self.register_instance()
        holder: dict = {}
        thread = threading.Thread(
            target=lambda: holder.update(
                response=REGISTRY.send_request(_request_payload(), timeout=5.0)
            )
        )
        thread.start()
        item = self.take_queued_request(instance.client_id)

        upstream = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "boom"},
        }
        REGISTRY.set_response(item["request_id"], upstream)
        thread.join(timeout=3)

        self.assertEqual(holder["response"], upstream)
        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["requests_completed"], 0)
        self.assertEqual(metrics["requests_failed"], 1)
        self.assertEqual(metrics["last_error"], "boom")
        self.assert_terminal_invariant(metrics)

    def test_routing_failures_keep_original_messages(self):
        self.register_instance("ida-1")
        self.register_instance("ida-2")

        ambiguous = REGISTRY.send_request(_request_payload(), timeout=0.05)
        self.assertEqual(ambiguous["error"]["code"], -32602)
        self.assertEqual(
            ambiguous["error"]["message"], "存在多个 IDA 实例或未指定 instance_id，无法路由。"
        )

        missing = REGISTRY.send_request(
            _request_payload(2), instance_id="nope", timeout=0.05
        )
        self.assertEqual(missing["error"]["code"], -32000)
        # 文案在 2.1.0 起附带了"当前可用实例 + 先调 instance_list"的提示，
        # 这里断言前缀与关键提示词，避免锁死整句。
        message = missing["error"]["message"]
        self.assertTrue(message.startswith("找不到目标实例: nope"), message)
        self.assertIn("当前可用实例", message)
        self.assertIn("instance_list", message)

        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["requests_routed"], 2)
        self.assertEqual(metrics["requests_failed"], 2)
        self.assertEqual(metrics["requests_timed_out"], 0)
        self.assert_terminal_invariant(metrics)

    def test_invariant_holds_after_mixed_traffic(self):
        instance = self.register_instance("ida-1")

        # 1) 成功
        holder: dict = {}
        thread = threading.Thread(
            target=lambda: holder.update(
                response=REGISTRY.send_request(_request_payload(), timeout=5.0)
            )
        )
        thread.start()
        item = self.take_queued_request(instance.client_id)
        REGISTRY.set_response(item["request_id"], {"jsonrpc": "2.0", "id": 1, "result": {}})
        thread.join(timeout=3)

        # 2) 超时 + 迟到响应
        REGISTRY.send_request(_request_payload(2), timeout=0.05)
        late = self.take_queued_request(instance.client_id)
        REGISTRY.set_response(late["request_id"], {"jsonrpc": "2.0", "id": 2, "result": {}})

        # 3) 路由失败
        REGISTRY.send_request(_request_payload(3), instance_id="missing", timeout=0.05)

        # 4) 未连接任何实例时的拒绝
        REGISTRY.unregister(instance.client_id)
        REGISTRY.note_rejected_request("没有活动的 IDA 实例。")

        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["requests_routed"], 4)
        self.assertEqual(metrics["requests_completed"], 1)
        self.assertEqual(metrics["requests_timed_out"], 1)
        self.assertEqual(metrics["requests_failed"], 2)
        self.assertEqual(metrics["requests_rejected"], 1)
        self.assertEqual(metrics["late_responses_discarded"], 1)
        self.assert_terminal_invariant(metrics)


class InstanceMetricsTests(RegistryMetricsTestBase):
    def test_instance_last_seen_and_queue_depth(self):
        instance = self.register_instance("ida-1")

        initial = REGISTRY.metrics_snapshot()["instances"][instance.client_id]
        self.assertTrue(initial["connected"])
        self.assertEqual(initial["queue_depth"], 0)
        self.assertEqual(initial["last_seen_reason"], "register")
        self.assertIsNotNone(initial["last_seen"])
        self.assertIsNotNone(initial["last_seen_age_sec"])

        REGISTRY.send_request(_request_payload(), timeout=0.05)

        after = REGISTRY.metrics_snapshot()["instances"][instance.client_id]
        self.assertEqual(after["requests_sent"], 1)
        self.assertEqual(after["timeouts"], 1)
        self.assertEqual(after["queue_depth"], 1)  # 未被消费的请求可被观测
        self.assertEqual(after["last_seen_reason"], "request")
        self.assertGreaterEqual(
            datetime.fromisoformat(after["last_seen"]),
            datetime.fromisoformat(initial["last_seen"]),
        )

    def test_response_updates_instance_last_seen(self):
        instance = self.register_instance("ida-1")
        holder: dict = {}
        thread = threading.Thread(
            target=lambda: holder.update(
                response=REGISTRY.send_request(_request_payload(), timeout=5.0)
            )
        )
        thread.start()
        item = self.take_queued_request(instance.client_id)
        REGISTRY.set_response(item["request_id"], {"jsonrpc": "2.0", "id": 1, "result": {}})
        thread.join(timeout=3)

        entry = REGISTRY.metrics_snapshot()["instances"][instance.client_id]
        self.assertEqual(entry["responses_received"], 1)
        self.assertEqual(entry["last_seen_reason"], "response")

    def test_disconnect_marks_orphans_and_keeps_bounded_history(self):
        instance = self.register_instance("ida-1")
        holder: dict = {}
        thread = threading.Thread(
            target=lambda: holder.update(
                response=REGISTRY.send_request(_request_payload(), timeout=1.0)
            )
        )
        thread.start()
        item = self.take_queued_request(instance.client_id)

        REGISTRY.unregister(instance.client_id)

        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["pending_orphaned_on_disconnect"], 1)
        self.assertEqual(metrics["instance_disconnects"], 1)
        self.assertEqual(metrics["instances_connected"], 0)
        self.assertIn(instance.client_id, metrics["instances"])
        self.assertFalse(metrics["instances"][instance.client_id]["connected"])

        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertIsNone(holder["response"])
        self.assertEqual(REGISTRY._pending, {})
        self.assertEqual(REGISTRY._instance_stats, {})

        # 断开后到达的迟到响应必须被安全丢弃
        REGISTRY.set_response(item["request_id"], {"jsonrpc": "2.0", "id": 1, "result": {}})
        self.assertEqual(REGISTRY.metrics_snapshot()["late_responses_discarded"], 1)

    def test_retired_instance_stats_are_bounded(self):
        for index in range(broker_server.MAX_RETIRED_INSTANCE_STATS + 8):
            instance = self.register_instance(f"ida-{index}")
            REGISTRY.unregister(instance.client_id)

        self.assertLessEqual(
            len(REGISTRY._retired_instance_stats),
            broker_server.MAX_RETIRED_INSTANCE_STATS,
        )
        metrics = REGISTRY.metrics_snapshot()
        self.assertEqual(metrics["instances_retired"], broker_server.MAX_RETIRED_INSTANCE_STATS)
        self.assertEqual(metrics["instance_disconnects"], broker_server.MAX_RETIRED_INSTANCE_STATS + 8)

    def test_reregister_replaces_old_connection_without_leaking_stats(self):
        first = self.register_instance("same-instance")
        REGISTRY.register({"instance_id": "same-instance"})

        self.assertNotIn(first.client_id, REGISTRY._instance_stats)
        self.assertEqual(len(REGISTRY._instances), 1)
        self.assertEqual(REGISTRY.metrics_snapshot()["instances_connected"], 1)


class PendingLeakTests(RegistryMetricsTestBase):
    def test_stale_pending_entry_is_pruned(self):
        """等待线程异常消失时，_pending 条目不会永久残留。"""
        with REGISTRY._lock:
            REGISTRY._pending["stale"] = {
                "event": threading.Event(),
                "response": None,
                "client_id": None,
                "deadline": time.monotonic()
                - broker_server.PENDING_PRUNE_GRACE_SEC
                - 1.0,
            }
        self.register_instance("ida-1")

        REGISTRY.send_request(_request_payload(), timeout=0.05)

        self.assertNotIn("stale", REGISTRY._pending)
        self.assertEqual(REGISTRY.metrics_snapshot()["pending_pruned"], 1)

    def test_expired_request_memory_is_bounded(self):
        for index in range(broker_server.MAX_EXPIRED_REQUEST_IDS + 20):
            with REGISTRY._lock:
                REGISTRY._remember_expired_request_locked(f"req-{index}")

        self.assertEqual(
            len(REGISTRY._expired_pending), broker_server.MAX_EXPIRED_REQUEST_IDS
        )
        # 最老的 id 被淘汰 -> 之后到达只能算"未知响应"
        REGISTRY.set_response("req-0", {"jsonrpc": "2.0", "id": 1, "result": {}})
        self.assertEqual(REGISTRY.metrics_snapshot()["unknown_responses_discarded"], 1)


class StatusEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_registry()
        self.port = _pick_free_port()
        self.server = broker_server.IDAHttpServer(port=self.port)
        self.server.start()
        self.addCleanup(self.server.stop)

    def tearDown(self) -> None:
        _reset_registry()

    def _get(self, path: str) -> tuple[int, object]:
        url = f"http://127.0.0.1:{self.port}{path}"
        deadline = time.monotonic() + 3.0
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    return response.status, json.loads(response.read().decode("utf-8"))
            except (urllib.error.URLError, ConnectionResetError, OSError) as exc:
                last_error = exc
                time.sleep(0.02)
        raise AssertionError(f"GET {path} 失败: {last_error}")

    def _post(self, path: str, payload: dict) -> tuple[int, object]:
        url = f"http://127.0.0.1:{self.port}{path}"
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_status_keeps_existing_keys_and_adds_metrics(self):
        REGISTRY.register(
            {
                "instance_id": "ida-1",
                "name": "sample",
                "binary_path": "C:/tmp/sample.exe",
                "idb_path": "C:/tmp/sample.exe.i64",
                "arch_info": {"processor": "metapc", "bitness": 64},
            }
        )

        status, payload = self._get("/status")

        self.assertEqual(status, 200)
        self.assertIsInstance(payload, dict)
        self.assertIn("instances", payload)
        self.assertIn("metrics", payload)
        self.assertEqual(len(payload["instances"]), 1)
        instance = payload["instances"][0]
        for key in PREEXISTING_INSTANCE_KEYS:
            self.assertIn(key, instance)
        self.assertEqual(instance["name"], "sample")
        self.assertEqual(instance["processor"], "metapc")

        metrics = payload["metrics"]
        for key in (
            "requests_routed",
            "requests_in_flight",
            "requests_completed",
            "requests_failed",
            "requests_timed_out",
            "responses_accepted",
            "late_responses_discarded",
            "unknown_responses_discarded",
            "pending_requests",
            "instances",
        ):
            self.assertIn(key, metrics)
        entry = metrics["instances"][instance["client_id"]]
        self.assertIn("last_seen", entry)
        self.assertEqual(entry["queue_depth"], 0)

    def test_api_instances_still_returns_bare_list(self):
        REGISTRY.register({"instance_id": "ida-1"})

        status, payload = self._get("/api/instances")

        self.assertEqual(status, 200)
        self.assertIsInstance(payload, list)
        self.assertEqual(payload[0]["instance_id"], "ida-1")

    def test_api_request_without_instances_keeps_error_and_counts_rejection(self):
        status, payload = self._post("/api/request", {"request": _request_payload()})

        self.assertEqual(status, 200)
        self.assertIsNone(payload["response"])
        self.assertEqual(payload["error"], "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。")

        _, status_payload = self._get("/status")
        metrics = status_payload["metrics"]
        self.assertEqual(metrics["requests_rejected"], 1)
        self.assertEqual(metrics["requests_routed"], 1)
        self.assertEqual(metrics["requests_in_flight"], 0)

    def test_api_request_timeout_metrics_over_http(self):
        REGISTRY.register({"instance_id": "ida-1"})

        status, payload = self._post(
            "/api/request", {"request": _request_payload(), "timeout": 0.05}
        )

        self.assertEqual(status, 200)
        self.assertIsNone(payload["response"])

        _, status_payload = self._get("/status")
        metrics = status_payload["metrics"]
        self.assertEqual(metrics["requests_timed_out"], 1)
        self.assertEqual(metrics["requests_in_flight"], 0)
        self.assertEqual(metrics["pending_requests"], 0)
        self.assertEqual(
            metrics["requests_routed"],
            metrics["requests_completed"]
            + metrics["requests_failed"]
            + metrics["requests_timed_out"],
        )


if __name__ == "__main__":
    unittest.main()
