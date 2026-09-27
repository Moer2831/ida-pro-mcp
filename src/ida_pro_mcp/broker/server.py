"""IDA HTTP+SSE 服务器

监听 HTTP 端口，接收 IDA 插件连接。
使用 SSE 推送 MCP 请求到 IDA。
"""

import json
import queue
import socketserver
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse
import sys

# 已超时/已断开请求的 request_id 记忆上限：用于区分"迟到响应"与"未知响应"，
# 同时保证这个集合有界（否则长期运行会内存泄漏）。
MAX_EXPIRED_REQUEST_IDS = 256

# _pending 条目超过 deadline 后仍未被等待线程回收时的宽限期（秒）。
# 正常路径下等待线程一定会在 deadline 时自行 pop，这里只兜底异常挂死的线程。
PENDING_PRUNE_GRACE_SEC = 60.0

# 已断开实例的指标保留数量上限（有界历史，便于排查"刚断开的实例"）。
MAX_RETIRED_INSTANCE_STATS = 16


@dataclass
class IDAInstance:
    """IDA 实例信息"""
    client_id: str
    instance_id: str
    instance_type: str = "gui"
    name: str = ""
    binary_path: str = ""
    idb_path: str = ""
    arch_info: dict = field(default_factory=dict)
    connected_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        result = {
            "client_id": self.client_id,
            "instance_id": self.instance_id,
            "type": self.instance_type,
            "name": self.name,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
        }
        if self.arch_info:
            result["processor"] = self.arch_info.get("processor", "")
            result["bitness"] = self.arch_info.get("bitness", 0)
            result["endian"] = self.arch_info.get("endian", "")
            result["file_type"] = self.arch_info.get("file_type", "")
            result["base_addr"] = self.arch_info.get("base_addr", "")
        return result


@dataclass
class BrokerMetrics:
    """Broker 路由指标（读写都在 IDARegistry._lock 保护下）

    计数口径（互斥的终态桶）:
      requests_routed == requests_completed + requests_failed + requests_timed_out
      - requests_routed: 进入路由的请求总数（含未找到实例等提前失败）
      - requests_completed: 拿到非 error 响应的请求数
      - requests_failed: 路由失败 / 响应带 error / 空响应
      - requests_timed_out: 等待 IDA 响应超时
      - requests_in_flight: 当前仍在等待响应的请求数
    """

    requests_routed: int = 0
    requests_in_flight: int = 0
    requests_completed: int = 0
    requests_failed: int = 0
    requests_timed_out: int = 0
    requests_rejected: int = 0
    responses_accepted: int = 0
    late_responses_discarded: int = 0
    unknown_responses_discarded: int = 0
    pending_pruned: int = 0
    pending_orphaned_on_disconnect: int = 0
    instance_disconnects: int = 0
    last_error: Optional[str] = None
    last_error_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "requests_routed": self.requests_routed,
            "requests_in_flight": self.requests_in_flight,
            "requests_completed": self.requests_completed,
            "requests_failed": self.requests_failed,
            "requests_timed_out": self.requests_timed_out,
            "requests_rejected": self.requests_rejected,
            "responses_accepted": self.responses_accepted,
            "late_responses_discarded": self.late_responses_discarded,
            "unknown_responses_discarded": self.unknown_responses_discarded,
            "pending_pruned": self.pending_pruned,
            "pending_orphaned_on_disconnect": self.pending_orphaned_on_disconnect,
            "instance_disconnects": self.instance_disconnects,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
        }


@dataclass
class InstanceStats:
    """单个 IDA 实例的请求侧统计"""

    requests_sent: int = 0
    responses_received: int = 0
    timeouts: int = 0
    last_seen: Optional[datetime] = None
    last_seen_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "requests_sent": self.requests_sent,
            "responses_received": self.responses_received,
            "timeouts": self.timeouts,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "last_seen_age_sec": (
                round((datetime.now() - self.last_seen).total_seconds(), 3)
                if self.last_seen
                else None
            ),
            "last_seen_reason": self.last_seen_reason,
        }


class IDARegistry:
    """IDA 实例注册表"""
    
    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}
        self._lock = threading.RLock()
        
        # SSE 队列：client_id -> Queue
        self._sse_queues: dict[str, queue.Queue] = {}
        
        # 待响应请求：request_id -> {event, response, client_id, deadline}
        self._pending: dict[str, dict] = {}

        # 已终结（超时/断开）请求的 request_id 记忆：request_id -> 记录时间(monotonic)
        self._expired_pending: "OrderedDict[str, float]" = OrderedDict()

        # 指标
        self._metrics = BrokerMetrics()
        self._instance_stats: dict[str, InstanceStats] = {}
        self._retired_instance_stats: "OrderedDict[str, tuple[IDAInstance, InstanceStats]]" = (
            OrderedDict()
        )
        self._started_at = datetime.now()
        self._started_monotonic = time.monotonic()
        
        # 回调
        self._on_connect: Optional[Callable[[IDAInstance], None]] = None
        self._on_disconnect: Optional[Callable[[str], None]] = None
    
    def register(self, data: dict) -> Optional[IDAInstance]:
        """注册 IDA 实例。同一 instance_id 重复连接时替换旧连接，避免列表中重复。"""
        with self._lock:
            instance_id = data.get("instance_id", "")
            # 同 instance_id 已存在则先移除旧连接（重连或重复点击导致）
            for old_client_id, old_inst in list(self._instances.items()):
                if old_inst.instance_id == instance_id:
                    self._retire_instance_stats_locked(old_client_id, old_inst)
                    self._instances.pop(old_client_id, None)
                    self._sse_queues.pop(old_client_id, None)
                    print(f"[HTTP] 替换旧连接: {old_inst.name or instance_id} ({old_client_id})", file=sys.stderr)
                    sys.stderr.flush()
                    break

            client_id = str(uuid.uuid4())[:8]
            arch_info = data.get("arch_info", {}) or {}
            # idb_path 优先顶层字段，兼容从 arch_info 传入（插件端为减少上游改动时会放这里）
            idb_path = data.get("idb_path", "") or arch_info.get("idb_path", "")
            instance = IDAInstance(
                client_id=client_id,
                instance_id=instance_id or client_id,
                instance_type=data.get("instance_type", "gui"),
                name=data.get("name", ""),
                binary_path=data.get("binary_path", ""),
                idb_path=idb_path,
                arch_info=arch_info,
            )
            self._instances[client_id] = instance
            self._sse_queues[client_id] = queue.Queue()
            self._instance_stats[client_id] = InstanceStats()
            self._note_instance_activity_locked(client_id, "register")

            print(f"[HTTP] +++ IDA 已连接: {instance.name or instance.instance_id} +++", file=sys.stderr)
            sys.stderr.flush()

            if self._on_connect:
                self._on_connect(instance)

            return instance
    
    def unregister(self, client_id: str):
        """注销 IDA 实例"""
        with self._lock:
            instance = self._instances.pop(client_id, None)
            self._sse_queues.pop(client_id, None)
            self._retire_instance_stats_locked(client_id, instance)

            if instance:
                # 断开时仍有请求在等待：记录并标记为"已终结"，避免它们被误判为未知响应
                orphaned = [
                    request_id
                    for request_id, entry in self._pending.items()
                    if entry.get("client_id") == client_id
                ]
                for request_id in orphaned:
                    self._remember_expired_request_locked(request_id)
                if orphaned:
                    self._metrics.pending_orphaned_on_disconnect += len(orphaned)
                    self._record_error_locked(
                        f"实例 {instance.instance_id} 断开时仍有 {len(orphaned)} 个请求等待响应"
                    )
                self._metrics.instance_disconnects += 1

                print(f"[HTTP] --- IDA 已断开: {instance.name or instance.instance_id} ---", file=sys.stderr)
                sys.stderr.flush()
                
                if self._on_disconnect:
                    self._on_disconnect(instance.instance_id)
    
    def get_by_client_id(self, client_id: str) -> Optional[IDAInstance]:
        """根据 client_id 获取实例"""
        with self._lock:
            return self._instances.get(client_id)
    
    def get_by_instance_id(self, instance_id: str) -> Optional[IDAInstance]:
        """根据 instance_id 获取实例"""
        with self._lock:
            for inst in self._instances.values():
                if inst.instance_id == instance_id:
                    return inst
            return None
    
    def list_all(self) -> list[dict]:
        """列出所有实例"""
        with self._lock:
            return [inst.to_dict() for inst in self._instances.values()]
    
    def has_instances(self) -> bool:
        """是否有实例"""
        with self._lock:
            return len(self._instances) > 0

    # ------------------------------------------------------------------
    # 指标
    # ------------------------------------------------------------------

    def _record_error_locked(self, message: str) -> None:
        """记录最近一次错误（供 /status 的 metrics 观察，不抛异常）。"""
        self._metrics.last_error = message
        self._metrics.last_error_at = datetime.now().isoformat()

    def _metrics_fail_locked(self, message: str) -> None:
        """记录一次路由失败（终态：failed）。"""
        self._metrics.requests_failed += 1
        self._record_error_locked(message)

    def _finish_request_locked(self, response: Optional[dict]) -> None:
        """记录一次请求的终态（completed / failed，二者互斥）。"""
        if response is None:
            self._metrics.requests_failed += 1
            self._record_error_locked("IDA 返回空响应")
            return
        if isinstance(response, dict) and response.get("error"):
            self._metrics.requests_failed += 1
            error = response.get("error")
            if isinstance(error, dict):
                self._record_error_locked(str(error.get("message", error)))
            else:
                self._record_error_locked(str(error))
            return
        self._metrics.requests_completed += 1

    def note_rejected_request(self, message: str) -> None:
        """记录在任何路由发生前就被拒绝的请求（例如没有任何 IDA 实例）。"""
        with self._lock:
            self._metrics.requests_routed += 1
            self._metrics.requests_rejected += 1
            self._metrics_fail_locked(message)

    def _note_instance_activity_locked(self, client_id: str, reason: str) -> None:
        """刷新实例的 last_seen（注册/发请求/收响应）。"""
        stats = self._instance_stats.get(client_id)
        if stats is None:
            return
        stats.last_seen = datetime.now()
        stats.last_seen_reason = reason

    def _retire_instance_stats_locked(
        self, client_id: str, instance: Optional[IDAInstance] = None
    ) -> None:
        """实例下线：指标移入有界历史，避免统计字典无限增长。"""
        stats = self._instance_stats.pop(client_id, None)
        if stats is None:
            return
        if instance is None:
            instance = self._instances.get(client_id)
        if instance is None:
            return
        self._retired_instance_stats[client_id] = (instance, stats)
        self._retired_instance_stats.move_to_end(client_id)
        while len(self._retired_instance_stats) > MAX_RETIRED_INSTANCE_STATS:
            self._retired_instance_stats.popitem(last=False)

    def metrics_snapshot(self) -> dict:
        """返回 /status 用的指标快照（线程安全）。"""
        with self._lock:
            instances: dict[str, dict] = {}
            for client_id, instance in self._instances.items():
                instances[client_id] = self._instance_metrics_locked(
                    client_id, instance, self._instance_stats.get(client_id), connected=True
                )
            for client_id, (instance, stats) in self._retired_instance_stats.items():
                instances[client_id] = self._instance_metrics_locked(
                    client_id, instance, stats, connected=False
                )

            snapshot = self._metrics.to_dict()
            snapshot.update(
                {
                    "pending_requests": len(self._pending),
                    "expired_requests_tracked": len(self._expired_pending),
                    "pending_prune_grace_sec": PENDING_PRUNE_GRACE_SEC,
                    "instances": instances,
                    "instances_connected": len(self._instances),
                    "instances_retired": len(self._retired_instance_stats),
                    "queue_depth_total": sum(
                        self._queue_depth_locked(client_id) for client_id in self._sse_queues
                    ),
                    "started_at": self._started_at.isoformat(),
                    "uptime_sec": round(time.monotonic() - self._started_monotonic, 3),
                }
            )
            return snapshot

    def _queue_depth_locked(self, client_id: str) -> int:
        sse_queue = self._sse_queues.get(client_id)
        if sse_queue is None:
            return 0
        try:
            return int(sse_queue.qsize())
        except Exception as exc:
            # 仅影响指标展示，不吞掉原因
            print(f"[HTTP] 读取队列深度失败 ({client_id}): {exc}", file=sys.stderr)
            sys.stderr.flush()
            return 0

    def _instance_metrics_locked(
        self,
        client_id: str,
        instance: IDAInstance,
        stats: Optional[InstanceStats],
        *,
        connected: bool,
    ) -> dict:
        payload = {
            "instance_id": instance.instance_id,
            "name": instance.name,
            "connected": connected,
            "queue_depth": self._queue_depth_locked(client_id) if connected else 0,
            "connected_at": instance.connected_at.isoformat(),
        }
        payload.update((stats or InstanceStats()).to_dict())
        return payload

    def _remember_expired_request_locked(self, request_id: str) -> None:
        """记住已终结的 request_id（有界），用于识别迟到响应。"""
        self._expired_pending[request_id] = time.monotonic()
        self._expired_pending.move_to_end(request_id)
        while len(self._expired_pending) > MAX_EXPIRED_REQUEST_IDS:
            self._expired_pending.popitem(last=False)

    def _prune_stale_pending_locked(self) -> None:
        """兜底清理：等待线程异常消失时，_pending 条目不会永久残留。"""
        now = time.monotonic()
        stale = [
            request_id
            for request_id, entry in self._pending.items()
            if now > float(entry.get("deadline", now)) + PENDING_PRUNE_GRACE_SEC
        ]
        for request_id in stale:
            self._pending.pop(request_id, None)
            self._remember_expired_request_locked(request_id)
            self._metrics.pending_pruned += 1
            print(f"[HTTP] 清理超时未回收的 pending 请求: {request_id}", file=sys.stderr)
            sys.stderr.flush()

    def send_request(self, request: dict, instance_id: Optional[str] = None, timeout: float = 60.0) -> Optional[dict]:
        """发送请求到 IDA 并等待响应"""
        with self._lock:
            self._metrics.requests_routed += 1
            self._metrics.requests_in_flight += 1
        try:
            with self._lock:
                self._prune_stale_pending_locked()
                # 确定目标实例
                if instance_id:
                    inst = self.get_by_instance_id(instance_id)
                else:
                    # 如果未指定且只有一个实例，自动路由；否则报错返回
                    if len(self._instances) == 1:
                        inst = next(iter(self._instances.values()))
                    else:
                        message = "存在多个 IDA 实例或未指定 instance_id，无法路由。"
                        self._metrics_fail_locked(message)
                        return {
                            "jsonrpc": "2.0",
                            "error": {"code": -32602, "message": message},
                            "id": request.get("id")
                        }
                
                if not inst:
                    available = ", ".join(
                        f"{i.instance_id}({i.name or '未命名'})"
                        for i in self._instances.values()
                    ) or "无"
                    message = (
                        f"找不到目标实例: {instance_id}。当前可用实例: {available}。"
                        "请先调用 instance_list（无需参数）获取 instance_id。"
                    )
                    self._metrics_fail_locked(message)
                    return {
                        "jsonrpc": "2.0",
                        "error": {"code": -32000, "message": message},
                        "id": request.get("id")
                    }
                
                client_id = inst.client_id
                sse_queue = self._sse_queues.get(client_id)
                if not sse_queue:
                    self._metrics_fail_locked(f"实例 {inst.instance_id} 没有可用的 SSE 队列")
                    return None
                
                # 创建请求跟踪
                request_id = str(uuid.uuid4())[:8]
                event = threading.Event()
                self._pending[request_id] = {
                    "event": event,
                    "response": None,
                    "client_id": client_id,
                    "deadline": time.monotonic() + max(0.0, float(timeout)),
                }
                stats = self._instance_stats.get(client_id)
                if stats is not None:
                    stats.requests_sent += 1
                self._note_instance_activity_locked(client_id, "request")
            
            # 放入 SSE 队列
            sse_queue.put({"request_id": request_id, "request": request})
            
            # 等待响应
            if event.wait(timeout):
                with self._lock:
                    result = self._pending.pop(request_id, {})
                    response = result.get("response")
                    self._finish_request_locked(response)
                    return response
            else:
                with self._lock:
                    self._pending.pop(request_id, None)
                    self._remember_expired_request_locked(request_id)
                    self._metrics.requests_timed_out += 1
                    self._record_error_locked("IDA 请求超时")
                    stats = self._instance_stats.get(client_id)
                    if stats is not None:
                        stats.timeouts += 1
                return None
        finally:
            # 任何退出路径都必须归还 in-flight 计数（含异常路径）
            with self._lock:
                self._metrics.requests_in_flight = max(
                    0, self._metrics.requests_in_flight - 1
                )

    def set_response(self, request_id: str, response: dict):
        """设置请求响应；迟到/未知响应安全丢弃并计入指标。"""
        with self._lock:
            entry = self._pending.get(request_id)
            if entry is not None:
                entry["response"] = response
                client_id = entry.get("client_id")
                if client_id:
                    stats = self._instance_stats.get(client_id)
                    if stats is not None:
                        stats.responses_received += 1
                    self._note_instance_activity_locked(client_id, "response")
                self._metrics.responses_accepted += 1
                entry["event"].set()
                return

            if request_id in self._expired_pending:
                # 请求已超时/实例已断开：响应迟到，安全丢弃，不能影响在途计数
                del self._expired_pending[request_id]
                self._metrics.late_responses_discarded += 1
                print(f"[HTTP] 丢弃迟到响应: {request_id}", file=sys.stderr)
                sys.stderr.flush()
                return

            self._metrics.unknown_responses_discarded += 1
            print(f"[HTTP] 丢弃未知响应: {request_id}", file=sys.stderr)
            sys.stderr.flush()
    
    def get_sse_queue(self, client_id: str) -> Optional[queue.Queue]:
        """获取 SSE 队列"""
        with self._lock:
            return self._sse_queues.get(client_id)


# 全局注册表
REGISTRY = IDARegistry()


class IDARequestHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""
    
    def log_message(self, format, *args):
        """重定向日志到 stderr"""
        print(f"[HTTP] {args[0]}", file=sys.stderr)
        sys.stderr.flush()
    
    def _send_json(self, data: dict, status: int = 200):
        """发送 JSON 响应"""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    
    def _read_json(self) -> Optional[dict]:
        """读取 JSON 请求体"""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            body = self.rfile.read(length)
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None
    
    def do_OPTIONS(self):
        """处理 CORS 预检"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_POST(self):
        """处理 POST 请求"""
        path = urlparse(self.path).path
        
        if path == "/register":
            self._handle_register()
        elif path == "/unregister":
            self._handle_unregister()
        elif path == "/response":
            self._handle_response()
        elif path == "/api/request":
            self._handle_api_request()
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_GET(self):
        """处理 GET 请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        if path == "/events":
            client_id = params.get("client_id", [None])[0]
            if client_id:
                self._handle_sse(client_id)
            else:
                self._send_json({"error": "Missing client_id"}, 400)
        elif path == "/status":
            # 新增 "metrics" 键（纯增量）；"instances" 键保持原样以兼容前端
            self._send_json({
                "instances": REGISTRY.list_all(),
                "metrics": REGISTRY.metrics_snapshot(),
            })
        elif path == "/api/instances":
            self._send_json(REGISTRY.list_all())
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def _handle_register(self):
        """处理 IDA 注册"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        instance = REGISTRY.register(data)
        if instance:
            self._send_json({"success": True, "client_id": instance.client_id})
        else:
            self._send_json({"error": "Registration failed"}, 500)
    
    def _handle_unregister(self):
        """处理 IDA 主动断开"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        client_id = data.get("client_id")
        if client_id:
            REGISTRY.unregister(client_id)
            self._send_json({"success": True})
        else:
            self._send_json({"error": "Missing client_id"}, 400)
    
    def _handle_response(self):
        """处理 IDA 响应"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        request_id = data.get("request_id")
        response = data.get("response")
        
        if request_id and response:
            REGISTRY.set_response(request_id, response)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "Missing request_id or response"}, 400)
    
    def _handle_api_request(self):
        """POST /api/request - 转发 MCP 请求到 IDA 并返回响应（供 MCP 客户端调用）"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        request = data.get("request")
        instance_id = data.get("instance_id")
        timeout = float(data.get("timeout", 60.0))
        if not request:
            self._send_json({"error": "Missing request"}, 400)
            return
        if not REGISTRY.has_instances():
            message = "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。"
            REGISTRY.note_rejected_request(message)
            self._send_json({
                "error": message,
                "response": None,
            })
            return
        response = REGISTRY.send_request(request, instance_id, timeout=timeout)
        self._send_json({"response": response})
    
    def _handle_sse(self, client_id: str):
        """处理 SSE 连接"""
        instance = REGISTRY.get_by_client_id(client_id)
        if not instance:
            self._send_json({"error": "Unknown client_id"}, 404)
            return
        
        sse_queue = REGISTRY.get_sse_queue(client_id)
        if not sse_queue:
            self._send_json({"error": "No queue"}, 500)
            return
        
        # 发送 SSE 头
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        
        # 发送连接成功事件
        self._send_sse_event("connected", {"client_id": client_id})
        
        try:
            while True:
                try:
                    # 每 10 秒发送心跳检测连接状态
                    # 注意：心跳是单向的，只有 TCP 连接断开（进程退出）才会失败
                    # IDA 主线程卡住时 TCP 连接仍存在，不会误判为断开
                    item = sse_queue.get(timeout=10)
                    self._send_sse_event("request", item)
                except queue.Empty:
                    # 发送心跳，写入失败会触发 BrokenPipeError
                    self._send_sse_event("ping", {})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            # 断开连接时注销
            REGISTRY.unregister(client_id)
    
    def _send_sse_event(self, event: str, data: dict):
        """发送 SSE 事件"""
        msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """多线程 HTTP 服务器：每个请求（含长连接 SSE）在独立线程中处理，避免第二个 IDA 的 /register 被阻塞。"""
    daemon_threads = True


class IDAHttpServer:
    """IDA HTTP+SSE 服务器"""

    def __init__(self, port: int = 13337):
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """启动服务器"""
        if self._running:
            return

        try:
            self._server = ThreadedHTTPServer(("0.0.0.0", self.port), IDARequestHandler)
            self._server.timeout = 1
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

            print(f"[HTTP] 服务器已启动 (多线程): http://0.0.0.0:{self.port}", file=sys.stderr)
            sys.stderr.flush()
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"[HTTP] 端口 {self.port} 已被占用，跳过 HTTP 服务器启动", file=sys.stderr)
                sys.stderr.flush()
            else:
                raise

    def _serve(self):
        """服务循环（每 accept 一个连接由 ThreadingMixIn 派发到新线程）"""
        while self._running:
            try:
                self._server.handle_request()
            except Exception:
                if self._running:
                    pass

    def stop(self):
        """停止服务器"""
        self._running = False
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    @property
    def registry(self) -> IDARegistry:
        """获取注册表"""
        return REGISTRY
