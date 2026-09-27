"""idalib supervisor 空闲回收配置 (T2) 的透传/CLI 测试，不需要 IDA。"""

import os
import unittest
from unittest import mock

from ida_pro_mcp import idalib_supervisor as supmod


class _FakePopen:
    """subprocess.Popen 替身，只记录参数。"""

    calls: list["_FakePopen"] = []

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.pid = 4242
        self.returncode = None
        _FakePopen.calls.append(self)

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def _make_supervisor(**kwargs) -> supmod.IdalibSupervisor:
    return supmod.IdalibSupervisor(supmod.McpServer("test"), **kwargs)


class WorkerEnvTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakePopen.calls = []

    def test_worker_env_is_inherited_by_default(self):
        supervisor = _make_supervisor()
        self.assertIsNone(supervisor._worker_env())

    def test_worker_env_carries_idle_configuration(self):
        supervisor = _make_supervisor(idle_ttl_sec=600, idle_sweep_sec=45)
        env = supervisor._worker_env()
        assert env is not None
        self.assertEqual(env[supmod.IDLE_TTL_ENV], "600.0")
        self.assertEqual(env[supmod.IDLE_SWEEP_ENV], "45.0")
        # 其余环境变量照旧继承
        for key, value in os.environ.items():
            self.assertEqual(env[key], value)

    def test_worker_env_clamps_out_of_range_values(self):
        supervisor = _make_supervisor(idle_ttl_sec=-5, idle_sweep_sec=0.01)
        env = supervisor._worker_env()
        assert env is not None
        self.assertEqual(env[supmod.IDLE_TTL_ENV], "0.0")
        self.assertEqual(env[supmod.IDLE_SWEEP_ENV], repr(supmod.MIN_IDLE_SWEEP_SEC))

    def test_spawn_worker_passes_env_to_popen(self):
        supervisor = _make_supervisor(idle_ttl_sec=120, idle_sweep_sec=5)
        with mock.patch.object(supmod.subprocess, "Popen", _FakePopen), mock.patch.object(
            supmod.IdalibSupervisor, "_wait_worker_ready", lambda self, worker, timeout=120.0: None
        ):
            worker = supervisor._spawn_worker()

        self.assertEqual(worker.pid, 4242)
        spawn = _FakePopen.calls[-1]
        self.assertIn("ida_pro_mcp.idalib_server", spawn.cmd)
        self.assertEqual(spawn.kwargs["env"][supmod.IDLE_TTL_ENV], "120.0")
        self.assertEqual(spawn.kwargs["env"][supmod.IDLE_SWEEP_ENV], "5.0")

    def test_spawn_worker_inherits_env_without_configuration(self):
        supervisor = _make_supervisor()
        with mock.patch.object(supmod.subprocess, "Popen", _FakePopen), mock.patch.object(
            supmod.IdalibSupervisor, "_wait_worker_ready", lambda self, worker, timeout=120.0: None
        ):
            supervisor._spawn_worker()

        self.assertIsNone(_FakePopen.calls[-1].kwargs["env"])


class ArgParserTests(unittest.TestCase):
    def test_defaults_keep_current_behavior(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(supmod.IDLE_TTL_ENV, None)
            os.environ.pop(supmod.IDLE_SWEEP_ENV, None)
            args = supmod._build_arg_parser().parse_args([])

        self.assertEqual(args.idle_ttl, 0.0)  # 默认禁用，保持旧行为
        self.assertEqual(args.idle_sweep, 30.0)

    def test_env_supplies_defaults(self):
        with mock.patch.dict(
            os.environ,
            {supmod.IDLE_TTL_ENV: "900", supmod.IDLE_SWEEP_ENV: "60"},
            clear=False,
        ):
            args = supmod._build_arg_parser().parse_args([])

        self.assertEqual(args.idle_ttl, 900.0)
        self.assertEqual(args.idle_sweep, 60.0)

    def test_flags_override_env(self):
        with mock.patch.dict(
            os.environ,
            {supmod.IDLE_TTL_ENV: "900", supmod.IDLE_SWEEP_ENV: "60"},
            clear=False,
        ):
            args = supmod._build_arg_parser().parse_args(
                ["--idle-ttl", "120", "--idle-sweep", "7.5"]
            )

        self.assertEqual(args.idle_ttl, 120.0)
        self.assertEqual(args.idle_sweep, 7.5)

    def test_invalid_env_value_falls_back_to_default(self):
        with mock.patch.dict(os.environ, {supmod.IDLE_TTL_ENV: "not-a-number"}, clear=False):
            args = supmod._build_arg_parser().parse_args([])

        self.assertEqual(args.idle_ttl, supmod.DEFAULT_IDLE_TTL_SEC)

    def test_parsed_values_reach_worker_env(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(supmod.IDLE_TTL_ENV, None)
            os.environ.pop(supmod.IDLE_SWEEP_ENV, None)
            args = supmod._build_arg_parser().parse_args(["--idle-ttl", "77"])

        supervisor = _make_supervisor(
            idle_ttl_sec=args.idle_ttl, idle_sweep_sec=args.idle_sweep
        )
        env = supervisor._worker_env()
        assert env is not None
        self.assertEqual(env[supmod.IDLE_TTL_ENV], "77.0")
        self.assertEqual(env[supmod.IDLE_SWEEP_ENV], "30.0")


if __name__ == "__main__":
    unittest.main()
