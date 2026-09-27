"""静态守卫：源码里不允许出现"未定义的全局名"与"危险的注册动作"。

`python -m py_compile` 只查语法，像"重构时漏改的旧名字"（例如把 `sys_stderr()` 删了
却还有调用点）只有在真正执行到那一行时才会炸成 `NameError` —— 本项目就在 IDA 里
真实炸过一次（缓存守护线程的启动打印）。这里用 `symtable` 做一次全树静态扫描，
并自带自检用例证明扫描器本身有效（不会把闭包变量误报成未定义）。

后半部分是**结构性守卫**（`ast`）：定时器 / IDB 钩子的注册点必须落在白名单里。
文本匹配只能守住"已经知道的那个文件"，而事故恰恰是换了个文件、换了个回调再次发生，
所以这里改成全树扫描 + 白名单 + "回调内禁止注册"三条规则。
"""

from __future__ import annotations

import ast
import builtins
import pathlib
import symtable
import unittest

_SRC_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp"

# 解释器注入的模块级名字，不算未定义
_ALLOWED = frozenset(
    {
        "__file__",
        "__name__",
        "__doc__",
        "__package__",
        "__spec__",
        "__loader__",
        "__builtins__",
        "__path__",
        "__debug__",
    }
)


def find_undefined_globals(source: str, filename: str = "<string>") -> set[str]:
    """返回源码中"被引用但在模块内既未定义也非内置"的全局名集合。"""
    top = symtable.symtable(source, filename, "exec")
    referenced: set[str] = set()

    def walk(table: symtable.SymbolTable) -> None:
        for sym in table.get_symbols():
            if sym.is_global() and not (
                sym.is_assigned()
                or sym.is_imported()
                or sym.is_namespace()
                or sym.is_parameter()
            ):
                referenced.add(sym.get_name())
        for child in table.get_children():
            walk(child)

    walk(top)

    defined = {
        sym.get_name()
        for sym in top.get_symbols()
        if sym.is_assigned() or sym.is_imported() or sym.is_namespace()
    }
    return referenced - defined - set(dir(builtins)) - _ALLOWED


class CheckerSelfTests(unittest.TestCase):
    """证明扫描器真的能抓到问题、且不会误报。"""

    def test_detects_undefined_global_call(self) -> None:
        source = "def f():\n    return missing_helper()\n"
        self.assertEqual(find_undefined_globals(source), {"missing_helper"})

    def test_detects_undefined_name_in_nested_scope(self) -> None:
        source = (
            "import os\n"
            "def outer():\n"
            "    def inner():\n"
            "        return os.path.join(ghost, 'x')\n"
            "    return inner\n"
        )
        self.assertEqual(find_undefined_globals(source), {"ghost"})

    def test_accepts_defined_imported_and_builtin(self) -> None:
        source = (
            "import sys, os.path\n"
            "from typing import Optional\n"
            "CONST = 1\n"
            "class C:\n"
            "    attr = 1\n"
            "def f(a: Optional[int] = None):\n"
            "    print(len(str(a)))\n"
            "    return CONST + C.attr + sys.maxsize\n"
        )
        self.assertEqual(find_undefined_globals(source), set())

    def test_does_not_flag_closure_variables(self) -> None:
        source = (
            "def outer():\n"
            "    captured = 1\n"
            "    def inner():\n"
            "        return captured\n"
            "    return inner\n"
        )
        self.assertEqual(find_undefined_globals(source), set())

    def test_does_not_flag_global_declarations(self) -> None:
        source = (
            "counter = 0\n"
            "def bump():\n"
            "    global counter\n"
            "    counter += 1\n"
            "    return counter\n"
        )
        self.assertEqual(find_undefined_globals(source), set())


class SourceTreeSanityTests(unittest.TestCase):
    def test_no_undefined_globals_in_source_tree(self) -> None:
        offenders: dict[str, list[str]] = {}
        scanned = 0
        for path in sorted(_SRC_ROOT.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            scanned += 1
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover - 环境问题
                self.fail(f"无法读取 {path}: {exc}")
            missing = find_undefined_globals(source, str(path))
            if missing:
                offenders[str(path.relative_to(_SRC_ROOT))] = sorted(missing)

        self.assertGreater(scanned, 20, "扫描到的文件数异常，可能路径配置有误")
        self.assertEqual(
            offenders,
            {},
            f"发现未定义的全局名（运行到这里会是 NameError）：{offenders}",
        )


class PluginStartupSafetyTests(unittest.TestCase):
    """插件启动路径的静态约束（防止再次出现"启动即死锁"）。

    事故：2.1.1 让 `IDB_Hooks.loaded()` 调用 `ida_kernwin.register_timer()` 安装空闲监视器，
    而 `loaded()` 是在**数据库加载序列内部**被调用的 —— 在那里注册 UI 定时器把主线程锁死：
    IDA 一启动就无响应、CPU 零增长、Broker 里看不到实例。

    结论：插件装载器不得注册任何 IDB 钩子；缓存生命周期只能由**主循环定时器**驱动。
    """

    def setUp(self) -> None:
        self.source = (_SRC_ROOT / "ida_mcp.py").read_text(encoding="utf-8")

    def test_no_idb_hooks_in_plugin_loader(self) -> None:        # 注意只检查**代码形态**（导入/调用），注释里提到 IDB_Hooks 不算
        self.assertNotIn(
            "ida_idp",
            self.source,
            "插件装载器不得导入 ida_idp / 注册 IDB 钩子（在启动路径里注册 = 死锁）",
        )
        self.assertNotIn(".hook()", self.source, "插件装载器不得注册任何钩子")

    def test_cache_lifecycle_is_timer_driven(self) -> None:
        self.assertIn("cache_supervisor_timer", self.source, "缓存生命周期应由主循环定时器轮询驱动")
        self.assertIn("sync_to_idb", self.source, "定时器应通过 sync_to_idb 同步守护线程")

    def test_no_metadata_scan_at_plugin_init(self) -> None:
        self.assertNotIn(
            "from importlib.metadata",
            self.source,
            "插件初始化不应扫描 sys.path 取版本号（IDA 的 site-packages 很大，会拖慢启动）",
        )
        self.assertNotIn("importlib.metadata.version", self.source)

    def test_daemon_start_path_never_registers_timers(self) -> None:
        """守护线程启动路径不得注册/注销定时器。

        实测事故：`start_cache_daemon` 里 `register_timer`（从定时器回调 / IDB 钩子里被调用）
        会把 IDA 主线程锁死 —— 启动即无响应、CPU 零增长。空闲状态改由插件在 init() 里
        注册的那一个定时器统一刷新（`refresh_idle_states`）。
        """
        source = (_SRC_ROOT / "broker" / "sqlite_cache.py").read_text(encoding="utf-8")
        start = source.index("def start_cache_daemon")
        end = source.index("def request_refresh")
        body = source[start:end]
        # 只检查**代码形态**（带括号的调用），注释里提到不算
        self.assertNotIn("register_timer(", body, "启动路径不得注册定时器")
        self.assertNotIn("unregister_timer(", body, "启动路径不得注销定时器")


class StructuralGuardTests(unittest.TestCase):
    """结构性守卫：注册动作必须落在白名单里，且不得发生在内核回调内部。

    为什么不用文本匹配：事故 2、3 是**同一个形状**换了地方再次发生（先是在
    `IDB_Hooks.loaded()`，后来是在定时器回调里）。文本 `assertNotIn` 只能守住
    已经知道的那一处；这里改成三条规则，任何新出现的注册点都会让测试失败。
    """

    # `register_timer` 允许出现的位置（其余一律失败）
    TIMER_SITE_ALLOWLIST = {
        # 插件 init() 里注册的两个主循环定时器（唯一的合法注册时机）
        "ida_mcp.py",
        # 上游 dbg_start 的一次性兜底定时器：在工具处理函数里注册，不在任何回调内
        "ida_mcp/api_debug.py",
    }

    # 允许定义 `IDB_Hooks` 子类（= 注册 IDB 钩子）的文件，必须精确匹配
    IDB_HOOK_ALLOWLIST = {
        # 保存 IDB 即唤醒缓存重建；stop_cache_daemon 会注销（见 test_incident_regressions）
        "broker/sqlite_cache.py",
        # 保存/关库时 flush 调用记录；shutdown() 会注销
        "ida_mcp/trace.py",
    }

    TIMER_CALLS = frozenset({"register_timer", "unregister_timer"})

    def _sources(self) -> list[tuple[str, pathlib.Path]]:
        out: list[tuple[str, pathlib.Path]] = []
        for path in sorted(_SRC_ROOT.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            out.append((str(path.relative_to(_SRC_ROOT)).replace("\\", "/"), path))
        return out

    def _tree(self, path: pathlib.Path) -> ast.Module:
        return ast.parse(path.read_text(encoding="utf-8"), str(path))

    @staticmethod
    def _called_names(node: ast.AST) -> set[str]:
        names: set[str] = set()
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            if isinstance(func, ast.Attribute):
                names.add(func.attr)
            elif isinstance(func, ast.Name):
                names.add(func.id)
        return names

    def test_broker_never_imports_ida_at_module_scope(self) -> None:
        """`broker/` 必须能在没有 IDA 的进程里 import（MCP 服务器 / CI / 单测）。

        模块级 `import ida_*` 会让 broker 在纯 Python 环境直接 ImportError，
        所以 IDA 依赖必须写在函数内部（惰性导入）。
        """
        offenders: dict[str, list[str]] = {}
        for rel, path in self._sources():
            if not rel.startswith("broker/"):
                continue
            tree = self._tree(path)
            found: list[str] = []
            for node in tree.body:  # 只看模块作用域
                if isinstance(node, ast.Import):
                    found += [a.name for a in node.names if a.name.split(".")[0].startswith("ida")]
                elif (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.split(".")[0].startswith("ida")
                ):
                    found.append(node.module)
            if found:
                offenders[rel] = found
        self.assertEqual(offenders, {}, f"broker 模块级导入了 IDA（应改为函数内惰性导入）: {offenders}")

    def test_timer_registration_sites_are_allowlisted(self) -> None:
        sites: dict[str, int] = {}
        for rel, path in self._sources():
            tree = self._tree(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in self.TIMER_CALLS:
                    sites[rel] = sites.get(rel, 0) + 1
        unknown = sorted(set(sites) - self.TIMER_SITE_ALLOWLIST)
        self.assertEqual(
            unknown,
            [],
            f"新的定时器注册点 {unknown} —— 在定时器回调/IDB 钩子里注册会锁死 IDA 主线程，"
            "确认安全后加入白名单并说明理由",
        )
        self.assertTrue(sites, "预期插件里存在定时器注册（白名单失效？）")

    def test_idb_hook_sites_are_allowlisted(self) -> None:
        sites: set[str] = set()
        for rel, path in self._sources():
            tree = self._tree(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                bases = {
                    (b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", ""))
                    for b in node.bases
                }
                if "IDB_Hooks" in bases:
                    sites.add(rel)
        self.assertEqual(
            sites,
            self.IDB_HOOK_ALLOWLIST,
            "IDB 钩子注册点发生变化：多一个就是泄漏/死锁风险，少一个要同步更新白名单",
        )

    def test_no_registration_inside_idb_callbacks(self) -> None:
        """事故 2/3 的精确形状：在 IDB 回调里注册定时器/钩子 → 主线程锁死。"""
        offenders: dict[str, list[str]] = {}
        for rel, path in self._sources():
            tree = self._tree(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                bases = {
                    (b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", ""))
                    for b in node.bases
                }
                if "IDB_Hooks" not in bases:
                    continue
                for item in node.body:
                    if not isinstance(item, ast.FunctionDef):
                        continue
                    called = self._called_names(item) & (
                        self.TIMER_CALLS | {"hook", "unhook"}
                    )
                    if called:
                        offenders.setdefault(rel, []).append(
                            f"{node.name}.{item.name}: {sorted(called)}"
                        )
        self.assertEqual(
            offenders,
            {},
            f"IDB 回调内禁止注册定时器/钩子（会锁死 IDA 主线程）: {offenders}",
        )


    def test_idb_savebase_never_writes_the_database(self) -> None:
        """事故：`trace` 的 `savebase()` 在**保存序列内部**写 netnode，导致保存后 IDA 死等。

        症状：`.i64` 已写盘、但 `Responding=False`、CPU 冻结、全部线程 Wait，
        随后所有需要主线程的工具（`idb_save` 等）全部超时。
        规则：`IDB_Hooks.savebase()` 里只允许置标志，不得调用任何写库动作。
        """
        offenders: dict[str, list[str]] = {}
        for rel, path in self._sources():
            tree = self._tree(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                bases = {
                    (b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", ""))
                    for b in node.bases
                }
                if "IDB_Hooks" not in bases:
                    continue
                for item in node.body:
                    if not isinstance(item, ast.FunctionDef) or item.name != "savebase":
                        continue
                    called = self._called_names(item) & {
                        "flush",
                        "close",
                        "save_database",
                        "savebase",
                    }
                    if called:
                        offenders.setdefault(rel, []).append(
                            f"{node.name}.savebase: {sorted(called)}"
                        )
        self.assertEqual(
            offenders,
            {},
            f"savebase 内不得写数据库（会与保存流程循环等待）: {offenders}",
        )

    def test_deferred_trace_flush_is_timer_driven(self) -> None:
        """`savebase` 只置标志，真正的 flush 必须由主循环定时器执行。"""
        loader = (_SRC_ROOT / "ida_mcp.py").read_text(encoding="utf-8")
        self.assertIn(
            "flush_pending",
            loader,
            "trace 的延迟 flush 必须挂在主循环定时器上（否则记录永远不落盘）",
        )
        trace_src = (_SRC_ROOT / "ida_mcp" / "trace.py").read_text(encoding="utf-8")
        self.assertIn("def flush_pending", trace_src)
        self.assertNotIn(
            "b.flush()\n",
            trace_src.split("def savebase")[1].split("def closebase")[0],
            "savebase 内不得直接 flush",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
