"""静态守卫：源码里不允许出现"未定义的全局名"。

`python -m py_compile` 只查语法，像"重构时漏改的旧名字"（例如把 `sys_stderr()` 删了
却还有调用点）只有在真正执行到那一行时才会炸成 `NameError` —— 本项目就在 IDA 里
真实炸过一次（缓存守护线程的启动打印）。这里用 `symtable` 做一次全树静态扫描，
并自带自检用例证明扫描器本身有效（不会把闭包变量误报成未定义）。
"""

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
