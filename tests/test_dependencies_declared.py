"""A consumer states what it depends on, and a test holds it to that.

Every package a root or console module imports must be the standard library, a module of this
repository, or named in the README's Dependencies section. A planted fault proves the check goes red.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _tracked_py() -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    return out or [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")]


def _dependencies_section() -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"^## Dependencies\n(.*?)(?=^## )", text, re.S | re.M)
    assert match, "README.md has no Dependencies section"
    return {name.lower() for name in re.findall(r"`([A-Za-z0-9_.-]+)`", match.group(1))}


# An import name that differs from its package name.
IMPORT_AS_PACKAGE = {"pil": "pillow"}


def undeclared(source: str, local: set[str], declared: set[str]) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        else:
            continue
        found |= {n for n in names if n not in sys.stdlib_module_names and n not in local
                   and IMPORT_AS_PACKAGE.get(n.lower(), n.lower()) not in declared}
    return found


def _scanned() -> list[str]:
    return [f for f in _tracked_py() if "/" not in f or (f.startswith("console/") and "/tests/" not in f)]


def test_every_imported_package_is_named_in_the_dependencies_section():
    files = _scanned()
    assert len(files) > 5, "the scan found almost nothing, so it proves nothing"
    local = {Path(f).stem for f in _tracked_py()}
    declared = _dependencies_section()
    bad = {f: undeclared((ROOT / f).read_text(encoding="utf-8"), local, declared) for f in files}
    assert {f: m for f, m in bad.items() if m} == {}


def test_the_check_goes_red_on_a_planted_undeclared_import():
    assert undeclared("import requests", set(), {"mcp"}) == {"requests"}
    assert undeclared("import json\nimport mcp.server", set(), {"mcp"}) == set()
    assert undeclared("from . import x\nimport mine", {"mine"}, set()) == set()
    assert undeclared("from PIL import Image", set(), {"pillow"}) == set()
    assert undeclared("import mcpx", set(), {"mcp"}) == {"mcpx"}
