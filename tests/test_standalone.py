"""amt-mcp depends on no other application, and no tracked file names one.

Other programs call this one through its public surfaces. This one never calls them back and never
mentions them. Two checks, each with a planted fault that must trip it:

  * every import in the Python files resolves to the standard library, a package this app declares,
    or a module in this repository;
  * no tracked text file names a sibling application, a tool of the workspace it was built in, a real
    host, a person's account or a local layout.

The forbidden words are built from fragments so this file does not contain them, and it is skipped by
the scan only for that reason. Adapted from the vault app's standalone test.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THIS = Path(__file__).resolve()

# Third-party import names, by where they are used. The bridges need fastmcp and httpx.
THIRD_PARTY = {"mcp", "patchright", "playwright", "starlette", "uvicorn", "httpx", "pydantic", "anyio", "websockets", "cryptography", "yaml", "cv2", "numpy", "PIL", "ocrmac"}
TESTS_THIRD_PARTY = THIRD_PARTY | {"pytest"}

_W = [
    "is" + "aac", "claude-" + "is" + "aac", "kb" + "_get", "kb" + "_store", "kb" + "_search", "whis" + "per",
    "q" + "vc", "shell" + "ware", "syn" + "man", "aka" + "mai", "az-" + "teams",
    "snow-" + "py", "snow-" + "mcp", "her" + "mes", "agent-" + "meetings", "node-kb", "node-git", "node-extract",
    "node-whis", "node-fed", "node-web", "node-proc", "~/" + "ai",
    "cla" + "ude", "open" + "code", "copi" + "lot", ".virtual" + "envs", ".s" + "sl", "ms" + "365",
    "ji" + "ra", 'zo' + 'needit-mcp', 'no' + 'de-vault', 'no' + 'de-signal', 'ds' + '1621', '/v' + 'olume1', '10' + '.151', 'dn' + 'smasq', 'DS' + 'M', "mcp-admin-" + "token", "mcp-admin-" + "one", "atlas" + "sian", "home-" + "assistant",
]
# A placeholder like <w-o-r-k-s-p-a-c-e>, but not a generic type such as Promise<Workspace>.
_PLACEHOLDER = r"(?<![A-Za-z0-9_])<" + "work" + "space>"
SHARED_TOKEN = r"fle" + r"et[ -](?:token|bearer|hash|gate|principal|admin)|principal=fle" + r"et"
FORBIDDEN = re.compile("|".join([SHARED_TOKEN] + [re.escape(w) for w in _W] + [_PLACEHOLDER]), re.I)

SKIP_DIRS = {".git", "node_modules", "dist", "__pycache__", ".pytest_cache", ".ruff_cache", ".test-artifacts"}
LOCK_FILES = {"package-lock.json"}


def tracked_files() -> list[Path]:
    res = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True)
    if res.returncode == 0 and res.stdout:
        return [ROOT / p for p in res.stdout.split("\0") if p]
    return [p for p in ROOT.rglob("*") if p.is_file() and not SKIP_DIRS & set(p.relative_to(ROOT).parts)]


# A host or an address that belongs to a real machine or person. Documentation hosts, loopback
# and one-letter test hosts are fine.
_URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
_EMAIL = re.compile(r"[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_DOC_HOSTS = ("example.com", "example.invalid", "example.org", "example.net", "example.test", "test.invalid", "test", "invalid", "example",
              "w3.org", "xmlsoap.org", "dmtf.org", "intel.com", "mozilla.org", "github.com", "modelcontextprotocol.io", "dequeuniversity.com",
              "system-rescue.org", "sourcelair.com", "bellard.org", "host.com")


def _is_real(host: str) -> bool:
    host = host.lower().rstrip(".")
    if "." not in host or host == "127.0.0.1" or host.endswith("python.org") or re.fullmatch(r"(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+|10\.0\.0\.\d+", host):
        return False
    return not any(host == d or host.endswith("." + d) for d in _DOC_HOSTS)


def named_siblings(text: str) -> set[str]:
    found = {m.group(0).lower() for m in FORBIDDEN.finditer(text)}
    found |= {h.lower() for h in _URL.findall(text) if _is_real(h)}
    found |= {h.lower() for h in _EMAIL.findall(text) if _is_real(h)}
    return found


def foreign_imports(source: str, local: set[str], third_party: set[str]) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        else:
            continue
        out |= {n for n in names if n not in sys.stdlib_module_names and n not in local and n not in third_party}
    return out


# --- the real tree ----------------------------------------------------------------------------------------------


def _py_files(top: str) -> list[Path]:
    return [p for p in tracked_files() if p.suffix == ".py" and p.relative_to(ROOT).parts[0] == top]


def _root_py() -> list[Path]:
    return [p for p in tracked_files() if p.suffix == ".py" and len(p.relative_to(ROOT).parts) == 1]


def _local_modules() -> set[str]:
    names = {p.stem for p in tracked_files() if p.suffix == ".py"}
    return names


@pytest.mark.parametrize("top,third_party", [("hooks", set()), ("tests", TESTS_THIRD_PARTY), ("deploy", THIRD_PARTY)])
def test_every_import_is_stdlib_declared_or_in_this_repository(top, third_party):
    files = _py_files(top) + (_root_py() if top == "tests" else [])
    assert files, top
    bad = {str(p.relative_to(ROOT)): foreign_imports(p.read_text(), _local_modules(), third_party) for p in files}
    assert {f: m for f, m in bad.items() if m} == {}


def test_no_tracked_text_file_names_a_sibling_application():
    scanned, bad = 0, {}
    for path in tracked_files():
        rel = str(path.relative_to(ROOT))
        if path == THIS or path.name in LOCK_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "vendor" in path.relative_to(ROOT).parts or "design" in path.relative_to(ROOT).parts:
            continue
        scanned += 1
        names = named_siblings(text)
        if names:
            bad[rel] = sorted(names)
    assert scanned > 15, "the scan found almost nothing, so it proves nothing"
    assert bad == {}


# --- planted faults: each check must go red on its own fault -----------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "see is" + "aac for the rest", "set the q" + "vc proxy", "kb" + "_get('x')", "~/" + "ai/x", "A" + "KAMAI edge",
        "<work" + "space>/x", "~/.cla" + "ude/x", "Open" + "Code config", "~/.virtual" + "envs/main", "https://meet.real-host.net/mcp",
        "someone@real-host.net", "CLA" + "UDE_CODE_X", "the fle" + "et token", "principal=fle" + "et",
    ],
)
def test_the_text_scan_catches_each_kind_of_name(text):
    assert named_siblings(text)


def test_the_text_scan_passes_plain_text():
    assert named_siblings("a vault with three surfaces and a plain bash cli") == set()


def test_the_text_scan_passes_documentation_hosts_and_loopback():
    text = "https://mcp.example.invalid/x http://127.0.0.1:9/mcp http://a/mcp t@example.com https://docs.python.org/3/"
    assert named_siblings(text) == set()


def test_the_import_scan_catches_a_sibling_module_in_each_import_form():
    sibling = "is" + "aac_db"
    for src in (f"import {sibling}", f"from {sibling} import x", f"import a.b\nimport {sibling}.sub"):
        assert foreign_imports(src, set(), set()) == {sibling} | ({"a"} if "a.b" in src else set())


def test_the_import_scan_passes_stdlib_declared_and_local():
    src = "import json\nfrom pathlib import Path\nimport mcp\nimport vault_secrets.core\nfrom . import x"
    assert foreign_imports(src, {"vault_secrets"}, {"mcp"}) == set()
