"""hooks/version_bump_gate.py — end-to-end in a scratch git repo.

Every case runs the real script against a real index; the install
case makes git itself dispatch the hook on ``git commit``.
"""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "hooks" / "version_bump_gate.py"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
}


def _mod():
    spec = importlib.util.spec_from_file_location("version_bump_gate", GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(cwd, *args, check=True):
    env = dict(os.environ, **GIT_ENV)
    return subprocess.run(["git", "-c", "commit.gpgsign=false"] + list(args), cwd=cwd, env=env,
                          capture_output=True, text=True, check=check)


def _run_gate(cwd, *args):
    env = dict(os.environ, **GIT_ENV)
    return subprocess.run([sys.executable, str(GATE)] + list(args), cwd=cwd, env=env,
                          capture_output=True, text=True)


def _serving_probe(mod):
    """A concrete repo-relative path that matches SERVING (first pattern, ``*`` -> ``probe``)."""
    return mod.SERVING[0].replace("*", "probe")


@pytest.fixture
def repo(tmp_path):
    mod = _mod()
    _git(tmp_path, "init", "-q", "--template=", ".")
    version = tmp_path / mod.VERSION_FILE
    version.parent.mkdir(parents=True, exist_ok=True)
    version.write_text('"""probe"""\n__version__ = "1.0.0"\n')
    probe = tmp_path / _serving_probe(mod)
    probe.parent.mkdir(parents=True, exist_ok=True)
    if probe != version:
        probe.write_text("# serving\n")
    (tmp_path / "README.md").write_text("docs\n")
    assert not mod.is_serving("README.md"), "README.md must sit outside SERVING for this suite"
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "--no-verify", "-m", "base")
    return tmp_path, mod, probe, version


def test_decide_is_pure_and_only_checks_movement():
    mod = _mod()
    serving = _serving_probe(mod)
    assert mod.decide(["README.md"], "1.0.0", "1.0.0") == (0, "")
    assert mod.decide([serving], "1.0.0", "1.0.0")[0] == 1
    assert mod.decide([serving], "1.0.0", "0.9.0") == (0, "")   # moved — direction is not judged
    assert mod.decide([serving], "1.0.0", "2.0.0") == (0, "")
    assert mod.decide([serving], None, None) == (0, "")         # nothing committed to compare against
    code, msg = mod.decide([serving], "1.0.0", None)
    assert code == 1 and "no __version__" in msg


def test_blocks_serving_change_without_bump(repo):
    root, mod, probe, _ = repo
    with probe.open("a") as fh:
        fh.write("# touched\n")
    _git(root, "add", "-A")
    res = _run_gate(root)
    assert res.returncode == 1
    assert "BLOCKED" in res.stderr and mod.VERSION_FILE in res.stderr


def test_passes_once_version_moved(repo):
    root, mod, probe, version = repo
    with probe.open("a") as fh:
        fh.write("# touched\n")
    version.write_text(version.read_text().replace('"1.0.0"', '"1.0.1"'))
    _git(root, "add", "-A")
    res = _run_gate(root)
    assert res.returncode == 0 and res.stdout == "" and res.stderr == ""


def test_silent_outside_serving(repo):
    root, _, _, _ = repo
    (root / "README.md").write_text("docs changed\n")
    _git(root, "add", "-A")
    res = _run_gate(root)
    assert res.returncode == 0 and res.stdout == "" and res.stderr == ""


def test_install_makes_git_dispatch_the_gate(repo):
    root, mod, probe, version = repo
    assert _run_gate(root, "--install").returncode == 0
    hook = root / ".git" / "hooks" / "pre-commit"
    assert not hook.is_symlink()                    # a copy, never a symlink
    assert hook.read_bytes() == GATE.read_bytes()   # byte-equal, so drift is a red test
    assert os.access(hook, os.X_OK)
    with probe.open("a") as fh:
        fh.write("# touched\n")
    _git(root, "add", "-A")
    refused = _git(root, "commit", "-q", "-m", "no bump", check=False)
    assert refused.returncode != 0 and "BLOCKED" in refused.stderr
    version.write_text(version.read_text().replace('"1.0.0"', '"1.0.1"'))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "bumped")


def test_install_refuses_a_foreign_pre_commit(repo):
    root, _, _, _ = repo
    hook = root / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho someone else\n")
    res = _run_gate(root, "--install")
    assert res.returncode == 1 and "foreign" in res.stderr and "version_bump_gate.py" in res.stderr
    assert hook.read_text() == "#!/bin/sh\necho someone else\n"


def test_serving_set_is_exactly_what_the_image_copies_and_the_app_name_is_ours():
    mod = _mod()
    assert mod.APP == "amt-mcp"
    assert mod.VERSION_FILE == "amt_server.py"
    copies = [line.split()[1:] for line in (REPO / "Dockerfile").read_text().splitlines()
              if line.startswith("COPY ")]
    modules = {n for c in copies for n in c if n.endswith(".py")}
    trees = {c[0] for c in copies if len(c) == 2 and not c[0].endswith(".py")}
    assert len(modules) >= 19 and trees == {"vendor"}          # non-vacuous
    serving_modules = {p for p in mod.SERVING if p.endswith(".py")}
    assert serving_modules == modules                           # a module added to the image must be added to SERVING
    assert "vendor/*" in mod.SERVING
    for f in ("README.md", "AGENTS.md", "Dockerfile", "deploy/compose.yaml", "deploy/amt_admin.py",
              "tests/test_skeleton.py", "console/server.py", "pyproject.toml"):
        assert not mod.is_serving(f), f
    assert mod.is_serving("vendor/xterm/__init__.py")
