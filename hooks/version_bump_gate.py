#!/usr/bin/env python3
"""Version-bump gate for amt-mcp — a repo-local pre-commit hook.

Blocks a commit that stages a change to one of this MCP's SERVING files
while the ``__version__`` constant in VERSION_FILE is unchanged against
HEAD. It checks only that the version MOVED — whether the step is major,
minor, or patch is the committer's own judgment. A commit that touches no
serving file passes silently.

Install once per clone::

    python3 hooks/version_bump_gate.py --install

Where no pre-commit hook exists it is installed as ``.git/hooks/pre-commit``.
A foreign pre-commit hook is never overwritten: ``--install`` refuses and says
so, and the owner of that hook can run ``python3 hooks/version_bump_gate.py``
from it, since the gate's exit code is the commit's. The install is a COPY,
never a symlink — a symlink into the worktree dangles in a linked worktree —
so re-run ``--install`` after editing this file.

The gate reads and writes nothing outside this repository.
"""
import fnmatch
import os
import re
import shutil
import subprocess
import sys

APP = "amt-mcp"
VERSION_FILE = "amt_server.py"
VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)
# Repo-relative paths that serve the MCP (fnmatch patterns; ``*`` also
# matches ``/``). These are exactly what the Dockerfile COPYs into the amt-mcp
# image: the modules and the vendored xterm tree. The version file counts as
# serving. Tests, deploy files, docs, the separate console image (console/)
# and pyproject do not change what the MCP server does, so they are not serving.
SERVING = (
    "amt_server.py",
    "amt_gate.py",
    "amt_registry.py",
    "amt_vault.py",
    "amt_parity.py",
    "amt_kvm.py",
    "amt_wsman.py",
    "amt_tools.py",
    "amt_wsman_write.py",
    "amt_redir.py",
    "amt_write.py",
    "amt_logdecode.py",
    "amt_mirror.py",
    "amt_serial.py",
    "amt_handoff.py",
    "amt_upload.py",
    "amt_fleet.py",
    "amt_identity.py",
    "amt_captures.py",
    "vendor/*",
)
HOOK = "pre-commit"


def _git(*args):
    return subprocess.run(["git"] + list(args), capture_output=True, text=True)


def staged_paths():
    res = _git("diff", "--cached", "--name-only", "--no-renames", "-z")
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "git diff --cached failed")
    return [p for p in res.stdout.split("\0") if p]


def version_at(rev):
    """Version string in VERSION_FILE at *rev* (``""`` = the index); None if absent."""
    res = _git("show", "%s:%s" % (rev, VERSION_FILE))
    if res.returncode != 0:
        return None
    match = VERSION_RE.search(res.stdout)
    return match.group(1) if match else None


def is_serving(path):
    return any(fnmatch.fnmatchcase(path, pat) for pat in SERVING)


def decide(staged, old, new):
    """Return (exit_code, message). Pure — reads no git state."""
    hit = sorted(p for p in staged if is_serving(p))
    if not hit:
        return 0, ""
    if old is None:  # no committed version to compare against
        return 0, ""
    if new is not None and new != old:
        return 0, ""
    lines = [
        '[%s version-bump-gate] BLOCKED: staged serving files changed but %s '
        'still reads __version__ = "%s".' % (APP, VERSION_FILE, old)
    ]
    if new is None:
        lines.append("  the staged %s carries no __version__ line" % VERSION_FILE)
    lines.append("  bump the version (major/minor/patch is your call), stage it, and commit again.")
    lines.append("  staged serving files: " + ", ".join(hit))
    return 1, "\n".join(lines)


def gate():
    try:
        staged = staged_paths()
    except RuntimeError as exc:
        print("[%s version-bump-gate] cannot read the index, refusing to guess: %s" % (APP, exc),
              file=sys.stderr)
        return 1
    code, msg = decide(staged, version_at("HEAD"), version_at(""))
    if msg:
        print(msg, file=sys.stderr)
    return code


# --- install -----------------------------------------------------------------

def _hooks_dir():
    res = _git("rev-parse", "--git-path", "hooks")
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "not a git repository")
    return os.path.abspath(res.stdout.strip())


def _is_ours(path):
    if os.path.islink(path):
        return os.path.basename(os.path.realpath(path)) == os.path.basename(__file__)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "version-bump-gate" in fh.read()
    except OSError:
        return False


def _install_copy(target, src):
    """Install *src* at *target* as a COPY, never a symlink.

    A symlink into the worktree dangles in a linked worktree, where the
    hooks dir is shared but this file's path is not. The installed copy
    does not track later edits to this file, so re-run ``--install``
    after changing it.
    """
    if os.path.lexists(target):
        os.remove(target)
    shutil.copy2(src, target)
    os.chmod(target, os.stat(target).st_mode | 0o111)


def install():
    src = os.path.abspath(__file__)
    try:
        hooks_dir = _hooks_dir()
    except RuntimeError as exc:
        print("[%s version-bump-gate] %s" % (APP, exc), file=sys.stderr)
        return 1
    os.makedirs(hooks_dir, exist_ok=True)
    pre = os.path.join(hooks_dir, HOOK)
    text = ""
    if os.path.lexists(pre):
        with open(pre, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    if text and not _is_ours(pre):
        print("[%s version-bump-gate] refusing to overwrite a foreign pre-commit hook at %s; "
              "run `python3 hooks/version_bump_gate.py` from it instead" % (APP, pre), file=sys.stderr)
        return 1
    _install_copy(pre, src)
    print("[%s version-bump-gate] installed %s -> %s" % (APP, pre, src))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--install"]:
        sys.exit(install())
    if sys.argv[1:]:
        print(__doc__)
        sys.exit(2)
    sys.exit(gate())
