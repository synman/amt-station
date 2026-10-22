"""In-process vault resolution for amt-mcp.

Reads a vault entry by calling the node-vault-mcp CLI (``secrets.py get <key>``) and capturing
stdout. The value is returned to the caller and never logged, echoed, put in argv/env, or
included in an exception. Any failure raises VaultError naming the vault KEY only, so a
caller that cannot resolve a credential fails closed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# The vault CLI (node-vault-mcp's services/secrets.py), named by AMT_SECRETS_CLI; a container points it
# at its mounted copy, with NVAULT_* naming a dedicated vault. Unset, every vault call fails closed. The
# CLI runs as a child so a vault fault is a VaultError here, not the SystemExit vault_secrets.core
# raises in-process, which would end the server.
SECRETS = Path(os.environ["AMT_SECRETS_CLI"]) if os.environ.get("AMT_SECRETS_CLI") else None
TIMEOUT_SECONDS = 15


class VaultError(Exception):
    """Vault read failed. The message names the vault key, never a value or stderr."""


def _cli() -> str:
    if SECRETS is None:
        raise VaultError("vault_cli_unset:AMT_SECRETS_CLI")
    return str(SECRETS)


def get_secret(key: str) -> str:
    """Resolve a vault entry. Raises VaultError on a miss, an empty value or a timeout."""
    if not key or not key.strip():
        raise VaultError("vault_key_missing")
    try:
        out = subprocess.run(
            [sys.executable, _cli(), "get", key],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except UnicodeDecodeError as ex:
        # Decode failures must not propagate: the exception text carries the
        # offending byte of the value. Name the key and the type only.
        raise VaultError(f"vault_decode_error:{key}:{type(ex).__name__}") from None
    except (OSError, subprocess.SubprocessError) as ex:
        raise VaultError(f"vault_unavailable:{key}:{type(ex).__name__}") from None
    if out.returncode != 0:
        raise VaultError(f"vault_miss:{key}")
    # rstrip only the CLI's trailing newline(s); preserve any intentional edge
    # whitespace in the secret itself (a wrong-by-a-space password risks lockout).
    value = out.stdout.rstrip("\n")
    if not value:
        raise VaultError(f"vault_empty:{key}")
    return value


def amt_password(vault_key: str) -> str:
    """Resolve the AMT admin password for a registry entry's ``amt_vault_key``."""
    return get_secret(vault_key)


def vault_entries() -> dict[str, str]:
    """The entry NAMES in this server's vault (``secrets.py list``), each with the rest of its list
    line (the notes column, where the CLI prints one); never a value."""
    try:
        out = subprocess.run([sys.executable, _cli(), "list"], capture_output=True, text=True,
                             timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as ex:
        raise VaultError(f"vault_unavailable:list:{type(ex).__name__}") from None
    if out.returncode != 0:
        raise VaultError("vault_list_failed")
    entries: dict[str, str] = {}
    for line in out.stdout.splitlines():
        words = line.split("❯", 1)[1].split() if "❯" in line else []
        if words:
            entries[words[0]] = " ".join(words[1:])
    return entries


def vault_names() -> set[str]:
    """The entry NAMES in this server's vault; never a value."""
    return set(vault_entries())


def vault_writable() -> bool:
    """False when a dedicated vault (``NVAULT_VAULT_PATH``) or its directory cannot be written, as
    when the container mounts it read-only. Unset (the main vault) cannot be judged here: True."""
    path = os.environ.get("NVAULT_VAULT_PATH")
    if not path:
        return True
    return os.access(path, os.W_OK) and os.access(os.path.dirname(path) or ".", os.W_OK)


def set_secret(key: str, value: str, notes: str, expires: str) -> None:
    """Store ``value`` under ``key``. The value goes to the CLI on stdin only, never argv or env, and
    the CLI's output is dropped. Raises VaultError naming the key, never the value."""
    try:
        done = subprocess.run(
            [sys.executable, _cli(), "set", key, "--expires", expires, "--notes", notes],
            input=(value + "\n").encode("utf-8"), capture_output=True, timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as ex:
        raise VaultError(f"vault_unavailable:{key}:{type(ex).__name__}") from None
    if done.returncode != 0:
        raise VaultError(f"vault_write_failed:{key}")


def delete_secret(key: str) -> None:
    """Delete the entry ``key``. Raises VaultError naming the key."""
    try:
        done = subprocess.run([sys.executable, _cli(), "delete", key], capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as ex:
        raise VaultError(f"vault_unavailable:{key}:{type(ex).__name__}") from None
    if done.returncode != 0:
        raise VaultError(f"vault_delete_failed:{key}")
