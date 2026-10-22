import sys
from pathlib import Path

import pytest

CONSOLE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CONSOLE))          # the console modules are top-level (server, auth, mcp_client ...) as in its container
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(CONSOLE.parent))   # the repo root: amt_server, design/ scripts


@pytest.fixture()
def fake_amt():
    from console_fakes import FakeAmt
    fake = FakeAmt()
    yield fake
    fake.close()


@pytest.fixture()
def console(tmp_path, fake_amt):
    from console_fakes import Console
    c = Console(tmp_path, fake_amt)
    yield c
    c.close()


@pytest.fixture()
def authn(console):
    from console_fakes import Authenticator
    return Authenticator(console.app.cfg.rp_id, console.origin)


@pytest.fixture()
def signed_in(console, authn):
    from console_fakes import enroll_first_passkey
    enroll_first_passkey(console, authn)
    return console
