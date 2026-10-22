import pytest


@pytest.fixture(autouse=True)
def _hermetic_amt_state(tmp_path_factory, monkeypatch):
    """Tool-set server settings (the IDE-R image root) and screenshots never touch the real ~/.amt-mcp
    or shot directory."""
    monkeypatch.setenv("AMT_STATE_DIR", str(tmp_path_factory.mktemp("amt-state")))
    # Fake sessions write screenshots; keep them out of the real shot directory.
    monkeypatch.setenv("AMT_SHOT_DIR", str(tmp_path_factory.mktemp("amt-shots")))
    # A deployed container sets the public base URL; tests opt in to handoffs explicitly.
    monkeypatch.delenv("AMT_PUBLIC_BASE_URL", raising=False)
