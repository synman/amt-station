"""The console's container and compose service: it ships every module it imports, and it can reach nothing of amt-mcp's."""
import ast
import re
from pathlib import Path

CONSOLE = Path(__file__).resolve().parent.parent
REPO = CONSOLE.parent
COMPOSE = (REPO / "deploy" / "compose.yaml").read_text()
SERVICE = COMPOSE[COMPOSE.index("\n  amt-console:"):]
MCP_SERVICE = COMPOSE[COMPOSE.index("\n  amt-mcp:"):COMPOSE.index("\n  amt-console:")]


def local_modules():
    return {p.stem for p in CONSOLE.glob("*.py") if p.stem != "make_theme"}   # make_theme is a developer tool


def test_the_dockerfile_copies_every_module_the_server_imports():
    copied = set(re.findall(r"console/(\w+)\.py", " ".join(re.findall(r"^COPY (.*) \./$", (CONSOLE / "Dockerfile").read_text(), re.M))))
    assert copied == local_modules(), "a console module is missing from (or extra in) the image"
    needed = set()
    for name in local_modules():
        for node in ast.walk(ast.parse((CONSOLE / f"{name}.py").read_text())):
            if isinstance(node, ast.Import):
                needed |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                needed.add(node.module.split(".")[0])
    assert (needed & local_modules()) <= copied
    text = (CONSOLE / "Dockerfile").read_text()
    assert "COPY console/pages ./pages" in text and "COPY console/static ./static" in text and "requirements.txt" in text


def test_the_console_runs_on_the_standard_library_and_the_pinned_requirement():
    third_party = set()
    for name in local_modules():
        for node in ast.walk(ast.parse((CONSOLE / f"{name}.py").read_text())):
            if isinstance(node, ast.Import):
                third_party |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                third_party.add(node.module.split(".")[0])
    import sys
    outside = {m for m in third_party - local_modules() if m not in sys.stdlib_module_names}
    assert outside == {"cryptography"}
    assert re.search(r"^cryptography==\d+\.\d+\.\d+$", (CONSOLE / "requirements.txt").read_text(), re.M)


def test_the_console_service_has_its_own_state_and_none_of_amt_mcps():
    mounts = re.findall(r"^\s+- (\./[^\s]+)$", SERVICE.split("    volumes:")[1].split("    ports:")[0], re.M)
    assert mounts == ["./console-data:/console-data", "./console-vault:/vault:ro", "./node-vault-mcp:/opt/node-vault-mcp/services:ro"]
    for forbidden in ("./data", "./iso", "./config", "./vault:", "amt-mcp.env", "env_file", "MCP_ADMIN_TOKEN", "MCP_CONSOLE_TOKEN", "AMT_SECRETS_CLI",
                      "AMT_DEVICES_FILE", "AMT_IMAGE_ROOT", "amt-mcp.vault"):
        assert forbidden not in SERVICE, forbidden
    assert 'user: "${DEPLOY_UID:?set in site.vars}:${DEPLOY_GID:?set in site.vars}"' in SERVICE         # the uid that owns console-data and the enroll.json delivered over ssh
    assert '- "127.0.0.1:8767:8767"' in SERVICE and "AMT_CONSOLE_DATA: /console-data" in SERVICE
    assert "AMT_CONSOLE_SECRETS_CLI: /opt/node-vault-mcp/services/secrets.py" in SERVICE
    assert "AMT_CONSOLE_MCP_URL: ${AMT_PUBLIC_BASE_URL:?set in site.vars}/mcp" in SERVICE
    assert "network_mode: bridge" in SERVICE        # the default bridge is inside the proxy's LAN-only allow rule; a compose network is not


def test_the_amt_mcp_service_is_untouched_by_adding_the_console():
    for line in ('container_name: amt-mcp', 'AMT_ALLOWED_HOSTS: ${AMT_ALLOWED_HOSTS:?set in site.vars}',
                 'AMT_PUBLIC_BASE_URL: ${AMT_PUBLIC_BASE_URL:?set in site.vars}',
                 '- ./vault:/vault ', '- "127.0.0.1:8765:8765"', '- "127.0.0.1:8766:8766"', 'env_file: ./amt-mcp.env',
                 'AMT_CONSOLE_ORIGIN: ${AMT_CONSOLE_ORIGIN:?set in site.vars}'):
        assert line in MCP_SERVICE, line


def test_every_site_value_comes_from_site_vars_and_the_example_names_each_one():
    """The compose file names no host, origin or uid of its own: each is a required site.vars value, and
    deploy/site.vars.example sets every one it uses."""
    compose = (REPO / "deploy" / "compose.yaml").read_text()
    used = set(re.findall(r"\$\{([A-Z_]+):\?set in site\.vars\}", compose))
    assert used == {"DEPLOY_UID", "DEPLOY_GID", "AMT_ALLOWED_HOSTS", "AMT_PUBLIC_BASE_URL", "AMT_VIEWER_PUBLIC_BASE_URL",
                    "AMT_CONSOLE_ORIGIN", "AMT_CONSOLE_RP_ID", "AMT_DEFAULT_DEVICE"}
    example = (REPO / "deploy" / "site.vars.example").read_text()
    assert used == set(re.findall(r"^([A-Z_]+)=", example, re.M))
    for line in compose.splitlines():
        if not line.lstrip().startswith("#"):
            assert "https://" not in line and not re.search(r'user: "\d', line), line


def test_no_page_script_or_mockup_of_the_console_names_meshcommander():
    """The console is its own product (operator, 2026-10-21: "there should be no reference to meshcommander"): nothing the browser is
    served, and no mockup it is built from, mentions it."""
    files = [*sorted((CONSOLE / "pages").glob("*.html")), *sorted((CONSOLE / "static").glob("*.*")), *sorted((REPO / "design").glob("*.html"))]
    assert len(files) > 40, "the scan found too few files to mean anything"
    hits = [f.relative_to(REPO).as_posix() for f in files if f.suffix != ".svg" and re.search(r"mesh\s*commander", f.read_text(errors="replace"), re.I)]
    assert hits == []
