"""Conformity: read the tool list a client actually receives, not the decorators.

The checks live in ``problems()`` so the tests can also feed it deliberately broken tools: a
checker that never fails on a missing field would pass every real run and prove nothing.
"""
import asyncio
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import amt_parity  # noqa: E402
from amt_server import mcp  # noqa: E402

# Nine read tools (amt_devices the seventh, amt_identities the eighth, amt_captures the ninth), the eight write tools,
# the two composite write tools, the mirror and the serial terminal, amt_device_manage and amt_identity_manage; each
# later packet raises this.
EXPECTED_TOOLS = 23
# Independent of the manifest: a tool mislabeled there must still fail here.
READ_TOOLS = frozenset({"amt_status", "amt_screenshot", "amt_inventory", "amt_logs", "amt_settings",
                        "amt_wsman_get", "amt_devices", "amt_identities", "amt_captures"})
WRITE_TOOLS = frozenset({"amt_power", "amt_set_next_boot", "amt_console_input", "amt_sol", "amt_ider",
                         "amt_images", "amt_configure", "amt_wsman_invoke", "amt_remote_logon", "amt_remote_logoff",
                         "amt_mirror_link", "amt_serial_link", "amt_device_manage", "amt_identity_manage"})
MAX_DESCRIPTION = 2048
MAX_INSTRUCTIONS = 2048
PROPERTY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _tools():
    return asyncio.run(mcp.list_tools())


def problems(t, is_read: bool) -> list[str]:
    """Every conformity violation of one tool as ``name: reason`` strings (empty = conformant)."""
    out: list[str] = []
    name = getattr(t, "name", None) or "<unnamed>"
    ann = getattr(t, "annotations", None)
    desc = getattr(t, "description", None) or ""
    if not desc.strip():
        out.append(f"{name}: no description")
    if len(desc) > MAX_DESCRIPTION:
        out.append(f"{name}: description {len(desc)} chars > {MAX_DESCRIPTION}")
    if ann is None or not getattr(ann, "title", None):
        out.append(f"{name}: no title")
    hint = getattr(ann, "readOnlyHint", None)
    if hint is None:
        out.append(f"{name}: no readOnlyHint")
    props = (getattr(t, "inputSchema", None) or {}).get("properties", {})
    for pname, prop in props.items():
        if not prop.get("description"):
            out.append(f"{name}.{pname}: parameter has no schema description")
        if not PROPERTY_NAME.fullmatch(pname):
            out.append(f"{name}.{pname}: property name outside [A-Za-z0-9_.-]{{1,64}}")
    if is_read:
        if hint is not True:
            out.append(f"{name}: read tool must be readOnlyHint=True")
        if "confirmed" in props:
            out.append(f"{name}: read tool must not take a confirmed parameter")
    else:
        if hint is not False:
            out.append(f"{name}: write tool must be readOnlyHint=False")
        guard = props.get("confirmed")
        if guard is None:
            out.append(f"{name}: write tool has no confirmed parameter")
        elif guard.get("type") != "boolean" or guard.get("default") is not False:
            out.append(f"{name}: confirmed must be a boolean defaulting to false")
    return out


def test_tool_surface_is_exactly_the_23_classified_tools():
    tools = _tools()
    names = {t.name for t in tools}
    assert len(tools) == EXPECTED_TOOLS == len(names), f"{len(tools)} tools, expected {EXPECTED_TOOLS}"
    assert names == READ_TOOLS | WRITE_TOOLS and not READ_TOOLS & WRITE_TOOLS
    assert (len(READ_TOOLS), len(WRITE_TOOLS)) == (9, 14)


def test_every_tool_conforms():
    found = []
    seen_props = 0
    for t in _tools():
        found += problems(t, t.name in READ_TOOLS)
        seen_props += len(t.inputSchema.get("properties", {}))
    assert not found, "\n".join(found)
    assert seen_props > 0, "no parameter was examined: the schema walk is vacuous"


def test_console_input_expect_parameter_is_conformant_optional_and_adds_no_tool():
    """The screen guard is a PARAMETER of amt_console_input, not a new tool: the surface stays at EXPECTED_TOOLS,
    the parameter carries a schema description (``problems`` checks every property), is optional and
    lists exactly the classifier labels a caller can name (``unknown`` asserts nothing)."""
    import amt_tools
    tools = {t.name: t for t in _tools()}
    assert len(tools) == EXPECTED_TOOLS
    t = tools["amt_console_input"]
    assert problems(t, is_read=False) == []
    prop = t.inputSchema["properties"]["expect"]
    assert prop["description"].strip() and "expect" not in t.inputSchema.get("required", [])
    labels = set(prop["anyOf"][0]["items"]["enum"])
    assert labels == set(amt_tools.SCREEN_LABELS) - {"unknown"}
    assert len(t.description) <= MAX_DESCRIPTION


def test_tool_titles_are_unique():
    titles = [t.annotations.title for t in _tools()]
    assert len(set(titles)) == len(titles)


def test_manifest_kinds_agree_with_the_literal_sets():
    kinds = {r["name"]: r["kind"] for r in amt_parity.TOOLS}
    assert {n for n, k in kinds.items() if k == "read"} == READ_TOOLS
    assert {n for n, k in kinds.items() if k in ("write", "composite", "mirror")} == WRITE_TOOLS


def test_tool_names_are_exactly_the_implemented_parity_rows():
    names = {t.name for t in _tools()}
    assert names == {r["name"] for r in amt_parity.TOOLS if r["status"] == amt_parity.IMPLEMENTED}


def test_tool_descriptions_lead_with_the_key_fact():
    for t in _tools():
        assert len((t.description or "").split(".")[0]) <= 400, t.name


def test_instructions_fit():
    assert (mcp.instructions or "").strip(), "server instructions are empty"
    assert len(mcp.instructions) <= MAX_INSTRUCTIONS


# --- mcp-builder Phase 4: the evaluation file ------------------------------------------------

def evaluation_problems(path: Path) -> list[str]:
    """Shape defects of an evaluation file: 10 pairs, each a non-empty question and answer."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as ex:
        return [f"evaluation file unreadable: {ex}"]
    pairs = root.findall("qa_pair")
    out = [] if root.tag == "evaluation" and len(pairs) == 10 else [f"expected 10 qa_pair under <evaluation>, got {len(pairs)}"]
    for i, qa in enumerate(pairs, 1):
        for tag in ("question", "answer"):
            if not (qa.findtext(tag) or "").strip():
                out.append(f"qa_pair {i}: empty or missing <{tag}>")
    if len({(qa.findtext("question") or "").strip() for qa in pairs}) != len(pairs):
        out.append("duplicate question")
    return out


def test_evaluation_has_ten_well_formed_pairs():
    assert evaluation_problems(Path(__file__).resolve().parent.parent / "evaluation.xml") == []


def test_evaluation_checker_can_fail(tmp_path):
    assert evaluation_problems(tmp_path / "absent.xml")
    (tmp_path / "bad.xml").write_text("<evaluation><qa_pair><question>q</question></qa_pair></evaluation>")
    assert len(evaluation_problems(tmp_path / "bad.xml")) >= 2


# --- the checker itself must be able to fail ---------------------------------------------------

def _fake(name="amt_x", title="X", hint=False, description="Does x.", props=None):
    ann = SimpleNamespace(title=title, readOnlyHint=hint)
    guard = {"confirmed": {"type": "boolean", "default": False, "description": "g"}}
    return SimpleNamespace(name=name, annotations=ann, description=description,
                           inputSchema={"properties": guard if props is None else props})


def test_checker_accepts_a_conformant_write_tool():
    assert problems(_fake(), is_read=False) == []


def test_checker_flags_each_missing_field():
    assert any("no title" in p for p in problems(_fake(title=None), False))
    assert any("no title" in p for p in problems(_fake(title=""), False))
    assert any("no readOnlyHint" in p for p in problems(_fake(hint=None), False))
    assert any("no description" in p for p in problems(_fake(description=""), False))
    assert any("chars >" in p for p in problems(_fake(description="x" * (MAX_DESCRIPTION + 1)), False))
    no_ann = _fake()
    no_ann.annotations = None
    assert any("no title" in p for p in problems(no_ann, False))
    assert any("no readOnlyHint" in p for p in problems(no_ann, False))


def test_checker_flags_parameter_and_name_defects():
    bare = {"confirmed": {"type": "boolean", "default": False, "description": "g"}, "p": {"type": "string"}}
    assert any("p: parameter has no schema description" in x for x in problems(_fake(props=bare), False))
    bad = {"confirmed": {"type": "boolean", "default": False, "description": "g"},
           "bad name": {"description": "d"}, "n" * 65: {"description": "d"}}
    assert sum("property name outside" in x for x in problems(_fake(props=bad), False)) == 2


def test_checker_enforces_read_and_write_contracts():
    guard = {"confirmed": {"type": "boolean", "default": False, "description": "g"}}
    assert any("must be readOnlyHint=True" in p for p in problems(_fake(hint=False, props={}), True))
    assert any("must not take a confirmed" in p for p in problems(_fake(hint=True, props=guard), True))
    assert problems(_fake(hint=True, props={}), True) == []
    assert any("must be readOnlyHint=False" in p for p in problems(_fake(hint=True), False))
    assert any("no confirmed parameter" in p for p in problems(_fake(props={}), False))
    loose = {"confirmed": {"type": "boolean", "default": True, "description": "g"}}
    assert any("defaulting to false" in p for p in problems(_fake(props=loose), False))
    stringy = {"confirmed": {"type": "string", "default": False, "description": "g"}}
    assert any("defaulting to false" in p for p in problems(_fake(props=stringy), False))


if __name__ == "__main__":
    test_tool_surface_is_exactly_the_23_classified_tools()
    test_every_tool_conforms()
    test_instructions_fit()
    print("CONFORMITY OK")
