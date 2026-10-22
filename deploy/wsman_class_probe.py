"""Read-only: for each AMT/CIM/IPS class named in amt-mcp's code, enumerate on my-server-1, derive a get selector from each
instance's key-shaped fields, and check that a get with it round-trips. Prints class names, counts, selector NAMES and
identifier values only (InstanceID/Name/DeviceID-style keys), never other field values."""
import json, re, sys
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import amt_wsman as W
names = sorted(set(re.findall(r"\b(?:AMT|CIM|IPS)_[A-Z][A-Za-z0-9]+[a-z][A-Za-z0-9]*\b",
    " ".join(p.read_text() for p in list(REPO.glob("*.py")) + list((REPO / "console/static").glob("*.js"))))))
KEYS = ["InstanceID", "CreationClassName", "Name", "SystemCreationClassName", "SystemName", "DeviceID", "Tag", "ElementName"]
out = {}
for cls in names:
    r = {"enumerate": None, "count": None, "get_bare": None, "keys": [], "get_with": []}
    try:
        items, trunc = W.enumerate_(cls, max_items=50)
        r["enumerate"], r["count"] = "ok", len(items)
    except Exception as e:
        r["enumerate"] = type(e).__name__ + ":" + str(e)[:90]; items = []
    try:
        W.get(cls); r["get_bare"] = "ok"
    except Exception as e:
        r["get_bare"] = type(e).__name__ + ":" + str(e)[:60]
    for it in items[:6]:
        sel = {k: str(it[k]) for k in KEYS[:-1] if isinstance(it.get(k), (str, int)) and it.get(k) != ""}
        # try the narrowest first: InstanceID alone, then all key-shaped fields
        tried = []
        for cand in ([{"InstanceID": sel["InstanceID"]}] if "InstanceID" in sel else []) + [sel]:
            try:
                W.get(cls, selectors=cand); tried = ("ok", sorted(cand)); break
            except Exception as e:
                tried = ("fail:" + str(e)[:50], sorted(cand))
        r["get_with"].append(tried)
        r["keys"].append({k: sel[k] for k in ("InstanceID", "Name", "DeviceID") if k in sel})
    out[cls] = r
    print(cls, r["enumerate"], r["count"], "bare:", r["get_bare"], "sel:", [t for t in r["get_with"]][:2], flush=True)
Path(sys.argv[1] if len(sys.argv) > 1 else "wsman_class_probe.json").write_text(json.dumps(out, indent=1))
