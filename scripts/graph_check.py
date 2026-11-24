#!/usr/bin/env python3
"""Validate the ckb knowledge graph: schema, IDs, dangling edges, provenance, citations, secrets.

Usage:
  graph_check.py --out OUT_DIR [--report] [--json]

Every node/edge citation (and dst_citation) is resolved with verify_citations.Verifier against the
registered repos; quotes on LLM edges are checked too. Writes <out>/evidence/graph-verification.md
with --report. Exit 1 on errors.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import find_secret_values, now_iso, repo_roots_for_output  # noqa: E402
from graph_common import graph_dir, validate  # noqa: E402
from verify_citations import CITE, Verifier  # noqa: E402


def check_citation(v: Verifier, c: str, quote: str | None = None):
    text = f"`{c}`" + (f" «{quote}»" if quote else "")
    m = CITE.search(text)
    if not m:
        return "bad citation format"
    res = v.check(m)
    return f"{res[0]} {res[1]}" if res else None


def run(out: Path) -> dict:
    g = json.loads((graph_dir(out) / "graph.json").read_text())
    errors, warnings = [], []
    errors += [f"schema: {p}" for p in validate(g)]
    v = Verifier(repo_roots_for_output(out))
    checked = 0
    for n in g["nodes"]:
        if n.get("citation"):
            checked += 1
            r = check_citation(v, n["citation"])
            if r:
                errors.append(f"node {n['id']}: {r}")
    for e in g["edges"]:
        checked += 1
        r = check_citation(v, e["citation"], e.get("quote") if e["provenance"]["extractor"] == "llm" else None)
        if r:
            errors.append(f"edge {e['kind']} {e['src']} -> {e['dst']}: {r}")
        if e.get("dst_citation"):
            checked += 1
            r = check_citation(v, e["dst_citation"])
            if r:
                errors.append(f"edge {e['kind']} dst_citation: {r}")
        if e["confidence"] == "low" and e["label"] == "observed":
            warnings.append(f"edge {e['kind']} {e['src']} -> {e['dst']}: low confidence labelled observed")
    blob = json.dumps(g)
    for name, a, _ in find_secret_values(blob):
        if "REDACTED" not in blob[a:a + 60]:
            errors.append(f"possible unredacted {name} in graph.json")
    return {"checked_citations": checked, "errors": errors, "warnings": warnings,
            "nodes": len(g["nodes"]), "edges": len(g["edges"])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    if not (graph_dir(out) / "graph.json").is_file():
        print("no graph.json; run graph_build.py first", file=sys.stderr)
        return 2
    r = run(out)
    if a.report:
        lines = ["# Graph verification", "", f"- Run: {now_iso()}", f"- Nodes: {r['nodes']}", f"- Edges: {r['edges']}",
                 f"- Citations checked: {r['checked_citations']}", f"- Errors: {len(r['errors'])}", f"- Warnings: {len(r['warnings'])}", ""]
        lines += [f"- **error** {x}" for x in r["errors"][:300]] + [f"- warning {x}" for x in r["warnings"][:300]]
        rej = graph_dir(out) / "rejected.jsonl"
        if rej.is_file():
            lines += ["", "## Rejected agent proposals", ""] + [f"- {re.sub(r'[`|]', '', ln)[:300]}" for ln in rej.read_text().splitlines()[:200]]
        p = out / "evidence" / "graph-verification.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(lines) + "\n")
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"graph check: {r['checked_citations']} citations, {len(r['errors'])} errors, {len(r['warnings'])} warnings")
        for x in r["errors"][:20]:
            print("  ", x)
    return 1 if r["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
