#!/usr/bin/env python3
"""Export the ckb knowledge graph to other formats.

Usage:
  graph_export.py --out OUT_DIR ua        # graph/ua-knowledge-graph.json (Understand-Anything-style layout)
  graph_export.py --out OUT_DIR cypher    # graph/neo4j/load.cypher (parameterized UNWIND batches) + params JSON
  graph_export.py --out OUT_DIR csv       # graph/neo4j/nodes.csv, edges.csv (neo4j-admin import headers)
  graph_export.py --out OUT_DIR graphml   # graph/graph.graphml

Every exported node/edge keeps its ckb citation, extractor, confidence and label so evidence survives export.
The UA export follows Understand-Anything's published concepts (typed nodes with filePath/lineRange,
typed weighted edges, layers, tour); it is a compatibility format, not a copy of their code.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parent))
from graph_common import atomic_write, graph_dir  # noqa: E402

UA_NODE = {"function": "function", "method": "function", "class": "class", "interface": "class", "file": "file", "module": "module",
           "endpoint": "endpoint", "table": "table", "topic": "pipeline", "queue": "pipeline", "cloud_resource": "resource",
           "service": "service", "external": "service", "env_var": "config", "config_flag": "config", "package": "module",
           "doc_section": "document", "contract_op": "schema"}
WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}


def ua(g):
    nodes = []
    for n in g["nodes"]:
        r = n.get("range") or {}
        nodes.append({"id": n["id"], "type": UA_NODE.get(n["kind"], "concept"), "name": n["name"], "filePath": n.get("path") or None,
                      "lineRange": [r.get("start"), r.get("end")] if n.get("path") else None, "summary": n.get("summary", ""),
                      "tags": n.get("tags", []) + [f"ckb:{n['kind']}"], "complexity": None,
                      "ckb": {"citation": n.get("citation"), "extractor": n["provenance"]["extractor"], "confidence": n["confidence"],
                              "label": n["label"], "attrs": n.get("attrs", {})}})
    edges = [{"source": e["src"], "target": e["dst"], "type": e["kind"], "direction": "forward", "weight": WEIGHT[e["confidence"]],
              "description": e.get("rationale", ""), "ckb": {"citation": e["citation"], "extractor": e["provenance"]["extractor"],
                                                             "label": e["label"], "verified": e["verified"]["status"]}} for e in g["edges"]]
    tour = [{"order": i + 1, "nodeId": st["node_id"], "note": st.get("note", ""), "citation": st.get("citation")}
            for t in g.get("tours", [])[:1] for i, st in enumerate(t.get("steps", []))]
    return {"version": "ckb-export-1", "project": {"name": ", ".join(g["repos"]), "analyzedAt": g["generated"]},
            "nodes": nodes, "edges": edges, "layers": g.get("layers", []), "tour": tour}


def label_of(kind):
    return "".join(p.capitalize() for p in kind.split("_"))


def cypher(g, outdir: Path):
    by_kind = {}
    for n in g["nodes"]:
        by_kind.setdefault(n["kind"], []).append({"id": n["id"], "name": n["name"], "repo": n.get("repo"), "path": n.get("path"),
                                                   "start": (n.get("range") or {}).get("start"), "end": (n.get("range") or {}).get("end"),
                                                   "citation": n.get("citation"), "extractor": n["provenance"]["extractor"],
                                                   "confidence": n["confidence"], "label": n["label"], "summary": n.get("summary"),
                                                   "attrs": json.dumps(n.get("attrs", {}))})
    rels = {}
    for e in g["edges"]:
        rels.setdefault(e["kind"], []).append({"id": e["id"], "src": e["src"], "dst": e["dst"], "citation": e["citation"],
                                               "extractor": e["provenance"]["extractor"], "confidence": e["confidence"],
                                               "label": e["label"], "dst_citation": e.get("dst_citation")})
    lines = ["// ckb knowledge graph -> Neo4j. Run with: cypher-shell -f load.cypher (params are inlined per batch).",
             "CREATE CONSTRAINT ckb_id IF NOT EXISTS FOR (n:CkbNode) REQUIRE n.id IS UNIQUE;"]
    for kind, rows in sorted(by_kind.items()):
        for i in range(0, len(rows), 500):
            lines.append(f":param rows => {json.dumps(rows[i:i + 500])};")
            lines.append(f"UNWIND $rows AS r MERGE (n:CkbNode {{id: r.id}}) SET n += r, n:{label_of(kind)};")
    for kind, rows in sorted(rels.items()):
        for i in range(0, len(rows), 500):
            lines.append(f":param rows => {json.dumps(rows[i:i + 500])};")
            lines.append(f"UNWIND $rows AS r MATCH (a:CkbNode {{id: r.src}}), (b:CkbNode {{id: r.dst}}) "
                         f"MERGE (a)-[x:{kind.upper()} {{id: r.id}}]->(b) SET x += r;")
    outdir.mkdir(parents=True, exist_ok=True)
    atomic_write(outdir / "load.cypher", "\n".join(lines) + "\n")
    atomic_write(outdir / "batches.json", json.dumps({"nodes": by_kind, "edges": rels}))
    return outdir / "load.cypher"


def csv_export(g, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    with open(outdir / "nodes.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id:ID", ":LABEL", "name", "repo", "path", "start:int", "end:int", "citation", "extractor", "confidence", "label", "summary"])
        for n in g["nodes"]:
            r = n.get("range") or {}
            w.writerow([n["id"], f"CkbNode;{label_of(n['kind'])}", n["name"], n.get("repo"), n.get("path"), r.get("start"), r.get("end"),
                        n.get("citation"), n["provenance"]["extractor"], n["confidence"], n["label"], n.get("summary", "")])
    with open(outdir / "edges.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([":START_ID", ":END_ID", ":TYPE", "id", "citation", "extractor", "confidence", "label", "dst_citation"])
        for e in g["edges"]:
            w.writerow([e["src"], e["dst"], e["kind"].upper(), e["id"], e["citation"], e["provenance"]["extractor"], e["confidence"],
                        e["label"], e.get("dst_citation", "")])
    return outdir


def graphml(g):
    out = ['<?xml version="1.0" encoding="UTF-8"?>', '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">']
    for k in ("kind", "name", "citation", "confidence", "label", "extractor"):
        out.append(f'<key id="{k}" for="all" attr.name="{k}" attr.type="string"/>')
    out.append('<graph edgedefault="directed">')
    for n in g["nodes"]:
        out.append(f"<node id={quoteattr(n['id'])}>" + "".join(
            f'<data key="{k}">{escape(str(v or ""))}</data>' for k, v in (("kind", n["kind"]), ("name", n["name"]), ("citation", n.get("citation")),
                                                                            ("confidence", n["confidence"]), ("label", n["label"]),
                                                                            ("extractor", n["provenance"]["extractor"]))) + "</node>")
    for e in g["edges"]:
        out.append(f"<edge id={quoteattr(e['id'])} source={quoteattr(e['src'])} target={quoteattr(e['dst'])}>" + "".join(
            f'<data key="{k}">{escape(str(v or ""))}</data>' for k, v in (("kind", e["kind"]), ("citation", e["citation"]),
                                                                            ("confidence", e["confidence"]), ("label", e["label"]),
                                                                            ("extractor", e["provenance"]["extractor"]))) + "</edge>")
    out += ["</graph>", "</graphml>"]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("format", choices=["ua", "cypher", "csv", "graphml"])
    a = ap.parse_args()
    gd = graph_dir(Path(a.out).resolve())
    g = json.loads((gd / "graph.json").read_text())
    if a.format == "ua":
        p = gd / "ua-knowledge-graph.json"
        atomic_write(p, json.dumps(ua(g), indent=1))
    elif a.format == "cypher":
        p = cypher(g, gd / "neo4j")
    elif a.format == "csv":
        p = csv_export(g, gd / "neo4j")
    else:
        p = gd / "graph.graphml"
        atomic_write(p, graphml(g))
    print(json.dumps({"format": a.format, "path": str(p)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
