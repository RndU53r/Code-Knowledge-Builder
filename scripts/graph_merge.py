#!/usr/bin/env python3
"""Verify and merge agent graph proposals (<out>/graph/proposals/*.jsonl) into the knowledge graph.

Proposal line format (one JSON object per line):
  {"op":"edge","src":ID,"kind":KIND,"dst":ID,"citation":"repo/path:L","quote":"exact text",
   "dst_citation":"repo/path:L"?, "confidence":"high|medium|low", "label":"observed|inferred|documented",
   "rationale":"..."}
  {"op":"node","kind":KIND,"repo":R,"path":P?,"qualname":Q,"name":N,"citation":"repo/path:L",
   "quote":"exact text", "confidence":..., "label":..., "summary":"..."?, "attrs":{...}?}
  {"op":"annotate","id":ID,"summary":"...","tags":[...],"layer":"..."}          (graph-curator)

Checks: JSON shape; kind allowed for extractor `llm`; citation resolves (E1-E4) and the quote matches
the cited lines; cross-repo edges need dst_citation; src/dst exist or are proposed in the same file;
strings redacted and capped; low confidence is forced to label `inferred`.

Usage:
  graph_merge.py --out OUT_DIR --check FILE.jsonl     # validate only (used by the PostToolUse hook)
graph_build.py calls merge_into() during a build.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import load_json, now_iso, repo_roots_for_output  # noqa: E402
from graph_common import (CONFIDENCE, EDGE_KINDS, LABELS, NODE_KINDS, atomic_write, graph_dir, make_edge,  # noqa: E402
                          make_node, safe_str)
from verify_citations import CITE, Verifier  # noqa: E402

# Node kinds an agent may add (structural code nodes come only from extractors).
LLM_NODE_KINDS = {"threat", "trust_boundary", "asset", "drift", "service", "external", "contract_op", "doc_section",
                  "queue", "topic", "table", "bucket", "cache", "endpoint", "consumer", "taint_source"}
assert LLM_NODE_KINDS <= NODE_KINDS


def cite_ok(v: Verifier, c, quote):
    if not isinstance(c, str):
        return "missing citation"
    m = CITE.search(f"`{c}`" + (f" «{quote}»" if quote else ""))
    if not m:
        return "bad citation format"
    r = v.check(m)
    return f"{r[0]}: {r[1]}" if r else None


def check_line(obj, v: Verifier, known: set, proposed: set):
    op = obj.get("op")
    if op == "annotate":
        if obj.get("id") not in known:
            return "annotate: unknown node id"
        return None
    if op == "tour":
        steps = obj.get("steps") or []
        if not obj.get("name") or not steps:
            return "tour needs name and steps"
        for i, st in enumerate(steps, 1):
            if st.get("node_id") not in known:
                return f"tour step {i}: unknown node {st.get('node_id')}"
            err = cite_ok(v, st.get("citation"), None)
            if err:
                return f"tour step {i}: {err}"
        return None
    if op not in ("edge", "node"):
        return "op must be edge, node, annotate or tour"
    if not obj.get("quote"):
        return "quote is required for agent proposals"
    err = cite_ok(v, obj.get("citation"), obj.get("quote"))
    if err:
        return err
    if obj.get("confidence", "medium") not in CONFIDENCE or obj.get("label", "inferred") not in LABELS:
        return "bad confidence/label"
    if op == "node":
        if obj.get("kind") not in LLM_NODE_KINDS:
            return f"agents may not propose node kind {obj.get('kind')}"
        if not obj.get("repo") or not obj.get("qualname"):
            return "node needs repo and qualname"
        return None
    k = obj.get("kind")
    ex = obj.get("_extractor", "llm")
    if k not in EDGE_KINDS or ex not in EDGE_KINDS[k]:
        return f"agents may not propose edge kind {k}"
    for end in ("src", "dst"):
        if obj.get(end) not in known and obj.get(end) not in proposed:
            return f"{end} {obj.get(end)} not in graph or proposed in this file"
    src_repo = str(obj.get("src", "")).split(":")[1:2]
    dst_repo = str(obj.get("dst", "")).split(":")[1:2]
    if src_repo and dst_repo and src_repo != dst_repo and "_system" not in (src_repo[0], dst_repo[0]):
        if not obj.get("dst_citation"):
            return "cross-repo edge needs dst_citation"
        err = cite_ok(v, obj["dst_citation"], None)
        if err:
            return "dst_citation " + err
    return None


def node_from(obj):
    ex = obj.get("_extractor", "llm")
    from graph_common import node_id
    path = obj.get("path") or ""
    n = make_node(obj["kind"], obj["repo"], path, obj["qualname"], obj.get("name") or obj["qualname"], 1, extractor=ex,
                  confidence=obj.get("confidence", "medium"), label=obj.get("label", "inferred"),
                  summary=obj.get("summary"), attrs={k: safe_str(v) if isinstance(v, str) else v for k, v in (obj.get("attrs") or {}).items()} or None)
    n["citation"] = obj["citation"]
    n["path"] = path
    m = re.search(r":(\d+)(?:-(\d+))?$", obj["citation"])
    if m:
        n["range"] = {"start": int(m.group(1)), "end": int(m.group(2) or m.group(1))}
    n["quote"] = safe_str(obj["quote"], 200)
    n["id"] = node_id(obj["kind"], obj["repo"], path, safe_str(obj["qualname"], 200))
    return n


def edge_from(obj):
    conf = obj.get("confidence", "medium")
    label = obj.get("label", "inferred")
    if conf == "low" and label == "observed":
        label = "inferred"
    return make_edge(obj["src"], obj["kind"], obj["dst"], obj["citation"], extractor=obj.get("_extractor", "llm"), confidence=conf, label=label,
                     quote=obj["quote"], dst_citation=obj.get("dst_citation"), rationale=obj.get("rationale"))


def process(out: Path, files, known: set, apply=None):
    v = Verifier(repo_roots_for_output(out))
    stats = {"accepted": 0, "rejected": 0, "annotations": 0}
    rejected = []
    for fp in files:
        lines = Path(fp).read_text(errors="replace").splitlines()
        objs = []
        for i, ln in enumerate(lines, 1):
            if not ln.strip():
                continue
            try:
                objs.append((i, json.loads(ln)))
            except ValueError:
                rejected.append({"file": Path(fp).name, "line": i, "reason": "invalid JSON"})
        # Deterministic generators (threat_seed, doc_claims) write seed-*.jsonl with extractor "rule"; everything else is "llm".
        for _, o in objs:
            o["_extractor"] = "rule" if (Path(fp).name.startswith("seed-") and o.get("extractor") == "rule") else "llm"
        proposed = set()
        for _, o in objs:
            if o.get("op") == "node" and o.get("kind") and o.get("repo") and o.get("qualname"):
                proposed.add(node_from({**o, "citation": o.get("citation", "x/y:1"), "quote": o.get("quote", "x")})["id"])
        for i, o in objs:
            err = check_line(o, v, known, proposed)
            if err:
                stats["rejected"] += 1
                rejected.append({"file": Path(fp).name, "line": i, "reason": err, "proposal": {k: safe_str(o.get(k), 120) for k in ("op", "kind", "src", "dst", "citation")}})
                continue
            if apply:
                apply(o)
            stats["annotations" if o["op"] in ("annotate", "tour") else "accepted"] += 1
    return stats, rejected


def merge_into(link, out: Path):
    pdir = graph_dir(out) / "proposals"
    files = sorted(pdir.glob("*.jsonl")) if pdir.is_dir() else []
    if not files:
        return {}
    ann_p = graph_dir(out) / "annotations.json"
    ann = load_json(ann_p, {"nodes": {}})
    tours = {}

    def apply(o):
        if o["op"] == "tour":
            tours[o["name"]] = {"name": safe_str(o["name"], 60), "title": safe_str(o.get("title") or o["name"], 120),
                                "audience": safe_str(o.get("audience", ""), 60),
                                "steps": [{"node_id": st["node_id"], "note": safe_str(st.get("note", ""), 500), "citation": st["citation"]}
                                          for st in o["steps"][:40]]}
            return
        if o["op"] == "node":
            n = node_from(o)
            link.add_node(n)
        elif o["op"] == "edge":
            link.add_edge(edge_from(o))
        else:
            n = link.nodes[o["id"]]
            prev = ann["nodes"].get(o["id"])
            new_summary = safe_str(o.get("summary", ""), 600)
            # Re-applying an unchanged annotation must not hide that the code changed since it was written.
            stale = bool(prev and prev.get("summary") == new_summary and prev.get("sig_hash") and prev.get("sig_hash") != n.get("sig_hash"))
            entry = ann["nodes"].setdefault(o["id"], {"repo": n.get("repo"), "path": n.get("path"), "name": n["name"], "kind": n["kind"]})
            for k in ("summary", "layer"):
                if o.get(k):
                    entry[k] = n[k] = safe_str(o[k], 600)
            if o.get("source") and o.get("summary"):
                entry["summary_source"] = n["summary_source"] = safe_str(o["source"], 30)
            if o.get("tags") and entry.get("tags"):
                o["tags"] = list(dict.fromkeys(list(entry["tags"]) + list(o["tags"])))
            if o.get("tags"):
                entry["tags"] = n["tags"] = [safe_str(t, 40) for t in o["tags"][:12]]
            if not stale:
                entry["sig_hash"] = n.get("sig_hash")
            n["summary_status"] = "OUTDATED" if stale else "fresh"
    # nodes first so edges can reference proposed nodes from any file
    known = set(link.nodes)
    stats, rejected = process(out, files, known, apply)
    atomic_write(ann_p, json.dumps(ann, indent=1))
    if tours:
        atomic_write(graph_dir(out) / "tours.json", json.dumps({"tours": list(tours.values())}, indent=1))
    rej_p = graph_dir(out) / "rejected.jsonl"
    atomic_write(rej_p, "".join(json.dumps({**r, "at": now_iso()}) + "\n" for r in rejected))
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--check", required=True)
    a = ap.parse_args()
    out = Path(a.out).resolve()
    gj = graph_dir(out) / "graph.json"
    known = {n["id"] for n in json.loads(gj.read_text())["nodes"]} if gj.is_file() else set()
    stats, rejected = process(out, [a.check], known)
    print(json.dumps({"stats": stats, "rejected": rejected[:50]}, indent=2))
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
