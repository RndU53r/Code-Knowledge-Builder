#!/usr/bin/env python3
"""Optional Neo4j support for teams that already run Neo4j (HTTP transactional Cypher API, stdlib urllib).

Usage:
  graph_neo4j.py --out OUT_DIR check                 # connectivity + server version (read-only)
  graph_neo4j.py --out OUT_DIR push --yes            # load graph (MERGE nodes/edges). Only after the user confirms.
  graph_neo4j.py --out OUT_DIR query "<MATCH ...>"   # read-only Cypher; write clauses are refused

Connection from env vars whose NAMES come from settings (neo4j_uri_env / neo4j_user_env /
neo4j_password_env; defaults NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD; optional NEO4J_DATABASE). Values
are never printed. Use a read-only Neo4j user for querying. Plain http:// to a non-localhost host is
refused unless --allow-insecure. Neo4j results are navigation aids; cite graph.json/source lines, not Neo4j.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from graph_common import graph_dir, resolve_out  # noqa: E402

WRITE = re.compile(r"(?i)\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|LOAD\s+CSV|FOREACH)\b|\bCALL\s+(dbms|apoc|db\.(create|drop|index|constraint))", re.I)


def settings_names():
    names = {"uri": "NEO4J_URI", "user": "NEO4J_USER", "password": "NEO4J_PASSWORD"}
    p = Path(".claude/code-knowledge-builder.local.md")
    if p.is_file():
        for k in names:
            m = re.search(rf"(?m)^neo4j_{k if k != 'password' else 'password'}_env:\s*(\S+)", p.read_text())
            if m:
                names[k] = m.group(1)
    return names


def conn(allow_insecure=False):
    n = settings_names()
    uri, user, pw = os.environ.get(n["uri"]), os.environ.get(n["user"]), os.environ.get(n["password"])
    if not uri or not user or pw is None:
        raise SystemExit(f"Neo4j not configured: set {n['uri']}, {n['user']} and {n['password']}")
    u = urlparse(uri)
    if u.scheme in ("bolt", "neo4j", "bolt+s", "neo4j+s"):
        scheme = "https" if u.scheme.endswith("+s") else "http"
        host = u.hostname
        port = 7473 if scheme == "https" else 7474
        base = f"{scheme}://{host}:{port}"
    else:
        base = f"{u.scheme}://{u.netloc}"
        host = u.hostname
    if base.startswith("http://") and host not in ("localhost", "127.0.0.1", "::1") and not allow_insecure:
        raise SystemExit("refusing plain-HTTP Neo4j on a non-local host (credentials would travel unencrypted); use https or --allow-insecure")
    db = os.environ.get("NEO4J_DATABASE", "neo4j")
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return base, db, auth


def tx(statements, allow_insecure=False):
    base, db, auth = conn(allow_insecure)
    body = json.dumps({"statements": statements}).encode()
    req = urllib.request.Request(f"{base}/db/{db}/tx/commit", data=body, method="POST",
                                 headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        return {"error": f"Neo4j request failed: {type(e).__name__}: {msg.replace(auth, '[REDACTED]')[:300]}"}
    if res.get("errors"):
        return {"error": res["errors"][0].get("message", "Neo4j error")[:500]}
    return res


def query(out: Path, q: str, allow_insecure=False):
    if WRITE.search(q):
        return {"error": "write clauses are not allowed in queries (read-only)"}
    res = tx([{"statement": q, "resultDataContents": ["row"]}], allow_insecure)
    if "error" in res:
        return res
    r = res["results"][0] if res.get("results") else {"columns": [], "data": []}
    return {"columns": r.get("columns", []), "rows": [d.get("row") for d in r.get("data", [])][:500],
            "note": "navigation aid: confirm facts with graph.json citations / source lines"}


def push(out: Path, allow_insecure=False):
    import graph_export
    g = json.loads((graph_dir(out) / "graph.json").read_text())
    stmts = [{"statement": "CREATE CONSTRAINT ckb_id IF NOT EXISTS FOR (n:CkbNode) REQUIRE n.id IS UNIQUE"}]
    by_kind, rels = {}, {}
    for n in g["nodes"]:
        by_kind.setdefault(n["kind"], []).append({"id": n["id"], "name": n["name"], "repo": n.get("repo"), "path": n.get("path"),
                                                   "citation": n.get("citation"), "extractor": n["provenance"]["extractor"],
                                                   "confidence": n["confidence"], "label": n["label"], "summary": n.get("summary")})
    for e in g["edges"]:
        rels.setdefault(e["kind"], []).append({"id": e["id"], "src": e["src"], "dst": e["dst"], "citation": e["citation"],
                                               "confidence": e["confidence"], "label": e["label"], "extractor": e["provenance"]["extractor"]})
    for kind, rows in by_kind.items():
        for i in range(0, len(rows), 500):
            stmts.append({"statement": f"UNWIND $rows AS r MERGE (n:CkbNode {{id: r.id}}) SET n += r, n:{graph_export.label_of(kind)}",
                          "parameters": {"rows": rows[i:i + 500]}})
    for kind, rows in rels.items():
        for i in range(0, len(rows), 500):
            stmts.append({"statement": f"UNWIND $rows AS r MATCH (a:CkbNode {{id: r.src}}), (b:CkbNode {{id: r.dst}}) "
                                       f"MERGE (a)-[x:{kind.upper()} {{id: r.id}}]->(b) SET x += r", "parameters": {"rows": rows[i:i + 500]}})
    res = tx(stmts, allow_insecure)
    return res if "error" in res else {"pushed_nodes": len(g["nodes"]), "pushed_edges": len(g["edges"])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out")
    ap.add_argument("cmd", choices=["check", "push", "query"])
    ap.add_argument("q", nargs="?")
    ap.add_argument("--yes", action="store_true", help="required for push (the user confirmed in chat)")
    ap.add_argument("--allow-insecure", action="store_true")
    a = ap.parse_args()
    out = resolve_out(a.out)
    if a.cmd == "check":
        r = tx([{"statement": "RETURN 1 AS ok"}], a.allow_insecure)
        print(json.dumps({"ok": "error" not in r, **({"error": r["error"]} if "error" in r else {})}))
    elif a.cmd == "push":
        if not a.yes:
            print(json.dumps({"error": "push writes to your Neo4j database; re-run with --yes after the user confirms"}))
            return 2
        print(json.dumps(push(out, a.allow_insecure)))
    else:
        print(json.dumps(query(out, a.q or "", a.allow_insecure), default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
