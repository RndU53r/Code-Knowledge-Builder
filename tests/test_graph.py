#!/usr/bin/env python3
"""Tests for the ckb knowledge graph. Run: python3 tests/test_graph.py

Temporary CKB_HOME and output dirs only; fixtures are copied, never executed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "scripts"
FX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(S))
tmp = Path(tempfile.mkdtemp(prefix="ckb-graph-test-"))
os.environ["CKB_HOME"] = str(tmp / "home")
env = dict(os.environ)
fails = 0


def check(name, ok, extra=""):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name, "" if ok else extra)


def run(script, *args, inp=None):
    return subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=env, input=inp)


# ---------------------------------------------------------------- build over a copy of the polyglot fixture
work = tmp / "polyglot"
shutil.copytree(FX / "polyglot", work)
out = tmp / ".ckb"
for k in ("gateway", "orders", "fulfillment"):
    run("fetch_source.py", "--out", out, "--key", k, work / k)
run("fetch_source.py", "--out", out, "--key", "platform", work / "deploy")
run("ingest_context.py", "--out", out, "--key", "ctx-arch", FX / "context")
for k, p in (("gateway", "gateway"), ("orders", "orders"), ("fulfillment", "fulfillment"), ("platform", "deploy")):
    run("scan_supply_chain.py", "--root", work / p, "--key", k, "--json-out", out / "evidence" / f"sc-{k}.json")
r = run("graph_build.py", "--out", out, "--extract")
res = json.loads(r.stdout)
check("build exits 0 with no schema problems", r.returncode == 0 and not res["schema_problems"], r.stderr[-500:])
g = json.loads((out / "graph" / "graph.json").read_text())
ids = {n["id"] for n in g["nodes"]}
E = {(e["kind"], e["src"], e["dst"]) for e in g["edges"]}
check("python AST: get_order function node", "function:orders:app/db.py:get_order" in ids)
check("endpoint nodes from FastAPI decorators", "endpoint:orders::POST /orders" in ids and "endpoint:orders::GET /orders/{order_id}" in ids)
check("routes_to endpoint -> handler", ("routes_to", "endpoint:orders::POST /orders", "function:orders:app/main.py:create_order") in E)
check("resolved call create_order -> insert_order (high)", any(e["kind"] == "calls" and e["dst"] == "function:orders:app/db.py:insert_order"
                                                               and e["confidence"] == "high" for e in g["edges"]))
check("cross-repo http_calls gateway -> orders POST /orders (G1)", any(e["kind"] == "http_calls" and e["dst"] == "endpoint:orders::POST /orders"
                                                                      and e["src"].startswith("function:gateway:") and e.get("dst_citation") for e in g["edges"]))
check("publishes/consumes share topic order.created (G2)", ("publishes", "function:orders:app/events.py:publish_order_created", "topic:_system::order.created") in E
      and any(e["kind"] == "consumes" and e["dst"] == "topic:_system::order.created" and e["src"].startswith("function:fulfillment:") for e in g["edges"]))
check("subprocess Python -> Go binary main (G3)", any(e["kind"] == "spawns" and e["dst"] == "function:fulfillment:cmd/pricing/main.go:main" for e in g["edges"]))
check("shared table written by orders and fulfillment (G4)", sum(1 for e in g["edges"] if e["kind"] == "writes" and e["dst"] == "table:_system::orders") >= 2)
sinks = {n["id"]: n for n in g["nodes"] if n["kind"] == "sink"}
check("unsafe SQL sink in get_order, safe in insert_order (G5)", sinks.get("sink:orders:app/db.py:get_order.sql.1", {}).get("attrs", {}).get("safe") is False
      and sinks.get("sink:orders:app/db.py:insert_order.sql.1", {}).get("attrs", {}).get("safe") is True)
check("cloud resources from IaC (G7)", any(n["kind"] == "cloud_resource" and "aws_s3_bucket" in n["id"] for n in g["nodes"]))
check("supply-chain finding attached to cloud resource (G8)", any(e["kind"] == "finding_at" and "aws_s3_bucket.invoices" in e["dst"] for e in g["edges"]))
check("CSPM finding affects S3 bucket (G9)", any(e["kind"] == "affects" and "aws_s3_bucket.invoices" in e["dst"] for e in g["edges"]))
ck = run("graph_check.py", "--out", out, "--report")
check("graph_check: all citations verify (0 errors)", ck.returncode == 0, ck.stdout[-800:])
check("every node/edge has provenance+confidence", all(n.get("provenance", {}).get("extractor") and n.get("confidence") for n in g["nodes"])
      and all(e.get("provenance", {}).get("extractor") and e.get("confidence") for e in g["edges"]))

# ---------------------------------------------------------------- queries
from graph_query import GraphStore  # noqa: E402

st = GraphStore(out)
imp = st.impact(["orders/app/db.py"])
eps = {x["name"] for x in imp["by_kind"].get("endpoint", [])}
check("impact(db.py) reaches gateway GET /orders/:id across repos (G6)", "GET /orders/:id" in eps, eps)
tp = st.taint()["paths"]
check("taint: public GET /orders/:id -> unsafe SQL (P5)", any(p["source"]["name"] == "GET /orders/:id" and p["sink_type"] == "sql" for p in tp))
check("taint: /admin/report -> SSRF (P6)", any(p["source"]["name"] == "GET /admin/report" and p["sink_type"] == "ssrf" for p in tp))
pth = st.path("gateway/src/server.js", "fulfillment/internal/queue/consumer.go", k=1)["paths"]
check("path gateway -> fulfillment consumer via RabbitMQ (P2)", bool(pth) and any(n["name"] == "order.created" for n in pth[0]["nodes"]))
check("sql: INSERT refused", "error" in st.sql("INSERT INTO nodes(id) VALUES('x')"))
check("sql: ATTACH refused", "error" in st.sql("SELECT 1; ATTACH DATABASE 'x' AS y") and "error" in st.sql("ATTACH DATABASE 'x' AS y"))
check("sql: recursive callers query works", len(st.sql("WITH RECURSIVE up(id,d) AS (SELECT 'function:orders:app/db.py:get_order',0 UNION "
                                                       "SELECT e.src,d+1 FROM edges e JOIN up ON e.dst=up.id WHERE e.kind='calls' AND d<5) SELECT DISTINCT id FROM up")["rows"]) >= 2)
check("impact rejects option-like diff revision", st.impact(diff_rev="--output=/tmp/x").get("error") == "invalid revision")
check("search finds price_items", any(x["name"] == "price_items" for x in st.search("price")))

# ---------------------------------------------------------------- proposals
pdir = out / "graph" / "proposals"
pdir.mkdir(parents=True, exist_ok=True)
good = {"op": "node", "kind": "threat", "repo": "_system", "qualname": "T1", "name": "T1 SQLi", "citation": "orders/app/db.py:23",
        "quote": "WHERE id = '{order_id}'", "confidence": "high", "label": "observed"}
lines = [good,
         {"op": "edge", "src": "threat:_system::T1", "kind": "threatens", "dst": "function:orders:app/db.py:get_order", "citation": "orders/app/db.py:23",
          "quote": "cur.execute", "confidence": "high", "label": "observed"},
         {"op": "edge", "src": "function:orders:app/main.py:read_order", "kind": "calls", "dst": "function:orders:app/db.py:get_order",
          "citation": "orders/app/main.py:999", "quote": "x", "confidence": "high"},
         {"op": "edge", "src": "function:orders:app/main.py:read_order", "kind": "calls", "dst": "function:orders:app/db.py:get_order",
          "citation": "orders/app/main.py:39", "quote": "not in file", "confidence": "high"},
         {"op": "edge", "src": "function:gateway:src/server.js:route GET /orders/:id", "kind": "flows_to", "dst": "function:orders:app/main.py:read_order",
          "citation": "gateway/src/server.js:27", "quote": "req.params.id", "confidence": "medium"},
         {"op": "edge", "src": "function:orders:app/db.py:get_order", "kind": "contains", "dst": "function:orders:app/db.py:get_conn",
          "citation": "orders/app/db.py:23", "quote": "cur.execute"},
         {"op": "annotate", "id": "function:orders:app/db.py:get_order", "summary": "Fetch order by id (string-built SQL). token=AKIAIOSFODNN7EXAMPLE"},
         {"op": "tour", "name": "onboarding", "title": "Order flow", "steps": [{"node_id": "endpoint:orders::POST /orders", "note": "entry", "citation": "orders/app/main.py:25"}]}]
pf = pdir / "test.jsonl"
pf.write_text("".join(json.dumps(x) + "\n" for x in lines))
chk = json.loads(run("graph_merge.py", "--out", out, "--check", pf).stdout)
reasons = [x["reason"] for x in chk["rejected"]]
check("merge rejects bad line (E3)", any(r.startswith("E3") for r in reasons))
check("merge rejects quote mismatch (E4)", any(r.startswith("E4") for r in reasons))
check("merge rejects cross-repo edge without dst_citation", any("dst_citation" in r for r in reasons))
check("merge rejects extractor-only kind", any("may not propose edge kind contains" in r for r in reasons))
run("graph_build.py", "--out", out)
g2 = json.loads((out / "graph" / "graph.json").read_text())
check("accepted threat + threatens merged as llm/mechanical", any(e["kind"] == "threatens" and e["provenance"]["extractor"] == "llm" for e in g2["edges"]))
gn = {n["id"]: n for n in g2["nodes"]}
check("annotation summary merged and secret redacted", "summary" in gn["function:orders:app/db.py:get_order"]
      and "AKIAIOSFODNN7EXAMPLE" not in json.dumps(g2))
check("tour merged", any(t["name"] == "onboarding" for t in g2.get("tours", [])))

# ---------------------------------------------------------------- stable IDs + incremental + carry-over
run("hash_index.py", "snapshot", "--out", out)
db = work / "orders" / "app" / "db.py"
src = db.read_text()
db.write_text("# a new comment line\n" + src.replace("def get_order(conn, order_id):", "def get_order(conn, order_id, tenant=None):"))
run("graph_build.py", "--out", out, "--extract", "--incremental")
g3 = json.loads((out / "graph" / "graph.json").read_text())
n3 = {n["id"]: n for n in g3["nodes"]}
go = n3.get("function:orders:app/db.py:get_order", {})
check("ID stable after inserting a line above (citation shifted)", bool(go) and go["citation"].startswith("orders/app/db.py:22"), go.get("citation"))
check("changed signature -> summary kept as [OUTDATED]", go.get("summary_status") == "OUTDATED" and go.get("summary"))
check("graph_check still 0 errors after incremental", run("graph_check.py", "--out", out).returncode == 0)

# ---------------------------------------------------------------- viewer escaping (hostile strings from target code)
evil = tmp / "evil"
(evil / "src").mkdir(parents=True)
(evil / "src" / "app.js").write_text("const app = require('express')();\napp.get('/</script><img src=x onerror=alert(1)>', (req, res) => res.send('x'));\n")
eout = tmp / ".ckb-evil"
run("fetch_source.py", "--out", eout, "--key", "evil", evil)
run("graph_build.py", "--out", eout, "--extract")
run("graph_viewer.py", "--out", eout)
html = (eout / "graph" / "index.html").read_text()
data_block = html.split('id="ckb-data">', 1)[1].split("</script>", 1)[0]
check("viewer: hostile </script> inert inside data block", "<img" in data_block and "</script><img" not in html)
scripts = html.split("<script>", 1)[1].split("</script>", 1)[0]
check("viewer: no external URLs in script/style", "http://" not in scripts and "https://" not in scripts and "<link" not in html)
check("viewer: strict CSP present", "default-src 'none'" in html and "connect-src 'none'" in html)

# ---------------------------------------------------------------- live server
import graph_serve  # noqa: E402

holder = {}
th = threading.Thread(target=graph_serve.serve, args=(out, 0, False, lambda h, t: holder.update(h=h, t=t)), daemon=True)
th.start()
for _ in range(50):
    if "h" in holder:
        break
    time.sleep(0.1)
port, tok = holder["h"].server_address[1], holder["t"]
check("server binds 127.0.0.1 only", holder["h"].server_address[0] == "127.0.0.1")


def http(path, method="GET", host=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


check("server: 403 without token", http("/api/status")[0] == 403)
check("server: 405 on POST", http(f"/api/status?token={tok}", "POST")[0] == 405)
check("server: bad Host rejected", http(f"/api/status?token={tok}", host="evil.example")[0] == 421)
code, body = http(f"/api/impact?token={tok}&targets=orders/app/db.py")
check("server: impact API works with token", code == 200 and b"affected" in body)
code, body = http(f"/?token={tok}")
check("server: live viewer served with connect-src 'self'", code == 200 and b"connect-src 'self'" in body)
holder["h"].shutdown()

# ---------------------------------------------------------------- MCP
msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ckb_explain", "arguments": {"target": "get_order", "out": str(out)}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "ckb_status", "arguments": {"out": str(tmp / "nope")}}}]
mr = run("graph_mcp.py", inp="".join(json.dumps(m) + "\n" for m in msgs))
resp = {r["id"]: r for r in map(json.loads, mr.stdout.splitlines())}
check("mcp: initialize + no reply to notification", resp[1]["result"]["serverInfo"]["name"] == "ckb-graph" and len(resp) == 4)
check("mcp: 11 read-only tools listed", len(resp[2]["result"]["tools"]) == 11)
check("mcp: explain returns cited node", "orders/app/db.py" in resp[3]["result"]["content"][0]["text"])
check("mcp: missing graph -> helpful error", resp[4]["result"]["isError"] and "graph build" in resp[4]["result"]["content"][0]["text"])

# ---------------------------------------------------------------- exports + neo4j safety
for fmt in ("ua", "cypher", "csv", "graphml"):
    check(f"export {fmt}", run("graph_export.py", "--out", out, fmt).returncode == 0)
import graph_neo4j  # noqa: E402

check("neo4j query refuses writes", "error" in graph_neo4j.query(out, "MATCH (n) DETACH DELETE n"))
os.environ.update({"NEO4J_URI": "http://neo4j.example.com:7474", "NEO4J_USER": "u", "NEO4J_PASSWORD": "supersecretpw"})
try:
    graph_neo4j.conn()
    check("neo4j refuses plain http to remote host", False)
except SystemExit as e:
    check("neo4j refuses plain http to remote host", "refusing" in str(e) and "supersecretpw" not in str(e))

# ---------------------------------------------------------------- auto mode
ap = json.loads(run("auto_plan.py", FX / "polyglot").stdout)
keys = {s["key"] for s in ap["sources"]}
check("auto: finds 3 services + platform", {"gateway", "orders", "fulfillment", "platform"} <= keys, keys)
check("auto: python->ast, others regex when tree-sitter absent", ap["parsers"].get("python") == "ast"
      and (ap["parsers"].get("go") in ("regex", "tree-sitter")))
check("auto: cloud layer on, LLM top10 off", ap["stages"]["cloud_layer"]["run"] and not ap["stages"]["owasp_llm_top10"]["run"])
ap2 = json.loads(run("auto_plan.py", tmp / "polyglot").stdout)  # work copy; add a doc folder with a nonstandard name
plat = next(s for s in ap2["sources"] if s["key"] == "platform")
check("auto: platform excludes service dirs (no double indexing)", set(plat.get("exclude", [])) >= {"gateway/**", "orders/**", "fulfillment/**"})
dd = tmp / "polyglot" / "docs-architecture"
dd.mkdir(exist_ok=True)
shutil.copy(FX / "context" / "whiteboard.png", dd / "whiteboard.png")
shutil.copy(FX / "context" / "security-design.docx", dd / "security-design.docx")
ctxs = {c["evidence"] for c in json.loads(run("auto_plan.py", tmp / "polyglot").stdout)["context"]}
check("auto: finds docs in nonstandard doc folder incl. images", {"docs-architecture/whiteboard.png", "docs-architecture/security-design.docx"} <= ctxs, ctxs)
xout = tmp / ".ckb-excl"
run("fetch_source.py", "--out", xout, "--key", "orders", tmp / "polyglot" / "orders")
run("fetch_source.py", "--out", xout, "--key", "platform", "--exclude", "orders/**", "--exclude", "gateway/**", "--exclude", "fulfillment/**", tmp / "polyglot")
run("graph_build.py", "--out", xout, "--extract")
gx = json.loads((xout / "graph" / "graph.json").read_text())
check("excluded service code not duplicated under platform", not any(n["id"].startswith("function:platform:orders/") for n in gx["nodes"])
      and any(n["id"].startswith("cloud_resource:platform:") for n in gx["nodes"]))
check("auto: never automates authorization", any("authorization" in x for x in ap["not_automated"]))

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
