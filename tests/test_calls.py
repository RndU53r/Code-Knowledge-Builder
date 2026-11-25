#!/usr/bin/env python3
"""Call-graph completeness: receiver typing, MRO, callbacks, library calls, class-level graph, resolution accounting, library reachability.
Run: python3 tests/test_calls.py   (fixture tests/fixtures/calls/shop is copied to a temp dir and only read)"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "scripts"
FX = ROOT / "tests" / "fixtures" / "calls"
sys.path.insert(0, str(S))
tmp = Path(tempfile.mkdtemp(prefix="ckb-calls-test-"))
os.environ["CKB_HOME"] = str(tmp / "home")
fails = 0


def check(name, ok, extra=""):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name, "" if ok else str(extra)[:400])


def run(script, *args):
    return subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=os.environ)


work = tmp / "calls"
shutil.copytree(FX, work)
out = tmp / ".ckb"
assert run("fetch_source.py", "--out", out, "--key", "shop", work / "shop").returncode == 0
(out / "evidence").mkdir(parents=True, exist_ok=True)
(out / "evidence" / "sc-shop.json").write_text(json.dumps({"repo": "shop", "findings": [], "dependencies": [
    {"ecosystem": "pypi", "name": "requests", "version": "2.19.0", "advisories": ["GHSA-aaaa-bbbb-cccc"], "path": "requirements.txt", "line": 1},
    {"ecosystem": "pypi", "name": "pyyaml", "version": "3.1", "advisories": ["GHSA-dddd-eeee-ffff"], "path": "requirements.txt", "line": 2}]}))
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
res = json.loads(r.stdout)
check("builds with no schema problems", r.returncode == 0 and not res["schema_problems"], res.get("schema_problems"))
g = json.loads((out / "graph" / "graph.json").read_text())
N = {n["id"]: n for n in g["nodes"]}


def edges(kind, tests=False):
    return {(N[e["src"]].get("qualname", N[e["src"]]["name"]), N[e["dst"]].get("qualname", N[e["dst"]]["name"]), e["confidence"]) for e in g["edges"]
            if e["kind"] == kind and e["src"] in N and e["dst"] in N and (tests or "test" not in (N[e["src"]].get("tags") or []))}


calls = edges("calls")
pair = {(a, b) for a, b, c in calls}
check("receiver typing: self.repo.save() through an annotated __init__ parameter", ("OrderService.place", "OrderRepo.save") in pair)
check("receiver typing: module-level service = OrderService(...) then service.place()", ("handle", "OrderService.place") in pair and ("worker", "OrderService.lookup") in pair, sorted(pair))
check("receiver typing: local repo = OrderRepo() then repo.find()", ("OrderService.lookup", "OrderRepo.find") in pair)
check("super().save() resolves through the class hierarchy", ("OrderRepo.save", "BaseRepo.save") in pair)
check("inherited method reached through the subclass (BaseRepo._write from BaseRepo.save)", ("BaseRepo.save", "BaseRepo._write") in pair)
check("overrides edge from the method rule", ("OrderRepo.save", "BaseRepo.save", "medium") in edges("overrides"))
refs = {(a, b) for a, b, c in edges("references")}
check("callbacks and decorators become references (notify(audit), Thread(target=worker), @log_call)", {("handle", "audit"), ("handle", "worker"), ("OrderService.place", "log_call")} <= refs, sorted(refs))
check("uses_type from annotations, constructors and class attributes", ("OrderService.__init__", "OrderRepo", "medium") in edges("uses_type") and ("OrderService.lookup", "OrderRepo", "medium") in edges("uses_type"))
lib = {(a, b) for a, b, c in edges("calls_lib")}
check("library calls: function -> package with the API names", ("OrderRepo.save", "requests") in lib and ("OrderRepo.save", "json") in lib and ("audit", "logging") in lib, sorted(lib))
api = next(e for e in g["edges"] if e["kind"] == "calls_lib" and N[e["dst"]]["name"] == "requests")
check("library edge carries the API names and a count", (api.get("attrs") or {}).get("apis") == ["post"] and (api.get("attrs") or {}).get("count") == 1, api.get("attrs"))
check("precision: a call on an arbitrary expression (handlers[name]().strip()) is never matched by its bare method name", not any(a == "OrderService.dynamic" for a, b in pair))
cr = json.loads((out / "evidence" / "call-resolution-shop.json").read_text())
check("accounting: resolved / library / dynamic / unresolved counts are written, nothing dropped silently", cr["summary"]["dynamic"] == 1 and cr["summary"]["external"] >= 5 and cr["summary"]["resolved"] >= 12
      and sum(cr["summary"][k] for k in ("resolved", "external", "ambiguous", "dynamic", "unresolved")) == cr["summary"]["calls"], cr["summary"])
check("accounting: the unresolved names are listed with a citation", any(x["name"].startswith("<expr>") and x["citation"] for x in cr["top_unresolved"]), cr["top_unresolved"])
check("graph stats carry the per-repo call resolution", g["stats"]["call_resolution"]["shop"]["calls"] == cr["summary"]["calls"])
cg = json.loads((out / "graph" / "callgraph.json").read_text())
cls = {(N[e["src"]]["name"], N[e["dst"]]["name"], e["mechanism"]) for e in cg["class"]["edges"]}
check("class-level call graph: calls, types, inheritance, overrides", {("OrderService", "OrderRepo", "call"), ("OrderService", "OrderRepo", "type"), ("OrderRepo", "BaseRepo", "inherit"), ("OrderRepo", "BaseRepo", "override")} <= cls, sorted(cls))
check("library-level call graph lists packages with their APIs", any(N[e["dst"]]["name"] == "requests" and "post" in e["mechanism"] for e in cg["library"]["edges"] if e["dst"] in N))
cov = json.loads((out / "evidence" / "coverage.json").read_text())["repos"]["shop"]
check("coverage report: reachability, resolution percentage, hotspot scan", cov["call_resolution"]["resolved_pct"] is not None and cov["functions"] >= 8 and "dynamic_hotspots" in cov)
tm = (out / "system" / "threat-model.md").read_text()
check("library reachability: an advisory on a package the code calls is rated up, one never called is rated down", "Vulnerable dependency requests is called by the code (post)" in tm
      and "Vulnerable dependency pyyaml is declared but no call into it was resolved" in tm)
check("threat model carries the coverage section and the attack-path section", "## Analysis coverage and blind spots" in tm and "## Attack paths" in tm)

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
