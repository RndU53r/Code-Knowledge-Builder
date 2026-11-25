#!/usr/bin/env python3
"""Tests for deployment context (scripts/deploy_facts.py) and its use in exposure, authentication and toggle conclusions.
Run: python3 tests/test_deploy.py    (fixtures under tests/fixtures/deploy are copied to a temp dir and only read)"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "scripts"
FX = ROOT / "tests" / "fixtures" / "deploy"
sys.path.insert(0, str(S))
tmp = Path(tempfile.mkdtemp(prefix="ckb-deploy-test-"))
os.environ["CKB_HOME"] = str(tmp / "home")
fails = 0


def check(name, ok, extra=""):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name, "" if ok else str(extra)[:400])


def run(script, *args):
    return subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=os.environ)


work = tmp / "deploy"
shutil.copytree(FX, work)
out = tmp / ".ckb"
for d in sorted(p for p in work.iterdir() if p.is_dir()):
    assert run("fetch_source.py", "--out", out, "--key", d.name, d).returncode == 0
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
res = json.loads(r.stdout)
check("builds with no schema problems; deployment proposals accepted", r.returncode == 0 and not res["schema_problems"] and res["proposals"].get("rejected", 1) == 0, (res.get("schema_problems"), res.get("proposals")))
facts = json.loads((out / "evidence" / "deploy-facts-shop-deploy.json").read_text())
W = {w["name"]: w for w in facts["workloads"]}
api, pay = W["shop-api"], W["pay-svc"]
check("workload is linked to the application repo it runs (image name)", api.get("app_repo") == "shop-api" and api["resolved_by"] == "image" and pay.get("app_repo") == "pay-svc")
check("exposure: Ingress host and TLS make shop-api public; ClusterIP service alone would not", api["exposure"]["public"] and api["exposure"]["hosts"] == ["shop.example.com"] and api["exposure"]["tls"], api["exposure"])
check("exposure: LoadBalancer service makes pay-svc public", pay["exposure"]["kind"] == "loadbalancer" and pay["exposure"]["public"], pay["exposure"])
check("controls in front: ingress auth-url is attached to the workload it routes to", any(c["kind"] == "gateway-auth" and "auth-url" in c["detail"] for c in api["external_controls"]) and not pay["external_controls"], (api["external_controls"], pay["external_controls"]))
env = {e["name"]: e for e in api["env"]}
check("injected config: literal vs secretKeyRef, deployed toggle values recorded for non-secret names", env["DEBUG"]["source"] == "literal" and env["DEBUG"]["value"] == "true" and env["AUTH_DISABLED"]["value"] == "false"
      and env["DATABASE_URL"]["source"] == "secretKeyRef" and "value" not in env["DATABASE_URL"], env)
check("a secret-like literal is flagged but its value is never stored", {e["name"]: e for e in pay["env"]}["DB_PASSWORD"]["source"] == "literal" and "changeme" not in json.dumps(facts))
check("identity and security context", api["identity"].endswith("role/shop-api") and api["security"]["privileged"] and not pay["security"]["privileged"], (api.get("identity"), api["security"]))
kinds = {c["kind"] for c in facts["controls"]}
check("controls: NetworkPolicy, WAF, internet-facing LB, insecure HTTP listener, API gateway route without authorizer, rate limit", {"network-policy", "waf", "load-balancer", "listener", "gateway-no-auth", "rate-limit"} <= kinds, kinds)
check("an HTTP listener without redirect is marked insecure", any(c["kind"] == "listener" and c.get("insecure") and c["detail"].startswith("HTTP:80") for c in facts["controls"]), [c for c in facts["controls"] if c["kind"] == "listener"])
g = json.loads((out / "graph" / "graph.json").read_text())
N = {n["id"]: n for n in g["nodes"]}
check("graph: service nodes and deploys edges to the application repos", {("shop-api", "shop-api"), ("pay-svc", "pay-svc")} <= {(N[e["src"]]["name"], N[e["dst"]]["name"]) for e in g["edges"] if e["kind"] == "deploys" and e["src"] in N and e["dst"] in N and N[e["src"]]["repo"] == "shop-deploy"})
cb = {N[e["src"]]["name"]: e for e in g["edges"] if e["kind"] == "configured_by" and e["src"] in N and N[e["dst"]]["repo"] == "shop-deploy"}
check("graph: env_var nodes read by the code are linked to the workload that injects them (value kept only when not secret)", (cb["DEBUG"].get("attrs") or {}).get("value") == "true" and "value" not in (cb["DB_PASSWORD"].get("attrs") or {}), {k: v.get("attrs") for k, v in cb.items()})
tm = (out / "system" / "threat-model.md").read_text()
check("threat model: deployed toggle value raises the switch threat (DEBUG=true)", "switched off in deployment by DEBUG=true" in tm)
check("threat model: authentication provided outside the code is annotated, not reported as missing", "Authentication for GET /orders lives outside the application code" in tm and "No authentication evidence on GET /orders" not in tm)
check("threat model: public workload with no control in code or in front of it is rated up", "Publicly exposed workload pay-svc has no authentication control" in tm and "No authentication evidence on POST /pay" in tm)
check("threat model: secret literal, privileged workload, HTTP listener, route without authorizer", all(x in tm for x in ("Secret-like variable set as a literal", "elevated privileges (privileged)", "HTTP listener without a redirect", "has no authorizer")))
ap = tm[tm.index("## Attack paths"):tm.index("## Analysis coverage")]
check("threat model: attack path from the public entry point to the SQL sink shows exposure, the control in front, and coverage", "GET /orders" in ap and "| public |" in ap and "gateway-auth" in ap and "sql (CWE-89)" in ap and "40.0%" in ap, ap[-700:])
check("threat model: analysis coverage section states resolution numbers", "Analysis coverage and blind spots" in tm and "| shop-api | 40.0% |" in tm and "Dynamic-dispatch hotspots" in tm)
cf = json.loads((out / "evidence" / "context-facts-shop-api.json").read_text())
ep = {e["name"]: e for e in cf["entry_points"]}["GET /orders"]
check("context facts: exposure comes from the deployment and auth shows the external control", ep["exposure"] == "public" and ep["auth"] == "external: gateway-auth", ep)
md = (out / "repos" / "shop-api" / "context-facts.md").read_text()
check("context facts: 'Deployment and controls outside application code' table", "Deployment and controls outside application code" in md and "shop.example.com" in md and "DEBUG=true" in md)

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
