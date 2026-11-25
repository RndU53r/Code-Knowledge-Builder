#!/usr/bin/env python3
"""Tests for v0.5: file roles, repo kinds, entry points / taint sources / sinks across languages, pipeline facts,
deploys links, context facts and their verification. Run: python3 tests/test_entrypoints.py

Fixtures under tests/fixtures/entrypoints and tests/fixtures/repokinds are static text; they are copied to a temp dir
and only ever read (never installed, built or run).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "scripts"
FX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(S))
tmp = Path(tempfile.mkdtemp(prefix="ckb-ep-test-"))
os.environ["CKB_HOME"] = str(tmp / "home")
fails = 0


def check(name, ok, extra=""):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name, "" if ok else str(extra)[:500])


def run(script, *args):
    return subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=os.environ)


def register(out, root, keys):
    for k in keys:
        r = run("fetch_source.py", "--out", out, "--key", k, root / k)
        assert r.returncode == 0, r.stderr


def load(out):
    return json.loads((out / "graph" / "graph.json").read_text())


def entries(g, repo, kind="endpoint"):
    return {n["name"]: n for n in g["nodes"] if n["kind"] == kind and (n.get("repo") == repo or n.get("citation", "").startswith(repo + "/"))}


def sinks(g, repo):
    return [(n["attrs"]["sink_type"], bool(n["attrs"].get("safe"))) for n in g["nodes"] if n["kind"] == "sink" and n["repo"] == repo]


def srcs(g, repo):
    return {n["attrs"]["source_type"] for n in g["nodes"] if n["kind"] == "taint_source" and n["repo"] == repo}


def handler_of(g, ep):
    ids = {n["id"]: n for n in g["nodes"]}
    return sorted({ids[e["dst"]]["name"] for e in g["edges"] if e["kind"] == "routes_to" and e["src"] == ep["id"]})


# ---------------------------------------------------------------- entry points, sources, sinks (8 languages)
work = tmp / "entrypoints"
shutil.copytree(FX / "entrypoints", work)
out = tmp / "ep" / ".ckb"
keys = sorted(p.name for p in work.iterdir() if p.is_dir())
register(out, work, keys)
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
res = json.loads(r.stdout)
check("entrypoints workspace builds with no schema problems", r.returncode == 0 and not res["schema_problems"], r.stderr[-400:] + str(res.get("schema_problems")))
chk = run("graph_check.py", "--out", out)
check("graph_check reports no errors", chk.returncode == 0, chk.stdout[-400:])
g = load(out)

# Spring
e = entries(g, "spring-svc")
check("spring: class prefix + method mappings", {"GET /api/orders/{id}", "POST /api/orders", "POST /api/orders/export", "GET /api/orders/fetch",
                                                 "POST /api/orders/import", "POST /api/orders/xml"} <= set(e), sorted(e))
check("spring: handlers bound to the annotated method", handler_of(g, e["GET /api/orders/{id}"]) == ["getOrder"] and handler_of(g, e["POST /api/orders/export"]) == ["export"])
check("spring: Kafka consumer and @Scheduled cron", "consume order.created" in entries(g, "spring-svc", "consumer") and any(n.startswith("schedule") for n in entries(g, "spring-svc", "cron_job")))
check("spring: nothing extracted from the test file", not [n for n in g["nodes"] if n["kind"] in ("sink", "endpoint", "taint_source") and "OrderControllerTest" in n.get("citation", "")])
sk = sinks(g, "spring-svc")
check("spring sinks: string-built SQL unsafe, prepared statement safe", ("sql", False) in sk and ("sql", True) in sk, sk)
check("spring sinks: exec, RestTemplate with variable URL, ObjectInputStream, XML parser", {("command", False), ("ssrf", False), ("deserialization", False), ("xxe", False)} <= set(sk), sk)
check("spring sources: @RequestParam/@PathVariable/@RequestBody", "http_param" in srcs(g, "spring-svc"))
# ASP.NET
e = entries(g, "aspnet-svc")
check("aspnet: [Route(api/[controller])] + verbs, minimal API, inline lambda", {"GET /api/users/{id}", "POST /api/users", "POST /api/users/run", "POST /api/users/load", "GET /health", "POST /webhook"} <= set(e), sorted(e))
check("aspnet: minimal API method group resolves to its handler", handler_of(g, e["POST /webhook"]) == ["HandleWebhook"], handler_of(g, e["POST /webhook"]))
check("aspnet: Azure Functions timer + queue triggers", entries(g, "aspnet-svc", "cron_job") and "consume ingest-queue" in entries(g, "aspnet-svc", "consumer"))
sk = sinks(g, "aspnet-svc")
check("aspnet sinks: interpolated SqlCommand unsafe, parameterized safe, Process.Start, BinaryFormatter", {("sql", False), ("sql", True), ("command", False), ("deserialization", False)} <= set(sk), sk)
# Rails
e = entries(g, "rails-app")
check("rails: resources(only) + namespace prefix + explicit routes", {"GET /api/orders", "GET /api/orders/:id", "POST /api/orders", "POST /api/import", "GET /ping"} <= set(e) and "DELETE /api/orders/:id" not in e, sorted(e))
ids = {n["id"]: n for n in g["nodes"]}
imp = [ids[x["dst"]] for x in g["edges"] if x["kind"] == "routes_to" and x["src"] == e["POST /api/import"]["id"]]
check("rails: controller#action resolves to the right controller file", imp and imp[0]["path"].endswith("imports_controller.rb"), [(n["path"], n["name"]) for n in imp])
sk = sinks(g, "rails-app")
check("rails sinks: interpolated find_by_sql, system(), redirect_to params, Marshal.load", {("sql", False), ("command", False), ("redirect", False), ("deserialization", False)} <= set(sk), sk)
# Laravel
e = entries(g, "laravel-app")
check("laravel: Route::get with controller array, 'C@m' string, prefix group, inline closure", {"GET /users/{id}", "POST /users/import", "GET /api/report", "POST /api/upload"} <= set(e), sorted(e))
check("laravel: controller method bound", handler_of(g, e["GET /api/report"]) == ["report"] and handler_of(g, e["POST /users/import"]) == ["import"])
sk = sinks(g, "laravel-app")
check("laravel sinks: DB::select concat, shell_exec, unserialize, file_get_contents($url)", {("sql", False), ("command", False), ("deserialization", False), ("ssrf", False)} <= set(sk), sk)
# Django / Python
e = entries(g, "django-app")
check("django: path() in urls.py incl. as_view()", len(e) == 2 and any("orders" in n for n in e) and any("search" in n for n in e), sorted(e))
check("django: celery task is a consumer, argparse a CLI entry", "consume task send_receipt" in entries(g, "django-app", "consumer") and entries(g, "django-app", "cli_command"))
sk = sinks(g, "django-app")
check("django sinks: cursor.execute(variable), yaml.load, mark_safe, redirect", {("sql", False), ("deserialization", False), ("xss", False), ("redirect", False)} <= set(sk), sk)
check("django sources: request.GET and task arguments", {"http_param", "message_body", "cli_arg"} <= srcs(g, "django-app"), srcs(g, "django-app"))
# Nest / TS
e = entries(g, "nest-app")
check("nest: @Controller prefix + @Get(':id') bound to its method despite decorated params", handler_of(g, e["GET /users/:id"]) == ["findOne"] and handler_of(g, e["POST /users"]) == ["create"], sorted(e))
check("nest: @MessagePattern consumer and @Cron", "consume user.created" in entries(g, "nest-app", "consumer") and entries(g, "nest-app", "cron_job"))
check("nest sinks: fs.readFileSync(dynamic path), innerHTML", {("path", False), ("xss", False)} <= set(sinks(g, "nest-app")), sinks(g, "nest-app"))
# Go
e = entries(g, "go-chi")
check("go: chi verbs, net/http 'GET /v2/ping', gorilla .Methods, gRPC service", {"GET /items/{id}", "POST /items", "GET /v2/ping", "POST /legacy", "GRPC /Billing"} <= set(e), sorted(e))
check("go: gRPC registration is not bound to a neighbouring function", handler_of(g, e["GRPC /Billing"]) == [], handler_of(g, e["GRPC /Billing"]))
check("go: cobra command bound to its Run function", entries(g, "go-chi", "cli_command") and handler_of(g, list(entries(g, "go-chi", "cli_command").values())[0]) == ["runTool"])
sk = sinks(g, "go-chi")
check("go sinks: sh -c with a variable is unsafe, os.ReadFile(dynamic), http.Get(variable)", {("command", False), ("path", False), ("ssrf", False)} <= set(sk), sk)
# no personal data in node names
check("no secret values in extracted nodes", "AKIA" not in json.dumps(g))

# taint candidates start from every entry kind and are de-duplicated
q = run("graph_query.py", "--out", out, "taint")
paths = json.loads(q.stdout)["paths"]
sig = [(p["source"]["id"], p["sink"]["id"]) for p in paths]
check("taint finds candidate paths across languages without duplicates", len(paths) >= 8 and len(set(sig)) == len(paths), len(paths))
q = json.loads(run("graph_query.py", "--out", out, "entrypoints", "--repo", "spring-svc").stdout)
by = {x["name"]: x for x in q["entrypoints"]}
check("entrypoints op: handler, sources and reachable unsafe sinks", by["GET /api/orders/{id}"]["handler"][0]["name"] == "getOrder" and "http_param" in by["GET /api/orders/{id}"]["sources"]
      and any(s["type"] == "sql" for s in by["GET /api/orders/{id}"]["reaches_unsafe_sinks"]), by.get("GET /api/orders/{id}"))

# ---------------------------------------------------------------- file roles
rd = json.loads((out / "evidence" / "file-roles-roles-demo.json").read_text())
role = {f["path"]: f["role"] for f in rd["files"]}
check("roles: entry file and I/O file are core", role["app/main.py"] == "core" and role["app/service.py"] == "core", role)
check("roles: helper dir with fan-in is utility", role["app/utils/strings.py"] == "utility" and role["app/utils/money.py"] == "utility")
check("roles: tests, generated, migration, docs, fixture, tooling by path/content", role["tests/test_service.py"] == "test" and role["app/gen/api_pb2.py"] == "generated" and role["migrations/001_init.sql"] == "migration"
      and role["docs/overview.md"] == "docs" and role["fixtures/sample_orders.json"] == "fixture" and role["scripts/seed.sh"] == "tooling", role)
check("roles: core/utility carry their signals", all(f.get("signals") for f in rd["files"] if f["role"] in ("core", "utility")))
check("roles: repo kind of an app with an endpoint is service", rd["repo_kind"]["repo_kind"] == "service", rd["repo_kind"])
cm = (out / "repos" / "roles-demo" / "code-map.md").read_text()
check("code-map lists core and utility files and test coverage", "app/main.py" in cm and "app/utils/strings.py" in cm and "test file(s)" in cm and "[inferred]" in cm)
node = next(n for n in g["nodes"] if n["kind"] == "file" and n["path"] == "app/utils/strings.py" and n["repo"] == "roles-demo")
check("file node carries role attrs and a role tag", node["attrs"]["role"] == "utility" and "role:utility" in node["tags"], node.get("attrs"))
rq = json.loads(run("graph_query.py", "--out", out, "roles", "--repo", "roles-demo", "--role", "utility").stdout)
check("roles op filters by role", {f["path"] for f in rq["files"]} == {"app/utils/strings.py", "app/utils/money.py"}, rq["files"])
sv = {f["path"]: f["role"] for f in json.loads((out / "evidence" / "file-roles-spring-svc.json").read_text())["files"]}
check("roles: Java test dir/name and helper class", sv["src/test/java/com/acme/orders/OrderControllerTest.java"] == "test" and sv["src/main/java/com/acme/util/StringUtils.java"] == "utility", sv)

# ---------------------------------------------------------------- repo kinds, pipelines, IaC, deploys
work2 = tmp / "repokinds"
shutil.copytree(FX / "repokinds", work2)
out2 = tmp / "rk" / ".ckb"
keys2 = sorted(p.name for p in work2.iterdir() if p.is_dir())
register(out2, work2, keys2)
for k in keys2:
    run("scan_supply_chain.py", "--root", work2 / k, "--key", k, "--json-out", out2 / "evidence" / f"sc-{k}.json")
r = run("graph_build.py", "--out", out2, "--extract", "--enrich")
res2 = json.loads(r.stdout)
check("repokinds workspace builds with no schema problems", r.returncode == 0 and not res2["schema_problems"], r.stderr[-400:] + str(res2.get("schema_problems")))
kinds = {n["repo"]: n["attrs"] for n in load(out2)["nodes"] if n["kind"] == "repo"}
check("repo kind: Terraform+Bicep repo is iac", kinds["infra-tf"]["repo_kind"] == "iac", kinds["infra-tf"])
check("repo kind: workflows + Azure Pipelines + Jenkinsfile repo is cicd-pipeline", kinds["ci-templates"]["repo_kind"] == "cicd-pipeline", kinds["ci-templates"])
check("repo kind: k8s + kustomize + Argo CD repo is gitops-config", kinds["gitops-manifests"]["repo_kind"] == "gitops-config", kinds["gitops-manifests"])
check("repo kind: app with its own Terraform is mixed (service + iac)", kinds["orders-app"]["repo_kind"] == "mixed" and kinds["orders-app"].get("primary_kind") == "service" and "iac" in kinds["orders-app"]["secondary_kinds"], kinds["orders-app"])
g2 = load(out2)
check("iac and pipeline repos have no endpoints", not entries(g2, "infra-tf") and not entries(g2, "ci-templates") and not entries(g2, "gitops-manifests"))
check("mixed repo still gets its endpoints", {"GET /orders/{order_id}", "POST /orders"} <= set(entries(g2, "orders-app")), sorted(entries(g2, "orders-app")))
pf = json.loads((out2 / "evidence" / "pipeline-facts-ci-templates.json").read_text())
fids = {(f["id"], f["path"].split("/")[0]) for f in pf["findings"]}
check("pipeline facts: Azure macro injection, mutable template repo, self-hosted + PR trigger, deploy without gate", {("PF02", "azure-pipelines"), ("PF01", "azure-pipelines"), ("PF03", "azure-pipelines"), ("PF04", "azure-pipelines")} <= fids, fids)
check("pipeline facts: Jenkins unpinned library, Groovy interpolation, GitHub PF03", {("PF01", "Jenkinsfile"), ("PF02", "Jenkinsfile"), ("PF03", ".github")} <= fids, fids)
byp = {p["path"]: p for p in pf["pipelines"]}
az = byp["azure-pipelines/templates/deploy.yml"]
check("pipeline facts: triggers, service connection names (not values), repo targets", az["pr_trigger"] and az["self_hosted"] and any(c["name"] == "prod-subscription-connection" for c in az["service_connections"]) and "orders-app" in az["targets"], az)
gh = byp[".github/workflows/release.yml"]
check("pipeline facts: pull_request_target is flagged fork-privileged, secrets by name only", gh["fork_privileged"] and gh["secrets"] == ["KUBE_TOKEN"], gh)
tm = (out2 / "system" / "threat-model.md").read_text()
check("threat draft: CI/CD pipeline threats (scanner + pipeline facts)", tm.count("CI/CD pipeline") >= 4 and "CWE-77" in tm and "CWE-250" in tm and "CWE-829" in tm, tm[:300])
check("threat draft: IaC exposure for the Terraform repo (public bucket, wildcard IAM)", "infra-tf" in tm and "CWE-284" in tm and "CWE-269" in tm, "")
cgm = (out2 / "system" / "call-graphs.md").read_text()
check("repo call graph: pipeline and GitOps repos link to the app repo they deploy", "| ci-templates | orders-app | deploy |" in cgm and "| gitops-manifests | orders-app | deploy |" in cgm, cgm[:500])

# ---------------------------------------------------------------- context facts + verification
cf = json.loads((out / "evidence" / "context-facts-spring-svc.json").read_text())
check("context facts: counts match the graph", len(cf["entry_points"]) == 8 and len(cf["sinks"]) >= 6 and cf["n_test"] == 1, {k: len(cf[k]) for k in ("entry_points", "sinks", "sources")})
auth = {x["name"]: x["auth"] for x in cf["entry_points"] if x["kind"] == "endpoint"}
check("context facts: method-level @PreAuthorize counted only for its method", auth["POST /api/orders"] == "yes" and auth["POST /api/orders/export"] == "none seen", auth)
rails = {x["name"]: x["auth"] for x in json.loads((out / "evidence" / "context-facts-rails-app.json").read_text())["entry_points"] if x["kind"] == "endpoint"}
check("context facts: class-level before_action covers actions; skip_before_action does not", rails["GET /api/orders"] == "yes" and rails["POST /api/import"] == "none seen", rails)
cs = {x["name"]: x["auth"] for x in json.loads((out / "evidence" / "context-facts-aspnet-svc.json").read_text())["entry_points"] if x["kind"] == "endpoint"}
check("context facts: [Authorize] class attribute vs [AllowAnonymous]", cs["GET /api/users/{id}"] == "yes" and cs["POST /api/users/load"] == "none seen", cs)
lv = {x["name"]: x["auth"] for x in json.loads((out / "evidence" / "context-facts-laravel-app.json").read_text())["entry_points"] if x["kind"] == "endpoint"}
check("context facts: ->middleware('auth') applies to its own route only", lv["POST /users/import"] == "yes" and lv["GET /users/{id}"] == "none seen", lv)
facts_md = (out / "repos" / "spring-svc" / "context-facts.md").read_text()
check("facts markdown carries the begin/end markers and citations", facts_md.startswith("<!-- ckb:facts:begin repo=spring-svc") and facts_md.rstrip().endswith("<!-- ckb:facts:end -->") and "OrderController.java:22" in facts_md)
rk = (out2 / "repos" / "ci-templates" / "context-facts.md").read_text()
check("facts markdown for a pipeline repo has the pipelines table", "Pipelines (triggers and blast radius)" in rk and "prod-subscription-connection" in rk)
ik = (out2 / "repos" / "infra-tf" / "context-facts.md").read_text()
check("facts markdown for an IaC repo has resources and findings", "Provisioned resources and exposure" in ik and "aws_s3_bucket" in ik and "SC-D07" in ik, ik[:600])
doc = out / "repos" / "spring-svc" / "context.md"
doc.write_text("---\nckb_context: 1\n---\n# Security context: spring-svc\n\n## Facts (generated)\n" + facts_md + "\n## 1. Purpose and tech stack\nx\n")
c1 = run("check_outputs.py", doc)
check("check_outputs F1: an embedded facts block that matches passes", "F1" not in c1.stdout, c1.stdout)
doc.write_text(doc.read_text().replace("entry_points=8", "entry_points=9"))
c2 = run("check_outputs.py", doc)
check("check_outputs F1: edited header counts are flagged", "F1" in c2.stdout and c2.returncode == 1, c2.stdout)
doc.write_text("---\n---\n" + facts_md.replace("OrderController.java:22", "OrderController.java:99") + "\n")
c3 = run("check_outputs.py", doc)
check("check_outputs F1: a hand-edited row is flagged", "F1" in c3.stdout, c3.stdout)

# ---------------------------------------------------------------- MCP, plan hint
import graph_mcp  # noqa: E402
names = {t["name"] for t in graph_mcp.TOOLS}
check("MCP exposes ckb_roles and ckb_entrypoints", {"ckb_roles", "ckb_entrypoints"} <= names)
import auto_plan  # noqa: E402
check("auto_plan kind_hint recognizes IaC and pipeline repos from paths alone",
      auto_plan.kind_hint(["main.tf", "variables.tf", "modules/a/main.tf"], "infra")["repo_kind"] == "iac"
      and auto_plan.kind_hint([".github/workflows/a.yml", ".github/workflows/b.yml", "Jenkinsfile"], "ci")["repo_kind"] == "cicd-pipeline")

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
