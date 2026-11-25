#!/usr/bin/env python3
"""Language depth conformance: every supported language runs one scenario (entry point -> controller -> service via a typed receiver
-> repository -> library call -> unsafe sink, plus an override, a test file and a generated file) and must pass the same matrix.
Run: python3 tests/test_langs.py        Fixtures under tests/fixtures/langs/<lang> are copied to a temp dir and only ever read.

Matrix rows (docs/languages.md):  1 declarations  2 imports  3 calls  4 objects/classes  5 libraries  6 entry points
                                  7 sources  8 sinks  9 auth evidence  10 roles  11 coverage
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
FX = ROOT / "tests" / "fixtures" / "langs"
sys.path.insert(0, str(S))
tmp = Path(tempfile.mkdtemp(prefix="ckb-langs-test-"))
os.environ["CKB_HOME"] = str(tmp / "home")
fails = 0


def check(name, ok, extra=""):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name, "" if ok else str(extra)[:400])


def run(script, *args):
    return subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=os.environ)


# per language: controller method, service method, repo method, base method (override target), expected library package fragment,
# explicit imports (src suffix, dst suffix) that must resolve, test file, generated file, whether the route carries an auth marker
CFG = {
    "python":     dict(ctl="create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="requests", imports=[("app/main.py", "app/service.py"), ("app/service.py", "app/repo.py")],
                       test="tests/test_service.py", gen="app/api_pb2.py", auth=True, path="/orders"),
    "javascript": dict(ctl="route POST /orders", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="axios", imports=[("src/controller.js", "src/service.js"), ("src/service.js", "src/repo.js")],
                       test="test/service.test.js", gen="src/api.min.js", auth=True, path="/orders"),
    "typescript": dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="axios", imports=[("src/order.controller.ts", "src/order.service.ts"), ("src/order.service.ts", "src/order.repo.ts")],
                       test="src/order.service.spec.ts", gen="src/api.generated.ts", auth=True, path="/orders"),
    "go":         dict(ctl="OrderHandler.Create", svc="OrderService.Place", repo="OrderRepo.Save", base="BaseRepo.Save", lib="net/http", imports=[("internal/web/handler.go", "internal/service/service.go"), ("internal/service/service.go", "internal/repo/repo.go")],
                       test="internal/service/service_test.go", gen="internal/api/api.pb.go", auth=True, path="/orders"),
    "java":       dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="org.springframework", imports=[],
                       test="src/test/java/com/acme/OrderServiceTest.java", gen="src/main/java/com/acme/Api.java", auth=True, path="/orders", implements=("OrderRepo", "Repo")),
    "kotlin":     dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="org.springframework", imports=[],
                       test="src/test/kotlin/com/acme/OrderServiceTest.kt", gen="src/main/kotlin/com/acme/Api.kt", auth=True, path="/orders", extra_entry="POST /ktor/orders"),
    "scala":      dict(ctl="OrderRoutes", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="scalaj", imports=[],
                       test="src/test/scala/shop/OrderServiceSpec.scala", gen="src/main/scala/shop/Api.scala", auth=True, path="/orders"),
    "csharp":     dict(ctl="OrdersController.Create", svc="OrderService.Place", repo="OrderRepo.Save", base="BaseRepo.Save", lib="HttpClient", imports=[],
                       test="Tests/OrderServiceTests.cs", gen="Generated/Api.g.cs", auth=True, path="/api/orders", implements=("OrderService", "IOrderService")),
    "ruby":       dict(ctl="OrdersController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="Net", imports=[("app/services/order_service.rb", "app/repos/order_repo.rb")],
                       test="spec/order_service_spec.rb", gen="app/api_pb.rb", auth=True, path="/orders"),
    "php":        dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="Illuminate", imports=[("app/Http/Controllers/OrderController.php", "app/Services/OrderService.php")],
                       test="tests/OrderServiceTest.php", gen="app/Generated/Api.php", auth=True, path="/orders"),
    "rust":       dict(ctl="create", svc="OrderService.place", repo="OrderRepo.save", base="Repo.save", lib="reqwest", imports=[("src/handlers.rs", "src/service.rs"), ("src/service.rs", "src/repo.rs")],
                       test="tests/service_test.rs", gen="src/api_generated.rs", auth=True, path="/orders", implements=("OrderRepo", "Repo")),
    "swift":      dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="URLSession", imports=[],
                       test="Tests/AppTests/OrderServiceTests.swift", gen="Sources/App/Api.generated.swift", auth=True, path="/orders"),
}
LANGS = sorted(CFG)

work = tmp / "langs"
shutil.copytree(FX, work)
out = tmp / ".ckb"
for lang in LANGS:
    r = run("fetch_source.py", "--out", out, "--key", lang, work / lang)
    assert r.returncode == 0, r.stderr
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
res = json.loads(r.stdout)
check("all language fixtures build with no schema problems", r.returncode == 0 and not res["schema_problems"], r.stderr[-400:] + str(res.get("schema_problems")))
g = json.loads((out / "graph" / "graph.json").read_text())
N = {n["id"]: n for n in g["nodes"]}
cg = json.loads((out / "graph" / "callgraph.json").read_text())


def qn(n):
    return n.get("qualname", n["name"])


def edges(repo, kind):
    return {(qn(N[e["src"]]), qn(N[e["dst"]])) for e in g["edges"] if e["kind"] == kind and N.get(e["src"], {}).get("repo") == repo and e["dst"] in N and "test" not in (N[e["src"]].get("tags") or [])}


def lib_edges(repo):
    return {(qn(N[e["src"]]), N[e["dst"]]["name"]) for e in g["edges"] if e["kind"] == "calls_lib" and N.get(e["src"], {}).get("repo") == repo and e["dst"] in N}


for lang in LANGS:
    c = CFG[lang]
    nodes = [n for n in g["nodes"] if n.get("repo") == lang]
    names = {qn(n) for n in nodes if n["kind"] in ("function", "method")}
    classes = {n["name"] for n in nodes if n["kind"] == "class"}
    # 1 declarations
    check(f"[{lang}] 1 declarations: classes and qualified methods", {c["svc"], c["repo"]} <= names and (c["ctl"] in names or c["ctl"] in classes) and {c["svc"].split(".")[0], c["repo"].split(".")[0]} <= classes, (sorted(names), sorted(classes)))
    # 2 imports
    imp = {(N[e["src"]]["path"], N[e["dst"]]["path"]) for e in g["edges"] if e["kind"] == "imports" and N.get(e["src"], {}).get("repo") == lang and N.get(e["dst"], {}).get("kind") == "file"}
    missing = [p for p in c["imports"] if p not in imp]
    check(f"[{lang}] 2 imports: in-repo imports resolve to files", not missing, (missing, sorted(imp)))
    # 3 calls
    calls = edges(lang, "calls")
    check(f"[{lang}] 3 calls: controller -> service -> repository through typed receivers", any(a.endswith(c["ctl"]) and b == c["svc"] for a, b in calls) and (c["svc"], c["repo"]) in calls, sorted(calls))
    # 4 objects and classes
    ov = edges(lang, "overrides")
    check(f"[{lang}] 4 objects: override edge, uses_type, class-level call graph", (c["repo"], c["base"]) in ov
          and any(b == c["repo"].split(".")[0] for a, b in edges(lang, "uses_type"))
          and any(N[r["src"]]["name"] == c["svc"].split(".")[0] and N[r["dst"]]["name"] == c["repo"].split(".")[0] for r in cg["class"]["edges"] if N.get(r["src"], {}).get("repo") == lang or True), (sorted(ov), sorted(edges(lang, "uses_type"))[:6]))
    if c.get("implements"):
        check(f"[{lang}] 4 objects: implements edge", c["implements"] in edges(lang, "implements"), sorted(edges(lang, "implements")))
    # 5 libraries
    check(f"[{lang}] 5 libraries: calls_lib edge to an external package", any(c["lib"] in pkg for _, pkg in lib_edges(lang)), sorted(lib_edges(lang)))
    # 6 entry points
    eps = {n["name"]: n for n in nodes if n["kind"] == "endpoint"} | {n["name"]: n for n in g["nodes"] if n["kind"] == "endpoint" and n.get("citation", "").startswith(lang + "/")}
    ep = eps.get("POST " + c["path"]) or next((n for k, n in eps.items() if k.startswith("POST") and k.endswith(c["path"])), None)
    bound = ep and {qn(N[e["dst"]]) for e in g["edges"] if e["kind"] == "routes_to" and e["src"] == ep["id"] and e["dst"] in N}
    check(f"[{lang}] 6 entry points: POST {c['path']} bound to its handler", bool(ep) and bool(bound) and any(x.endswith(c["ctl"]) or x == c["ctl"] for x in bound), (sorted(eps), bound))
    if c.get("extra_entry"):
        check(f"[{lang}] 6 entry points: second framework ({c['extra_entry']})", c["extra_entry"] in eps, sorted(eps))
    # 7 sources, 8 sinks
    check(f"[{lang}] 7 sources: user-controlled input", any(n["kind"] == "taint_source" and n["repo"] == lang and n["attrs"]["source_type"] == "http_param" for n in g["nodes"]))
    check(f"[{lang}] 8 sinks: string-built SQL is unsafe", any(n["kind"] == "sink" and n["repo"] == lang and n["attrs"]["sink_type"] == "sql" and not n["attrs"].get("safe") for n in g["nodes"]),
          [(n["attrs"]["sink_type"], n["attrs"].get("safe")) for n in g["nodes"] if n["kind"] == "sink" and n["repo"] == lang])
    # 9 auth evidence
    cf = json.loads((out / "evidence" / f"context-facts-{lang}.json").read_text())
    auths = {e["name"]: e["auth"] for e in cf["entry_points"] if e["kind"] == "endpoint"}
    check(f"[{lang}] 9 auth evidence: the route's auth marker is recognised", any(v == "yes" for k, v in auths.items() if k.endswith(c["path"])), auths)
    # 10 roles
    roles = {f["path"]: f["role"] for f in json.loads((out / "evidence" / f"file-roles-{lang}.json").read_text())["files"]}
    check(f"[{lang}] 10 roles: test and generated files", roles.get(c["test"]) == "test" and roles.get(c["gen"]) == "generated", {k: v for k, v in roles.items() if k in (c["test"], c["gen"])} or sorted(roles))
    check(f"[{lang}] 10 roles: nothing is extracted from the test or generated file", not [n for n in nodes if n["kind"] in ("sink", "endpoint", "taint_source") and n.get("citation", "").split("/", 1)[-1].rsplit(":", 1)[0] in (c["test"], c["gen"])])
    # 11 coverage (resolution accounting exists and the declared path resolved)
    summ = json.loads((out / "evidence" / f"call-resolution-{lang}.json").read_text())["summary"]
    check(f"[{lang}] 11 coverage: call resolution is accounted for", summ["calls"] >= 3 and summ["resolved"] >= 3 and summ["resolved_pct"] is not None, summ)

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
