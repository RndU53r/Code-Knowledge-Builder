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
    # 0.7.0
    "c":          dict(ctl="create_order_handler", svc="place_order", repo="save_order", base=None, lib="curl", imports=[("src/main.c", "src/handlers.h"), ("src/handlers.c", "src/service.h"), ("src/service.c", "src/repo.h")],
                       test="tests/test_service.c", gen="src/order.pb.h", auth=True, path="/orders", method="ANY", procedural=True, extra_sinks=("memory",), extra_entry="signal handler on_term"),
    "cpp":        dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="Repo.save", lib="httplib", imports=[("src/order_controller.cpp", "src/order_controller.h"), ("src/order_service.cpp", "src/order_service.h")],
                       test="tests/order_service_test.cpp", gen="src/order.pb.cc", auth=True, path="/orders"),
    "dart":       dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="http", imports=[("lib/controller.dart", "lib/service.dart"), ("lib/service.dart", "lib/repo.dart")],
                       test="test/service_test.dart", gen="lib/api.g.dart", auth=True, path="/orders"),
    "perl":       dict(ctl="OrderController.create", svc="OrderService.place", repo="OrderRepo.save", base="BaseRepo.save", lib="LWP", imports=[("lib/Shop/OrderController.pm", "lib/Shop/OrderService.pm"), ("lib/Shop/OrderService.pm", "lib/Shop/OrderRepo.pm")],
                       test="t/service.t", gen="lib/Shop/Api.pm", auth=True, path="/orders"),
    "abap":       dict(ctl="zcl_order_controller.if_rest_resource~post", svc="zcl_order_service.place", repo="zcl_order_repo.save", base="zcl_base_repo.save", lib="cl_http_client", imports=[],
                       test="src/zcl_order_service.clas.testclasses.abap", gen="src/zcl_zorders_mpc.clas.abap", auth=True, path="/orders", method="ANY", implements=("zcl_order_repo", "zif_repo"), extra_sinks=("ssrf",)),
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
    if c.get("procedural"):  # C has no classes: functions are the units
        check(f"[{lang}] 1 declarations: functions", {c["svc"], c["repo"], c["ctl"]} <= names, sorted(names))
    else:
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
    if c.get("procedural"):
        refs = edges(lang, "references")
        check(f"[{lang}] 4 objects: callback registration becomes a references edge", any(b == c["ctl"] for a, b in refs) or any(b == c["ctl"] for a, b in {(qn(N[e["src"]]), qn(N[e["dst"]])) for e in g["edges"] if e["kind"] == "references" and e["dst"] in N and N.get(e["src"], {}).get("repo") == lang}), sorted(refs))
    else:
      check(f"[{lang}] 4 objects: override edge, uses_type, class-level call graph", (c["repo"], c["base"]) in ov
          and any(b == c["repo"].split(".")[0] for a, b in edges(lang, "uses_type"))
          and any(N[r["src"]]["name"] == c["svc"].split(".")[0] and N[r["dst"]]["name"] == c["repo"].split(".")[0] for r in cg["class"]["edges"] if N.get(r["src"], {}).get("repo") == lang or True), (sorted(ov), sorted(edges(lang, "uses_type"))[:6]))
    if c.get("implements"):
        check(f"[{lang}] 4 objects: implements edge", c["implements"] in edges(lang, "implements"), sorted(edges(lang, "implements")))
    # 5 libraries
    check(f"[{lang}] 5 libraries: calls_lib edge to an external package", any(c["lib"] in pkg for _, pkg in lib_edges(lang)), sorted(lib_edges(lang)))
    # 6 entry points
    eps = {n["name"]: n for n in nodes if n["kind"] == "endpoint"} | {n["name"]: n for n in g["nodes"] if n["kind"] == "endpoint" and n.get("citation", "").startswith(lang + "/")}
    verb = c.get("method", "POST")
    ep = eps.get(verb + " " + c["path"]) or next((n for k, n in eps.items() if k.startswith(verb) and k.endswith(c["path"])), None)
    bound = ep and {qn(N[e["dst"]]) for e in g["edges"] if e["kind"] == "routes_to" and e["src"] == ep["id"] and e["dst"] in N}
    check(f"[{lang}] 6 entry points: {verb} {c['path']} bound to its handler", bool(ep) and bool(bound) and any(x.endswith(c["ctl"]) or x == c["ctl"] for x in bound), (sorted(eps), bound))
    if c.get("extra_entry"):
        ent_names = {n["name"] for n in g["nodes"] if n["kind"] in ("endpoint", "consumer", "cli_command", "cron_job") and n.get("repo") == lang}
        check(f"[{lang}] 6 entry points: second framework ({c['extra_entry']})", c["extra_entry"] in eps or c["extra_entry"] in ent_names, sorted(ent_names))
    # 7 sources, 8 sinks
    check(f"[{lang}] 7 sources: user-controlled input", any(n["kind"] == "taint_source" and n["repo"] == lang and n["attrs"]["source_type"] == "http_param" for n in g["nodes"]))
    check(f"[{lang}] 8 sinks: string-built SQL is unsafe", any(n["kind"] == "sink" and n["repo"] == lang and n["attrs"]["sink_type"] == "sql" and not n["attrs"].get("safe") for n in g["nodes"]),
          [(n["attrs"]["sink_type"], n["attrs"].get("safe")) for n in g["nodes"] if n["kind"] == "sink" and n["repo"] == lang])
    for st in c.get("extra_sinks", ()):
        check(f"[{lang}] 8 sinks: {st} sink is found", any(n["kind"] == "sink" and n["repo"] == lang and n["attrs"]["sink_type"] == st for n in g["nodes"]),
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

# ---- framework variants for the 0.7.0 languages: entry points, sources and sinks beyond the conformance scenario
FW = ROOT / "tests" / "fixtures" / "frameworks"
out2 = tmp / ".ckb-fw"
fwk = {"c": "fwc", "cpp": "fwcpp", "dart": "fwdart", "perl": "fwperl", "abap": "fwabap"}
for lang, key in fwk.items():
    r = run("fetch_source.py", "--out", out2, "--key", key, FW / lang)
    assert r.returncode == 0, r.stderr
r = run("graph_build.py", "--out", out2, "--extract", "--enrich")
check("framework fixtures build with no schema problems", r.returncode == 0 and not json.loads(r.stdout)["schema_problems"], r.stderr[-300:])
g2 = json.loads((out2 / "graph" / "graph.json").read_text())
EXPECT = {
    "fwc": {"entries": {"ANY /api/orders", "POST /items", "ANY /api/v1/stock", "ANY /nginx/ngx_http_orders_handler", "main", "command line options"}, "sinks": {"command", "format"}, "sources": {"http_param", "cli_arg"}},
    "fwcpp": {"entries": {"POST /orders", "GET /items", "POST /stock", "POST /api/orders", "POST /users", "GRPC /Order/Create"}, "sinks": {"command"}, "sources": {"http_param"}},
    "fwdart": {"entries": {"ANY /orders", "GET /orders", "GET /settings", "POST /shelf/orders", "RPC /orders/create"}, "sinks": set(), "sources": set()},
    "fwperl": {"entries": {"POST /orders", "GET /items", "ANY /orders", "ANY /list", "ANY /", "script lite.pl"}, "sinks": {"command"}, "sources": {"http_param"}},
    "fwabap": {"entries": {"ANY /sap/bc/zcl_handler", "RFC /z_get_order", "ODATA /orderset_create_entity", "report start-of-selection"}, "sinks": {"sql", "code", "path", "command"}, "sources": {"http_param", "rfc_param"}},
}
for key, exp in EXPECT.items():
    ents = {n["name"] for n in g2["nodes"] if n["kind"] in ("endpoint", "cli_command", "consumer", "cron_job") and n.get("repo") == key}
    check(f"[{key}] frameworks: entry points {sorted(exp['entries'] - ents) or 'all found'}", exp["entries"] <= ents, sorted(ents))
    sk = {n["attrs"]["sink_type"] for n in g2["nodes"] if n["kind"] == "sink" and n["repo"] == key and not n["attrs"].get("safe")}
    check(f"[{key}] frameworks: sinks {sorted(exp['sinks'])}", exp["sinks"] <= sk, sorted(sk))
    so = {n["attrs"]["source_type"] for n in g2["nodes"] if n["kind"] == "taint_source" and n["repo"] == key}
    check(f"[{key}] frameworks: sources {sorted(exp['sources'])}", exp["sources"] <= so, sorted(so))
chan = [n for n in g2["nodes"] if n["kind"] == "topic" and n["name"] == "channel:com.acme/orders"]
check("Flutter platform channel becomes a shared node the native side can meet", bool(chan), [n["name"] for n in g2["nodes"] if n["kind"] == "topic"])

# ---- hostile inputs: the new parsers must stay linear on pathological files and never crash
import time

hostile = tmp / "hostile"
(hostile / "src").mkdir(parents=True)
TQ3 = "'" * 3
BIG = {
    "a.c": "int " + "f(" * 20000 + "\n" + "struct x {\n" * 3000 + "/* never closed\n" + "evhttp_set_cb(" * 500 + "\n",
    "b.cpp": "template<" * 5000 + "\nclass " + "A" * 30000 + " : public " + "B," * 5000 + " {\n" + ("void a::b(" + "(" * 40 + "\n") * 400 + "std::string " + "x(" * 8000 + "\n",
    "c.dart": TQ3 + "x" * 50000 + "\nclass A extends " + "B<" * 5000 + " {\n" + "Future<" * 3000 + " f(" * 3000 + "\n",
    "d.pm": "=pod\n" + "package " + "A::" * 20000 + "B;\n" + "sub " + "x" * 30000 + " {\n" + "$self->" + "{a}->" * 8000 + "m(\n",
    "e.abap": "CLASS " + "z" * 30000 + " DEFINITION.\n" + "METHOD m.\n" * 3000 + "SELECT * FROM x WHERE (" + "a" * 30000 + ").\n" + "lo->" * 8000 + "m( \n",
}
for name, body in BIG.items():
    (hostile / "src" / name).write_text(body)
r = run("fetch_source.py", "--out", out, "--key", "hostile", hostile)
assert r.returncode == 0, r.stderr
t0 = time.time()
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
elapsed = time.time() - t0
check("hostile C/C++/Dart/Perl/ABAP files are processed in bounded time without crashing", r.returncode == 0 and elapsed < 90, (round(elapsed, 1), r.stderr[-300:]))


# ---- regressions found in review: no silent coverage inflation
reg = tmp / "regress"
for sub, files in {
    "py": {"a.py": "from abc import ABC\n\nclass Svc(ABC):\n    def run(self):\n        self.missing_helper()\n"},
    "c": {"a.c": "#include <curl/curl.h>\nint check(int q) { return q; }\nint run(int p, int q) {\n    if (p && check(q)) { return 1; }\n    totally_missing(p);\n    snprintf(buf, n, \"%d\", p);\n    return 0;\n}\n"},
    "pl": {"A.pm": "package A;\n# &old_commented(1)\nsub x { my ($s) = @_; return 1 }\n1;\n"},
    "abap": {"z.abap": "CLASS zc DEFINITION.\nENDCLASS.\nCLASS zc IMPLEMENTATION.\n  METHOD m.\n    NEW zc( ).\n* CALL FUNCTION 'BAPI_OLD'.\n  ENDMETHOD.\nENDCLASS.\n"},
}.items():
    (reg / sub).mkdir(parents=True)
    for fn, body in files.items():
        (reg / sub / fn).write_text(body)
    r = run("fetch_source.py", "--out", out, "--key", "rg" + sub, reg / sub)
    assert r.returncode == 0, r.stderr
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
g3 = json.loads((out / "graph" / "graph.json").read_text())
N3 = {n["id"]: n for n in g3["nodes"]}
libs = {(N3[e["src"]]["repo"], N3[e["dst"]]["name"]) for e in g3["edges"] if e["kind"] == "calls_lib" and e["dst"] in N3}
check("an unresolved self call in a class with an unresolved base is not turned into a library call", not any(rp == "rgpy" for rp, _ in libs), sorted(x for x in libs if x[0] == "rgpy"))
cs = {x["name"] for x in json.loads((out / "evidence" / "call-resolution-rgc.json").read_text()).get("top_unresolved", [])}
check("a call after && is recorded, and a single-library guess stays counted as unresolved", {"totally_missing"} <= cs and not any("check" == x for x in cs), cs)
check("snprintf with a literal format is not a format-string sink", not [n for n in g3["nodes"] if n["kind"] == "sink" and n["repo"] == "rgc" and n["attrs"]["sink_type"] == "format"])
summ = json.loads((out / "evidence" / "call-resolution-rgpl.json").read_text())["summary"]
check("a commented-out Perl call is not counted", summ["calls"] == 0, summ)
summ = json.loads((out / "evidence" / "call-resolution-rgabap.json").read_text())["summary"]
check("ABAP NEW is a counted call and a commented-out CALL FUNCTION is not", summ["calls"] == 1, summ)

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
