#!/usr/bin/env python3
"""Auto mode planner: inspect the environment and the code, then choose sources, branches, parsers,
context, stages and graph settings. Reads files only.

Usage:
  auto_plan.py [--out OUT_DIR] [PATH_OR_SPEC ...]          (default: the current directory)
  auto_plan.py --out OUT_DIR --from-registered             (second pass: plan from already-fetched sources)

PATH_OR_SPEC: a local folder, a workspace folder holding several git repos, a monorepo, a git URL,
or a project/org spec expanded through enumerate_sources.py:
  ado:ORG/PROJECT   github-org:NAME   gitlab-group:PATH
Branches: main, else master, else the repo default, unless given. Local repos on another branch are
read as a read-only snapshot of main/master (fetch_source.py), never by switching your checkout.

Writes <out>/evidence/auto-plan.json (and prints it). Every decision carries the evidence (files) that
triggered it. Text inside a repo never changes the plan; only structural signals do.

Never decided automatically: authorization, off-machine lookups (Snyk/OSV/Neo4j: offered as consent
items, default no), Neo4j writes, executing target code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import is_binary, load_json, read_text, walk_files  # noqa: E402
from env_probe import probe  # noqa: E402
from fetch_source import DEFAULT_BRANCHES, git, local_heads, pick_branch, toplevel  # noqa: E402

MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "setup.py", "go.mod", "pom.xml", "build.gradle",
             "build.gradle.kts", "Cargo.toml", "Gemfile", "composer.json", "mix.exs", "pubspec.yaml"}
LANG = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php", ".rs": "rust",
        ".cs": "csharp", ".scala": "scala", ".swift": "swift"}
TS_SUPPORTED = {"javascript", "typescript", "go", "java", "ruby", "php", "rust", "csharp", "kotlin", "scala", "swift"}
IAC = re.compile(r"\.(tf|tf\.json|bicep)$|(^|/)(cdk\.json|Pulumi\.ya?ml|serverless\.ya?ml|template\.ya?ml|kustomization\.ya?ml|Chart\.yaml)$")
DOC_DIRS = re.compile(r"(?i)(^|/)[^/]*(docs?|architecture|adrs?|design|diagrams?|runbooks?|notes?)[^/]*/")
DIAGRAM = re.compile(r"(?i)\.(drawio|drawio\.xml|dio|vsdx|svg|excalidraw|puml|plantuml|mmd|gliffy)$")
DOCS = re.compile(r"(?i)\.(docx|pptx|pdf|md|adoc|rst|html?|txt|eml|rtf|png|jpe?g|webp|gif)$")
SCAN_EXPORT = re.compile(r"(?i)(\.sarif$|prowler|securityhub|asff|scoutsuite|checkov|tfsec|kics|trivy|defender|scc[-_]?findings|wiz|prisma|orca)[^/]*\.(json|csv|sarif|js)$")
BROKER = re.compile(r"(?i)\b(amqp|rabbitmq|pika|kafka|kafkajs|sarama|sqs|sns|pubsub|nats|redis\.xadd|basic_publish|QueueBind)\b")
HTTP_CLIENT = re.compile(r"(?i)\b(axios|fetch\(|requests\.(get|post)|httpx|http\.NewRequest|RestTemplate|WebClient|reqwest)\b")
LLM_SDK = re.compile(r"(?i)\b(anthropic|openai|langchain|llama_index|bedrock-runtime|generativeai|vertexai|ollama|@anthropic-ai/sdk|cohere|mistralai)\b")
CI = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml|\.circleci/config\.ya?ml)$")
REMOTE_SPEC = re.compile(r"^(ado|github-org|gitlab-group):")
SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")
SKIP_DIRS = {"node_modules", "vendor", ".venv", "venv", "dist", "build", "__pycache__", ".git"}


def ts_mod():
    for m in ("tree_sitter_language_pack", "tree_sitter_languages"):
        import importlib.util
        if importlib.util.find_spec(m):
            return m
    return None


# ---------------------------------------------------------------- local repo discovery

def has_git(p: Path) -> bool:
    return (p / ".git").exists()


def find_workspace_repos(path: Path, cap: int) -> list[Path]:
    """A folder with several git repos as children (e.g. a checked-out ADO project) -> those repos."""
    if has_git(path) or any((path / m).exists() for m in MANIFESTS):
        return []
    kids = sorted(c for c in path.iterdir() if c.is_dir() and c.name not in SKIP_DIRS and not c.name.startswith(".") and has_git(c))
    return kids[:cap] if len(kids) >= 2 else []


def git_plan(path: Path, explicit_ref: str | None = None) -> dict:
    """Read-only prediction of how fetch_source.py will treat a local path."""
    top = toplevel(path)
    if top is None:
        return {"git": False, "source_mode": "in-place", "note": "not a git repository: analyzed as it is on disk"}
    cur = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=top, check=False).stdout.strip()
    heads = local_heads(top)
    branch, how = pick_branch(heads, explicit_ref)
    base = {"git": True, "toplevel": str(top), "checked_out_branch": cur, "branches": sorted(heads)[:20]}
    if branch is None:
        return {**base, "source_mode": "in-place", "note": "no main/master branch: analyzed in place"}
    if explicit_ref and explicit_ref not in heads:
        return {**base, "source_mode": "error", "note": f"branch {explicit_ref!r} not found"}
    if cur == branch:
        return {**base, "ref": branch, "ref_source": how, "source_mode": "in-place", "note": f"checked out on {branch}"}
    return {**base, "ref": branch, "ref_source": how, "source_mode": "snapshot",
            "note": f"checked out on {cur}; reading a read-only snapshot of {branch} (checkout untouched; uncommitted work excluded)"}


# ---------------------------------------------------------------- analysis of one root

def scan_root(root: Path, excludes: list[str]):
    files = [(p, rel) for p, rel in walk_files(root, excludes)]
    return files


def service_roots(files) -> list[str]:
    man_dirs = sorted({str(Path(rel).parent) for _, rel in files if Path(rel).name in MANIFESTS or rel.endswith(".csproj")},
                      key=lambda d: (d.count("/"), d))
    roots = []
    for d in man_dirs:
        if not any(d == r or d.startswith(r + "/") for r in roots if r != "."):
            roots.append(d)
    if "." in roots and len(roots) > 1:
        roots.remove(".")  # a root manifest alongside real services is a workspace file
    return roots or ["."]


def collect_signals(files, signals, context, with_context=True):
    for p, rel in files:
        if IAC.search(rel):
            signals["iac"].append(rel)
        if CI.search(rel):
            signals["ci"].append(rel)
        if re.search(r"(?i)(openapi|swagger|asyncapi)[^/]*\.(ya?ml|json)$|\.proto$|\.graphql$", rel):
            signals["contracts"].append(rel)
        if with_context:
            if SCAN_EXPORT.search(rel):
                context.append({"path": str(p), "kind": "cspm/scanner export", "evidence": rel})
            elif DIAGRAM.search(rel) or (DOC_DIRS.search(rel) and DOCS.search(rel) and not rel.lower().endswith("readme.md")):
                context.append({"path": str(p), "kind": "architecture doc/diagram/notes", "evidence": rel})
        suf = Path(rel).suffix.lower()
        if suf in LANG or Path(rel).name in MANIFESTS:
            if is_binary(p):
                continue
            t = read_text(p, max_bytes=400_000) or ""
            for name, rx in (("broker", BROKER), ("http_client", HTTP_CLIENT), ("llm_sdk", LLM_SDK)):
                m = rx.search(t)
                if m and len(signals[name]) < 10:
                    signals[name].append(f"{rel}:{t.count(chr(10), 0, m.start()) + 1}")


def unique(key: str, taken: set, prefix: str = "") -> str:
    k = SAFE_KEY.sub("-", key)[:60] or "repo"
    if k in taken and prefix:
        k = f"{SAFE_KEY.sub('-', prefix)}-{k}"[:60]
    base, n = k, 2
    while k in taken:
        k = f"{base}-{n}"
        n += 1
    taken.add(k)
    return k


def plan_local(paths: list[Path], settings: dict, ref: str | None):
    sources, context = [], []
    signals = {"broker": [], "http_client": [], "llm_sdk": [], "iac": [], "ci": [], "contracts": []}
    langs_total, files_total, taken = Counter(), 0, set()
    workspaces, cap = [], int(settings.get("auto_max_repos", 50) or 50)
    expanded = []
    for p in paths:
        p = p.resolve()
        if not p.is_dir():
            raise SystemExit(f"not a directory: {p}")
        repos = find_workspace_repos(p, cap)
        if repos:
            workspaces.append({"path": str(p), "repos": [r.name for r in repos], "note": "folder of git repos: each is a source"})
            expanded += repos
        else:
            expanded.append(p)
    multi = len(expanded) > 1
    for root in expanded:
        files = scan_root(root, [])
        files_total += len(files)
        roots = service_roots(files)
        gp = git_plan(root, ref)
        for d in roots:
            raw = root.name if d == "." else d.replace("/", "-")
            key = unique(raw, taken, prefix=root.name if multi and d != "." else "")
            svc_files = [(p, rel) for p, rel in files if d == "." or rel == d or rel.startswith(d + "/")]
            lc = Counter(LANG[Path(rel).suffix.lower()] for _, rel in svc_files if Path(rel).suffix.lower() in LANG)
            langs_total.update(lc)
            man = [rel for _, rel in svc_files if Path(rel).name in MANIFESTS][:5]
            path = str(root if d == "." else root / d)
            args = ["--key", key, path] + (["--ref", ref] if ref else [])
            sources.append({"key": key, "path": path, "kind": "local", "languages": dict(lc), "git": gp,
                            "evidence": [f"{key}/{Path(m).relative_to(d) if d != '.' else m}:1" for m in man], "fetch_args": args})
        outside = [(p, rel) for p, rel in files if roots != ["."] and not any(rel.startswith(r + "/") for r in roots)]
        if roots != ["."] and any(IAC.search(rel) or rel.endswith((".yaml", ".yml")) for _, rel in outside):
            key = unique("platform", taken, prefix=root.name if multi else "")
            excl = [f"{r}/**" for r in roots if r != "."]
            sources.append({"key": key, "path": str(root), "kind": "local", "role": "platform", "git": gp, "exclude": excl,
                            "evidence": [rel for _, rel in outside if IAC.search(rel)][:8],
                            "note": "IaC/contracts/deploy files outside service dirs; registered so they are scanned and cited",
                            "fetch_args": ["--key", key, str(root)] + sum((["--exclude", g] for g in excl), []) + (["--ref", ref] if ref else [])})
        collect_signals(files, signals, context)
    return sources, context, signals, langs_total, files_total, workspaces


def plan_registered(out: Path):
    """Second pass: plan from sources already registered (and fetched) by fetch_source.py."""
    targets = load_json(out / "evidence" / "targets.json", {"repos": {}}).get("repos", {})
    sources, context = [], []
    signals = {"broker": [], "http_client": [], "llm_sdk": [], "iac": [], "ci": [], "contracts": []}
    langs_total, files_total = Counter(), 0
    ctx_keys = [k for k in targets if k.startswith("ctx")]
    for key, meta in sorted(targets.items()):
        if key.startswith("ctx"):
            continue
        root = Path(meta["root"])
        files = scan_root(root, meta.get("exclude", []))
        files_total += len(files)
        lc = Counter(LANG[Path(rel).suffix.lower()] for _, rel in files if Path(rel).suffix.lower() in LANG)
        langs_total.update(lc)
        sources.append({"key": key, "path": str(root), "kind": meta.get("kind"), "languages": dict(lc), "ref": meta.get("ref"),
                        "source_mode": meta.get("source_mode"), "exclude": meta.get("exclude", []), "registered": True,
                        "evidence": [f"{key}/{rel}:1" for _, rel in files if Path(rel).name in MANIFESTS][:5]})
        collect_signals(files, signals, context, with_context=not ctx_keys)
    return sources, context, signals, langs_total, files_total, [], ctx_keys


# ---------------------------------------------------------------- remote specs

def plan_remote(specs: list[str], a) -> tuple[list[dict], list[dict], list[dict]]:
    sources, skipped, errors = [], [], []
    if not specs:
        return sources, skipped, errors
    cmd = [sys.executable, str(HERE / "enumerate_sources.py"), *specs, "--max-repos", str(a.max_repos)]
    for g in a.include:
        cmd += ["--include", g]
    for g in a.exclude:
        cmd += ["--exclude", g]
    if a.include_forks:
        cmd.append("--include-forks")
    for flag, val in (("--api-base", a.api_base), ("--gitlab-base", a.gitlab_base), ("--token-env", a.token_env)):
        if val:
            cmd += [flag, val]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        res = json.loads(r.stdout)
    except ValueError:
        return [], [], [{"spec": ",".join(specs), "error": (r.stderr or "enumeration failed")[:300]}]
    for s in res.get("sources", []):
        args = [s["source"], "--key", s["key"]]
        if s.get("gitlab_base"):
            args += ["--gitlab-base", s["gitlab_base"]]
        if a.token_env:
            args += ["--token-env", a.token_env]
        sources.append({"key": s["key"], "path": s["source"], "kind": "remote", "branch": s.get("branch"), "branch_source": s.get("branch_source"),
                        "default_branch": s.get("default_branch"), "origin": s["spec"], "auth": s.get("auth"),
                        "languages": {}, "evidence": [], "fetch_args": args,
                        "note": "languages and services are detected after fetch (second pass: auto_plan.py --from-registered)"})
    skipped = res.get("skipped", [])
    if res.get("capped"):
        errors.append({"spec": ",".join(specs), "error": f"capped at {a.max_repos} of {res.get('total_found')} repos; raise auto_max_repos or use --include"})
    return sources, skipped, errors


# ---------------------------------------------------------------- capabilities and consent

def capabilities(env: dict, parsers: dict, n_sources: int, remote: list[dict]) -> dict:
    t, tok, rt = env["tools"], env["tokens"], env["runtime"]
    caps = {
        "parsers": {lang: {"chosen": p, "why": ("stdlib ast" if p == "ast" else f"tree-sitter module {t['tree_sitter']['module']}" if p == "tree-sitter" else "tree-sitter not installed: regex fallback")}
                    for lang, p in parsers.items()},
        "pdf": {"chosen": "pdftotext" if t["pdftotext"]["available"] else "read-tool", "why": "poppler installed" if t["pdftotext"]["available"] else "no pdftotext: Claude reads PDFs page by page"},
        "images": {"chosen": "read-tool", "why": "images and scanned PDFs are described by Claude (context-reader agent)"},
        "git": {"available": t["git"]["available"], "version": t["git"].get("version")},
        "parallelism": {"chosen": max(1, min(rt["cpus"], 6, max(1, n_sources))), "why": f"{rt['cpus']} CPUs, {n_sources} source(s)"},
        "ci_mode": {"chosen": bool(rt["ci"]), "provider": rt["ci"]},
        "interactive": rt["interactive"],
    }
    hosts = {"github": any(tok["github"].values()), "gitlab": any(tok["gitlab"].values())}
    ado_auth = "az" if t["az"]["logged_in"] else ("pat" if any(tok["azure_devops"].values()) else "anonymous")
    caps["remote"] = {"github": {"token_present": hosts["github"]}, "gitlab": {"token_present": hosts["gitlab"]},
                      "azure_devops": {"auth": ado_auth, "why": "az CLI logged in" if ado_auth == "az" else "PAT env var present" if ado_auth == "pat" else "no az login or PAT: public projects only"}}
    caps["scratch_free_gb"] = rt["scratch_free_gb"]
    return caps


def consent_items(env: dict, settings: dict, has_manifests: bool, remote_sources: list[dict]) -> list[dict]:
    tok = env["tokens"]
    adv = (settings.get("advisory_lookup") or "off").lower()
    items = []
    if remote_sources:
        hosts = sorted({("dev.azure.com" if "dev.azure.com" in s["path"] or s["path"].startswith("ado:") else "github.com" if s["path"].startswith("github:") else "gitlab") for s in remote_sources})
        items.append({"id": "remote_clone", "what": f"clone {len(remote_sources)} repo(s) (shallow, hooks off)", "sends": f"git requests and your token/login to {', '.join(hosts)}",
                      "default": "yes", "required": True})
    if has_manifests:
        items.append({"id": "osv", "what": "OSV.dev vulnerability lookups for exactly pinned dependencies", "sends": "package names + versions to api.osv.dev",
                      "default": "no", "preconsented": adv in ("osv", "osv,snyk")})
    if all(tok["snyk"].values()):
        items.append({"id": "snyk", "what": "Snyk advisory lookups (SNYK_TOKEN and SNYK_ORG_ID are set)", "sends": "package names + versions to api.snyk.io",
                      "default": "no", "preconsented": adv in ("snyk", "osv,snyk")})
    if all(tok["neo4j"].values()):
        items.append({"id": "neo4j", "what": "push the graph to your Neo4j (NEO4J_* are set)", "sends": "the graph (names, paths, citations, summaries) to your Neo4j server",
                      "default": "no", "preconsented": False})
    return items


# ---------------------------------------------------------------- plan

def build_plan(sources, context, signals, langs_total, files_total, workspaces, ctx_keys, settings, env, skipped, errors, registered):
    n_services = len([s for s in sources if s.get("role") != "platform"])
    n_local_py = sum(1 for s in sources if "python" in s.get("languages", {}))
    tsm = ts_mod()
    parsers = {lang: ("ast" if lang == "python" else ("tree-sitter" if tsm and lang in TS_SUPPORTED else "regex")) for lang in langs_total}
    remote_unknown = any(s["kind"] == "remote" and not s["languages"] for s in sources)
    has_ctx = bool(context) or bool(ctx_keys)
    stages = {
        "inventory": {"run": True, "why": "always"},
        "code_analysis": {"run": True, "why": "always"},
        "cross_repo_flows": {"run": n_services >= 2 or bool(signals["broker"] or signals["http_client"]) or remote_unknown,
                             "why": f"{n_services} service(s); broker={bool(signals['broker'])}; http_client={bool(signals['http_client'])}",
                             "evidence": (signals["broker"] + signals["http_client"])[:6]},
        "outputs_and_conditions": {"run": True, "why": "always"},
        "knowledge_graph": {"run": True, "why": "always (structural graph before agents)"},
        "call_graphs": {"run": True, "why": "always: function, file and repo call graphs from the knowledge graph", "levels": ["function", "file", "repo"]},
        "repo_context": {"run": True, "why": "always: docstrings, READMEs, ADRs, API descriptions enrich the graph and context.md"},
        "supply_chain": {"run": True, "why": "manifests/CI present" if (signals["ci"] or any(s["evidence"] for s in sources)) else "always (cheap static scan)",
                         "evidence": signals["ci"][:5]},
        "cloud_layer": {"run": bool(signals["iac"]) or remote_unknown, "why": f"{len(signals['iac'])} IaC file(s)" + (" (re-evaluated after fetch)" if remote_unknown else ""),
                        "evidence": signals["iac"][:6]},
        "context_ingest": {"run": has_ctx, "why": f"{len(context)} doc/diagram/note/scan file(s)" + (f"; {len(ctx_keys)} context source(s) already ingested" if ctx_keys else ""),
                           "evidence": [c["evidence"] for c in context][:8]},
        "context_from_docs": {"run": has_ctx, "why": "doc_claims maps documented components/controls onto the graph and records drift candidates"},
        "threat_model": {"run": True, "why": "always: deterministic draft (threat_seed.py), then the threat-modeler agent refines it"},
        "owasp_llm_top10": {"run": bool(signals["llm_sdk"]), "why": "LLM SDK detected" if signals["llm_sdk"] else "no LLM SDK detected",
                            "evidence": signals["llm_sdk"][:5]},
        "security_context": {"run": True, "why": "always"},
        "tours": {"run": True, "count": 1 if files_total < 200 else (3 if files_total < 3000 else 5), "why": f"{files_total} files"},
    }
    graph = {"impact_depth": 6 if files_total < 5000 else 4, "taint_max_depth": 10 if files_total < 5000 else 7,
             "viewer_node_cap": 5000, "backend": "auto", "tree_sitter": tsm or "not installed (regex for non-Python)"}
    remote = [s for s in sources if s["kind"] == "remote"]
    has_manifests = any(s.get("evidence") for s in sources) or bool(remote)
    caps = capabilities(env, parsers, len(sources), remote)
    return {
        "sources": sources,
        "workspaces": workspaces,
        "context": context[:50],
        "context_sources_registered": ctx_keys,
        "parsers": parsers,
        "capabilities": caps,
        "stages": stages,
        "graph": graph,
        "consent": consent_items(env, settings, has_manifests, remote),
        "branch_rule": "main, else master, else the repo default, unless a branch is given; local repos on another branch are read as a read-only snapshot",
        "skipped": skipped,
        "warnings": errors,
        "second_pass": ("planned from registered sources" if registered else
                        "run `auto_plan.py --out <out> --from-registered` after fetching to finalize stages for remote sources" if remote_unknown else None),
        "advisory_lookup": settings.get("advisory_lookup", "off"),
        "not_automated": ["authorization question (one question for all sources, context paths and consent items)",
                          "off-machine lookups (Snyk, OSV, Neo4j) without a yes", "Neo4j writes", "executing target code"],
        "stats": {"files": files_total, "languages": dict(langs_total), "services": n_services, "python_services": n_local_py},
    }


def read_settings() -> dict:
    p = Path(".claude/code-knowledge-builder.local.md")
    if not p.is_file():
        return {}
    fm = p.read_text().split("---")
    body = fm[1] if len(fm) > 2 else ""
    return {m.group(1): m.group(2).strip() for m in re.finditer(r"(?m)^([a-z_0-9]+):\s*([^\n#]+)", body)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="folders or ado:/github-org:/gitlab-group: specs (default: current directory)")
    ap.add_argument("--out")
    ap.add_argument("--from-registered", action="store_true")
    ap.add_argument("--ref", help="branch to analyze (default: main, else master)")
    ap.add_argument("--include", action="append", default=[])
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--max-repos", type=int)
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--api-base")
    ap.add_argument("--gitlab-base")
    ap.add_argument("--token-env")
    a = ap.parse_args()
    settings = read_settings()
    a.max_repos = a.max_repos or int(settings.get("auto_max_repos", 50) or 50)
    a.include_forks = a.include_forks or settings.get("include_forks", "").lower() in ("true", "yes", "on")
    a.token_env = a.token_env or settings.get("ado_token_env") or None
    env = probe(None, None, [a.token_env] if a.token_env else None)
    skipped, errors, registered = [], [], False
    if a.from_registered:
        if not a.out:
            raise SystemExit("--from-registered needs --out")
        sources, context, signals, langs, files, workspaces, ctx_keys = plan_registered(Path(a.out))
        registered = True
    else:
        specs = [t for t in a.targets if REMOTE_SPEC.match(t)]
        local = [Path(t).expanduser() for t in a.targets if not REMOTE_SPEC.match(t)]
        if not a.targets:
            local = [Path(".")]
        sources, context, signals, langs, files, workspaces = ([], [], {k: [] for k in ("broker", "http_client", "llm_sdk", "iac", "ci", "contracts")}, Counter(), 0, [])
        ctx_keys = []
        if local:
            sources, context, signals, langs, files, workspaces = plan_local(local, settings, a.ref)
        rs, skipped, errors = plan_remote(specs, a)
        taken = {s["key"] for s in sources}
        for s in rs:
            s["key"] = unique(s["key"], taken)
        sources += rs
    res = build_plan(sources, context, signals, langs, files, workspaces, ctx_keys, settings, env, skipped, errors, registered)
    js = json.dumps(res, indent=2)
    if a.out:
        p = Path(a.out) / "evidence" / ("auto-plan-final.json" if registered else "auto-plan.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(js + "\n")
    print(js)
    return 0


if __name__ == "__main__":
    sys.exit(main())
