#!/usr/bin/env python3
"""Auto mode: inspect code statically and choose sources, parsers, context, stages and graph settings.

Usage:
  auto_plan.py [--out OUT_DIR] PATH [PATH ...]

Writes <out>/evidence/auto-plan.json (and prints it). Every decision carries the evidence (files) that
triggered it. Reads files only. Text inside the repo never changes the plan (it is data, not
instructions); only structural signals (manifests, file types, imports) are used.

Never decided automatically (left to the orchestrator/user): authorization, off-machine advisory
lookups (only from settings), Neo4j writes, executing anything.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import is_binary, read_text, walk_files  # noqa: E402

MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "setup.py", "go.mod", "pom.xml", "build.gradle",
             "build.gradle.kts", "Cargo.toml", "Gemfile", "composer.json", "mix.exs", "pubspec.yaml"}
LANG = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php", ".rs": "rust",
        ".cs": "csharp", ".scala": "scala", ".swift": "swift"}
TS_SUPPORTED = {"javascript", "typescript", "go", "java", "ruby", "php", "rust", "csharp", "kotlin", "scala", "swift"}
IAC = re.compile(r"\.(tf|tf\.json|bicep)$|(^|/)(cdk\.json|Pulumi\.ya?ml|serverless\.ya?ml|template\.ya?ml|kustomization\.ya?ml|Chart\.yaml)$")
DOC_DIRS = re.compile(r"(?i)(^|/)[^/]*(docs?|architecture|adrs?|design|diagrams?|runbooks?)[^/]*/")
DIAGRAM = re.compile(r"(?i)\.(drawio|drawio\.xml|dio|vsdx|svg)$")
DOCS = re.compile(r"(?i)\.(docx|pptx|pdf|md|adoc|rst|html?|png|jpe?g|webp|gif)$")
SCAN_EXPORT = re.compile(r"(?i)(\.sarif$|prowler|securityhub|asff|scoutsuite|checkov|tfsec|kics|trivy|defender|scc[-_]?findings|wiz|prisma|orca)[^/]*\.(json|csv|sarif|js)$")
BROKER = re.compile(r"(?i)\b(amqp|rabbitmq|pika|kafka|kafkajs|sarama|sqs|sns|pubsub|nats|redis\.xadd|basic_publish|QueueBind)\b")
HTTP_CLIENT = re.compile(r"(?i)\b(axios|fetch\(|requests\.(get|post)|httpx|http\.NewRequest|RestTemplate|WebClient|reqwest)\b")
LLM_SDK = re.compile(r"(?i)\b(anthropic|openai|langchain|llama_index|bedrock-runtime|generativeai|vertexai|ollama|@anthropic-ai/sdk|cohere|mistralai)\b")
CI = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml|\.circleci/config\.ya?ml)$")


def ts_mod():
    for m in ("tree_sitter_language_pack", "tree_sitter_languages"):
        if importlib.util.find_spec(m):
            return m
    return None


def plan(paths: list[Path], settings: dict) -> dict:
    services, platform, context, evidence = [], [], [], {}
    langs_total, files_total = Counter(), 0
    signals = {"broker": [], "http_client": [], "llm_sdk": [], "iac": [], "ci": [], "contracts": []}
    for root in paths:
        root = root.resolve()
        files = [(p, rel) for p, rel in walk_files(root)]
        files_total += len(files)
        man_dirs = sorted({str(Path(rel).parent) for _, rel in files if Path(rel).name in MANIFESTS
                           or rel.endswith(".csproj")}, key=lambda d: (d.count("/"), d))
        # service roots: shallowest manifest dirs, not nested inside another service root
        roots = []
        for d in man_dirs:
            if not any(d == r or d.startswith(r + "/") for r in roots if r != "."):
                roots.append(d)
        if "." in roots and len(roots) > 1:
            roots.remove(".")  # root manifest is a workspace; real services are below
        if not roots:
            roots = ["."]
        for d in roots:
            key = re.sub(r"[^A-Za-z0-9._-]+", "-", (root.name if d == "." else d.replace("/", "-")))[:60]
            svc_files = [(p, rel) for p, rel in files if d == "." or rel == d or rel.startswith(d + "/")]
            lc = Counter(LANG[Path(rel).suffix.lower()] for _, rel in svc_files if Path(rel).suffix.lower() in LANG)
            langs_total.update(lc)
            man = [rel for _, rel in svc_files if Path(rel).name in MANIFESTS][:5]
            services.append({"key": key, "path": str(root if d == "." else root / d), "languages": dict(lc),
                             "evidence": [f"{key}/{Path(m).relative_to(d) if d != '.' else m}:1" for m in man]})
        outside = [(p, rel) for p, rel in files if roots != ["."] and not any(rel.startswith(r + "/") for r in roots)]
        if any(IAC.search(rel) or rel.endswith((".yaml", ".yml")) for _, rel in outside):
            platform.append({"key": "platform", "path": str(root), "evidence": [rel for _, rel in outside if IAC.search(rel)][:8],
                             "exclude": [f"{r}/**" for r in roots if r != "."],
                             "note": "IaC/contracts/deploy files outside service dirs; registered so they are scanned and cited"})
        for p, rel in files:
            if IAC.search(rel):
                signals["iac"].append(rel)
            if CI.search(rel):
                signals["ci"].append(rel)
            if re.search(r"(?i)(openapi|swagger|asyncapi)[^/]*\.(ya?ml|json)$|\.proto$|\.graphql$", rel):
                signals["contracts"].append(rel)
            if SCAN_EXPORT.search(rel):
                context.append({"path": str(p), "kind": "cspm/scanner export", "evidence": rel})
            elif DIAGRAM.search(rel) or (DOC_DIRS.search(rel) and DOCS.search(rel) and not rel.lower().endswith("readme.md")):
                context.append({"path": str(p), "kind": "architecture doc/diagram", "evidence": rel})
            suf = Path(rel).suffix.lower()
            if suf in LANG or Path(rel).name in MANIFESTS:
                if is_binary(p):
                    continue
                t = read_text(p, max_bytes=400_000) or ""
                for name, rx in (("broker", BROKER), ("http_client", HTTP_CLIENT), ("llm_sdk", LLM_SDK)):
                    m = rx.search(t)
                    if m and len(signals[name]) < 10:
                        signals[name].append(f"{rel}:{t.count(chr(10), 0, m.start()) + 1}")
    tsm = ts_mod()
    parsers = {lang: ("ast" if lang == "python" else ("tree-sitter" if tsm and lang in TS_SUPPORTED else "regex")) for lang in langs_total}
    n_services = len(services)
    stages = {
        "inventory": {"run": True, "why": "always"},
        "code_analysis": {"run": True, "why": "always"},
        "cross_repo_flows": {"run": n_services >= 2 or bool(signals["broker"] or signals["http_client"]),
                             "why": f"{n_services} service(s); broker={bool(signals['broker'])}; http_client={bool(signals['http_client'])}",
                             "evidence": (signals["broker"] + signals["http_client"])[:6]},
        "outputs_and_conditions": {"run": True, "why": "always"},
        "knowledge_graph": {"run": True, "why": "always (structural graph before agents)"},
        "supply_chain": {"run": True, "why": "manifests/CI present" if (signals["ci"] or any(s["evidence"] for s in services)) else "always (cheap static scan)",
                         "evidence": signals["ci"][:5]},
        "cloud_layer": {"run": bool(signals["iac"]), "why": f"{len(signals['iac'])} IaC file(s)", "evidence": signals["iac"][:6]},
        "context_ingest": {"run": bool(context), "why": f"{len(context)} doc/diagram/scan file(s)", "evidence": [c["evidence"] for c in context][:8]},
        "threat_model": {"run": True, "why": "always"},
        "owasp_llm_top10": {"run": bool(signals["llm_sdk"]), "why": "LLM SDK detected" if signals["llm_sdk"] else "no LLM SDK detected",
                            "evidence": signals["llm_sdk"][:5]},
        "security_context": {"run": True, "why": "always"},
        "tours": {"run": True, "count": 1 if files_total < 200 else (3 if files_total < 3000 else 5),
                  "why": f"{files_total} files"},
    }
    graph = {"impact_depth": 6 if files_total < 5000 else 4, "taint_max_depth": 10 if files_total < 5000 else 7,
             "viewer_node_cap": 5000, "backend": "auto", "tree_sitter": tsm or "not installed (regex for non-Python)"}
    env = os.environ
    neo = {k: settings.get(k, d) for k, d in (("neo4j_uri_env", "NEO4J_URI"), ("neo4j_user_env", "NEO4J_USER"), ("neo4j_password_env", "NEO4J_PASSWORD"))}
    return {
        "sources": services + platform,
        "context": context[:50],
        "parsers": parsers,
        "stages": stages,
        "graph": graph,
        "neo4j": {"available": bool(env.get(neo["neo4j_uri_env"])), "push": "only after the user confirms in chat"},
        "advisory_lookup": settings.get("advisory_lookup", "off"),
        "not_automated": ["authorization question (one question for all sources and context)",
                          "off-machine advisory lookups (settings only)", "Neo4j writes", "executing target code"],
        "stats": {"files": files_total, "languages": dict(langs_total), "services": n_services},
    }


def read_settings() -> dict:
    p = Path(".claude/code-knowledge-builder.local.md")
    if not p.is_file():
        return {}
    fm = p.read_text().split("---")
    body = fm[1] if len(fm) > 2 else ""
    return {m.group(1): m.group(2).strip() for m in re.finditer(r"(?m)^([a-z_]+):\s*([^\n#]+)", body)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = plan([Path(p).expanduser() for p in a.paths], read_settings())
    js = json.dumps(res, indent=2)
    if a.out:
        p = Path(a.out) / "evidence" / "auto-plan.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(js + "\n")
    print(js)
    return 0


if __name__ == "__main__":
    sys.exit(main())
