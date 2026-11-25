#!/usr/bin/env python3
"""Deterministic fact tables for each repo's context.md, built from the knowledge graph and evidence files.

Usage:
  context_facts.py --out OUT_DIR [--repo KEY]

Writes, per repo:
  <out>/evidence/context-facts-<repo>.json   counts and rows (machine-readable)
  <out>/repos/<repo>/context-facts.md        markdown tables between <!-- ckb:facts:begin ... --> / <!-- ckb:facts:end --> markers

The tables depend on the repo kind (evidence/file-roles-<repo>.json):
  application / service / library   code map, entry points (with auth evidence and exposure), taint sources, sinks
                                    (CWE, safe/unsafe verdict, entry points that reach each sink), known-safe patterns
  iac / gitops-config               provisioned resources with the scanner and CSPM findings against them
  cicd-pipeline                     pipelines: triggers, runners, secrets, third-party code and pinning, deploy steps and gates
  mixed                             every section that has content
The context skill embeds these blocks verbatim into context.md and adds judgement beside them (never over them);
check_outputs.py verifies the embedded counts against the facts JSON. Everything is [inferred] static analysis:
source-to-sink paths are candidates, not proven dataflow.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import now_iso, repo_roots_for_output  # noqa: E402
from graph_common import atomic_write, md_safe  # noqa: E402

ENTRY_KINDS = ("endpoint", "consumer", "cron_job", "cli_command")
CWE_OF = {"sql": "CWE-89", "command": "CWE-78", "ssrf": "CWE-918", "code": "CWE-94", "deserialization": "CWE-502", "template": "CWE-1336", "xss": "CWE-79",
          "path": "CWE-22", "redirect": "CWE-601", "nosql": "CWE-943", "ldap": "CWE-90", "xpath": "CWE-643", "xxe": "CWE-611"}
BEGIN = "<!-- ckb:facts:begin repo={repo} kind={kind} entry_points={ep} sources={src} sinks={snk} core_files={core} test_files={tst} -->"
END = "<!-- ckb:facts:end -->"
BEGIN_RX = re.compile(r"<!-- ckb:facts:begin repo=(\S+) kind=(\S+) entry_points=(\d+) sources=(\d+) sinks=(\d+) core_files=(\d+) test_files=(\d+) -->")


def cell(x, n: int = 90) -> str:
    return md_safe(str(x if x is not None else ""), n) or "-"


def path_of(n: dict) -> str:
    return n.get("path") or (n.get("citation", "").split("/", 1)[-1].rsplit(":", 1)[0] if n.get("citation") else "")


def gather(out: Path, repo: str, store, ctx) -> dict:
    nodes = store.nodes
    roles = {}
    rp = out / "evidence" / f"file-roles-{repo}.json"
    if rp.is_file():
        roles = json.loads(rp.read_text())
    kind = (roles.get("repo_kind") or {}).get("repo_kind") or "application"
    primary = (roles.get("repo_kind") or {}).get("primary_kind") or kind
    secondary = (roles.get("repo_kind") or {}).get("secondary_kinds", [])
    files = roles.get("files", [])
    handler = defaultdict(list)
    for e in store.edges:
        if e["kind"] == "routes_to":
            handler[e["src"]].append(e["dst"])
    src_into = defaultdict(list)
    for e in store.edges:
        if e["kind"] == "flows_to" and nodes.get(e["src"], {}).get("kind") == "taint_source":
            src_into[e["dst"]].append(nodes[e["src"]])
    reach = defaultdict(set)
    try:
        for p in store.taint(max_depth=10, limit=2000)["paths"]:
            reach[p["sink"]["id"]].add(nodes[p["source"]["id"]]["name"])
    except Exception:  # noqa: BLE001 - the tables still work without reachability
        pass

    def mine(n):
        return n.get("repo") == repo or (n["kind"] == "endpoint" and n.get("citation", "").startswith(repo + "/"))
    entries = []
    from threat_seed import HEALTH_RX, has_auth_evidence
    for n in sorted((n for n in nodes.values() if n["kind"] in ENTRY_KINDS and mine(n)), key=lambda n: (n["kind"], n["citation"])):
        hs = handler.get(n["id"], [])
        a = n.get("attrs") or {}
        if n["kind"] == "endpoint":
            exp, _ = ctx.exposure(n["id"])
            if a.get("method") == "GRPC":
                auth = "unknown"
            else:
                auth = "yes" if has_auth_evidence(ctx, n) else ("n/a (health/static)" if HEALTH_RX.search(a.get("path", "")) else "none seen")
        else:
            exp, auth = "internal (trigger)", "n/a"
        srcs = sorted({s["attrs"]["source_type"] for h in hs for s in src_into.get(h, [])})
        entries.append({"kind": n["kind"], "name": n["name"], "handler": nodes[hs[0]]["name"] if hs and hs[0] in nodes else "-", "auth": auth, "exposure": exp,
                        "sources": srcs, "citation": n["citation"], "label": n.get("label", "observed"), "protocol": a.get("protocol", "")})
    sources = [{"type": (n.get("attrs") or {}).get("source_type"), "where": n["name"].split(" in ", 1)[-1], "detail": (n.get("attrs") or {}).get("detail", ""),
                "count": (n.get("attrs") or {}).get("count", 1), "citation": n["citation"]}
               for n in sorted((n for n in nodes.values() if n["kind"] == "taint_source" and n.get("repo") == repo), key=lambda n: n["citation"])]
    sinks = []
    for n in sorted((n for n in nodes.values() if n["kind"] == "sink" and n.get("repo") == repo), key=lambda n: ((n.get("attrs") or {}).get("safe") is True, n["citation"])):
        a = n.get("attrs") or {}
        st = a.get("sink_type")
        sinks.append({"type": st, "cwe": CWE_OF.get(st, "-"), "verdict": "safe pattern" if a.get("safe") is True else "unsafe/unknown", "where": n["name"].split(" in ", 1)[-1],
                      "reason": a.get("reason", ""), "reached_from": sorted(reach.get(n["id"], []))[:4], "citation": n["citation"], "confidence": n["confidence"]})
    resources, findings = [], []
    for n in sorted((n for n in nodes.values() if n["kind"] == "cloud_resource" and n.get("repo") == repo), key=lambda n: n["citation"]):
        fs = [nodes[e["src"]] for e in store.in_adj.get(n["id"], []) if e["kind"] == "finding_at" and e["src"] in nodes]
        cs = [nodes[e["src"]] for e in store.in_adj.get(n["id"], []) if e["kind"] == "affects" and e["src"] in nodes]
        resources.append({"type": (n.get("attrs") or {}).get("type", n["name"]), "name": n["name"], "iac": (n.get("attrs") or {}).get("iac", ""),
                          "issues": sorted({f"{(f.get('attrs') or {}).get('check')} {f['name'].split(' ', 1)[-1][:70]}" for f in fs}) + [f"CSPM: {c['name'][:70]}" for c in cs[:2]],
                          "citation": n["citation"]})
    for n in sorted((n for n in nodes.values() if n["kind"] == "sc_finding" and n.get("repo") == repo and (n.get("attrs") or {}).get("check", "").startswith(("SC-C", "SC-D", "SC-I04"))),
                    key=lambda n: n["citation"]):
        a = n.get("attrs") or {}
        findings.append({"check": a.get("check"), "severity": a.get("severity"), "message": n["name"].split(" ", 1)[-1][:100], "citation": n["citation"]})
    pipelines = []
    pf = out / "evidence" / f"pipeline-facts-{repo}.json"
    pf_findings = []
    if pf.is_file():
        d = json.loads(pf.read_text())
        pipelines = d.get("pipelines", [])
        pf_findings = [{"check": x["id"], "severity": x["severity"], "message": x["message"][:110], "citation": f"{repo}/{x['path']}:{x['line']}"} for x in d.get("findings", [])]
    role_counts = roles.get("role_counts", {})
    core = [f for f in files if f.get("role") == "core"]
    util = [f for f in files if f.get("role") == "utility"]
    return {"repo": repo, "kind": kind, "primary_kind": primary, "secondary_kinds": secondary, "role_counts": role_counts,
            "core_files": sorted(core, key=lambda f: -(f.get("fan_in") or 0))[:25], "utility_files": util[:25],
            "n_core": role_counts.get("core", 0), "n_test": role_counts.get("test", 0),
            "entry_points": entries, "sources": sources, "sinks": sinks, "resources": resources, "iac_findings": findings,
            "pipelines": pipelines, "pipeline_findings": pf_findings}


def render(d: dict) -> str:
    kind = d["kind"]
    L = [BEGIN.format(repo=d["repo"], kind=kind, ep=len(d["entry_points"]), src=len(d["sources"]), snk=len(d["sinks"]), core=d["n_core"], tst=d["n_test"]),
         "> Generated by `scripts/context_facts.py` from the knowledge graph; do not edit by hand (re-run it). All rows are [inferred] static analysis; "
         "source-to-sink paths are candidates, not proven dataflow.", ""]
    if kind in ("config", "docs", "tooling") and not d["entry_points"] and not d["resources"] and not d["pipelines"]:
        L += [f"No code, IaC or pipeline content to tabulate for this `{md_safe(kind)}` repo.", "", END]
        return "\n".join(L) + "\n"
    L += ["#### Code map", "", f"- Repo kind: **{md_safe(kind)}**" + (f" (primary {md_safe(d['primary_kind'])}; also {md_safe(', '.join(d['secondary_kinds']))})" if kind == "mixed" else
                                                                       (f" (also {md_safe(', '.join(d['secondary_kinds']))})" if d["secondary_kinds"] else "")) + " [inferred]",
          "- Files by role: " + (", ".join(f"{md_safe(k)} {v}" for k, v in sorted(d["role_counts"].items(), key=lambda kv: -kv[1])) or "[unknown]"), ""]
    if d["core_files"]:
        L += ["| Core file [inferred] | Why |", "| --- | --- |"]
        L += [f"| `{cell(f['path'], 80)}` | {cell('; '.join(f.get('signals', [])[-2:]), 100)} |" for f in d["core_files"][:12]]
        L.append("")
    if d["entry_points"] or d["sources"] or d["sinks"]:
        L += ["#### Entry points", "", "| Kind | Trigger / route | Handler | Auth evidence | Exposure | Reads | Source |", "| --- | --- | --- | --- | --- | --- | --- |"]
        L += [f"| {e['kind']} | {cell(e['name'])} | {cell(e['handler'], 40)} | {cell(e['auth'])} | {cell(e['exposure'], 40)} | {cell(', '.join(e['sources']) or '-', 40)} | `{e['citation']}` |"
              for e in d["entry_points"]] or ["| [unknown] none found | | | | | | |"]
        L += ["", "#### Taint sources (user-controlled input)", "", "| Type | In | Detail | Hits | Source |", "| --- | --- | --- | --- | --- |"]
        L += [f"| {cell(s['type'])} | {cell(s['where'], 50)} | {cell(s['detail'], 50)} | {s['count']} | `{s['citation']}` |" for s in d["sources"][:60]] or ["| [unknown] none found | | | | |"]
        unsafe = [s for s in d["sinks"] if s["verdict"] != "safe pattern"]
        safe = [s for s in d["sinks"] if s["verdict"] == "safe pattern"]
        L += ["", "#### Dangerous sinks", "", "| Sink | CWE | Verdict | In | Why | Reached from entry points | Source |", "| --- | --- | --- | --- | --- | --- | --- |"]
        L += [f"| {cell(s['type'])} | {s['cwe']} | {cell(s['verdict'])} | {cell(s['where'], 40)} | {cell(s['reason'], 70)} | {cell(', '.join(s['reached_from']) or '-', 60)} | `{s['citation']}` |"
              for s in unsafe[:80]] or ["| [n/a] none detected | | | | | | |"]
        L += ["", "#### Known-safe patterns", "", "| Sink | In | Why | Source |", "| --- | --- | --- | --- |"]
        L += [f"| {cell(s['type'])} | {cell(s['where'], 40)} | {cell(s['reason'], 70)} | `{s['citation']}` |" for s in safe[:40]] or ["| [n/a] none detected | | | |"]
        L.append("")
    if d["resources"] or d["iac_findings"]:
        L += ["#### Provisioned resources and exposure", "", "| Type | Name | IaC | Issues | Source |", "| --- | --- | --- | --- | --- |"]
        L += [f"| {cell(r['type'], 50)} | {cell(r['name'], 40)} | {cell(r['iac'], 20)} | {cell('; '.join(r['issues']) or '-', 120)} | `{r['citation']}` |" for r in d["resources"][:80]] \
            or ["| [unknown] no resources extracted | | | | |"]
        if d["iac_findings"]:
            L += ["", "| Check | Severity | Finding | Source |", "| --- | --- | --- | --- |"]
            L += [f"| {cell(x['check'])} | {cell(x['severity'])} | {cell(x['message'], 100)} | `{x['citation']}` |" for x in d["iac_findings"][:60]]
        L.append("")
    if d["pipelines"]:
        L += ["#### Pipelines (triggers and blast radius)", "", "| Pipeline | Platform | Triggers | PR-reachable | Runner | Secrets / credentials | Third-party code | Deploys | Gate |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for p in d["pipelines"][:60]:
            tp = p.get("third_party", [])
            unpinned = sum(1 for t in tp if t.get("pinned") is False)
            gate = "environment" if p.get("environments") else ("approval" if p.get("approvals") else ("none seen" if p.get("deploy_steps") else "-"))
            creds = sorted(set(p.get("secrets", []) + [c["name"] for c in p.get("credentials", [])] + [c["name"] for c in p.get("service_connections", [])]))
            L.append(f"| `{cell(p['path'], 60)}` | {cell(p['platform'], 20)} | {cell(', '.join(p.get('triggers', [])) or '-', 40)} | "
                     f"{'yes (privileged)' if p.get('fork_privileged') else 'yes' if p.get('pr_trigger') else 'no'} | {cell(', '.join(p.get('runners', [])) or '-', 30)}{' (self-hosted)' if p.get('self_hosted') else ''} | "
                     f"{cell(', '.join(creds[:6]) or '-', 70)} | {len(tp)} ({unpinned} unpinned) | {len(p.get('deploy_steps', []))} | {gate} |")
        allf = d["pipeline_findings"] + d["iac_findings"]
        ci = [x for x in allf if str(x["check"]).startswith(("PF", "SC-C", "SC-I04"))]
        if ci:
            L += ["", "| Check | Severity | Finding | Source |", "| --- | --- | --- | --- |"]
            L += [f"| {cell(x['check'])} | {cell(x['severity'])} | {cell(x['message'], 110)} | `{x['citation']}` |" for x in ci[:60]]
        L.append("")
    L.append(END)
    return "\n".join(L) + "\n"


def run(out: Path, only: str | None = None) -> dict:
    from graph_query import GraphStore
    from threat_seed import Ctx
    ctx = Ctx(out)
    stats = {}
    for repo in sorted(repo_roots_for_output(out)):
        if repo.startswith("ctx") or (only and repo != only):
            continue
        d = gather(out, repo, ctx.store, ctx)
        d["generated"] = now_iso()
        atomic_write(out / "evidence" / f"context-facts-{repo}.json", json.dumps(d, indent=1))
        atomic_write(out / "repos" / repo / "context-facts.md", render(d))
        stats[repo] = {"kind": d["kind"], "entry_points": len(d["entry_points"]), "sources": len(d["sources"]), "sinks": len(d["sinks"]),
                       "core_files": d["n_core"], "test_files": d["n_test"], "resources": len(d["resources"]), "pipelines": len(d["pipelines"])}
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo")
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve(), a.repo), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
