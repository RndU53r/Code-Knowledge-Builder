#!/usr/bin/env python3
"""How completely ckb resolved the code, so gaps are visible instead of silent. Reads the graph and evidence only.

Usage:
  coverage_report.py --out OUT_DIR

Per repo and language it reports: files by extractor, call-resolution counts (resolved / external library / ambiguous / dynamic /
unresolved, with the top unresolved names), entry points, the functions reachable from an entry point over calls, references,
route/handler, agent dispatch and FFI edges versus the ones that are NOT (dead code, library API, or reached only through dynamic
dispatch), classes nothing instantiates or references, dynamic-dispatch hotspots (reflection, eval, getattr, dynamic require,
DI lookups) with citations, and how many unsafe sinks no entry point reaches (dormant) versus how many are reached.

Writes <out>/system/coverage.md and <out>/evidence/coverage.json. Static analysis cannot prove "all paths": this report says how much
was resolved and where the blind spots are. The threat model reads it to downgrade confidence and to list hotspots as unknown risk.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import now_iso, read_text, repo_roots_for_output  # noqa: E402
from graph_common import atomic_write, graph_dir, md_safe, safe_quote  # noqa: E402

REACH_EDGES = {"calls", "references", "routes_to", "dispatches", "invokes", "ffi", "contains", "spawns", "overrides", "implements"}
ENTRY_KINDS = {"endpoint", "consumer", "cron_job", "cli_command", "agent", "command"}
HOTSPOT = re.compile(r"(?<![\w.$])(getattr|setattr|__import__|importlib\.import_module|eval|exec)(?=\s*\()|(?<![\w.$])(Class\.forName|Activator\.CreateInstance|Type\.GetType|call_user_func(?:_array)?|"
                     r"const_get|constantize|public_send|send\(\s*[a-z_]+|instance_eval|class_eval|method_missing|reflect\.(?:ValueOf|TypeOf)|Reflect\.(?:get|apply)|"
                     r"require\(\s*[a-zA-Z_$][\w$]*\s*\)|import\(\s*[a-zA-Z_$][\w$]*\s*\)|dlopen|GetProcAddress|NSClassFromString|performSelector|\$\$\w+|\$\{?\w+\}?\s*\()")


def run(out: Path) -> dict:
    gp = graph_dir(out) / "graph.json"
    g = json.loads(gp.read_text())
    N = {n["id"]: n for n in g["nodes"]}
    adj = defaultdict(list)
    for e in g["edges"]:
        if e["kind"] in REACH_EDGES:
            adj[e["src"]].append(e["dst"])
    roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
    report = {"generated": now_iso(), "repos": {}}
    for repo, root in roots.items():
        code = {nid: n for nid, n in N.items() if n.get("repo") == repo and n["kind"] in ("function", "method")}
        entries = [n for n in N.values() if n["kind"] in ENTRY_KINDS and (n.get("repo") == repo or n.get("citation", "").startswith(repo + "/"))]
        seen, stack = set(), []
        for en in entries:
            stack.append(en["id"])
            seen.add(en["id"])
        while stack:
            cur = stack.pop()
            for nxt in adj.get(cur, []):
                if nxt not in seen and nxt in N:
                    seen.add(nxt)
                    stack.append(nxt)
        tested = {nid for nid, n in code.items() if "test" in (n.get("tags") or [])}
        library = {nid for nid, n in code.items() if (N.get(f"file:{repo}:{n['path']}:") or {}).get("attrs", {}).get("role") == "utility"}
        unreachable = [n for nid, n in code.items() if nid not in seen and nid not in tested and not n["name"].startswith("route ")]
        classes = [n for n in N.values() if n.get("repo") == repo and n["kind"] == "class" and "test" not in (n.get("tags") or [])]
        incoming = Counter(e["dst"] for e in g["edges"] if e["kind"] in ("calls", "uses_type", "inherits", "implements", "references"))
        unused_classes = [n for n in classes if not incoming.get(n["id"])]
        files = Counter((n.get("attrs") or {}).get("language", "?") + " / " + n["provenance"]["extractor"] for n in N.values() if n["kind"] == "file" and n.get("repo") == repo and (n.get("attrs") or {}).get("language"))
        cres = {}
        cp = out / "evidence" / f"call-resolution-{repo}.json"
        if cp.is_file():
            cres = json.loads(cp.read_text())
        # dynamic-dispatch hotspots
        hot = []
        for fid, n in N.items():
            if n["kind"] == "file" and n.get("repo") == repo and len(hot) < 40:
                text = read_text(Path(root) / n["path"], max_bytes=400_000) or ""
                if re.search(r"(^|/)(tests?|spec|__tests__)/", n["path"]):
                    continue
                for i, ln in enumerate(text.splitlines(), 1):
                    m = HOTSPOT.search(ln)
                    if m and not ln.lstrip().startswith(("#", "//", "*", "--")) and len(hot) < 40:
                        hot.append({"citation": f"{repo}/{n['path']}:{i}", "what": m.group(0)[:40], "quote": safe_quote(ln)[:110]})
        sinks = [n for n in N.values() if n["kind"] == "sink" and n.get("repo") == repo and not (n.get("attrs") or {}).get("safe")]
        reached = set()
        for sk in sinks:
            seen2 = set()
            # a sink is reached when some entry point can get to its owning function
            owner = next((e["src"] for e in g["edges"] if e["kind"] == "reaches_sink" and e["dst"] == sk["id"]), None)
            if owner in seen:
                reached.add(sk["id"])
        sk = out / "evidence" / f"extract-skips-{repo}.json"
        skips = json.loads(sk.read_text()).get("skipped", []) if sk.is_file() else []
        report["repos"][repo] = {"extract_skips": skips[:20], "extract_skip_count": len(skips),
            "files_by_extractor": dict(files), "call_resolution": cres.get("summary"), "top_unresolved": cres.get("top_unresolved", [])[:15],
            "entry_points": len(entries), "entry_citations": [e["citation"] for e in entries if e.get("citation")][:6],
            "sample_file": next((n["citation"] for n in N.values() if n["kind"] == "file" and n.get("repo") == repo and n.get("citation")), None), "functions": len(code), "reachable_functions": len([1 for nid in code if nid in seen]), "unreachable": [{"name": n.get("qualname", n["name"]), "citation": n["citation"]} for n in unreachable[:40]],
            "unreachable_count": len(unreachable), "unused_classes": [{"name": n["name"], "citation": n["citation"]} for n in unused_classes[:30]], "dynamic_hotspots": hot,
            "unsafe_sinks": len(sinks), "unsafe_sinks_reached": len(reached), "dormant_sinks": [{"name": N[s]["name"], "citation": N[s]["citation"]} for s in [x["id"] for x in sinks] if s not in reached][:20]}
    atomic_write(out / "evidence" / "coverage.json", json.dumps(report, indent=1))
    atomic_write(out / "system" / "coverage.md", render(report))
    return {r: {"resolved_pct": (v["call_resolution"] or {}).get("resolved_pct"), "entry_points": v["entry_points"], "unreachable": v["unreachable_count"], "hotspots": len(v["dynamic_hotspots"])}
            for r, v in report["repos"].items()}


def render(rep: dict) -> str:
    L = ["# Analysis coverage and blind spots", "", "> **ckb provenance**", f"> - Sources: {', '.join(f'`{md_safe(r)}`' for r in rep['repos'])}", f"> - Generated: {rep['generated']} by ckb coverage_report, stage `coverage`",
         "> - Method: counts from the graph build and a text scan for dynamic dispatch; static analysis cannot prove that every path was found, so this page lists what was and was not resolved.", ""]
    for repo, v in rep["repos"].items():
        cr = v.get("call_resolution") or {}
        L += [f"## {md_safe(repo)}", "", "| Measure | Value |", "| --- | --- |",
              f"| Calls seen | {cr.get('calls', '[unknown]')} (resolved {cr.get('resolved', 0)}, library {cr.get('external', 0)}, ambiguous {cr.get('ambiguous', 0)}, dynamic {cr.get('dynamic', 0)}, unresolved {cr.get('unresolved', 0)}) |",
              f"| Resolved or library | {cr.get('resolved_pct', '[unknown]')}% |", f"| Entry points | {v['entry_points']}" + (" (" + ", ".join(f"`{c}`" for c in v["entry_citations"][:4]) + ")" if v["entry_citations"] else (f" (parsed, for example: `{v['sample_file']}`)" if v.get("sample_file") else "")) + " |",
              f"| Functions reachable from an entry point | {v['reachable_functions']} of {v['functions']} |", f"| Unsafe sinks reached by an entry point | {v['unsafe_sinks_reached']} of {v['unsafe_sinks']} |",
              f"| Parsers | {md_safe(', '.join(f'{k}: {n}' for k, n in sorted(v['files_by_extractor'].items())) or '[unknown]')} |", ""]
        if v.get("extract_skip_count"):
            L += [f"Files that were not fully extracted ({v['extract_skip_count']}):", ""] + [f"- `{md_safe(x['path'], 70)}`: {md_safe(x['reason'], 100)}" for x in v["extract_skips"][:10]] + [""]
        if v["top_unresolved"]:
            L += ["Top unresolved calls:", "", "| Name | Count | First seen |", "| --- | --- | --- |"]
            L += [f"| {md_safe(x['name'], 50)} | {x['count']} | `{x['citation']}` |" for x in v["top_unresolved"]]
            L.append("")
        if v["unreachable"]:
            L += [f"Functions no entry point reaches ({v['unreachable_count']}; dead code, library API, or reached only through dynamic dispatch):", ""]
            L += [f"- `{md_safe(x['name'], 60)}` (`{x['citation']}`)" for x in v["unreachable"][:15]]
            L.append("")
        if v["dormant_sinks"]:
            L += ["Unsafe sinks no entry point reaches (dormant unless something calls them dynamically):", ""] + [f"- {md_safe(x['name'])} (`{x['citation']}`)" for x in v["dormant_sinks"][:10]] + [""]
        if v["dynamic_hotspots"]:
            L += ["Dynamic-dispatch hotspots (paths through these are invisible to the call graph):", "", "| What | Source |", "| --- | --- |"]
            L += [f"| {md_safe(h['what'])} | `{h['citation']}` |" for h in v["dynamic_hotspots"][:15]]
            L.append("")
        if v["unused_classes"]:
            L += ["Classes nothing instantiates, extends or references: " + ", ".join(f"`{md_safe(x['name'])}`" for x in v["unused_classes"][:12]), ""]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve()), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
