#!/usr/bin/env python3
"""Call graphs at three levels, rolled up from the ckb knowledge graph. Reads graph.json only.

Usage:
  callgraph.py --out OUT_DIR [--max-rows 80]

Levels
  function -> function   calls, HTTP calls resolved to the handler behind the endpoint, subprocess/FFI
                         spawns, and publish -> consume pairs over a topic
  file -> file           the function-level edges rolled up by containing file, plus import edges
  repo -> repo           HTTP/gRPC calls, topics (publisher repo -> consumer repo), shared tables
                         (writer repo -> reader repo), subprocess spawns, internal package dependencies
                         and calls to external systems

Every row keeps the citations of the edges it summarizes and the weakest confidence along the way.
Writes <out>/graph/callgraph.json, <out>/system/call-graphs.md, <out>/diagrams/callgraph-*.mmd.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import now_iso, repo_roots_for_output  # noqa: E402
from graph_common import atomic_write, edge_id, graph_dir, md_safe, node_id  # noqa: E402

CODE = {"function", "method"}
RANK = {"high": 3, "medium": 2, "low": 1}
INV = {3: "high", 2: "medium", 1: "low"}
MECH_KIND = {"call": "calls", "http": "http_calls", "grpc": "grpc_calls", "spawn": "spawns", "event": "publishes",
             "import": "imports", "table": "writes", "package": "imports", "deploy": "deploys",
             "type": "uses_type", "inherit": "inherits", "implement": "implements", "lib": "calls_lib", "new": "calls", "override": "overrides", "ref": "references"}
SAFE_LABEL = re.compile(r"[^A-Za-z0-9_./ :-]")


def label(s: str, n: int = 40) -> str:
    return SAFE_LABEL.sub("", str(s))[:n] or "node"


def mech_class(m: str) -> str:
    return m.split(":", 1)[0]


class Acc:
    """Accumulates rolled-up edges keyed by (src, dst, mechanism)."""

    def __init__(self):
        self.edges = {}

    def add(self, src, dst, mech, conf, cites, dst_cite=None):
        if src == dst:
            return
        e = self.edges.setdefault((src, dst, mech), {"weight": 0, "rank": 3, "cites": [], "dst_cites": []})
        e["weight"] += 1
        e["rank"] = min(e["rank"], RANK.get(conf, 1))
        for c in cites:
            if c and c not in e["cites"] and len(e["cites"]) < 6:
                e["cites"].append(c)
        if dst_cite and dst_cite not in e["dst_cites"] and len(e["dst_cites"]) < 3:
            e["dst_cites"].append(dst_cite)

    def rows(self, nodes):
        out = []
        for (s, d, m), e in self.edges.items():
            if s not in nodes or d not in nodes:
                continue
            label_ = "observed" if e["rank"] >= 2 else "inferred"
            out.append({"id": edge_id(s, MECH_KIND[mech_class(m)], d, m), "src": s, "dst": d, "kind": MECH_KIND[mech_class(m)], "mechanism": m,
                        "weight": e["weight"], "confidence": INV[e["rank"]], "label": label_,
                        "citation": e["cites"][0] if e["cites"] else "", "dst_citation": e["dst_cites"][0] if e["dst_cites"] else None,
                        "evidence": e["cites"] + e["dst_cites"]})
        out.sort(key=lambda r: (-r["weight"], -RANK[r["confidence"]], r["src"], r["dst"]))
        return out


def package_names(roots: dict[str, Path]) -> dict[str, str]:
    """Names other repos could import this repo by: key, package.json name, go.mod module, pyproject name."""
    names = {}
    for key, root in roots.items():
        names[key.lower()] = key
        try:
            pj = root / "package.json"
            if pj.is_file():
                n = json.loads(pj.read_text()).get("name")
                if n:
                    names[str(n).lower()] = key
            gm = root / "go.mod"
            if gm.is_file():
                m = re.search(r"(?m)^module\s+(\S+)", gm.read_text(errors="replace"))
                if m:
                    names[m.group(1).lower()] = key
            pp = root / "pyproject.toml"
            if pp.is_file():
                m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', pp.read_text(errors="replace"))
                if m:
                    names[m.group(1).lower().replace("_", "-")] = key
        except (OSError, ValueError):
            continue
    return names


def deploy_links(out: Path, graph: dict) -> list[tuple]:
    """Repo -> repo links from pipelines, IaC and GitOps content that names another registered repo: a checkout or repository
    resource (medium), or an image/source/repoURL line that mentions the repo (low-medium). [inferred] unless named explicitly."""
    keys = sorted({n["repo"] for n in graph["nodes"] if n["kind"] == "repo"})
    kinds = {n["repo"]: (n.get("attrs") or {}) for n in graph["nodes"] if n["kind"] == "repo"}
    links, seen = [], set()

    def add(src, dst, conf, cite):
        if src != dst and (src, dst) not in seen:
            seen.add((src, dst))
            links.append((src, dst, "deploy", conf, [cite]))
    for p in sorted((out / "evidence").glob("pipeline-facts-*.json")):
        try:
            d = json.loads(p.read_text())
        except ValueError:
            continue
        for pf in d.get("pipelines", []):
            for t in pf.get("targets", []):
                name = t.replace("\\", "/").rstrip("/").split("/")[-1].lower()
                dst = next((k for k in keys if k.lower() == name), None)
                if dst:
                    add(d["repo"], dst, "medium", f"{d['repo']}/{pf['path']}:{(pf.get('target_lines') or {}).get(t, 1)}")
    roots = repo_roots_for_output(out)
    for repo, attrs in kinds.items():
        k = attrs.get("repo_kind")
        if k not in ("gitops-config", "iac", "cicd-pipeline", "mixed") or repo.startswith("ctx"):
            continue
        fr = out / "evidence" / f"file-roles-{repo}.json"
        if not fr.is_file() or repo not in roots:
            continue
        files = [r["path"] for r in json.loads(fr.read_text()).get("files", []) if r.get("role") in ("iac", "pipeline")][:200]
        for rel in files:
            try:
                lines = (Path(roots[repo]) / rel).read_text(errors="replace").splitlines()[:2000]
            except OSError:
                continue
            for i, ln in enumerate(lines, 1):
                if len(ln) > 400 or not re.search(r"(?i)\b(image|repoURL|repository|source|chart|name|checkout|git|url)\b", ln):
                    continue
                for dst in keys:
                    if len(dst) >= 4 and dst != repo and not dst.startswith("ctx") and re.search(rf"(?<![\w-]){re.escape(dst)}(?![\w-])", ln, re.I):
                        add(repo, dst, "low", f"{repo}/{rel}:{i}")
    return links


def compute(graph: dict, roots: dict[str, Path] | None = None, extra_repo_links: list | None = None) -> dict:
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    handlers = defaultdict(list)
    producers, consumers = defaultdict(list), defaultdict(list)
    readers, writers = defaultdict(list), defaultdict(list)
    for e in edges:
        k = e["kind"]
        if k == "routes_to":
            handlers[e["src"]].append(e["dst"])
        elif k == "publishes":
            producers[e["dst"]].append(e)
        elif k == "consumes":
            consumers[e["dst"]].append(e)
        elif k == "reads":
            readers[e["dst"]].append(e)
        elif k == "writes":
            writers[e["dst"]].append(e)

    def kind_of(i):
        return nodes.get(i, {}).get("kind")

    def file_of(i):
        n = nodes.get(i)
        if not n:
            return None
        if n["kind"] == "file":
            return i
        if n.get("path") and n["kind"] in CODE | {"class", "sink", "cloud_resource"}:
            return node_id("file", n["repo"], n["path"], "")
        return None

    fn, fl, rp, cl, lb = Acc(), Acc(), Acc(), Acc(), Acc()

    def class_of(i):
        n = nodes.get(i)
        if not n:
            return None
        if n["kind"] == "class":
            return i
        q = n.get("qualname", "")
        if n["kind"] in CODE and "." in q:
            cid = node_id("class", n["repo"], n["path"], q.rsplit(".", 1)[0])
            return cid if cid in nodes else None
        return None

    def fn_and_file(src, dst, mech, conf, cites, dst_cite=None):
        if kind_of(src) in CODE and kind_of(dst) in CODE:
            fn.add(src, dst, mech, conf, cites, dst_cite)
        fs, fd = file_of(src), file_of(dst)
        if fs and fd and fs in nodes and fd in nodes:
            fl.add(fs, fd, mech, conf, cites, dst_cite)

    for e in edges:
        k, c = e["kind"], e["confidence"]
        if k in ("calls", "references", "overrides"):
            cs_, cd_ = class_of(e["src"]), (class_of(e["dst"]))
            if cs_ and cd_ and cs_ != cd_:
                cl.add(cs_, cd_, {"calls": "call", "references": "ref", "overrides": "override"}[k], c, [e["citation"]])
            elif kind_of(e["dst"]) == "class" and kind_of(e["src"]) in CODE and cs_ != e["dst"]:
                cl.add(cs_ or file_of(e["src"]) or e["src"], e["dst"], "new", c, [e["citation"]])
        elif k in ("uses_type", "inherits", "implements") and kind_of(e["dst"]) == "class":
            s_ = class_of(e["src"])
            if s_ and s_ != e["dst"]:
                cl.add(s_, e["dst"], {"uses_type": "type", "inherits": "inherit", "implements": "implement"}[k], c, [e["citation"]])
        elif k == "calls_lib":
            apis = ",".join((e.get("attrs") or {}).get("apis", [])[:3])
            lb.add(e["src"], e["dst"], f"lib:{label(apis, 30)}", c, [e["citation"]])
            fs_ = file_of(e["src"])
            if fs_ and fs_ in nodes:
                lb.add(fs_, e["dst"], f"lib:{label(apis, 30)}", c, [e["citation"]])
        if k == "calls":
            fn_and_file(e["src"], e["dst"], "call", c, [e["citation"]])
        elif k in ("http_calls", "grpc_calls"):
            ep = nodes.get(e["dst"], {})
            mech = "http" if k == "http_calls" else "grpc"
            targets = handlers.get(e["dst"], [])
            for h in targets:
                fn_and_file(e["src"], h, mech, c, [e["citation"]], e.get("dst_citation") or ep.get("citation"))
            if ep.get("kind") == "endpoint" and ep.get("repo") != nodes.get(e["src"], {}).get("repo"):
                rp.add(node_id("repo", nodes[e["src"]]["repo"], "", nodes[e["src"]]["repo"]), node_id("repo", ep["repo"], "", ep["repo"]),
                       mech, c, [e["citation"]], e.get("dst_citation") or ep.get("citation"))
            elif ep.get("kind") == "external" and nodes.get(e["src"]):
                rp.add(node_id("repo", nodes[e["src"]]["repo"], "", nodes[e["src"]]["repo"]), e["dst"], f"{mech}:external", c, [e["citation"]])
        elif k == "spawns":
            fn_and_file(e["src"], e["dst"], "spawn", c, [e["citation"]], e.get("dst_citation"))
            s, d = nodes.get(e["src"]), nodes.get(e["dst"])
            if s and d and d.get("kind") in CODE and s["repo"] != d["repo"]:
                rp.add(node_id("repo", s["repo"], "", s["repo"]), node_id("repo", d["repo"], "", d["repo"]), "spawn", c, [e["citation"]], e.get("dst_citation"))
        elif k == "imports":
            s, d = nodes.get(e["src"]), nodes.get(e["dst"])
            if s and d and s["kind"] == "file" and d["kind"] == "file":
                fl.add(e["src"], e["dst"], "import", c, [e["citation"]])
    for t, ps in producers.items():
        for p in ps:
            for q in consumers.get(t, []):
                tname = label(nodes.get(t, {}).get("name", "topic"), 30)
                conf = INV[min(RANK[p["confidence"]], RANK[q["confidence"]])]
                fn_and_file(p["src"], q["src"], f"event:{tname}", conf, [p["citation"], q["citation"]])
                sp, sq = nodes.get(p["src"]), nodes.get(q["src"])
                if sp and sq and sp["repo"] != sq["repo"]:
                    rp.add(node_id("repo", sp["repo"], "", sp["repo"]), node_id("repo", sq["repo"], "", sq["repo"]), f"event:{tname}", conf,
                           [p["citation"], q["citation"]])
    shared = []
    for t, ws in writers.items():
        rs = readers.get(t, [])
        wrepos = {nodes[w["src"]]["repo"] for w in ws if w["src"] in nodes}
        rrepos = {nodes[r["src"]]["repo"] for r in rs if r["src"] in nodes}
        tname = label(nodes.get(t, {}).get("name", "table"), 30)
        for w in ws:
            for r in rs:
                sw, sr = nodes.get(w["src"]), nodes.get(r["src"])
                if sw and sr and sw["repo"] != sr["repo"]:
                    rp.add(node_id("repo", sw["repo"], "", sw["repo"]), node_id("repo", sr["repo"], "", sr["repo"]), f"table:{tname}",
                           INV[min(RANK[w["confidence"]], RANK[r["confidence"]])], [w["citation"], r["citation"]])
        if len(wrepos) >= 2 or (wrepos and rrepos - wrepos):
            shared.append({"table": nodes.get(t, {}).get("name"), "writers": sorted(wrepos), "readers": sorted(rrepos),
                           "evidence": [x["citation"] for x in (ws + rs)][:6]})
    for s_, d_, mech_, conf_, cites_ in extra_repo_links or []:
        rp.add(node_id("repo", s_, "", s_), node_id("repo", d_, "", d_), mech_, conf_, cites_)
    if roots:
        pkg = package_names(roots)
        for e in edges:
            if e["kind"] == "imports" and kind_of(e["dst"]) == "package":
                target = pkg.get(nodes[e["dst"]]["name"].lower())
                s = nodes.get(e["src"])
                if target and s and target != s["repo"]:
                    rp.add(node_id("repo", s["repo"], "", s["repo"]), node_id("repo", target, "", target), "package", e["confidence"], [e["citation"]])
    # nodes per level (only nodes that appear)
    def used(rows):
        ids = {r["src"] for r in rows} | {r["dst"] for r in rows}
        return ids
    f_rows = fn.rows(nodes)
    fl_rows = fl.rows(nodes)
    rp_rows = rp.rows(nodes)
    cl_rows = cl.rows(nodes)
    lb_rows = [r for r in lb.rows(nodes)]
    for rep_id in {n["id"] for n in graph["nodes"] if n["kind"] == "repo"}:
        nodes.setdefault(rep_id, {"id": rep_id, "kind": "repo", "name": rep_id.split(":")[1], "repo": rep_id.split(":")[1], "path": "", "citation": ""})

    def slim(i, level):
        n = nodes[i]
        d = {"id": i, "kind": n["kind"], "name": n["name"], "repo": n.get("repo"), "path": n.get("path", ""),
             "citation": n.get("citation", ""), "confidence": n.get("confidence", "high"), "label": n.get("label", "observed"),
             "provenance": {"extractor": "rollup"}}
        if n["kind"] == "file":
            d["name"] = n.get("path") or n["name"]
        return d
    res = {"generated": now_iso(), "repos": sorted({n["repo"] for n in graph["nodes"] if n["kind"] == "repo"}),
           "function": {"nodes": [slim(i, "function") for i in sorted(used(f_rows))], "edges": f_rows},
           "file": {"nodes": [slim(i, "file") for i in sorted(used(fl_rows))], "edges": fl_rows},
           "repo": {"nodes": [slim(i, "repo") for i in sorted(used(rp_rows))], "edges": rp_rows},
           "class": {"nodes": [slim(i, "class") for i in sorted(used(cl_rows)) if i in nodes], "edges": cl_rows},
           "library": {"nodes": [slim(i, "library") for i in sorted(used(lb_rows)) if i in nodes], "edges": lb_rows},
           "shared_stores": shared}
    res["stats"] = {lv: {"nodes": len(res[lv]["nodes"]), "edges": len(res[lv]["edges"])} for lv in ("function", "file", "repo", "class", "library")}
    return res


# ---------------------------------------------------------------- outputs

def nodes_kind(res, i):
    for lv in ("file", "function", "class", "library"):
        for n in res[lv]["nodes"]:
            if n["id"] == i:
                return n["kind"]
    return None


def md_cell(s) -> str:
    return md_safe(s, 80)


def cites(row, n=2) -> str:
    seen = []
    for c in row["evidence"]:
        if c and c not in seen:
            seen.append(c)
    return " ".join(f"`{c}`" for c in seen[:n]) or "[unknown]"


def mermaid(res_level, names, cap):
    rows = res_level["edges"][:cap]
    ids = {}
    lines = ["flowchart LR"]
    for r in rows:
        for x in (r["src"], r["dst"]):
            if x not in ids:
                ids[x] = f"N{len(ids) + 1}"
                lines.append(f'  {ids[x]}["{label(names[x])}"]')
    for r in rows:
        arrow = "-.->" if r["label"] == "inferred" else "-->"
        lines.append(f'  {ids[r["src"]]} {arrow}|"{label(r["mechanism"], 28)}"| {ids[r["dst"]]}')
    return "\n".join(lines) + "\n"


def write_outputs(out: Path, res: dict, max_rows: int, targets: dict) -> list[str]:
    names = {n["id"]: n["name"] for lv in ("function", "file", "repo", "class", "library") for n in res[lv]["nodes"]}
    repo_of = {n["id"]: n.get("repo") for lv in ("function", "file", "repo", "class", "library") for n in res[lv]["nodes"]}
    srcs = ", ".join(f"`{k}` @ `{str((v.get('revision') or 'local'))[:12]}`" for k, v in targets.items() if not k.startswith("ctx"))
    L = ["# Call graphs", "", "> **ckb provenance**", f"> - Sources: {srcs}", f"> - Generated: {res['generated']} by ckb callgraph, stage `callgraph`",
         "> - Scope: registered code repos · Excluded: vendored, generated, binaries, symlinks",
         "> - Method: rolled up from the knowledge graph (static analysis; no target code executed); confidence is the weakest edge on each row",
         "> - Verification: see evidence/graph-verification.md", "",
         "## Summary", "", "| Level | Nodes | Edges |", "| --- | --- | --- |"]
    for lv in ("function", "file", "repo"):
        L.append(f"| {lv} → {lv} | {res['stats'][lv]['nodes']} | {res['stats'][lv]['edges']} |")
    L += ["", "[n/a] counts above are derived from the tables below.", "", "Mechanisms: `call` (resolved call), `http`/`grpc` (client call matched to the endpoint's handler), `spawn` (subprocess or binary), "
          "`event:<topic>` (publisher to consumer over a topic), `table:<name>` (writer repo to reader repo), `import`, `package` (internal dependency). "
          "Dashed arrows and `inferred` rows rest on medium/low-confidence links: confirm them in the cited code.", ""]
    repo_rows = res["repo"]["edges"]
    L += ["## Repo → repo", "", "| From | To | Mechanism | Count | Confidence | Source |", "| --- | --- | --- | --- | --- | --- |"]
    L += [f"| {md_cell(names[r['src']])} | {md_cell(names[r['dst']])} | {md_cell(r['mechanism'])} | {r['weight']} | {r['confidence']} | {cites(r, 3)} |" for r in repo_rows] \
        or ["| [unknown] no cross-repo edges found statically | | | | | |"]
    if res["shared_stores"]:
        L += ["", "### Shared stores", "", "| Store | Writers | Readers | Source |", "| --- | --- | --- | --- |"]
        L += [f"| {md_cell(s['table'])} | {', '.join(s['writers'])} | {', '.join(s['readers']) or '[unknown]'} | " + " ".join(f"`{c}`" for c in s["evidence"][:3]) + " |"
              for s in res["shared_stores"]]
    L += ["", "```mermaid", mermaid(res["repo"], names, 60).rstrip(), "```", ""]
    file_rows = res["file"]["edges"]
    L += ["## File → file", "", f"Top {min(max_rows, len(file_rows))} of {len(file_rows)} by weight.", "",
          "| From | To | Mechanism | Count | Confidence | Source |", "| --- | --- | --- | --- | --- | --- |"]
    L += [f"| {md_cell(repo_of[r['src']])}/{md_cell(names[r['src']])} | {md_cell(repo_of[r['dst']])}/{md_cell(names[r['dst']])} | {md_cell(r['mechanism'])} | {r['weight']} | {r['confidence']} | {cites(r)} |"
          for r in file_rows[:max_rows]] or ["| [unknown] none | | | | | |"]
    func_rows = res["function"]["edges"]
    L += ["", "## Function → function", "", f"Top {min(max_rows, len(func_rows))} of {len(func_rows)}: cross-file and cross-repo edges first.", "",
          "| From | To | Mechanism | Count | Confidence | Source |", "| --- | --- | --- | --- | --- | --- |"]
    cross = sorted(func_rows, key=lambda r: (repo_of[r["src"]] == repo_of[r["dst"]], -r["weight"]))
    L += [f"| {md_cell(repo_of[r['src']])}: {md_cell(names[r['src']])} | {md_cell(repo_of[r['dst']])}: {md_cell(names[r['dst']])} | {md_cell(r['mechanism'])} | {r['weight']} | {r['confidence']} | {cites(r)} |"
          for r in cross[:max_rows]] or ["| [unknown] none | | | | | |"]
    cls_rows = res["class"]["edges"]
    L += ["", "## Class → class", "", "Calls between methods of different classes, instantiation (`new`), inheritance, interface implementation, overrides and type use; receiver types come from constructors, annotations and injected fields.", "",
          "| From | To | Mechanism | Count | Confidence | Source |", "| --- | --- | --- | --- | --- | --- |"]
    L += [f"| {md_cell(repo_of[r['src']])}: {md_cell(names[r['src']])} | {md_cell(repo_of[r['dst']])}: {md_cell(names[r['dst']])} | {md_cell(r['mechanism'])} | {r['weight']} | {r['confidence']} | {cites(r)} |"
          for r in sorted(cls_rows, key=lambda r: -r["weight"])[:max_rows]] or ["| [unknown] none | | | | | |"]
    lib_rows = [r for r in res["library"]["edges"] if names.get(r["src"]) and repo_of.get(r["src"]) and nodes_kind(res, r["src"]) == "file"]
    L += ["", "## Library calls (file → package)", "", "External packages the code calls, with the API names seen. Unresolved externals are listed in `evidence/call-resolution-<repo>.json`.", "",
          "| File | Package | APIs | Count | Source |", "| --- | --- | --- | --- | --- |"]
    L += [f"| {md_cell(repo_of[r['src']])}/{md_cell(names[r['src']])} | {md_cell(names[r['dst']])} | {md_cell(r['mechanism'].split(':', 1)[-1])} | {r['weight']} | {cites(r)} |"
          for r in sorted(lib_rows, key=lambda r: -r["weight"])[:max_rows]] or ["| [unknown] no library calls resolved | | | | |"]
    L += ["", "Full machine-readable data: `graph/callgraph.json`. Per-repo diagrams: `diagrams/callgraph-<level>-<repo>.mmd`.", ""]
    atomic_write(out / "system" / "call-graphs.md", "\n".join(L))
    written = ["system/call-graphs.md"]
    d = out / "diagrams"
    atomic_write(d / "callgraph-repo.mmd", mermaid(res["repo"], names, 60))
    written.append("diagrams/callgraph-repo.mmd")
    for lv in ("file", "function"):
        by_repo = defaultdict(list)
        for r in res[lv]["edges"]:
            by_repo[repo_of[r["src"]]].append(r)
        for rep, rows in by_repo.items():
            if not rep:
                continue
            atomic_write(d / f"callgraph-{lv}-{label(rep, 40).replace(' ', '_')}.mmd", mermaid({"edges": rows}, names, 30))
            written.append(f"diagrams/callgraph-{lv}-{rep}.mmd")
    return written


def run(out: Path, max_rows: int = 80) -> dict:
    g = json.loads((graph_dir(out) / "graph.json").read_text())
    roots = repo_roots_for_output(out)
    res = compute(g, {k: v for k, v in roots.items() if not k.startswith("ctx")}, deploy_links(out, g))
    atomic_write(graph_dir(out) / "callgraph.json", json.dumps(res))
    targets = json.loads((out / "evidence" / "targets.json").read_text()).get("repos", {}) if (out / "evidence" / "targets.json").is_file() else {}
    written = write_outputs(out, res, max_rows, targets)
    return {"stats": res["stats"], "written": written}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-rows", type=int, default=80)
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve(), a.max_rows), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
