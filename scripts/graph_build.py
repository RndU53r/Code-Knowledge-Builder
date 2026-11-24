#!/usr/bin/env python3
"""Build the ckb knowledge graph from fragments: link cross-file references, attach security findings,
merge verified agent proposals, carry over summaries, and write graph.json + graph.sqlite.

Usage:
  graph_build.py --out OUT_DIR [--extract] [--incremental] [--structural-only]

  --extract          run graph_extract.py for every registered code repo first (ctx-* keys are skipped)
  --incremental      with --extract: re-extract only files changed since the last hash snapshot
  --structural-only  skip proposals (used by the git-commit auto-update hook)

Outputs: <out>/graph/graph.json, <out>/graph/graph.sqlite, <out>/system/graph.md
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import load_json, now_iso, repo_roots_for_output  # noqa: E402
from graph_common import (EXTRACTOR_VERSION, SCHEMA_VERSION, atomic_write, cite, graph_dir, make_edge,  # noqa: E402
                          make_node, node_id, validate)

CODE_KINDS = {"function", "method", "class"}


def load_fragments(out: Path, repos: dict) -> list[dict]:
    frags = []
    for key in repos:
        d = graph_dir(out) / "fragments" / key
        for p in sorted(d.glob("*.json")):
            try:
                frags.append(json.loads(p.read_text()))
            except ValueError:
                continue
    return frags


class Linker:
    def __init__(self, frags, repos, out: Path):
        self.nodes, self.edges, self.out = {}, {}, out
        self.repos = repos
        self.frags = frags
        self.by_file = {}          # (repo, path) -> frag
        self.defs_by_name = defaultdict(list)   # (repo, name) -> [node ids]
        self.file_defs = defaultdict(dict)       # (repo, path) -> {name: id}
        self.go_module = {}
        for f in frags:
            self.by_file[(f["repo"], f["path"])] = f
            for n in f["nodes"]:
                self.add_node(n)
                if n["kind"] in CODE_KINDS:
                    short = n.get("qualname", n["name"]).split(".")[-1]
                    self.defs_by_name[(f["repo"], short)].append(n["id"])
                    self.file_defs[(f["repo"], f["path"])][n.get("qualname", n["name"])] = n["id"]
            for e in f["edges"]:
                self.edges[e["id"]] = e
        for key, root in repos.items():
            gm = Path(root) / "go.mod"
            if gm.is_file():
                m = re.search(r"(?m)^module\s+(\S+)", gm.read_text(errors="replace"))
                if m:
                    self.go_module[key] = m.group(1)

    def add_node(self, n):
        cur = self.nodes.get(n["id"])
        if cur is None:
            self.nodes[n["id"]] = n
        elif n["kind"] in ("table", "topic", "external", "env_var", "endpoint"):
            seen = cur.setdefault("attrs", {}).setdefault("also_cited", [])
            if n["citation"] != cur["citation"] and n["citation"] not in seen and len(seen) < 20:
                seen.append(n["citation"])
            for k, v in (n.get("attrs") or {}).items():
                if v and not cur["attrs"].get(k):
                    cur["attrs"][k] = v

    def add_edge(self, e):
        self.edges.setdefault(e["id"], e)

    # ------------------------------------------------------------ structure
    def structure(self):
        for key, root in self.repos.items():
            meta = load_json(self.out / "evidence" / "targets.json", {}).get("repos", {}).get(key, {})
            rn = make_node("repo", key, "", key, key, 1, extractor="regex", citation="",
                           attrs={"revision": meta.get("revision"), "kind": meta.get("kind")})
            rn["citation"] = ""
            self.add_node(rn)
        for (repo, path), f in self.by_file.items():
            fid = node_id("file", repo, path, "")
            parts = path.split("/")[:-1]
            parent = node_id("repo", repo, "", repo)
            for i in range(len(parts)):
                d = "/".join(parts[: i + 1])
                did = node_id("dir", repo, d, "")
                if did not in self.nodes:
                    dn = make_node("dir", repo, d, "", d, 1, extractor="regex")
                    dn["citation"] = ""
                    self.add_node(dn)
                    self.add_edge(make_edge(parent, "contains", did, cite(repo, path, 1)))
                parent = did
            self.add_edge(make_edge(parent, "contains", fid, cite(repo, path, 1)))

    # ------------------------------------------------------------ imports
    def resolve_import(self, f, r) -> str | None:
        repo, path = f["repo"], f["path"]
        mod = r.get("module") or ""
        lang = r.get("lang") or ("python" if path.endswith(".py") else "")
        cands = []
        if path.endswith(".py"):
            base = Path(path).parent
            level = r.get("level") or 0
            if level:
                for _ in range(level - 1):
                    base = base.parent
                pieces = [p for p in (mod or "").split(".") if p]
                stem = base.joinpath(*pieces) if pieces else base
                if r.get("name"):
                    cands += [str(stem / r["name"]) + ".py", str(stem / r["name"] / "__init__.py")]
                cands += [str(stem) + ".py", str(stem / "__init__.py")]
            else:
                stem = Path(*mod.split(".")) if mod else None
                if stem:
                    cands += [str(stem) + ".py", str(stem / "__init__.py"), str(Path(path).parent / stem) + ".py"]
        elif lang in ("javascript", "typescript") and mod.startswith("."):
            stem = (Path(path).parent / mod)
            norm = str(Path(*[p for p in stem.parts if p != "."]))
            parts = []
            for p in norm.split("/"):
                if p == ".." and parts:
                    parts.pop()
                elif p != "..":
                    parts.append(p)
            s = "/".join(parts)
            cands += [s, s + ".js", s + ".ts", s + ".tsx", s + ".mjs", s + "/index.js", s + "/index.ts"]
        elif lang == "go" and self.go_module.get(repo) and mod.startswith(self.go_module[repo] + "/"):
            d = mod[len(self.go_module[repo]) + 1:]
            for (rp, p) in self.by_file:
                if rp == repo and str(Path(p).parent) == d:
                    cands.append(p)
        for c in cands:
            c = c.lstrip("./") if c.startswith("./") else c
            if (repo, c) in self.by_file:
                return c
        return None

    def imports(self):
        self.aliases = defaultdict(dict)  # (repo,path) -> alias -> (target_path or None, name)
        for f in self.frags:
            for r in f["refs"]:
                if r["type"] != "import":
                    continue
                tgt = self.resolve_import(f, r)
                src = f"file:{f['repo']}:{f['path']}:"
                c = cite(f["repo"], f["path"], r["line"])
                if tgt:
                    self.add_edge(make_edge(src, "imports", node_id("file", f["repo"], tgt, ""), c,
                                            extractor=f["extractor"] if f["extractor"] != "tree-sitter" else "tree-sitter"))
                    alias = r.get("alias") or Path(tgt).stem
                    self.aliases[(f["repo"], f["path"])][alias] = (tgt, r.get("name"))
                else:
                    pkg = (r.get("module") or r.get("name") or "").split(".")[0].split("/")[0] if not (r.get("module") or "").startswith(".") else None
                    if pkg:
                        pid = node_id("package", f["repo"], "", pkg)
                        if pid not in self.nodes:
                            pn = make_node("package", f["repo"], "", pkg, pkg, r["line"], extractor=f["extractor"] if f["extractor"] != "tree-sitter" else "regex",
                                           confidence="medium", citation=c)
                            self.add_node(pn)
                        self.add_edge(make_edge(src, "imports", pid, c, extractor=f["extractor"], confidence="medium"))
                        if r.get("alias"):
                            self.aliases[(f["repo"], f["path"])][r["alias"]] = (None, pkg)

    # ------------------------------------------------------------ calls / inherits / handlers
    def resolve_name(self, f, name, src) -> tuple[str | None, str]:
        repo, path = f["repo"], f["path"]
        parts = name.split(".")
        local = self.file_defs[(repo, path)]
        al = self.aliases[(repo, path)]
        if len(parts) == 1:
            if name in local:
                return local[name], "high"
            if name in al and al[name][0]:
                tgt, imported = al[name]
                t = self.file_defs[(repo, tgt)].get(imported or name)
                if t:
                    return t, "high"
        else:
            head, last = parts[0], parts[-1]
            if head in al and al[head][0]:
                t = self.file_defs[(repo, al[head][0])].get(last)
                if t:
                    return t, "high"
            if head in ("self", "this", "cls"):
                owner_q = self.nodes.get(src, {}).get("qualname", "")
                cls = owner_q.rsplit(".", 1)[0] if "." in owner_q else ""
                t = local.get(f"{cls}.{last}") if cls else None
                if t:
                    return t, "medium"
            if head in al and not al[head][0]:
                return None, ""  # external package method
        short = parts[-1]
        cands = [c for c in self.defs_by_name.get((repo, short), []) if c != src]
        if len(cands) == 1 and (len(parts) == 1 or parts[0][0].islower()):
            return cands[0], "medium" if len(parts) == 1 else "low"
        return None, ""

    def calls(self):
        for f in self.frags:
            for r in f["refs"]:
                c = cite(f["repo"], f["path"], r["line"])
                ex = f["extractor"]
                if r["type"] == "call":
                    tgt, conf = self.resolve_name(f, r["name"], r["src"])
                    if tgt and tgt != r["src"]:
                        if ex == "regex" and conf == "high":
                            conf = "medium"
                        self.add_edge(make_edge(r["src"], "calls", tgt, c, extractor=ex, confidence=conf,
                                                label="observed" if conf != "low" else "inferred"))
                        if "test" in (self.nodes.get(r["src"], {}).get("tags") or []):
                            self.add_edge(make_edge(tgt, "tested_by", r["src"], c, extractor=ex if ex != "tree-sitter" else "regex", confidence=conf))
                elif r["type"] == "inherit":
                    tgt, conf = self.resolve_name(f, r["name"], r["src"])
                    if tgt:
                        self.add_edge(make_edge(r["src"], "inherits", tgt, c, extractor=ex, confidence=conf or "medium"))
                elif r["type"] == "route_handler":
                    tgt, conf = self.resolve_name(f, r["name"], r["src"])
                    if tgt:
                        self.add_edge(make_edge(r["src"], "routes_to", tgt, c, extractor=ex, confidence=conf or "medium"))

    # ------------------------------------------------------------ cross-repo HTTP
    def http(self):
        from graph_extract import norm_path
        eps = [n for n in self.nodes.values() if n["kind"] == "endpoint"]
        for f in self.frags:
            for r in f["refs"]:
                if r["type"] != "http":
                    continue
                url = r["url"]
                path = norm_path(re.sub(r"^\$\{[^}]*\}|^\{p\}", "", url))
                method = r.get("method", "GET").upper()
                c = cite(f["repo"], f["path"], r["line"])
                matches = [e for e in eps if e["attrs"].get("norm") == path and e["repo"] != f["repo"]
                           and e["attrs"].get("method") in (method, "ANY")]
                if not matches:
                    matches = [e for e in eps if e["attrs"].get("norm") == path and e["repo"] != f["repo"]]
                for e in matches[:3]:
                    conf = "medium" if len(matches) == 1 else "low"
                    self.add_edge(make_edge(r["src"], "http_calls", e["id"], c, extractor="regex" if f["extractor"] != "ast" else "ast",
                                            confidence=conf, label="inferred" if conf == "low" else "observed",
                                            dst_citation=e["citation"], attrs={"method": method, "url": url[:120]}))
                if not matches:
                    xid = node_id("external", "_system", "", re.sub(r"^\$\{([^}]*)\}.*", r"\1", url)[:80] or "http")
                    if xid not in self.nodes:
                        xn = make_node("external", "_system", "", xid.split("::", 1)[1], xid.split("::", 1)[1], r["line"], extractor="regex",
                                       confidence="low", citation=c)
                        xn["path"] = ""
                        self.add_node(xn)
                    self.add_edge(make_edge(r["src"], "http_calls", xid, c, extractor="regex" if f["extractor"] != "ast" else "ast",
                                            confidence="low", label="inferred", attrs={"method": method, "url": url[:120]}))

    # ------------------------------------------------------------ subprocess -> built binary
    def spawns(self):
        for e in list(self.edges.values()):
            if e["kind"] != "spawns":
                continue
            ext = self.nodes.get(e["dst"])
            if not ext or ext["kind"] != "external":
                continue
            binname = ext["name"]
            for (repo, path), f in self.by_file.items():
                if re.search(rf"(^|/)cmd/{re.escape(binname)}/main\.go$", path) or re.search(rf"(^|/){re.escape(binname)}/__main__\.py$", path):
                    main = self.file_defs[(repo, path)].get("main") or node_id("file", repo, path, "")
                    self.add_edge(make_edge(e["src"], "spawns", main, e["citation"], extractor=e["provenance"]["extractor"],
                                            confidence="medium", label="inferred", dst_citation=cite(repo, path, 1),
                                            attrs={"via": binname}))

    def build(self):
        self.structure()
        self.imports()
        self.calls()
        self.http()
        self.spawns()
        return self


# ---------------------------------------------------------------- security, proposals, carry-over

def attach_security(link: Linker, out: Path):
    try:
        import graph_security
    except ImportError:
        return {}
    return graph_security.attach(link, out)


def merge_proposals(link: Linker, out: Path):
    try:
        import graph_merge
    except ImportError:
        return {}
    return graph_merge.merge_into(link, out)


def carry_over(link: Linker, out: Path):
    """Keep agent-written summaries across rebuilds (idea from Bevel's description merge; own code)."""
    ann_p = graph_dir(out) / "annotations.json"
    ann = load_json(ann_p, {"nodes": {}})
    by_sig = defaultdict(list)
    for nid, n in link.nodes.items():
        if n.get("sig_hash"):
            by_sig[(n["repo"], n["sig_hash"])].append(nid)
    stats = {"kept": 0, "outdated": 0, "moved": 0, "dropped": 0}
    new_ann = {}
    for old_id, a in ann.get("nodes", {}).items():
        n = link.nodes.get(old_id)
        target, status = None, None
        if n is not None:
            target = old_id
            status = "fresh" if n.get("sig_hash") == a.get("sig_hash") else "OUTDATED"
        else:
            cands = by_sig.get((a.get("repo"), a.get("sig_hash")), [])
            if len(cands) == 1:
                target, status = cands[0], "fresh"
                link.nodes[target].setdefault("attrs", {})["moved_from"] = old_id
                stats["moved"] += 1
            else:
                same = [nid for nid, x in link.nodes.items() if x.get("path") == a.get("path") and x.get("name") == a.get("name")
                        and x["kind"] == a.get("kind")]
                if len(same) == 1:
                    target, status = same[0], "OUTDATED"
        if target is None:
            stats["dropped"] += 1
            continue
        node = link.nodes[target]
        if node.get("summary_status") == "OUTDATED":
            status = "OUTDATED"
        for k in ("summary", "tags", "layer"):
            if a.get(k):
                node[k] = a[k]
        node["summary_status"] = status
        stats["kept" if status == "fresh" else "outdated"] += 1
        new_ann[target] = {**a, "sig_hash": node.get("sig_hash") if status == "fresh" else a.get("sig_hash")}
    if ann.get("nodes"):
        atomic_write(ann_p, json.dumps({"nodes": new_ann}, indent=1))
    return stats


# ---------------------------------------------------------------- outputs

def write_sqlite(graph: dict, path: Path):
    tmp = path.with_suffix(".sqlite.tmp")
    if tmp.exists():
        tmp.unlink()
    db = sqlite3.connect(tmp)
    db.executescript("""
      CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
      CREATE TABLE nodes(id TEXT PRIMARY KEY, kind TEXT, repo TEXT, path TEXT, start INT, "end" INT, name TEXT,
                         qualname TEXT, confidence TEXT, extractor TEXT, label TEXT, citation TEXT, json TEXT);
      CREATE TABLE edges(id TEXT PRIMARY KEY, src TEXT, dst TEXT, kind TEXT, confidence TEXT, extractor TEXT,
                         label TEXT, citation TEXT, json TEXT);
      CREATE INDEX e_src ON edges(src, kind); CREATE INDEX e_dst ON edges(dst, kind); CREATE INDEX n_kind ON nodes(kind);
    """)
    try:
        db.execute("CREATE VIRTUAL TABLE nodes_fts USING fts5(id UNINDEXED, name, qualname, path, summary)")
        fts = True
    except sqlite3.OperationalError:
        fts = False
    db.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
        (n["id"], n["kind"], n["repo"], n.get("path", ""), n.get("range", {}).get("start"), n.get("range", {}).get("end"),
         n["name"], n.get("qualname", ""), n["confidence"], n["provenance"]["extractor"], n["label"], n.get("citation", ""),
         json.dumps(n)) for n in graph["nodes"]])
    db.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?)", [
        (e["id"], e["src"], e["dst"], e["kind"], e["confidence"], e["provenance"]["extractor"], e["label"], e["citation"],
         json.dumps(e)) for e in graph["edges"]])
    if fts:
        db.executemany("INSERT INTO nodes_fts VALUES (?,?,?,?,?)",
                       [(n["id"], n["name"], n.get("qualname", ""), n.get("path", ""), n.get("summary", "")) for n in graph["nodes"]])
    db.executemany("INSERT INTO meta VALUES (?,?)", [("schema_version", graph["schema_version"]), ("generated", graph["generated"]),
                                                     ("fts", "1" if fts else "0"), ("stats", json.dumps(graph["stats"]))])
    db.commit()
    db.close()
    tmp.replace(path)


def report(graph: dict, out: Path, sec: dict, props: dict, carry: dict) -> str:
    st = graph["stats"]
    repos = ", ".join(f"`{k}` @ `{(v.get('revision') or 'local')[:12]}`" for k, v in graph["repos"].items())
    lines = ["# System knowledge graph", "",
             "> **ckb provenance**", f"> - Sources: {repos}", f"> - Generated: {graph['generated']} by ckb graph {EXTRACTOR_VERSION}, stage `graph`",
             "> - Scope: registered code repos · Excluded: vendored, generated, binaries, symlinks, secret files",
             "> - Method: static extraction (ast / tree-sitter if installed / regex); agent proposals merged only after citation verification",
             "> - Verification: see evidence/graph-verification.md", "",
             "## Size", "", "| Item | Count |", "| --- | --- |"]
    lines += [f"| nodes: {k} | {v} |" for k, v in sorted(st["nodes_by_kind"].items())]
    lines += [f"| edges: {k} | {v} |" for k, v in sorted(st["edges_by_kind"].items())]
    lines += ["", "## Extractors", "", "| Extractor | Nodes | Edges |", "| --- | --- | --- |"]
    for ex in sorted(set(st["nodes_by_extractor"]) | set(st["edges_by_extractor"])):
        lines.append(f"| {ex} | {st['nodes_by_extractor'].get(ex, 0)} | {st['edges_by_extractor'].get(ex, 0)} |")
    eps = [n for n in graph["nodes"] if n["kind"] == "endpoint"][:40]
    lines += ["", "## Entry points (endpoints)", "", "| Endpoint | Repo | Source |", "| --- | --- | --- |"]
    lines += [f"| {n['name'].replace('|', '/')} | {n['repo']} | `{n['citation']}` |" for n in eps] or ["| [unknown] none found | | |"]
    unsafe = [n for n in graph["nodes"] if n["kind"] == "sink" and not (n.get("attrs") or {}).get("safe")][:40]
    lines += ["", "## Unsafe sink candidates", "", "| Sink | Type | Reason | Source |", "| --- | --- | --- | --- |"]
    lines += [f"| {n['name'].replace('|', '/')} | {n['attrs'].get('sink_type')} | {n['attrs'].get('reason')} | `{n['citation']}` |" for n in unsafe] \
        or ["| [n/a] none detected | | | |"]
    xr = [e for e in graph["edges"] if e.get("dst_citation")][:40]
    lines += ["", "## Cross-repo edges", "", "| From | Kind | To | Confidence | Source |", "| --- | --- | --- | --- | --- |"]
    lines += [f"| {e['src'].split(':', 2)[-1].strip(':')} | {e['kind']} | {e['dst'].split(':', 2)[-1].strip(':')} | {e['confidence']} | `{e['citation']}` |"
              for e in xr] or ["| [unknown] none matched statically | | | | |"]
    lines += ["", "## Merge and carry-over", "",
              f"- Security nodes attached: {json.dumps(sec)} [inferred]",
              f"- Agent proposals: {json.dumps(props)} [inferred]",
              f"- Summary carry-over: {json.dumps(carry)} [inferred]",
              "", "Query it with `/ckb:ask`, `/ckb:impact`, the viewer (`graph/index.html`), or the `ckb-graph` MCP server."]
    return "\n".join(lines) + "\n"


def build(out: Path, structural_only=False) -> dict:
    roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
    frags = load_fragments(out, roots)
    link = Linker(frags, roots, out).build()
    sec = attach_security(link, out)
    props = {} if structural_only else merge_proposals(link, out)
    carry = carry_over(link, out)
    # drop edges whose ends vanished (e.g. removed files)
    link.edges = {k: e for k, e in link.edges.items() if e["src"] in link.nodes and e["dst"] in link.nodes}
    targets = load_json(out / "evidence" / "targets.json", {}).get("repos", {})
    nodes, edges = list(link.nodes.values()), list(link.edges.values())

    def count(items, f):
        d = defaultdict(int)
        for x in items:
            d[f(x)] += 1
        return dict(d)
    tours = load_json(graph_dir(out) / "tours.json", {"tours": []}).get("tours", [])
    layers = load_json(graph_dir(out) / "layers.json", {"layers": []}).get("layers", [])
    graph = {"schema_version": SCHEMA_VERSION, "generator": f"ckb-graph/{EXTRACTOR_VERSION}", "generated": now_iso(),
             "repos": {k: {"revision": targets.get(k, {}).get("revision"), "dirty": targets.get(k, {}).get("dirty")} for k in roots},
             "nodes": nodes, "edges": edges, "layers": layers, "tours": tours,
             "stats": {"nodes": len(nodes), "edges": len(edges), "nodes_by_kind": count(nodes, lambda n: n["kind"]),
                       "edges_by_kind": count(edges, lambda e: e["kind"]),
                       "nodes_by_extractor": count(nodes, lambda n: n["provenance"]["extractor"]),
                       "edges_by_extractor": count(edges, lambda e: e["provenance"]["extractor"])}}
    probs = validate(graph)
    gd = graph_dir(out)
    atomic_write(gd / "graph.json", json.dumps(graph, indent=1))
    write_sqlite(graph, gd / "graph.sqlite")
    atomic_write(out / "system" / "graph.md", report(graph, out, sec, props, carry))
    return {"nodes": len(nodes), "edges": len(edges), "schema_problems": probs[:20], "security": sec, "proposals": props, "carry_over": carry}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--incremental", action="store_true")
    ap.add_argument("--structural-only", action="store_true")
    ap.add_argument("--backend", default="auto")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    if a.extract:
        roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
        changed = None
        if a.incremental and (out / "evidence" / "hashes.json").is_file():
            r = subprocess.run([sys.executable, str(HERE / "hash_index.py"), "diff", "--out", str(out)], capture_output=True, text=True)
            try:
                changed = json.loads(r.stdout)
            except ValueError:
                changed = None
        for key in roots:
            cmd = [sys.executable, str(HERE / "graph_extract.py"), "--out", str(out), "--key", key, "--backend", a.backend]
            if changed and key in changed and changed[key].get("status") == "unchanged":
                continue
            if changed and key in changed and changed[key].get("status") == "changed":
                files = changed[key].get("added", []) + changed[key].get("changed", []) + changed[key].get("removed", [])
                cmd += ["--files", *files]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL)
    res = build(out, a.structural_only)
    print(json.dumps(res, indent=2))
    return 1 if res["schema_problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
