#!/usr/bin/env python3
"""Query the ckb knowledge graph. The GraphStore class is shared by this CLI, the MCP server
(graph_mcp.py) and the local viewer server (graph_serve.py). Read-only.

Usage:
  graph_query.py --out OUT_DIR status
  graph_query.py --out OUT_DIR search <text> [--kinds function,endpoint] [--repo R] [--limit N]
  graph_query.py --out OUT_DIR node <id>
  graph_query.py --out OUT_DIR explain <id|repo/path|name>
  graph_query.py --out OUT_DIR neighbors <id> [--dir out|in|both] [--kinds calls,...] [--depth 1..3]
  graph_query.py --out OUT_DIR path <src> <dst> [--kinds ...] [--max-depth 8] [--k 3]
  graph_query.py --out OUT_DIR impact <target ...> [--diff REV] [--depth 6]
  graph_query.py --out OUT_DIR taint [--source ID] [--sink ID] [--max-depth 10]
  graph_query.py --out OUT_DIR callgraph [function|file|repo] [--repo R] [--focus X] [--depth N]
  graph_query.py --out OUT_DIR roles [--repo R] [--role core|utility|test|iac|pipeline|...] [--limit N]
  graph_query.py --out OUT_DIR entrypoints [--repo R] [--kinds endpoint,consumer,cron_job,cli_command] [--limit N]
  graph_query.py --out OUT_DIR tour [name]
  graph_query.py --out OUT_DIR sql "<SELECT ...>"
  graph_query.py --out OUT_DIR cypher "<MATCH ...>"      (only when Neo4j is configured; see graph_neo4j.py)

Targets accept a node id, `repo/path` (a file), a path suffix, or a symbol name.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import repo_roots_for_output  # noqa: E402
from graph_common import graph_dir, resolve_out  # noqa: E402

DEPENDENCY_REVERSE = {"calls", "imports", "routes_to", "http_calls", "grpc_calls", "spawns", "inherits", "implements",
                      "overrides", "uses_type", "references", "tested_by_rev"}
SECURITY_KINDS = {"endpoint", "sink", "threat", "sc_finding", "cspm_finding", "trust_boundary", "drift", "taint_source"}
TAINT_FORWARD = {"routes_to", "calls", "http_calls", "grpc_calls", "spawns", "reaches_sink", "flows_to", "publishes", "consumes", "contains"}


class GraphStore:
    def __init__(self, out: Path):
        self.out = Path(out)
        self.db_path = graph_dir(self.out) / "graph.sqlite"
        if not self.db_path.is_file():
            raise FileNotFoundError(f"no graph at {self.db_path}; run graph_build.py --out {self.out} --extract")
        self._load()

    def _connect(self):
        db = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
        db.execute("PRAGMA query_only=1")
        return db

    def _load(self):
        self.mtime = self.db_path.stat().st_mtime
        db = self._connect()
        self.nodes = {r[0]: json.loads(r[1]) for r in db.execute("SELECT id, json FROM nodes")}
        self.edges = [json.loads(r[0]) for r in db.execute("SELECT json FROM edges")]
        self.meta = dict(db.execute("SELECT key, value FROM meta").fetchall())
        db.close()
        self.out_adj, self.in_adj = defaultdict(list), defaultdict(list)
        for e in self.edges:
            self.out_adj[e["src"]].append(e)
            self.in_adj[e["dst"]].append(e)
        gj = graph_dir(self.out) / "graph.json"
        self.tours = json.loads(gj.read_text()).get("tours", []) if gj.is_file() else []

    def refresh(self) -> bool:
        if self.db_path.stat().st_mtime != self.mtime:
            self._load()
            return True
        return False

    # ------------------------------------------------------------ helpers
    def brief(self, nid):
        n = self.nodes.get(nid, {"id": nid, "kind": "?", "name": nid})
        return {"id": nid, "kind": n["kind"], "name": n["name"], "repo": n.get("repo"), "citation": n.get("citation", ""),
                "confidence": n.get("confidence"), "label": n.get("label"), "summary": n.get("summary")}

    def ebrief(self, e):
        return {"kind": e["kind"], "src": e["src"], "dst": e["dst"], "citation": e["citation"], "confidence": e["confidence"],
                "label": e["label"], "extractor": e["provenance"]["extractor"], "dst_citation": e.get("dst_citation")}

    def resolve(self, target: str) -> list[str]:
        if target in self.nodes:
            return [target]
        t = target.strip()
        if "/" in t and ":" not in t:
            repo, _, path = t.partition("/")
            fid = f"file:{repo}:{path}:"
            if fid in self.nodes:
                return [fid]
            hits = [nid for nid, n in self.nodes.items() if n["kind"] == "file" and n.get("path", "").endswith(t)]
            if hits:
                return hits
        hits = [nid for nid, n in self.nodes.items() if n["kind"] in ("function", "method", "class", "endpoint", "table", "topic")
                and (n["name"] == t or n.get("qualname") == t or n.get("qualname", "").endswith("." + t))]
        return hits[:10]

    def contained(self, nid) -> list[str]:
        out, q = [nid], [nid]
        while q:
            cur = q.pop()
            for e in self.out_adj.get(cur, []):
                if e["kind"] == "contains" and e["dst"] not in out:
                    out.append(e["dst"])
                    q.append(e["dst"])
        return out

    # ------------------------------------------------------------ ops
    def status(self):
        return {"graph": str(self.db_path), "nodes": len(self.nodes), "edges": len(self.edges),
                "generated": self.meta.get("generated"), "schema_version": self.meta.get("schema_version"),
                "stats": json.loads(self.meta.get("stats", "{}")), "tours": [t.get("name") for t in self.tours]}

    def search(self, q, kinds=None, repo=None, limit=20):
        kinds = set(kinds or [])
        rows = []
        if self.meta.get("fts") == "1" and q.strip():
            db = self._connect()
            term = " ".join('"' + w.replace('"', "") + '"*' for w in re.findall(r"[\w./-]+", q)) or '""'
            try:
                rows = [r[0] for r in db.execute("SELECT id FROM nodes_fts WHERE nodes_fts MATCH ? LIMIT 500", (term,))]
            except sqlite3.OperationalError:
                rows = []
            db.close()
        if not rows:
            ql = q.lower()
            rows = [nid for nid, n in self.nodes.items() if ql in n["name"].lower() or ql in nid.lower()]
        res = [self.brief(r) for r in rows if r in self.nodes and (not kinds or self.nodes[r]["kind"] in kinds)
               and (not repo or self.nodes[r].get("repo") == repo)]
        return res[:limit]

    def node(self, nid):
        return self.nodes.get(nid) or {"error": f"no node {nid}"}

    def explain(self, target):
        ids = self.resolve(target)
        if not ids:
            return {"error": f"nothing matches {target}"}
        nid = ids[0]
        outs, ins = self.out_adj.get(nid, []), self.in_adj.get(nid, [])
        sec = []
        for x in self.contained(nid):
            for e in self.in_adj.get(x, []) + self.out_adj.get(x, []):
                other = e["src"] if e["dst"] == x else e["dst"]
                if self.nodes.get(other, {}).get("kind") in SECURITY_KINDS - {"endpoint"} or e["kind"] in ("threatens", "finding_at", "affects", "drifts_from"):
                    sec.append({"edge": self.ebrief(e), "node": self.brief(other)})
        return {"node": self.nodes[nid], "alternatives": ids[1:], "out": [self.ebrief(e) for e in outs][:80],
                "in": [self.ebrief(e) for e in ins][:80], "security": sec[:50]}

    def neighbors(self, nid, direction="both", kinds=None, depth=1):
        depth = max(1, min(int(depth), 3))
        kinds = set(kinds or [])
        seen, frontier, edges = {nid}, [nid], []
        for _ in range(depth):
            nxt = []
            for cur in frontier:
                cand = (self.out_adj.get(cur, []) if direction in ("out", "both") else []) + \
                       (self.in_adj.get(cur, []) if direction in ("in", "both") else [])
                for e in cand:
                    if kinds and e["kind"] not in kinds:
                        continue
                    edges.append(self.ebrief(e))
                    other = e["dst"] if e["src"] == cur else e["src"]
                    if other not in seen:
                        seen.add(other)
                        nxt.append(other)
            frontier = nxt
        return {"nodes": [self.brief(x) for x in seen], "edges": edges[:500]}

    def forward(self, cur, kinds=None):
        """Outgoing edges plus data-flow through shared stores: producer -> topic/table -> consumer/reader."""
        for e in self.out_adj.get(cur, []):
            if not kinds or e["kind"] in kinds:
                yield e["dst"], e
        if self.nodes.get(cur, {}).get("kind") in ("topic", "table", "queue", "bucket", "cache"):
            for e in self.in_adj.get(cur, []):
                if e["kind"] in ("consumes", "reads") and (not kinds or e["kind"] in kinds):
                    yield e["src"], e

    def path(self, src, dst, kinds=None, max_depth=8, k=3):
        s, d = self.resolve(src), self.resolve(dst)
        if not s or not d:
            return {"error": "source or destination not found", "src": s, "dst": d}
        kinds = set(kinds or [])
        targets = set()
        for x in d:
            targets.update(self.contained(x))
        results = []
        q = deque([(x, [x], []) for x in s])
        while q and len(results) < k:
            cur, nodes, hops = q.popleft()
            if len(hops) >= max_depth:
                continue
            for nxt, e in self.forward(cur, kinds):
                if nxt in nodes:
                    continue
                np_, nh = nodes + [nxt], hops + [e]
                if nxt in targets:
                    results.append({"nodes": [self.brief(x) for x in np_], "hops": [self.ebrief(h) for h in nh]})
                    if len(results) >= k:
                        break
                else:
                    q.append((nxt, np_, nh))
        return {"paths": results}

    def _dependents(self, nid):
        """Nodes affected if nid changes (one step), with the edge that justifies it."""
        for e in self.in_adj.get(nid, []):
            if e["kind"] in DEPENDENCY_REVERSE:
                yield e["src"], e
        n = self.nodes.get(nid, {})
        if n.get("kind") == "endpoint":
            for e in self.in_adj.get(nid, []):
                if e["kind"] in ("http_calls", "grpc_calls"):
                    yield e["src"], e
        for e in self.out_adj.get(nid, []):
            if e["kind"] in ("publishes", "writes"):  # data dependents: consumers/readers of what we produce
                for e2 in self.in_adj.get(e["dst"], []):
                    if e2["kind"] in ("consumes", "reads") and e2["src"] != nid:
                        yield e2["src"], e2
            if e["kind"] == "tested_by":
                yield e["dst"], e

    def impact(self, targets=None, diff_rev=None, depth=6, security=True):
        start = []
        for t in targets or []:
            start += self.resolve(t)
        if diff_rev:
            # diff_rev can arrive via MCP/HTTP: reject option-looking or odd revisions (e.g. --output=FILE)
            if diff_rev.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._/~^@{}-]{1,200}", diff_rev):
                return {"error": "invalid revision"}
            for key, root in repo_roots_for_output(self.out).items():
                r = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=", "-C", str(root), "diff",
                                    "--name-only", "--no-ext-diff", "--no-textconv", "--end-of-options", diff_rev, "--"],
                                   capture_output=True, text=True)
                for rel in r.stdout.split():
                    fid = f"file:{key}:{rel}:"
                    if fid in self.nodes:
                        start.append(fid)
        if not start:
            return {"error": "no targets resolved"}
        seeds = []
        for s in start:
            seeds += self.contained(s)
        dist, via = {x: 0 for x in seeds}, {}
        q = deque(seeds)
        while q:
            cur = q.popleft()
            if dist[cur] >= depth:
                continue
            for nxt, e in self._dependents(cur):
                if nxt not in dist:
                    dist[nxt] = dist[cur] + 1
                    via[nxt] = e
                    q.append(nxt)
                    # an affected handler makes its endpoint affected; an affected function affects its file's importers
                    for e2 in self.in_adj.get(nxt, []):
                        if e2["kind"] == "routes_to" and e2["src"] not in dist:
                            dist[e2["src"]] = dist[nxt] + 1
                            via[e2["src"]] = e2
                            q.append(e2["src"])

        def chain(x):
            hops = []
            while x in via and len(hops) < 20:
                hops.append(self.ebrief(via[x]))
                x = via[x]["dst"] if via[x]["src"] == x else via[x]["src"]
            return hops
        affected = [x for x in dist if x not in seeds]
        groups = defaultdict(list)
        for x in affected:
            groups[self.nodes.get(x, {}).get("kind", "?")].append({**self.brief(x), "hops": dist[x], "why": chain(x)})
        res = {"targets": [self.brief(x) for x in start], "seed_nodes": len(seeds), "affected": len(affected),
               "by_kind": {k: sorted(v, key=lambda i: i["hops"]) for k, v in groups.items()}}
        if security:
            sec = defaultdict(list)
            for x in list(dist):
                n = self.nodes.get(x, {})
                if n.get("kind") == "endpoint":
                    sec["endpoints_reached"].append(self.brief(x))
                for e in self.out_adj.get(x, []):
                    if e["kind"] == "reaches_sink":
                        sk = self.nodes.get(e["dst"], {})
                        sec["sinks_in_scope"].append({**self.brief(e["dst"]), "safe": (sk.get("attrs") or {}).get("safe")})
                for e in self.in_adj.get(x, []) + self.out_adj.get(x, []):
                    if e["kind"] in ("threatens", "finding_at", "affects", "crosses_boundary", "drifts_from"):
                        other = e["src"] if e["dst"] == x else e["dst"]
                        sec[self.nodes.get(other, {}).get("kind", "related") + "s"].append({**self.brief(other), "via": e["citation"]})
            res["security"] = {k: list({v["id"]: v for v in vals}.values())[:50] for k, vals in sec.items()}
        return res

    def taint(self, source=None, sink=None, max_depth=10, limit=25):
        order = {"endpoint": 0, "consumer": 1, "cli_command": 1, "cron_job": 1, "taint_source": 2}
        srcs = self.resolve(source) if source else sorted((nid for nid, n in self.nodes.items() if n["kind"] in order), key=lambda x: order[self.nodes[x]["kind"]])
        seen_paths = set()
        sinks = set(self.resolve(sink)) if sink else {nid for nid, n in self.nodes.items()
                                                      if n["kind"] == "sink" and not (n.get("attrs") or {}).get("safe")}
        out = []
        for s in srcs:
            q = deque([(s, [s], [])])
            seen = {s}
            while q and len(out) < limit:
                cur, nodes, hops = q.popleft()
                if len(hops) >= max_depth:
                    continue
                for nxt, e in self.forward(cur):
                    if e["kind"] not in TAINT_FORWARD or nxt in seen:
                        continue
                    if e["kind"] == "contains" and self.nodes.get(cur, {}).get("kind") not in ("class",):
                        continue
                    seen.add(nxt)
                    np_, nh = nodes + [nxt], hops + [e]
                    if nxt in sinks:
                        sig = (nxt, tuple(np_[1:]))
                        if sig in seen_paths:
                            continue  # same route reached from an endpoint and from a source inside its handler
                        seen_paths.add(sig)
                        all_high = all(h["confidence"] == "high" for h in nh)
                        out.append({"source": self.brief(s), "sink": self.brief(nxt),
                                    "sink_type": (self.nodes[nxt].get("attrs") or {}).get("sink_type"),
                                    "label": "observed-path" if all_high else "inferred",
                                    "note": "candidate path: confirm data actually flows by reading each hop",
                                    "hops": [self.ebrief(h) for h in nh]})
                    else:
                        q.append((nxt, np_, nh))
        return {"paths": out, "sources_considered": len(srcs), "sinks_considered": len(sinks)}

    def roles(self, repo=None, role=None, limit=200):
        """Repo kinds and file roles (core, utility, test, iac, pipeline, ...). Rows carry the signals behind each label ([inferred] for core/utility)."""
        import json as _json
        res = {"repos": [], "files": []}
        for n in sorted((n for n in self.nodes.values() if n["kind"] == "repo" and (not repo or n["repo"] == repo)), key=lambda n: n["repo"]):
            a = n.get("attrs") or {}
            res["repos"].append({"repo": n["repo"], "repo_kind": a.get("repo_kind"), "secondary_kinds": a.get("secondary_kinds", []), "signals": a.get("repo_kind_signals", []),
                                 "role_counts": a.get("role_counts", {})})
        for r in res["repos"]:
            p = self.out / "evidence" / f"file-roles-{r['repo']}.json"
            if not p.is_file():
                continue
            try:
                rows = _json.loads(p.read_text()).get("files", [])
            except ValueError:
                continue
            for row in rows:
                if (not role or row.get("role") == role) and len(res["files"]) < limit:
                    res["files"].append({"repo": r["repo"], **row})
        res["note"] = "core/utility are inferred from graph signals; other roles come from path/content rules"
        return res

    def entrypoints(self, repo=None, kinds=None, limit=100):
        """Entry points (endpoints, consumers, cron jobs, CLI commands) with their handler, taint sources read and unsafe sinks reachable from them."""
        kinds = set(kinds or ("endpoint", "consumer", "cron_job", "cli_command"))
        handler = defaultdict(list)
        sources = defaultdict(list)
        for e in self.edges:
            if e["kind"] == "routes_to":
                handler[e["src"]].append(e["dst"])
            elif e["kind"] == "flows_to" and self.nodes.get(e["src"], {}).get("kind") == "taint_source":
                sources[e["dst"]].append(e["src"])
        reach = defaultdict(list)
        for p in self.taint(max_depth=10, limit=2000)["paths"]:
            reach[p["source"]["id"]].append({"sink": p["sink"]["name"], "type": p["sink_type"], "citation": p["sink"].get("citation")})
        out = []
        for nid, n in sorted(self.nodes.items(), key=lambda kv: kv[1].get("citation", "")):
            if n["kind"] not in kinds or (repo and n.get("repo") != repo and not n.get("citation", "").startswith((repo or "") + "/")):
                continue
            hs = handler.get(nid, [])
            out.append({**self.brief(nid), "handler": [self.brief(h) for h in hs[:2]],
                        "sources": sorted({(self.nodes[s].get("attrs") or {}).get("source_type") for h in hs for s in sources.get(h, []) if s in self.nodes}),
                        "reaches_unsafe_sinks": reach.get(nid, [])[:6]})
            if len(out) >= limit:
                break
        return {"entrypoints": out, "note": "sink reachability is a candidate path over the call graph, not proven dataflow"}

    def tour(self, name=None):
        if not self.tours:
            return {"tours": [], "note": "no tours yet; run /ckb:tour to have the graph-curator create them"}
        if not name:
            return {"tours": [{"name": t.get("name"), "title": t.get("title"), "steps": len(t.get("steps", []))} for t in self.tours]}
        t = next((t for t in self.tours if t.get("name") == name), None)
        return t or {"error": f"no tour {name}"}

    def callgraph(self, level="repo", repo=None, focus=None, depth=2, limit=200):
        """Rolled-up call graph at function, file or repo level (see callgraph.py), optionally for one repo or around a focus."""
        if level not in ("function", "file", "repo"):
            return {"error": "level must be function, file or repo"}
        from callgraph import compute, deploy_links
        if getattr(self, "_cg_mtime", None) != self.mtime:
            roots = {k: v for k, v in repo_roots_for_output(self.out).items() if not k.startswith("ctx")}
            g = {"nodes": list(self.nodes.values()), "edges": self.edges}
            self._cg = compute(g, roots, deploy_links(self.out, g))
            self._cg_mtime = self.mtime
        lv = self._cg[level]
        nodes = {n["id"]: n for n in lv["nodes"]}
        rows = [r for r in lv["edges"] if not repo or (nodes[r["src"]].get("repo") == repo or nodes[r["dst"]].get("repo") == repo)]
        if focus:
            seeds = set()
            for t in self.resolve(focus):
                n = self.nodes.get(t, {})
                seeds.add(t)
                if n.get("path"):
                    seeds.add(f"file:{n['repo']}:{n['path']}:")
                if n.get("repo"):
                    seeds.add(f"repo:{n['repo']}::{n['repo']}")
            seen, frontier = set(seeds), set(seeds)
            for _ in range(max(1, min(int(depth), 6))):
                nxt = set()
                for r in rows:
                    if r["src"] in frontier and r["dst"] not in seen:
                        nxt.add(r["dst"])
                    if r["dst"] in frontier and r["src"] not in seen:
                        nxt.add(r["src"])
                seen |= nxt
                frontier = nxt
            rows = [r for r in rows if r["src"] in seen and r["dst"] in seen]
        rows = rows[:limit]
        ids = {r["src"] for r in rows} | {r["dst"] for r in rows}
        return {"level": level, "repo": repo, "focus": focus, "stats": self._cg["stats"][level],
                "nodes": [nodes[i] for i in sorted(ids) if i in nodes], "edges": rows, "shared_stores": self._cg["shared_stores"] if level == "repo" else []}

    def subgraph(self, ids=None, kinds=None, max_nodes=5000):
        kinds = set(kinds or [])
        sel = [nid for nid in (ids or self.nodes) if nid in self.nodes and (not kinds or self.nodes[nid]["kind"] in kinds)][:max_nodes]
        s = set(sel)
        return {"nodes": [self.nodes[x] for x in sel], "edges": [e for e in self.edges if e["src"] in s and e["dst"] in s]}

    def sql(self, query):
        if not re.match(r"(?is)^\s*(SELECT|WITH)\b", query):
            return {"error": "only SELECT/WITH queries are allowed"}
        db = self._connect()

        def auth(action, *_):
            allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
            return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
        db.set_authorizer(auth)
        try:
            cur = db.execute(query)
            cols = [d[0] for d in cur.description or []]
            rows = [dict(zip(cols, r)) for r in cur.fetchmany(500)]
            return {"columns": cols, "rows": rows}
        except sqlite3.DatabaseError as e:
            return {"error": str(e)}
        finally:
            db.close()

    def cypher(self, query):
        try:
            import graph_neo4j
        except ImportError:
            return {"error": "Neo4j support not available"}
        return graph_neo4j.query(self.out, query)

    def dispatch(self, op: str, args: dict):
        ops = {"status": lambda: self.status(), "search": lambda: self.search(args.get("q", ""), args.get("kinds"), args.get("repo"), int(args.get("limit", 20))),
               "node": lambda: self.node(args["id"]), "explain": lambda: self.explain(args["target"]),
               "neighbors": lambda: self.neighbors(args["id"], args.get("dir", "both"), args.get("kinds"), args.get("depth", 1)),
               "path": lambda: self.path(args["src"], args["dst"], args.get("kinds"), int(args.get("max_depth", 8)), int(args.get("k", 3))),
               "impact": lambda: self.impact(args.get("targets"), args.get("diff"), int(args.get("depth", 6))),
               "taint": lambda: self.taint(args.get("source"), args.get("sink"), int(args.get("max_depth", 10))),
               "callgraph": lambda: self.callgraph(args.get("level", "repo"), args.get("repo"), args.get("focus"), int(args.get("depth", 2)), int(args.get("limit", 200))),
               "roles": lambda: self.roles(args.get("repo"), args.get("role"), int(args.get("limit", 200))),
               "entrypoints": lambda: self.entrypoints(args.get("repo"), args.get("kinds"), int(args.get("limit", 100))),
               "tour": lambda: self.tour(args.get("name")), "subgraph": lambda: self.subgraph(args.get("ids"), args.get("kinds")),
               "sql": lambda: self.sql(args["query"]), "cypher": lambda: self.cypher(args["query"])}
        if op not in ops:
            return {"error": f"unknown op {op}", "ops": sorted(ops)}
        try:
            return ops[op]()
        except KeyError as e:
            return {"error": f"missing argument {e}"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out")
    ap.add_argument("op")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--kinds")
    ap.add_argument("--repo")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--dir", default="both")
    ap.add_argument("--depth", type=int)
    ap.add_argument("--max-depth", type=int)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--diff")
    ap.add_argument("--focus")
    ap.add_argument("--source")
    ap.add_argument("--sink")
    ap.add_argument("--role")
    a = ap.parse_args()
    store = GraphStore(resolve_out(a.out))
    kinds = a.kinds.split(",") if a.kinds else None
    p = a.args
    argmap = {
        "search": {"q": " ".join(p), "kinds": kinds, "repo": a.repo, "limit": a.limit},
        "node": {"id": p[0] if p else ""}, "explain": {"target": " ".join(p)},
        "neighbors": {"id": p[0] if p else "", "dir": a.dir, "kinds": kinds, "depth": a.depth or 1},
        "path": {"src": p[0] if p else "", "dst": p[1] if len(p) > 1 else "", "kinds": kinds, "max_depth": a.max_depth or 8, "k": a.k},
        "impact": {"targets": p, "diff": a.diff, "depth": a.depth or 6},
        "taint": {"source": a.source, "sink": a.sink, "max_depth": a.max_depth or 10},
        "callgraph": {"level": p[0] if p else "repo", "repo": a.repo, "focus": a.focus, "depth": a.depth or 2, "limit": a.limit if a.limit != 20 else 200},
        "roles": {"repo": a.repo, "role": a.role, "limit": a.limit if a.limit != 20 else 200},
        "entrypoints": {"repo": a.repo, "kinds": kinds, "limit": a.limit if a.limit != 20 else 100},
        "tour": {"name": p[0] if p else None}, "sql": {"query": " ".join(p)}, "cypher": {"query": " ".join(p)}, "status": {},
    }
    print(json.dumps(store.dispatch(a.op, argmap.get(a.op, {})), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
