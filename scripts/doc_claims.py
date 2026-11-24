#!/usr/bin/env python3
"""Turn documentation, diagrams and notes into checkable claims and compare them with the code graph.

Usage:
  doc_claims.py --out OUT_DIR

Input: converted context under <out>/evidence/context/ctx-*/ (from ingest_context.py: draw.io, Visio,
Excalidraw, Mermaid, PlantUML, Gliffy, Word, PowerPoint, PDF, email/notes, agent-written *.notes.md for
images) and the built knowledge graph.

Claims it extracts (deterministic patterns, no model): components and their containers, documented
connections (A -> B : label), and controls: mTLS / TLS, encryption at rest, authentication on a
component, internal-only exposure. Each claim is matched to graph entities (repos, endpoints, cloud
resources) and checked:
  consistent | drift | not verifiable statically | unmatched
Every verdict cites the document line AND the code/IaC evidence. Documents record intent, so
documents never overrule code: disagreements are reported as drift.

Writes
  <out>/system/documented-vs-observed.md      the table the HLD and threat model include
  <out>/evidence/doc-claims.json              all claims, matches, verdicts
  <out>/graph/proposals/seed-docs.jsonl       doc_section nodes + documented_as edges, drift nodes +
                                              drifts_from edges (extractor "rule"; verified by graph_merge)
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import load_json, now_iso  # noqa: E402
from graph_common import atomic_write, graph_dir, md_safe, safe_quote, safe_str  # noqa: E402
from threat_seed import HEALTH_RX, Ctx, has_auth_evidence  # noqa: E402

STOP = {"service", "services", "api", "app", "the", "server", "worker", "system", "component", "module", "main", "layer", "of", "and", "a", "an", "in", "to"}
STORE_WORDS = {"database", "db", "datastore", "postgres", "postgresql", "mysql", "sql", "mongodb", "mongo", "dynamodb", "rds", "storage", "bucket", "blob"}
BROKER_WORDS = {"rabbitmq", "kafka", "broker", "queue", "sqs", "mq", "pubsub", "servicebus", "amqp"}
STORE_TYPE = re.compile(r"(?i)(db_instance|rds|sql|dynamo|storage|bucket|blob|mongo|cosmos|database|redis|cache)")
BROKER_TYPE = re.compile(r"(?i)(mq|sqs|sns|kafka|pubsub|servicebus|eventhub|queue)")
RX = {
    "mtls": re.compile(r"(?i)\bmtls\b|mutual\s+tls"),
    "tls": re.compile(r"(?i)\bhttps\b|\btls\b|\bamqps\b|encrypt\w*\s+in\s+transit|\bssl\b"),
    "enc-rest": re.compile(r"(?i)encrypt\w*(\s+at\s+rest)?|encryption\s+at\s+rest"),
    "authn": re.compile(r"(?i)(validates?|verifies?|checks?|requires?|enforces?)\s+(the\s+)?(caller\s+)?(jwt|token|authentication|credentials)|authenticat\w+\s+(every|all)\s+request|jwt"),
    "internal": re.compile(r"(?i)internal[- ]only|not\s+(be\s+)?(publicly\s+)?(reachable|exposed|accessible)|no\s+public\s+(ingress|access)|private\s+(network|vpc|subnet)"),
}
GLOBAL_SCOPE = re.compile(r"(?i)\b(all|every)\b|service[- ]to[- ]service|between\s+(all\s+)?services")
GLOBAL_COMPONENTS = re.compile(r"(?i)\b(all|every)\s+(services?|components?|microservices?)\b|service[- ]to[- ]service|between\s+(all\s+)?services")
DB_WORDS = {"database", "db", "datastore", "postgres", "postgresql", "mysql", "sql", "mongodb", "mongo", "dynamodb", "rds"}
OBJ_WORDS = {"storage", "bucket", "blob"}
DB_TYPE = re.compile(r"(?i)(db_instance|rds|sql|dynamo|mongo|cosmos|database)")
OBJ_TYPE = re.compile(r"(?i)(bucket|storage|blob)")
SHAPE = re.compile(r"^- shape `([^`]*)`: (.*?)(?: · in: (.*?))?(?: · style: .*)?$")
CONN = re.compile(r"^- `([^`]*)` -> `([^`]*)`(?: : (.*))?$")
PLAIN_HTTP = re.compile(r"['\"`](http://(?!localhost|127\.0\.0\.1)[A-Za-z0-9_.-]+(?::\d+)?)")
TLS_CFG = re.compile(r"(?i)\b(cert|ca_?file|tls\.Config|https\.Agent|rejectUnauthorized|mtls|ssl_context|verify\s*=)\b")


def toks(s: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", s.lower()) if t not in STOP and len(t) > 1}


class Matcher:
    def __init__(self, c: Ctx):
        self.c = c
        self.repos = {n["repo"]: n["id"] for n in c.nodes.values() if n["kind"] == "repo"}
        self.res = [n for n in c.nodes.values() if n["kind"] == "cloud_resource"]
        self.tables = [n for n in c.nodes.values() if n["kind"] == "table"]

    def match(self, label: str) -> list[tuple[str, str, str]]:
        """-> [(node_id, kind_class, confidence)] where kind_class in repo|store|broker."""
        t = toks(label)
        out = []
        for key, nid in self.repos.items():
            kt = toks(key)
            if kt and kt <= t:
                out.append((nid, "repo", "high"))
            elif any(difflib.SequenceMatcher(None, key.lower(), x).ratio() >= 0.85 for x in t if len(x) > 3):
                out.append((nid, "repo", "medium"))
        if t & STORE_WORDS:
            for r in self.res:
                typ = (r.get("attrs") or {}).get("type", "")
                names = {x.lower() for x in (r.get("attrs") or {}).get("names", [])}
                named = any(toks(x) & t for x in names)
                generic = (t & DB_WORDS and DB_TYPE.search(typ)) or (t & OBJ_WORDS and OBJ_TYPE.search(typ))
                if STORE_TYPE.search(typ) and (named or generic):
                    out.append((r["id"], "store", "high" if named else "medium"))
            for tb in self.tables:
                if toks(tb["name"]) & t:
                    out.append((tb["id"], "store", "medium"))
        if t & BROKER_WORDS:
            for r in self.res:
                if BROKER_TYPE.search((r.get("attrs") or {}).get("type", "")) or BROKER_TYPE.search(r["name"]):
                    out.append((r["id"], "broker", "medium"))
        return out


# ---------------------------------------------------------------- parsing context files

def context_files(out: Path):
    for d in sorted((out / "evidence" / "context").glob("ctx*")):
        man = load_json(d / "manifest.json", {})
        key = man.get("key", d.name)
        for it in man.get("items", []):
            if it.get("file") and (str(it.get("kind", "")).startswith(("diagram", "document")) or it["file"].endswith(".notes.md")):
                yield key, d / it["file"], it
        for p in sorted(d.glob("*.notes.md")):  # agent-written notes for images / scanned PDFs
            if not any(p.name == it.get("file") for it in man.get("items", [])):
                yield key, p, {"kind": "document: notes (agent-read image)", "source": p.name}


def extract_claims(out: Path):
    claims, comps, conns = [], [], []
    for key, path, item in context_files(out):
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        rel = path.name
        is_diagram = str(item.get("kind", "")).startswith("diagram") or "### Shapes" in "\n".join(lines[:60])
        for i, ln in enumerate(lines, 1):
            cite = f"{key}/{rel}:{i}"
            s = SHAPE.match(ln) if is_diagram else None
            if s:
                label, cont = s.group(2).strip(), (s.group(3) or "").strip()
                comps.append({"label": label, "container": cont, "cite": cite, "quote": ln.strip()[:140]})
                if RX["tls"].search(label) and not RX["mtls"].search(label):
                    claims.append({"type": "control", "control": "tls", "scope": [label], "text": f"'{label}' is documented as TLS-protected", "cite": cite, "quote": ln.strip()[:140]})
                if re.search(r"(?i)encrypted", label):
                    claims.append({"type": "control", "control": "enc-rest", "scope": [label], "text": f"'{label}' is documented as encrypted", "cite": cite, "quote": ln.strip()[:140]})
                if RX["internal"].search(label):  # the container shape itself: "Private VPC (no public ingress)"
                    claims.append({"type": "control", "control": "internal", "scope": ["@container"], "container": label, "cite": cite, "quote": ln.strip()[:140],
                                   "text": f"'{label}' is documented as private / no public ingress"})
                continue
            cm = CONN.match(ln) if is_diagram else None
            if cm:
                a, b, lab = cm.group(1), cm.group(2), (cm.group(3) or "").strip()
                conns.append({"from": a, "to": b, "label": lab, "cite": cite, "quote": ln.strip()[:140]})
                for ctl in ("mtls", "tls"):
                    if RX[ctl].search(lab) and not (ctl == "tls" and RX["mtls"].search(lab)):
                        claims.append({"type": "control", "control": ctl, "scope": [a, b], "conn": True, "text": f"{a} → {b} documented as {lab}", "cite": cite, "quote": ln.strip()[:140]})
                continue
            if is_diagram or not ln.strip() or ln.startswith(("#", "<!--", "- Kind:", "- Converted", "- Status", "|")):
                continue
            for sent in re.split(r"(?<=[.!?])\s+", ln.strip()):
                if len(sent) < 12:
                    continue
                for ctl, rx in RX.items():
                    if not rx.search(sent):
                        continue
                    scope_all = bool(GLOBAL_SCOPE.search(sent)) if ctl in ("mtls", "tls") else bool(GLOBAL_COMPONENTS.search(sent))
                    if ctl == "tls" and RX["mtls"].search(sent):
                        continue
                    if ctl == "enc-rest" and not re.search(r"(?i)at\s+rest|database|storage|bucket|disk", sent):
                        continue
                    claims.append({"type": "control", "control": ctl, "scope": ["*"] if scope_all else [sent], "text": sent[:200], "cite": cite, "quote": sent[:140]})
    for cl in claims:  # a container claim covers the shapes drawn inside it
        if cl.get("scope") == ["@container"]:
            members = [x["label"] for x in comps if x["container"] == cl["container"]]
            cl["scope"] = members or ["*"]
            cl["text"] += (" (contains: " + ", ".join(members[:6]) + ")") if members else ""
    return claims, comps, conns


# ---------------------------------------------------------------- checks

def plain_http_hits(c: Ctx, src_repo: str, path: str):
    ls = c.lines(src_repo, path)
    for i, ln in enumerate(ls, 1):
        m = PLAIN_HTTP.search(ln)
        if m:
            return m.group(1), f"{src_repo}/{path}:{i}", ln.strip()[:140]
    return None


def http_edges(c: Ctx, repos_a: set | None, repos_b: set | None):
    for e in c.store.edges:
        if e["kind"] == "http_calls" and e.get("dst_citation"):
            s, d = c.nodes.get(e["src"], {}), c.nodes.get(e["dst"], {})
            if s.get("repo") != d.get("repo") and (repos_a is None or s.get("repo") in repos_a or d.get("repo") in repos_a) and \
                    (repos_b is None or s.get("repo") in repos_b or d.get("repo") in repos_b):
                yield e, s, d


def check_mtls_tls(c: Ctx, m: Matcher, claim, ctl):
    if claim["scope"] == ["*"]:
        a = b = None
    elif not claim.get("conn") and any(k == "broker" for _, k, _ in m.match(claim["scope"][0])):
        a = b = None  # a broker shape documented as TLS: checked via the broker URL below
    else:
        ents = [m.match(x) for x in claim["scope"][:2]] if claim.get("conn") else [m.match(claim["scope"][0])]
        sets = [{c.nodes[n]["repo"] for n, k, _ in ms if k == "repo"} for ms in ents]
        a = sets[0] or None
        b = sets[1] if len(sets) > 1 and sets[1] else None
        if claim.get("conn") and (not sets[0] or not sets[1]) and not any(k == "broker" for ms in ents for _, k, _ in ms):
            return None
        if not claim.get("conn") and not sets[0]:
            return None
    broker_involved = any(k == "broker" for x in claim["scope"][:2] for _, k, _ in m.match(x)) and (claim.get("conn") or claim["scope"] != ["*"])
    if broker_involved:
        for n in c.nodes.values():
            if n["kind"] == "file" and n.get("path") and n.get("repo") in c.roots:
                for i, ln in enumerate(c.lines(n["repo"], n["path"]), 1):
                    mm = re.search(r"['\"`](amqp://(?!localhost|127\.0\.0\.1)[A-Za-z0-9_.@:-]+)", ln)
                    if mm and "REDACTED" not in ln:
                        return {"verdict": "drift", "observed": f"broker URL default uses plain `amqp://` (no TLS) in {n['repo']}", "evidence": [f"{n['repo']}/{n['path']}:{i}"],
                                "target": next((e["src"] for e in c.store.edges if e["kind"] in ("publishes", "consumes") and c.nodes.get(e["src"], {}).get("path") == n["path"]), None),
                                "code_quote": safe_quote(ln), "security": "yes"}
        return {"verdict": "not verifiable statically", "observed": "no plain amqp:// URL found; broker TLS is configured outside the code in scope", "evidence": [], "security": "yes"}
    edges = list(http_edges(c, a, b))
    if not edges:
        return {"verdict": "not verifiable statically", "observed": "no HTTP calls between the named components were found in the code", "evidence": [], "security": "yes"}
    cfg = []
    for e, s, d in edges:
        hit = plain_http_hits(c, s["repo"], s["path"])
        if hit:
            return {"verdict": "drift", "observed": f"{s['repo']} calls {d['repo']} with a plain-http default (`{hit[0]}`); no client certificate settings", "evidence": [hit[1], e["citation"]],
                    "target": e["src"], "code_quote": safe_quote(hit[2]), "security": "yes"}
        if TLS_CFG.search(c.file_text(s["repo"], s["path"])):
            cfg.append(e["citation"])
    if ctl == "tls" and edges and all(re.search(r"https://", c.file_text(s["repo"], s["path"])) for _, s, _ in edges):
        return {"verdict": "consistent", "observed": "calls use https:// URLs", "evidence": [edges[0][0]["citation"]], "security": "yes"}
    if ctl == "mtls" and cfg:
        return {"verdict": "consistent", "observed": "client certificate/TLS settings found at the call site", "evidence": cfg[:2], "security": "yes"}
    return {"verdict": "not verifiable statically", "observed": "no plain-http default found, but no TLS/mTLS client configuration found either (may be set by a mesh or at deploy time)",
            "evidence": [edges[0][0]["citation"]], "security": "yes"}


def redact_line(ln: str) -> str:
    return safe_str(ln.strip(), 140)


def check_enc_rest(c: Ctx, m: Matcher, claim):
    label = claim["scope"][0]
    ents = [(n, k, cf) for n, k, cf in m.match(label) if k == "store"] if claim["scope"] != ["*"] else [(r["id"], "store", "medium") for r in m.res if STORE_TYPE.search((r.get("attrs") or {}).get("type", ""))]
    if not ents:
        return None
    for nid, _, _ in ents:
        res = c.nodes[nid]
        if res["kind"] != "cloud_resource":
            continue
        for e in c.store.in_adj.get(nid, []):
            if e["kind"] == "finding_at":
                f = c.nodes[e["src"]]
                if (f.get("attrs") or {}).get("check") == "SC-D09":
                    ln = c.line(f["citation"]) or ""
                    corro = [x for x in c.store.in_adj.get(nid, []) if x["kind"] == "affects"]
                    return {"verdict": "drift", "observed": f"IaC disables encryption/TLS for {res['name']}: `{redact_line(ln)}`", "evidence": [f["citation"]] + [c.nodes[x["src"]]["citation"] for x in corro[:1]],
                            "target": nid, "code_quote": safe_quote(ln), "security": "yes"}
    for nid, _, _ in ents:
        res = c.nodes[nid]
        if res["kind"] == "cloud_resource":
            blk = "\n".join(c.lines(res["repo"], res["path"])[res["range"]["start"] - 1: res["range"]["end"]])
            mm = re.search(r"(?i)(storage_encrypted|encrypted|kms_key|encryption)\w*\s*[=:]\s*(true|\"?[A-Za-z0-9/:_-]+)", blk)
            if mm:
                ln = next((i for i, x in enumerate(c.lines(res["repo"], res["path"]), 1) if mm.group(0) in x), res["range"]["start"])
                return {"verdict": "consistent", "observed": f"IaC sets encryption for {res['name']}", "evidence": [f"{res['repo']}/{res['path']}:{ln}"], "security": "yes"}
    return {"verdict": "not verifiable statically", "observed": "no disabling encryption setting found in IaC, but no explicit enabling setting either", "evidence": [], "security": "yes"}


def check_internal(c: Ctx, m: Matcher, claim):
    sc_open = [c.nodes[n["id"]] for n in c.nodes.values() if n["kind"] == "sc_finding" and (n.get("attrs") or {}).get("check") == "SC-D05"]
    if claim.get("container"):
        if sc_open:
            f = sc_open[0]
            ln = c.line(f["citation"]) or ""
            tgt = next((e["dst"] for e in c.store.out_adj.get(f["id"], []) if e["kind"] == "finding_at"), None)
            return {"verdict": "drift", "observed": f"{len(sc_open)} ingress rule(s) open to the internet in IaC (e.g. `{redact_line(ln)}`)", "evidence": [x["citation"] for x in sc_open[:2]],
                    "target": tgt, "code_quote": safe_quote(ln), "security": "yes"}
        return {"verdict": "not verifiable statically", "observed": "no internet-open ingress found in IaC in scope", "evidence": [], "security": "yes"}
    ents = [n for n, k, _ in m.match(claim["scope"][0]) if k == "repo"] if claim["scope"] != ["*"] else []
    if not ents:
        return None
    repo = c.nodes[ents[0]]["repo"]
    for r in m.res:
        if (r.get("attrs") or {}).get("type") == "Ingress":
            blk = "\n".join(c.lines(r["repo"], r["path"])[r["range"]["start"] - 1: r["range"]["end"] + 25])
            mm = re.search(rf"name:\s*{re.escape(repo)}\b", blk)
            if mm:
                ln = next((i for i, x in enumerate(c.lines(r["repo"], r["path"]), 1) if re.search(rf"name:\s*{re.escape(repo)}\b", x)), r["range"]["start"])
                cite = f"{r['repo']}/{r['path']}:{ln}"
                return {"verdict": "drift", "observed": f"{repo} is routed by an Ingress ({r['name']})", "evidence": [cite], "target": r["id"], "code_quote": safe_quote(c.line(cite) or ""), "security": "yes"}
    callers = [e for n in c.nodes.values() if n["kind"] == "endpoint" and n["repo"] == repo for e in c.in_http.get(n["id"], [])]
    if callers:
        return {"verdict": "consistent", "observed": f"{repo}'s endpoints are only called by other services; no ingress routes to it", "evidence": [callers[0]["citation"]], "security": "yes"}
    return {"verdict": "not verifiable statically", "observed": f"no ingress to {repo} found; its endpoints are not called by other services either, so exposure is unknown", "evidence": [], "security": "yes"}


def check_authn(c: Ctx, m: Matcher, claim):
    ents = [n for n, k, _ in m.match(claim["scope"][0]) if k == "repo"] if claim["scope"] != ["*"] else []
    if not ents:
        return None
    repo = c.nodes[ents[0]]["repo"]
    eps = [n for n in c.nodes.values() if n["kind"] == "endpoint" and n["repo"] == repo and not HEALTH_RX.search((n.get("attrs") or {}).get("path", ""))]
    if not eps:
        return {"verdict": "not verifiable statically", "observed": f"no endpoints found in {repo}", "evidence": [], "security": "yes"}
    bad = [n for n in sorted(eps, key=lambda x: x["citation"]) if not has_auth_evidence(c, n)]
    if bad:
        h = (c.handler.get(bad[0]["id"]) or [bad[0]["id"]])[0]
        return {"verdict": "drift", "observed": f"{len(bad)} of {len(eps)} endpoint(s) in {repo} show no authentication evidence (e.g. {bad[0]['name']})", "evidence": [x["citation"] for x in bad[:3]],
                "target": h, "code_quote": safe_quote(c.line(bad[0]["citation"]) or ""), "security": "yes"}
    return {"verdict": "consistent", "observed": f"all {len(eps)} endpoint(s) in {repo} show authentication on the route or handler chain", "evidence": [sorted(eps, key=lambda x: x["citation"])[0]["citation"]], "security": "yes"}


def check_connections(c: Ctx, m: Matcher, conns, rows, drifts):
    cg_pairs = defaultdict(list)
    from callgraph import compute
    cg = compute({"nodes": list(c.nodes.values()), "edges": c.store.edges}, {k: v for k, v in c.roots.items() if not k.startswith("ctx")})
    names = {n["id"]: n["name"] for n in cg["repo"]["nodes"]}
    for r in cg["repo"]["edges"]:
        cg_pairs[(names[r["src"]], names[r["dst"]])].append(r)
    documented = set()
    for cn in conns:
        a = [c.nodes[n]["repo"] for n, k, _ in m.match(cn["from"]) if k == "repo"]
        b = [c.nodes[n]["repo"] for n, k, _ in m.match(cn["to"]) if k == "repo"]
        if not a or not b:
            continue
        documented |= {(a[0], b[0]), (b[0], a[0])}
        hit = cg_pairs.get((a[0], b[0])) or cg_pairs.get((b[0], a[0]))
        if hit:
            rows.append({"claim": f"{cn['from']} → {cn['to']}" + (f" ({cn['label']})" if cn["label"] else ""), "doc": cn["cite"], "observed": f"connection exists in code ({hit[0]['mechanism']}); this row checks existence only", "evidence": hit[0]["evidence"][:2], "verdict": "consistent"})
        else:
            drifts.append({"claim": f"documented connection {cn['from']} → {cn['to']}", "doc": cn["cite"], "observed": "no call, topic, shared table, or subprocess link found between them in the code",
                           "evidence": [], "target": next((n for n, k, _ in m.match(cn["from"]) if k == "repo"), None), "code_quote": cn["quote"], "security": "no", "doc_only": True,
                           "verdict": "drift", "quote_cite": cn["cite"]})
    if conns and documented:
        for (s, d), rs in cg_pairs.items():
            if (s, d) not in documented and s in {x for p in documented for x in p} and d in {x for p in documented for x in p} and not rs[0]["mechanism"].endswith("external"):
                drifts.append({"claim": f"undocumented flow {s} → {d}", "doc": "", "observed": f"{rs[0]['mechanism']} link exists in code but no diagram shows it", "evidence": rs[0]["evidence"][:2],
                               "target": next((e["src"] for e in c.store.edges if e["citation"] == rs[0]["citation"] and e["kind"] in ("http_calls", "publishes", "spawns")), None),
                               "code_quote": safe_quote(c.line(rs[0]["citation"]) or ""), "security": "no", "verdict": "drift"})
                if sum(1 for d_ in drifts if d_["claim"].startswith("undocumented")) >= 8:
                    break


# ---------------------------------------------------------------- run

def esc(s) -> str:
    return md_safe(s)


def run(out: Path) -> dict:
    claims, comps, conns = extract_claims(out)
    if not (claims or comps or conns):
        return {"claims": 0, "note": "no converted context found"}
    c = Ctx(out)
    m = Matcher(c)
    rows, drifts, unmatched, seen = [], [], [], set()
    for cl in claims:
        key = (cl["control"], tuple(cl["scope"]), cl["cite"])
        if key in seen:
            continue
        seen.add(key)
        ctl = cl["control"]
        res = (check_mtls_tls(c, m, cl, ctl) if ctl in ("mtls", "tls") else check_enc_rest(c, m, cl) if ctl == "enc-rest" else
               check_internal(c, m, cl) if ctl == "internal" else check_authn(c, m, cl))
        if res is None:
            unmatched.append(cl)
            continue
        row = {"claim": cl["text"], "doc": cl["cite"], "observed": res["observed"], "evidence": res["evidence"], "verdict": res["verdict"], "type": ctl}
        rows.append(row)
        if res["verdict"] == "drift":
            drifts.append({**row, "target": res.get("target"), "code_quote": res.get("code_quote"), "security": res.get("security", "yes"), "doc_quote": cl["quote"]})
    check_connections(c, m, conns, rows, drifts)
    for r in rows:
        r.setdefault("type", "connection")
    # proposals
    props, n_d = [], 0
    for cl in {x["doc"]: x for x in rows if x["verdict"] in ("consistent", "drift")}.values():
        pass
    for d in drifts:
        n_d += 1
        evid = d["evidence"][0] if d.get("evidence") else None
        cite = evid if (evid and not d.get("doc_only")) else d.get("quote_cite") or d.get("doc")
        quote = (d.get("code_quote") or d.get("quote") or d.get("doc_quote") or "").strip()
        if not cite or not quote or not d.get("target") and not d.get("doc_only"):
            continue
        qn = f"D-{n_d:02d}-{re.sub(r'[^a-z0-9]+', '-', d['claim'].lower())[:40].strip('-')}"
        props.append({"op": "node", "extractor": "rule", "kind": "drift", "repo": "_system", "qualname": qn, "name": d["claim"][:200], "citation": cite, "quote": quote[:140],
                      "confidence": "medium", "label": "inferred", "attrs": {"claim": d["claim"][:200], "observed": d["observed"][:200], "doc_citation": d.get("doc", ""), "security": d.get("security", "yes"),
                                                                            "claim_type": d.get("type", "connection")}})
        if d.get("target") and d["target"] in c.nodes:
            props.append({"op": "edge", "extractor": "rule", "src": f"drift:_system::{qn}", "kind": "drifts_from", "dst": d["target"], "citation": cite, "quote": quote[:140],
                          "confidence": "medium", "label": "inferred", "rationale": d["observed"][:200]})
    for cl in claims:
        for label in cl["scope"][:2]:
            if label == "*" or cl["control"] == "internal" and False:
                continue
            ents = m.match(label)
            if ents and cl["quote"]:
                nid, kind, cf = ents[0]
                qn = f"{cl['cite']}:{cl['control']}"
                props.append({"op": "node", "extractor": "rule", "kind": "doc_section", "repo": "_system", "qualname": qn, "name": cl["text"][:200], "citation": cl["cite"],
                              "quote": cl["quote"], "confidence": cf, "label": "documented", "attrs": {"control": cl["control"], "source_kind": "context"}})
                props.append({"op": "edge", "extractor": "rule", "src": nid, "kind": "documented_as", "dst": f"doc_section:_system::{qn}", "citation": cl["cite"], "quote": cl["quote"],
                              "confidence": cf, "label": "documented"})
                break
    p = graph_dir(out) / "proposals" / "seed-docs.jsonl"
    atomic_write(p, "".join(json.dumps(x) + "\n" for x in props))
    # outputs
    targets = load_json(out / "evidence" / "targets.json", {"repos": {}}).get("repos", {})
    srcs = ", ".join(f"`{k}`" for k in targets if not k.startswith("ctx"))
    ctxs = ", ".join(f"`{k}`" for k in targets if k.startswith("ctx"))
    counts = defaultdict(int)
    for r in rows:
        counts[r["verdict"]] += 1
    L = ["# Documented vs observed", "", "> **ckb provenance**", f"> - Sources: code {srcs}; context {ctxs}", f"> - Generated: {now_iso()} by ckb doc_claims, stage `context-from-docs`",
         "> - Scope: claims extracted from supplied documents, diagrams and notes · Excluded: statements the patterns do not recognize", "> - Method: deterministic claim extraction and checks against the knowledge graph; documents record intent, code and IaC record what is built",
         "> - Verification: drift items are mirrored as graph proposals (graph/proposals/seed-docs.jsonl), verified by graph_merge", "",
         "## Summary", "", f"[inferred] {len(claims)} control claim(s) and {len(conns)} documented connection(s) extracted: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + f"; {len(unmatched)} claim(s) matched no code entity.", "",
         "## Documented vs observed", "", "| Claim (documented) | Source | Observed | Evidence | Verdict |", "| --- | --- | --- | --- | --- |"]
    order = {"drift": 0, "consistent": 1, "not verifiable statically": 2}
    for r in sorted(rows, key=lambda r: (order.get(r["verdict"], 3), r["doc"])):
        ev = " ".join(f"`{x}`" for x in dict.fromkeys(r["evidence"])) or "[unknown]"
        doc = f"`{r['doc']}`" if r["doc"] else "[n/a] (not in any document)"
        L.append(f"| {esc(r['claim'])[:160]} | {doc} | {esc(r['observed'])[:220]} | {ev} | **{r['verdict']}** |")
    if not rows:
        L.append("| [unknown] no checkable claims | | | | |")
    L += ["", "## Claims not matched to the code", "", "| Claim | Source | Why |", "| --- | --- | --- |"]
    L += [f"| {esc(u['text'])[:160]} | `{u['cite']}` | no repo, endpoint or cloud resource matched the named component |" for u in unmatched[:40]] or ["| [n/a] none | | |"]
    L += ["", "Drift on a security control becomes a threat in `system/threat-model.md` (the documented control is the claimed mitigation; the code or IaC is the gap).", ""]
    atomic_write(out / "system" / "documented-vs-observed.md", "\n".join(L))
    atomic_write(out / "evidence" / "doc-claims.json", json.dumps({"generated": now_iso(), "claims": claims, "connections": conns, "rows": rows, "unmatched": unmatched}, indent=1))
    return {"claims": len(claims), "connections": len(conns), "verdicts": dict(counts), "drift": len(drifts), "proposals": len(props), "unmatched": len(unmatched)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve()), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
