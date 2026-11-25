"""Shared definitions for the ckb knowledge graph: schema, IDs, validation, safe strings.

Python stdlib only. Imported by graph_extract / graph_build / graph_query / graph_merge /
graph_check / graph_viewer / graph_serve / graph_mcp / graph_export / graph_neo4j.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from ckb_common import now_iso, redact_text

SCHEMA_VERSION = "1.0"
EXTRACTOR_VERSION = "1"
MAX_STR = 300

NODE_KINDS = {
    # structure
    "repo", "dir", "file", "module", "class", "interface", "function", "method", "field", "variable",
    # interfaces
    "endpoint", "consumer", "topic", "queue", "contract_op", "cli_command", "cron_job",
    # state & config
    "table", "cache", "bucket", "env_var", "config_flag", "package", "cloud_resource", "service", "external",
    # security
    "taint_source", "sink", "threat", "sc_finding", "cspm_finding", "trust_boundary", "asset", "drift",
    # docs
    "doc_section",
}
EXTRACTORS = {"ast", "tree-sitter", "regex", "llm", "context", "scanner", "rule"}  # rule = deterministic rule engine (threat_seed, doc_claims)
CONFIDENCE = {"high", "medium", "low"}
LABELS = {"observed", "inferred", "documented", "unknown"}

# edge kind -> extractors allowed to produce it
EDGE_KINDS = {
    "contains": {"ast", "tree-sitter", "regex", "context", "scanner"},
    "defines": {"ast", "tree-sitter", "regex"},
    "imports": {"ast", "tree-sitter", "regex"},
    "calls": {"ast", "tree-sitter", "regex", "llm"},
    "inherits": {"ast", "tree-sitter", "regex", "llm"},
    "implements": {"ast", "tree-sitter", "regex", "llm"},
    "overrides": {"ast", "tree-sitter", "llm"},
    "uses_type": {"ast", "tree-sitter", "llm"},
    "references": {"ast", "tree-sitter", "regex", "llm"},
    "routes_to": {"ast", "tree-sitter", "regex", "llm"},
    "http_calls": {"regex", "ast", "tree-sitter", "llm"},
    "grpc_calls": {"regex", "llm"},
    "publishes": {"ast", "regex", "tree-sitter", "llm"},
    "consumes": {"ast", "regex", "tree-sitter", "llm"},
    "reads": {"ast", "regex", "tree-sitter", "llm"},
    "writes": {"ast", "regex", "tree-sitter", "llm"},
    "reads_env": {"ast", "regex", "tree-sitter"},
    "spawns": {"ast", "regex", "tree-sitter", "llm"},
    "ffi": {"regex", "llm"},
    "depends_on": {"scanner", "regex"},
    "deploys": {"regex", "context", "llm"},
    "tested_by": {"ast", "regex", "llm"},
    "flows_to": {"ast", "regex", "tree-sitter", "llm", "rule"},
    "reaches_sink": {"ast", "regex", "tree-sitter", "llm"},
    "threatens": {"llm", "rule"},
    "finding_at": {"scanner"},
    "affects": {"context", "scanner", "llm", "rule"},
    "crosses_boundary": {"llm", "rule"},
    "inside_boundary": {"llm", "rule"},
    "mitigated_by": {"llm", "rule"},
    "documented_as": {"llm", "context", "rule"},
    "drifts_from": {"llm", "rule"},
}

ID_RE = re.compile(r"^[a-z_]+:[A-Za-z0-9._-]+:[^\n]{0,400}$")
CITE_RE = re.compile(r"^[A-Za-z0-9._-]+/[^\s:]+:\d+(-\d+)?$")
SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")


def safe_str(v, limit: int = MAX_STR) -> str:
    s = redact_text(str(v if v is not None else ""))
    s = "".join(ch for ch in s if ch == "\t" or ord(ch) >= 32)
    return s[:limit] + ("…" if len(s) > limit else "")


def safe_quote(line: str, limit: int = 140) -> str:
    """Exact text from a source line for use as a proposal quote, cut before any secret-looking value so
    credentials never land in proposal files. (The verifier checks the quote is a substring of the line.)"""
    from ckb_common import find_secret_values
    line = (line or "").strip()
    hits = sorted(find_secret_values(line), key=lambda t: t[1])
    if hits:
        a = hits[0][1]
        head = line[:a].rstrip()
        tail = line[hits[0][2]:].strip()
        line = head if len(head) >= 8 else (tail if len(tail) >= 8 else head)
    return line[:limit]


def md_safe(s, limit: int = 0) -> str:
    """Make target-derived text inert inside generated markdown tables: no HTML tags, no event-handler or
    javascript: patterns, no table/code breakers."""
    s = str(s).replace("|", "/").replace("`", "'").replace("\n", " ").replace("\r", " ")
    s = s.replace("<", "\u2039").replace(">", "\u203a")
    s = re.sub(r"(?i)\b(on[a-z]+)\s*=", r"\1:", s)
    s = re.sub(r"(?i)javascript\s*:", "javascript[:]", s)
    return s[:limit] if limit else s


def node_id(kind: str, repo: str, path: str = "", qualname: str = "") -> str:
    return f"{kind}:{repo}:{path}:{qualname}" if path else f"{kind}:{repo}::{qualname}"


def edge_id(src: str, kind: str, dst: str, ref: str = "") -> str:
    return hashlib.sha1(f"{src}|{kind}|{dst}|{ref}".encode()).hexdigest()[:16]


def sig_hash(signature: str) -> str:
    return hashlib.sha1(re.sub(r"\s+", " ", signature or "").strip().encode()).hexdigest()[:12]


def cite(repo: str, path: str, start: int, end: int | None = None) -> str:
    return f"{repo}/{path}:{start}" + (f"-{end}" if end and end != start else "")


def prov(extractor: str, run: str | None = None) -> dict:
    return {"extractor": extractor, "tool_version": f"ckb-graph/{EXTRACTOR_VERSION}", "run": run or now_iso()}


def make_node(kind, repo, path, qualname, name, start, end=None, extractor="regex", confidence="high",
              label="observed", **extra) -> dict:
    n = {"id": node_id(kind, repo, path, qualname), "kind": kind, "name": safe_str(name, 200), "repo": repo,
         "path": path, "range": {"start": int(start), "end": int(end or start)},
         "citation": cite(repo, path, int(start), int(end or start)) if path else extra.pop("citation", ""),
         "provenance": prov(extractor), "confidence": confidence, "label": label}
    if qualname:
        n["qualname"] = safe_str(qualname, 300)
    for k, v in extra.items():
        if v not in (None, "", [], {}):
            n[k] = safe_str(v) if isinstance(v, str) else v
    return n


def make_edge(src, kind, dst, citation, extractor="regex", confidence="high", label="observed", quote=None,
              dst_citation=None, **extra) -> dict:
    e = {"id": edge_id(src, kind, dst, citation), "src": src, "dst": dst, "kind": kind, "citation": citation,
         "provenance": prov(extractor), "confidence": confidence, "label": label,
         "verified": {"status": "mechanical" if extractor != "llm" else "unverified", "by": "extractor"}}
    if quote:
        e["quote"] = safe_str(quote, 200)
    if dst_citation:
        e["dst_citation"] = dst_citation
    for k, v in extra.items():
        if v not in (None, "", [], {}):
            e[k] = safe_str(v) if isinstance(v, str) else v
    return e


def validate(graph: dict) -> list[str]:
    """Return a list of schema problems (empty = valid). Stdlib replacement for a JSON Schema validator."""
    probs = []
    for k in ("schema_version", "generated", "repos", "nodes", "edges"):
        if k not in graph:
            probs.append(f"missing top-level '{k}'")
    ids = set()
    for n in graph.get("nodes", []):
        nid = n.get("id", "")
        for f in ("id", "kind", "name", "repo", "citation", "provenance", "confidence", "label"):
            if f not in n:
                probs.append(f"node {nid or '?'}: missing {f}")
        if n.get("kind") not in NODE_KINDS:
            probs.append(f"node {nid}: unknown kind {n.get('kind')}")
        if not ID_RE.match(nid or ""):
            probs.append(f"node {nid}: bad id")
        if nid in ids:
            probs.append(f"duplicate node id {nid}")
        ids.add(nid)
        if (n.get("provenance") or {}).get("extractor") not in EXTRACTORS:
            probs.append(f"node {nid}: bad extractor")
        if n.get("confidence") not in CONFIDENCE or n.get("label") not in LABELS:
            probs.append(f"node {nid}: bad confidence/label")
        if n.get("citation") and not CITE_RE.match(n["citation"]):
            probs.append(f"node {nid}: bad citation {n['citation']}")
    eids = set()
    for e in graph.get("edges", []):
        eid = e.get("id", "?")
        for f in ("id", "src", "dst", "kind", "citation", "provenance", "confidence", "label", "verified"):
            if f not in e:
                probs.append(f"edge {eid}: missing {f}")
        k, ex = e.get("kind"), (e.get("provenance") or {}).get("extractor")
        if k not in EDGE_KINDS:
            probs.append(f"edge {eid}: unknown kind {k}")
        elif ex not in EDGE_KINDS[k]:
            probs.append(f"edge {eid}: extractor {ex} not allowed for {k}")
        if ex == "llm" and not e.get("quote"):
            probs.append(f"edge {eid}: llm edge without quote")
        if e.get("src") not in ids or e.get("dst") not in ids:
            probs.append(f"edge {eid}: dangling ({e.get('src')} -> {e.get('dst')})")
        if eid in eids:
            probs.append(f"duplicate edge id {eid}")
        eids.add(eid)
        if e.get("citation") and not CITE_RE.match(e["citation"]):
            probs.append(f"edge {eid}: bad citation {e['citation']}")
    return probs


def graph_dir(out: Path) -> Path:
    return Path(out) / "graph"


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_text(text)
    tmp.replace(path)


def load_graph(out: Path) -> dict:
    return json.loads((graph_dir(out) / "graph.json").read_text())


def resolve_out(explicit: str | None = None) -> Path:
    """Output dir: explicit arg > CKB_OUT env > settings output_dir > ./.ckb"""
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.environ.get("CKB_OUT"):
        return Path(os.environ["CKB_OUT"]).expanduser().resolve()
    s = Path(".claude/code-knowledge-builder.local.md")
    if s.is_file():
        m = re.search(r"(?m)^output_dir:\s*(\S+)", s.read_text())
        if m:
            return Path(m.group(1)).expanduser().resolve()
    return Path(".ckb").resolve()
