#!/usr/bin/env python3
"""Enrich the knowledge graph with context that lives in the repos themselves (deterministic, no model).

Usage:
  repo_context.py --out OUT_DIR

Reads, per registered repo: README (first real paragraph), ADRs, CODEOWNERS, OpenAPI/AsyncAPI specs
(summaries and descriptions per operation), and docker-compose service metadata. Function/class
summaries from docstrings and leading comments are already attached at extraction time (graph_extract).

Writes <out>/graph/proposals/seed-repo-context.jsonl (extractor "rule"): doc_section / contract_op nodes,
documented_as edges, and annotate lines (summary, tags). graph_merge verifies every line against the
source like any proposal, so rebuild afterwards. All text is untrusted: lines that address AI agents are
never used in a summary, secrets are redacted, strings are capped.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import load_json, read_text, repo_excludes, repo_roots_for_output, walk_files  # noqa: E402
from graph_common import atomic_write, graph_dir, node_id, safe_quote, safe_str  # noqa: E402
from graph_extract import norm_path  # noqa: E402
from scan_supply_chain import AGENT_PHRASES, DANGEROUS_IMPERATIVE  # noqa: E402

HTTP = ("get", "post", "put", "patch", "delete", "head", "options")
ADR_RX = re.compile(r"(?i)(^|/)(adrs?|decisions?)/[^/]+\.(md|markdown)$")
OWNERS_RX = re.compile(r"(?i)(^|/)(\.github/|docs/)?CODEOWNERS$")
README_RX = re.compile(r"(?i)^readme(\.(md|markdown|rst|txt))?$")
SPEC_RX = re.compile(r"(?i)(openapi|swagger|asyncapi)[^/]*\.(ya?ml|json)$")
COMPOSE_RX = re.compile(r"(?i)(^|/)(docker-)?compose[^/]*\.ya?ml$")


def hostile(text: str) -> bool:
    return bool(AGENT_PHRASES.search(text) or DANGEROUS_IMPERATIVE.search(text))


def first_paragraph(lines: list[str]) -> tuple[str, int] | None:
    """First prose paragraph after the title: skips badges, headings, code, html, tables, and hostile text."""
    para, start = [], 0
    in_code = False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        skip = (not s or s.startswith(("#", "![", "[![", "<", "|", "---", "===", "- [", ">", "[")) or re.match(r"^[=\-~]{3,}$", s))
        if skip:
            if para:
                text = " ".join(para)
                if not hostile(text):
                    return safe_str(re.sub(r"[*_`]", "", text), 300), start
                para, start = [], 0
            continue
        if not para:
            start = i
        para.append(s)
    if para and not hostile(" ".join(para)):
        return safe_str(re.sub(r"[*_`]", "", " ".join(para)), 300), start
    return None


def yaml_ops(lines: list[str]):
    """Light scan of an OpenAPI YAML: yields (path, method, summary_or_description, line_of_path_key)."""
    in_paths, cur_path, cur_line, cur_method = False, None, 0, None
    for i, ln in enumerate(lines, 1):
        if re.match(r"^paths:\s*$", ln):
            in_paths = True
            continue
        if in_paths and re.match(r"^\S", ln):
            in_paths = False
        if not in_paths:
            continue
        m = re.match(r"^  (/\S*?):\s*$", ln) or re.match(r'^  ["\'](/\S*?)["\']:\s*$', ln)
        if m:
            cur_path, cur_line, cur_method = m.group(1), i, None
            continue
        m = re.match(r"^    (%s):\s*$" % "|".join(HTTP), ln)
        if m and cur_path:
            cur_method = m.group(1)
            continue
        m = re.match(r"^      (summary|description):\s*(.+?)\s*$", ln)
        if m and cur_path and cur_method and not m.group(2).startswith(("|", ">")):
            yield cur_path, cur_method.upper(), m.group(2).strip("'\""), i
            cur_method = None


def json_ops(text: str):
    try:
        spec = json.loads(text)
    except ValueError:
        return
    lines = text.splitlines()
    for path, item in (spec.get("paths") or {}).items():
        for meth, op in (item or {}).items():
            if meth.lower() in HTTP and isinstance(op, dict):
                desc = op.get("summary") or op.get("description")
                if desc:
                    ln = next((i for i, x in enumerate(lines, 1) if f'"{path}"' in x), 1)
                    yield path, meth.upper(), str(desc), ln


def asyncapi_channels(lines: list[str]):
    in_ch, cur, cur_line = False, None, 0
    for i, ln in enumerate(lines, 1):
        if re.match(r"^channels:\s*$", ln):
            in_ch = True
            continue
        if in_ch and re.match(r"^\S", ln):
            in_ch = False
        if not in_ch:
            continue
        m = re.match(r"^  ['\"]?([^\s'\":]+)['\"]?:\s*$", ln)
        if m:
            cur, cur_line = m.group(1), i
            continue
        m = re.match(r"^    (summary|description):\s*(.+?)\s*$", ln)
        if m and cur:
            yield cur, m.group(2).strip("'\""), cur_line
            cur = None


def run(out: Path) -> dict:
    g = json.loads((graph_dir(out) / "graph.json").read_text())
    nodes = {n["id"]: n for n in g["nodes"]}
    endpoints = [n for n in g["nodes"] if n["kind"] == "endpoint"]
    topics = {n["name"]: n for n in g["nodes"] if n["kind"] == "topic"}
    roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
    excl = repo_excludes(out)
    props, counts = [], {"readme": 0, "adr": 0, "owners": 0, "api_ops": 0, "channels": 0, "compose": 0}
    compose_tags = {}  # service name (lower) -> tags; compose files often live in a different repo than the service

    def add_doc(kind, key, rel, qual, name, line, quote, target, conf="medium", attrs=None):
        q = safe_quote(quote)
        if not q or hostile(quote):
            return
        cite = f"{key}/{rel}:{line}"
        props.append({"op": "node", "extractor": "rule", "kind": kind, "repo": "_system", "qualname": qual, "name": safe_str(name, 200), "citation": cite, "quote": q,
                      "confidence": conf, "label": "documented", "attrs": attrs or {}})
        if target in nodes:
            props.append({"op": "edge", "extractor": "rule", "src": target, "kind": "documented_as", "dst": f"{kind}:_system::{qual}", "citation": cite, "quote": q,
                          "confidence": conf, "label": "documented"})

    for key, root in sorted(roots.items()):
        repo_node = node_id("repo", key, "", key)
        files = list(walk_files(root, excl.get(key, [])))
        tags = []
        for p, rel in files:
            base = rel.rsplit("/", 1)[-1]
            text = None
            if README_RX.match(base) and rel.count("/") <= 1:
                text = read_text(p) or ""
                fp = first_paragraph(text.splitlines())
                if fp and repo_node in nodes:
                    summary, line = fp
                    add_doc("doc_section", key, rel, f"{key}:README:{rel}", f"README: {rel}", line, text.splitlines()[line - 1], repo_node)
                    if rel.count("/") == 0:
                        props.append({"op": "annotate", "id": repo_node, "summary": summary, "source": "readme"})
                    counts["readme"] += 1
            elif ADR_RX.search(rel) and counts["adr"] < 30 * max(1, len(roots)):
                lines = (read_text(p) or "").splitlines()
                title_i = next((i for i, x in enumerate(lines, 1) if x.startswith("# ")), None)
                if title_i:
                    st = next((x.strip() for x in lines[:25] if re.match(r"(?i)^\**status\**\s*[:\-]", x.strip())), "")
                    add_doc("doc_section", key, rel, f"{key}:ADR:{rel}", f"ADR: {lines[title_i - 1][2:].strip()}", title_i, lines[title_i - 1], repo_node,
                            attrs={"status": safe_str(st, 80), "kind": "decision-record"})
                    counts["adr"] += 1
            elif OWNERS_RX.search(rel):
                handles = []
                for ln in (read_text(p) or "").splitlines():
                    if ln.strip().startswith("#"):
                        continue
                    handles += re.findall(r"(?<![\w.])@[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", ln)
                tags += [f"owner:{h}" for h in dict.fromkeys(handles)][:4]
                counts["owners"] += 1 if handles else 0
            elif SPEC_RX.search(base):
                text = read_text(p) or ""
                lines = text.splitlines()
                is_async = "asyncapi" in base.lower() or re.search(r"(?m)^asyncapi:\s", text)
                if is_async:
                    for chan, desc, ln in asyncapi_channels(lines):
                        t = topics.get(chan)
                        if t and not hostile(desc):
                            add_doc("contract_op", key, rel, f"{rel}:channel {chan}", f"channel {chan}", ln, lines[ln - 1], t["id"], attrs={"description": safe_str(desc, 200)})
                            props.append({"op": "annotate", "id": t["id"], "summary": safe_str(desc, 300), "source": "asyncapi"})
                            counts["channels"] += 1
                else:
                    ops = list(json_ops(text)) if base.lower().endswith(".json") else list(yaml_ops(lines))
                    for path, meth, desc, ln in ops[:150]:
                        if hostile(desc):
                            continue
                        norm = norm_path(path)
                        match = [e for e in endpoints if (e.get("attrs") or {}).get("norm") == norm and (e.get("attrs") or {}).get("method") in (meth, "ANY")]
                        src_line = next((i for i, x in enumerate(lines, 1) if re.search(rf"^\s*[\"']?{re.escape(path)}[\"']?\s*:", x) or f'"{path}"' in x), ln)
                        for e in match[:2]:
                            add_doc("contract_op", key, rel, f"{rel}:{meth} {path}", f"{meth} {path} (spec)", src_line, lines[src_line - 1] if src_line <= len(lines) else path, e["id"],
                                    attrs={"description": safe_str(desc, 200), "spec": rel})
                            props.append({"op": "annotate", "id": e["id"], "summary": safe_str(desc, 300), "source": "openapi"})
                            counts["api_ops"] += 1
            elif COMPOSE_RX.search(rel):
                text = read_text(p) or ""
                svc, in_services = None, False
                for ln in text.splitlines():
                    if re.match(r"^services:\s*$", ln):
                        in_services = True
                        continue
                    if in_services and re.match(r"^\S", ln):
                        in_services = False
                    m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", ln) if in_services else None
                    if m:
                        svc = m.group(1).lower()
                        compose_tags.setdefault(svc, [])
                    if svc and in_services:
                        pm = re.match(r"^\s*-\s*[\"']?(\d+):(\d+)", ln) or re.match(r"^\s*ports:\s*\[\s*[\"']?(\d+):(\d+)", ln)
                        if pm:
                            compose_tags[svc].append(f"port:{pm.group(1)}")
                        if re.match(r"^\s*(build|image):", ln) and "deploy:compose" not in compose_tags[svc]:
                            compose_tags[svc].append("deploy:compose")
        if tags and repo_node in nodes:
            props.append({"op": "annotate", "id": repo_node, "tags": list(dict.fromkeys(tags))[:12]})
    for key in roots:
        t = compose_tags.get(key.lower())
        if t and node_id("repo", key, "", key) in nodes:
            props.append({"op": "annotate", "id": node_id("repo", key, "", key), "tags": list(dict.fromkeys(t))[:6]})
            counts["compose"] += 1
    p = graph_dir(out) / "proposals" / "seed-repo-context.jsonl"
    atomic_write(p, "".join(json.dumps(x) + "\n" for x in props))
    return {"proposals": len(props), **counts}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve()), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
