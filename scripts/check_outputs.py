#!/usr/bin/env python3
"""LLM-free checks over ckb output markdown.

Usage:
  check_outputs.py [--json] PATH [PATH ...]

Checks:
  M1 Mermaid block: unknown diagram type, unbalanced brackets/quotes, raw HTML/script,
     click/callback directives (blocked: diagrams must be inert)
  L1 broken relative markdown link (target file missing)
  S1 secret-looking value present (type only; value is never printed)
  H1 active HTML (<script>, <iframe>, on*= handlers, javascript: URLs)
  F1 generated facts block (<!-- ckb:facts:begin ... -->) that no longer matches evidence/context-facts-<repo>.json
     (hand-edited, stale, or the file is missing)

Exit 0 clean, 1 problems found, 2 usage. Idea inspired by arden/Codebase-Knowledge-Builder
(deterministic doc checks); independent implementation.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import find_secret_values  # noqa: E402

MERMAID_TYPES = ("flowchart", "graph", "sequenceDiagram", "classDiagram", "stateDiagram", "stateDiagram-v2",
                 "erDiagram", "journey", "gantt", "pie", "mindmap", "timeline", "C4Context", "C4Container",
                 "C4Component", "C4Dynamic", "block-beta", "architecture-beta", "requirementDiagram")
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HTML_BAD = re.compile(r"(?i)<\s*(script|iframe|object|embed|form)\b|\son\w+\s*=|javascript:")


def mermaid_problems(src: str) -> list[str]:
    probs = []
    body = [l for l in src.splitlines() if l.strip() and not l.strip().startswith("%%")]
    if not body:
        return ["empty diagram"]
    head = body[0].strip().split()[0]
    if head not in MERMAID_TYPES and not head.startswith("---"):
        probs.append(f"unknown diagram type '{head}'")
    stripped = re.sub(r'"[^"\n]*"', '""', src)
    if src.count('"') % 2:
        probs.append("unbalanced double quotes")
    for o, c in ("[]", "()", "{}"):
        if stripped.count(o) != stripped.count(c):
            probs.append(f"unbalanced {o}{c}")
    if re.search(r"(?im)^\s*click\s+\w+", src) or "callback" in src:
        probs.append("interactive click/callback directive (diagrams must be inert)")
    if HTML_BAD.search(src):
        probs.append("active HTML in diagram")
    return probs


FACTS_BEGIN = re.compile(r"<!-- ckb:facts:begin repo=(\S+) kind=(\S+) entry_points=(\d+) sources=(\d+) sinks=(\d+) core_files=(\d+) test_files=(\d+) -->")


def facts_problems(path: Path, text: str) -> list[dict]:
    """Verify every embedded facts block against its facts JSON (counts) and against the generated markdown (verbatim)."""
    out = []
    for m in FACTS_BEGIN.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        repo = m.group(1)
        end = text.find("<!-- ckb:facts:end -->", m.end())
        if end == -1:
            out.append({"code": "F1", "line": line, "message": "facts block has no end marker"})
            continue
        block = text[m.start(): end + len("<!-- ckb:facts:end -->")]
        base = path.parent
        facts = None
        for d in [base, *base.parents][:4]:
            cand = d / "evidence" / f"context-facts-{repo}.json"
            if cand.is_file():
                facts = cand
                gen = d / "repos" / repo / "context-facts.md"
                break
        if facts is None:
            out.append({"code": "F1", "line": line, "message": f"no evidence/context-facts-{repo}.json found for this facts block"})
            continue
        try:
            j = json.loads(facts.read_text())
        except ValueError:
            out.append({"code": "F1", "line": line, "message": "facts JSON is unreadable"})
            continue
        want = (len(j.get("entry_points", [])), len(j.get("sources", [])), len(j.get("sinks", [])), j.get("n_core", 0), j.get("n_test", 0))
        got = tuple(int(x) for x in m.groups()[2:])
        if want != got:
            out.append({"code": "F1", "line": line, "message": f"facts counts in the header {got} differ from {facts.name} {want} (stale or hand-edited)"})
        if gen.is_file():
            ref = gen.read_text().strip()
            if ref and block.strip() != ref:
                out.append({"code": "F1", "line": line, "message": "facts block differs from repos/%s/context-facts.md (hand-edited or stale); re-run context_facts.py and re-embed it verbatim" % repo})
    return out


def check(path: Path) -> list[dict]:
    text = path.read_text(errors="replace")
    out = facts_problems(path, text)
    for m in re.finditer(r"```mermaid\n(.*?)```", text, re.S):
        ln = text.count("\n", 0, m.start()) + 1
        for p in mermaid_problems(m.group(1)):
            out.append({"code": "M1", "line": ln, "message": p})
    no_code = re.sub(r"```.*?```", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    for m in LINK.finditer(no_code):
        target = m.group(1).split("#", 1)[0]
        if not target or re.match(r"^[a-z]+:", target):
            continue
        if not (path.parent / target).exists():
            out.append({"code": "L1", "line": no_code.count("\n", 0, m.start()) + 1, "message": f"broken link: {target}"})
    for name, a, _ in find_secret_values(text):
        ctx = text[max(0, a - 40):a]
        if "REDACTED" in text[a:a + 60]:
            continue
        out.append({"code": "S1", "line": text.count("\n", 0, a) + 1, "message": f"possible unredacted {name}"})
    for m in HTML_BAD.finditer(no_code):
        out.append({"code": "H1", "line": no_code.count("\n", 0, m.start()) + 1, "message": "active HTML or script URL"})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    files = []
    for p in map(Path, a.paths):
        files += sorted(p.rglob("*.md")) if p.is_dir() else [p]
    if not files:
        return 2
    res = {str(f): check(f) for f in files if f.is_file()}
    n = sum(len(v) for v in res.values())
    if a.json:
        print(json.dumps({"problems": n, "results": res}, indent=2))
    else:
        for f, probs in res.items():
            for p in probs:
                print(f"{f}:{p['line']}: {p['code']} {p['message']}")
        print(f"{n} problem(s) in {len(res)} file(s)")
    return 1 if n else 0


if __name__ == "__main__":
    sys.exit(main())
