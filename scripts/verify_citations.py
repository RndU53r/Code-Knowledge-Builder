#!/usr/bin/env python3
"""Verify ckb citations against the registered target repos.

Usage:
  verify_citations.py [--out OUT_DIR] [--report] [--json] PATH [PATH ...]

PATH is an output .md file or a directory (all .md files under it). OUT_DIR is the
ckb output dir holding evidence/targets.json; it is found automatically by walking
up from PATH when omitted.

Checks, per citation `repo/path:LINE` or `repo/path:START-END`:
  E1 unknown repo key           E2 file not found / outside repo root
  E3 line out of range          E4 quoted text «...» not found in cited lines (±2)
Per file:
  E5 no citations at all (except index.md and evidence/*)
  E6 missing provenance block   W1 section with content but no citation/marker

Exit 0 when no errors, 1 when errors, 2 on usage problems.
Quote matching idea inspired by arden/Codebase-Knowledge-Builder (independent code).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import find_out_dir, now_iso, repo_roots_for_output, within  # noqa: E402

CITE = re.compile(r"`(?P<repo>[A-Za-z0-9._-]+)/(?P<path>[^`\s:]+):(?P<start>\d+)(?:-(?P<end>\d+))?`"
                  r"(?:\s*«(?P<quote>[^»]{1,400})»)?")
MARKER = re.compile(r"\[(inferred|unknown|n/a)\]")
SLACK = 2


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


class Verifier:
    def __init__(self, roots: dict[str, Path]):
        self.roots = roots
        self.cache: dict[Path, list[str]] = {}

    def lines(self, p: Path) -> list[str] | None:
        if p not in self.cache:
            try:
                self.cache[p] = p.read_bytes().decode("utf-8", errors="replace").splitlines()
            except OSError:
                return None
        return self.cache[p]

    def check(self, m: re.Match) -> tuple[str, str] | None:
        repo, rel = m["repo"], m["path"]
        start = int(m["start"])
        end = int(m["end"] or start)
        if repo not in self.roots:
            return "E1", f"unknown repo key '{repo}' (known: {', '.join(sorted(self.roots)) or 'none'})"
        root = self.roots[repo]
        p = root / rel
        if ".." in Path(rel).parts or not within(p, root) or not p.is_file():
            return "E2", f"file not found in {repo}: {rel}"
        ls = self.lines(p)
        if ls is None:
            return "E2", f"unreadable: {repo}/{rel}"
        if start < 1 or end < start or end > len(ls):
            return "E3", f"line {start}-{end} out of range (file has {len(ls)} lines)"
        if m["quote"]:
            want = norm(m["quote"])
            lo, hi = max(0, start - 1 - SLACK), min(len(ls), end + SLACK)
            window = norm(" ".join(ls[lo:hi]))
            if want not in window:
                return "E4", f"quote «{want[:60]}» not found near line {start}"
        return None


def sections(text: str):
    cur, buf = "(preamble)", []
    for line in text.splitlines():
        if line.startswith("## "):
            yield cur, "\n".join(buf)
            cur, buf = line[3:].strip(), []
        else:
            buf.append(line)
    yield cur, "\n".join(buf)


def has_content(body: str) -> bool:
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith(("<!--", "```", "%%", ">")):
            continue
        if re.fullmatch(r"\|[\s|:-]*\|", s):  # table separator or empty row
            continue
        if s.startswith("|") and all(not c.strip() for c in s.strip("|").split("|")):
            continue
        if s.startswith("|") and s.count("|") >= 3 and re.match(r"^\|\s*[A-Z][^|]*\|", s) and "`" not in s:
            # likely a header row; content rows normally carry citations/backticks
            continue
        return True
    return False


def verify_file(path: Path, out_dir: Path, v: Verifier) -> dict:
    text = path.read_text(errors="replace")
    rel = path.relative_to(out_dir).as_posix() if within(path, out_dir) else path.name
    errors, warnings = [], []
    cites = list(CITE.finditer(text))
    for m in cites:
        res = v.check(m)
        if res:
            line_no = text.count("\n", 0, m.start()) + 1
            errors.append({"code": res[0], "line": line_no, "citation": m.group(0)[:120], "message": res[1]})
    exempt = rel == "index.md" or rel.startswith("evidence/")
    if not exempt and not cites and not MARKER.search(text):
        errors.append({"code": "E5", "line": 1, "message": "no citations in file"})
    if not rel.startswith("evidence/") and "ckb provenance" not in text:
        errors.append({"code": "E6", "line": 1, "message": "missing provenance block"})
    if not exempt:
        for title, body in sections(text):
            if title == "(preamble)":
                continue
            if has_content(body) and not CITE.search(body) and not MARKER.search(body):
                warnings.append({"code": "W1", "section": title, "message": "section has content but no citation or [inferred]/[unknown]/[n/a] marker"})
    return {"file": rel, "citations": len(cites), "errors": errors, "warnings": warnings}


def collect(paths: list[str]) -> list[Path]:
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*.md") if x.is_file())
        elif p.suffix == ".md" and p.is_file():
            files.append(p)
    return files


def write_report(out_dir: Path, results: list[dict]) -> Path:
    total = sum(r["citations"] for r in results)
    nerr = sum(len(r["errors"]) for r in results)
    lines = ["# Citation verification", "", f"- Run: {now_iso()}", f"- Files: {len(results)}",
             f"- Citations checked: {total}", f"- Errors: {nerr}",
             f"- Warnings: {sum(len(r['warnings']) for r in results)}", "",
             "| File | Citations | Errors | Warnings |", "| --- | --- | --- | --- |"]
    for r in results:
        lines.append(f"| {r['file']} | {r['citations']} | {len(r['errors'])} | {len(r['warnings'])} |")
    for r in results:
        if r["errors"] or r["warnings"]:
            lines += ["", f"## {r['file']}"]
            for e in r["errors"]:
                lines.append(f"- **{e['code']}** line {e['line']}: {e['message']}")
            for w in r["warnings"]:
                lines.append(f"- {w['code']} section '{w['section']}': {w['message']}")
    p = out_dir / "evidence" / "verification.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n")
    return p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out")
    ap.add_argument("--report", action="store_true", help="write <out>/evidence/verification.md")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    files = collect(a.paths)
    if not files:
        print("no markdown files found", file=sys.stderr)
        return 2
    out_dir = Path(a.out).resolve() if a.out else find_out_dir(files[0].resolve())
    if not out_dir:
        print("cannot find evidence/targets.json; pass --out", file=sys.stderr)
        return 2
    v = Verifier(repo_roots_for_output(out_dir))
    results = [verify_file(f.resolve(), out_dir, v) for f in files]
    if a.report:
        write_report(out_dir, results)
    nerr = sum(len(r["errors"]) for r in results)
    if a.json:
        print(json.dumps({"errors": nerr, "results": results}, indent=2))
    else:
        for r in results:
            status = "FAIL" if r["errors"] else "ok"
            print(f"[{status}] {r['file']}: {r['citations']} citations, {len(r['errors'])} errors, {len(r['warnings'])} warnings")
            for e in r["errors"]:
                print(f"    {e['code']} L{e['line']}: {e['message']}")
    return 1 if nerr else 0


if __name__ == "__main__":
    sys.exit(main())
