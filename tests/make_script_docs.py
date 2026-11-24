#!/usr/bin/env python3
"""Generate docs/scripts.md from the scripts' own module docstrings (usage text), so the reference cannot drift.
Run: python3 tests/make_script_docs.py        (CI-style check: python3 tests/make_script_docs.py --check)"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUPS = [
    ("Planning", ["env_probe", "auto_plan", "enumerate_sources"]),
    ("Acquisition", ["fetch_source"]),
    ("Extraction", ["inventory", "graph_extract", "scan_supply_chain", "ingest_context"]),
    ("Graph", ["graph_build", "graph_merge", "graph_check"]),
    ("Derivation", ["callgraph", "threat_seed", "doc_claims", "repo_context"]),
    ("Query, view and export", ["graph_query", "graph_viewer", "graph_serve", "graph_mcp", "graph_export", "graph_neo4j"]),
    ("Assurance", ["verify_citations", "check_outputs", "hash_index", "guard"]),
]
INTERNAL = ["ckb_common", "graph_common", "graph_security"]


def doc(name: str) -> str:
    tree = ast.parse((ROOT / "scripts" / f"{name}.py").read_text())
    return (ast.get_docstring(tree) or "").strip()


def build() -> str:
    out = ["# Script reference", "",
           "Every ckb step is a plain Python 3 script (standard library only) under `scripts/`. In a Claude Code session the commands call them for you; you can also run them directly, for example in CI or to debug a stage. `${CLAUDE_PLUGIN_ROOT}` is the plugin directory; `<out>` is the output directory (default `<target>/.ckb`).", "",
           "None of these scripts executes, builds, installs or imports code from the repos they analyze. This page is generated from each script's own usage text by `tests/make_script_docs.py`; run any script with no arguments or `--help` for the same text.", ""]
    for title, names in GROUPS:
        out += [f"## {title}", ""]
        for n in names:
            out += [f"### `{n}.py`", "", "```text", doc(n), "```", ""]
    out += ["## Internal modules", "", "Imported by the scripts above; not run directly.", ""]
    for n in INTERNAL:
        first = doc(n).splitlines()[0] if doc(n) else ""
        out.append(f"* `{n}.py`: {first}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    target = ROOT / "docs" / "scripts.md"
    text = build()
    covered = {n for _, ns in GROUPS for n in ns} | set(INTERNAL)
    missing = sorted(p.stem for p in (ROOT / "scripts").glob("*.py") if p.stem not in covered)
    if missing:
        print("scripts not listed in make_script_docs.py:", ", ".join(missing))
        return 1
    if "--check" in sys.argv:
        ok = target.is_file() and target.read_text() == text
        print("docs/scripts.md is up to date" if ok else "docs/scripts.md is stale: run python3 tests/make_script_docs.py")
        return 0 if ok else 1
    target.write_text(text)
    print(f"wrote {target.relative_to(ROOT)} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
