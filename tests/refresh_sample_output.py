#!/usr/bin/env python3
"""Regenerate the deterministic parts of examples/sample-output from the polyglot fixtures (no agents involved).
Run: python3 tests/refresh_sample_output.py
Refreshed: system/{threat-model,call-graphs,graph,documented-vs-observed,coverage}.md, repos/<repo>/{code-map,context-facts}.md, graph/graph.json,
evidence/{call-resolution-*,file-roles-*,coverage}.json. Everything else (HLD, flows, supply-chain narrative, ...) is agent-written and kept as is.
Temp paths are replaced by <workspace>; the script fails if a local path is left behind."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S, FX, DEST = ROOT / "scripts", ROOT / "tests" / "fixtures", ROOT / "examples" / "sample-output"
tmp = Path(tempfile.mkdtemp(prefix="ckb-sample-"))
os.environ["CKB_HOME"] = str(tmp / "home")


def run(script, *args):
    r = subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=os.environ)
    if r.returncode not in (0, 1):
        raise SystemExit(f"{script} failed: {r.stderr[-400:]}")
    return r


work = tmp / "workspace"
shutil.copytree(FX / "polyglot", work)
out = tmp / ".ckb"
for k in ("gateway", "orders", "fulfillment"):
    run("fetch_source.py", "--out", out, "--key", k, work / k)
run("fetch_source.py", "--out", out, "--key", "platform", work / "deploy")
run("ingest_context.py", "--out", out, "--key", "ctx-platform", FX / "context")
for k, p in (("gateway", "gateway"), ("orders", "orders"), ("fulfillment", "fulfillment"), ("platform", "deploy")):
    run("scan_supply_chain.py", "--root", work / p, "--key", k, "--json-out", out / "evidence" / f"sc-{k}.json")
run("graph_build.py", "--out", out, "--extract", "--enrich")
scrub = [(str(tmp), "<workspace>"), (str(Path.home()), "<home>"), (tempfile.gettempdir(), "<scratch>")]


def clean(text: str) -> str:
    for a, b in scrub:
        text = text.replace(a, b)
    return text


copied = []
for rel in ["system/threat-model.md", "system/call-graphs.md", "system/graph.md", "system/documented-vs-observed.md", "system/coverage.md", "graph/graph.json", "evidence/coverage.json"] + \
        [str(p.relative_to(out)) for pat in ("repos/*/code-map.md", "repos/*/context-facts.md", "evidence/call-resolution-*.json", "evidence/file-roles-*.json", "evidence/context-facts-*.json", "evidence/deploy-facts-*.json") for p in sorted(out.glob(pat))]:
    src = out / rel
    if src.is_file():
        dst = DEST / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(clean(src.read_text()))
        copied.append(rel)
old = DEST / "evidence" / "threat-model.draft-snapshot.md.txt"
if old.exists():
    old.unlink()
bad = [r for r in copied if re.search(r"/(var/folders|private/tmp|Users/[^/]+/)", (DEST / r).read_text())]
shutil.rmtree(tmp, ignore_errors=True)
if bad:
    raise SystemExit(f"local paths left in: {bad}")
print(f"refreshed {len(copied)} files in {DEST.relative_to(ROOT)}")
