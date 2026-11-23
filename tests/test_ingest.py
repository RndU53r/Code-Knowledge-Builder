#!/usr/bin/env python3
"""Tests for scripts/ingest_context.py and the IaC checks. Run: python3 tests/test_ingest.py"""
import json, os, subprocess, sys, tempfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures"
tmp = Path(tempfile.mkdtemp(prefix="ckb-ingest-test-"))
env = {**os.environ, "CKB_HOME": str(tmp / "home")}
fails = 0


def check(name, ok):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name)


def run(*args):
    r = subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, env=env)
    return r


out = tmp / ".ckb"
r = run(ROOT / "scripts/ingest_context.py", "--out", out, "--key", "ctx-arch", FX / "context")
man = json.loads(r.stdout)
by = {i["source"]: i for i in man["items"]}
ctx = out / "evidence/context/ctx-arch"
check("ingest exits 0", r.returncode == 0)
check("draw.io converted with compressed page", "Shipping API (3rd party)" in (ctx / "architecture.drawio.md").read_text())
check("draw.io connector with label", "`API Gateway (Express)` -> `Orders service` : mTLS REST" in (ctx / "architecture.drawio.md").read_text())
check("visio connectors resolved", "`gateway` -> `orders`" in (ctx / "network.vsdx.md").read_text())
check("docx headings and table", "### Trust boundaries" in (ctx / "security-design.docx.md").read_text() and "| orders | core team | internal |" in (ctx / "security-design.docx.md").read_text())
for f, tool in [("securityhub-asff.json", "ASFF"), ("prowler-ocsf.json", "Prowler"), ("checkov.sarif", "Checkov"),
                ("defender-assessments.json", "Defender"), ("gcp-scc-findings.json", "Security Command Center"), ("wiz-issues.csv", "CSV")]:
    check(f"CSPM detected: {f}", tool in by[f].get("kind", ""))
check("image flagged needs_reading", by["whiteboard.png"]["status"] == "needs_reading")
check("pdf converted or needs_reading", by["runbook.pdf"]["status"] in ("converted", "needs_reading"))
check("ctx key registered", "ctx-arch" in json.loads((out / "evidence/targets.json").read_text())["repos"])
sc = run(ROOT / "scripts/scan_supply_chain.py", "--root", ctx, "--key", "ctx-arch")
check("injection in docx detected", any(f["check"] == "SC-A01" and "security-design" in f["path"] for f in json.loads(sc.stdout)["findings"]))
# refusals
bad = tmp / "bad"; bad.mkdir()
(bad / "evil.drawio").write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><mxfile><diagram>&a;</diagram></mxfile>')
with zipfile.ZipFile(bad / "bomb.docx", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("word/document.xml", "<w:document xmlns:w='x'>" + " " * 5_000_000 + "</w:document>")
(bad / "secret.md").write_text("db url postgres://admin:hunter2pass@db:5432/x\n")
r2 = run(ROOT / "scripts/ingest_context.py", "--out", out, "--key", "ctx-bad", bad)
items = {i["source"]: i for i in json.loads(r2.stdout)["items"]}
check("XML entity refused", items["evil.drawio"]["status"] == "refused")
check("zip bomb ratio refused", items["bomb.docx"]["status"] == "refused")
check("secret redacted in converted text", "hunter2pass" not in (out / "evidence/context/ctx-bad/secret.md.md").read_text())
# IaC checks on the polyglot deploy folder
sc2 = json.loads(run(ROOT / "scripts/scan_supply_chain.py", "--root", FX / "polyglot/deploy", "--key", "platform").stdout)
checks = {f["check"] for f in sc2["findings"]}
for c in ("SC-D05", "SC-D07", "SC-D08", "SC-D09"):
    check(f"IaC check {c} fires on fixtures", c in checks)
inv = json.loads(run(ROOT / "scripts/inventory.py", "--root", FX / "polyglot/deploy", "--key", "platform").stdout)
kinds = {c["kind"] for c in inv["cloud_resources"]}
check("cloud resources across AWS/Azure/GCP/CFN", {"terraform", "azure-bicep", "cloudformation"} <= kinds and any(c["type"].startswith("google_") for c in inv["cloud_resources"]))
print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
