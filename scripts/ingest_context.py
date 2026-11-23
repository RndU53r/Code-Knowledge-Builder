#!/usr/bin/env python3
"""Ingest supporting context (architecture documents, diagrams, IaC, CSPM results) into a
citable, normalized form under <out>/evidence/context/<key>/ and register it as a ckb
source so citations like `ctx-arch/design.docx.md:42` verify.

Usage:
  ingest_context.py --out OUT_DIR [--key ctx-NAME] PATH [PATH ...]

Supported (Python stdlib only; nothing is executed, macros are never run):
  Diagrams   .drawio .drawio.xml .dio (incl. compressed pages), .vsdx (Visio), .svg (text labels)
  Documents  .docx .pptx .md .txt .rst .adoc .html .htm, .pdf (via `pdftotext` if installed,
             otherwise listed under needs_reading for Claude's Read tool), images
             (.png .jpg .jpeg .gif .webp) listed under needs_reading
  CSPM       AWS Security Hub ASFF, Prowler (JSON/OCSF/CSV), ScoutSuite, SARIF (Checkov/tfsec/
             KICS/Trivy...), Checkov JSON, Microsoft Defender for Cloud assessments, GCP Security
             Command Center findings, generic CSV with severity/resource/title columns
  IaC        .tf .tfvars .hcl .bicep, ARM templates, CloudFormation/SAM, GCP Deployment Manager,
             Kubernetes/Helm YAML, Pulumi/CDK sources: copied verbatim (citable by original line)

Every output file starts with a header naming the original file. Secret-looking values are
redacted. Archives (docx/pptx/vsdx) are read in memory with size limits; XML with DOCTYPE or
ENTITY declarations is refused. Prints a JSON manifest.
"""
from __future__ import annotations

import argparse
import base64
import csv
import html
import io
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import now_iso, redact_text, register_target  # noqa: E402

MAX_MEMBER = 25 * 1024 * 1024
MAX_TOTAL = 100 * 1024 * 1024
MAX_FILE = 50 * 1024 * 1024
TEXT_EXT = {".md", ".txt", ".rst", ".adoc"}
IAC_EXT = {".tf", ".tfvars", ".hcl", ".bicep", ".jinja", ".j2"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class Refused(Exception):
    pass


def safe_xml(data: bytes) -> ET.Element:
    head = data[:4096].decode("utf-8", errors="ignore")
    if "<!DOCTYPE" in head or "<!ENTITY" in data.decode("utf-8", errors="ignore"):
        raise Refused("XML with DOCTYPE/ENTITY declarations refused")
    return ET.fromstring(data)


def strip_html(s: str) -> str:
    s = re.sub(r"(?i)<br\s*/?>|</div>|</p>", " ", s or "")
    s = re.sub(r"<[^>]+>", "", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def lname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def read_zip(path: Path) -> zipfile.ZipFile:
    z = zipfile.ZipFile(path)
    total = 0
    for info in z.infolist():
        if info.file_size > MAX_MEMBER:
            raise Refused(f"archive member too large: {info.filename}")
        total += info.file_size
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 200:
            raise Refused(f"suspicious compression ratio in {info.filename}")
    if total > MAX_TOTAL:
        raise Refused("archive too large when uncompressed")
    return z


def header(src: Path, kind: str, extra: str = "") -> list[str]:
    return [f"<!-- ckb context: converted from {src.name} ({kind}); original path recorded in manifest.json -->",
            f"# Context: {src.name}", "", f"- Kind: {kind}", f"- Converted: {now_iso()}" + (f" · {extra}" if extra else ""),
            "- Status: untrusted input. Claims here are what the document says, not proof of what the code does.", ""]


# ------------------------------------------------------------------ diagrams

def drawio(path: Path) -> list[str]:
    root = safe_xml(path.read_bytes())
    pages = root.findall(".//diagram") if lname(root.tag) == "mxfile" else []
    models = []
    if pages:
        for d in pages:
            model = d.find("mxGraphModel")
            if model is None and (d.text or "").strip():
                raw = base64.b64decode(d.text.strip())
                try:
                    xml = urllib.parse.unquote(zlib.decompress(raw, -15).decode("utf-8"))
                except zlib.error:
                    xml = raw.decode("utf-8", errors="replace")
                model = safe_xml(xml.encode())
            models.append((d.get("name") or d.get("id") or "page", model))
    elif lname(root.tag) == "mxGraphModel":
        models.append(("page", root))
    out = header(path, "draw.io diagram", f"{len(models)} page(s)")
    for name, model in models:
        if model is None:
            continue
        cells = {c.get("id"): c for c in model.iter("mxCell")}
        label = lambda cid: strip_html((cells.get(cid).get("value") if cells.get(cid) is not None else "") or "") or f"#{cid}"
        out += [f"## Page: {strip_html(name)}", "", "### Shapes", ""]
        for cid, c in cells.items():
            if c.get("vertex") == "1":
                parent = c.get("parent")
                container = label(parent) if parent in cells and cells[parent].get("vertex") == "1" else ""
                style = c.get("style") or ""
                hint = next((h for h in ("swimlane", "group", "container", "cylinder", "actor", "cloud", "mxgraph.aws", "mxgraph.azure", "mxgraph.gcp") if h in style), "")
                out.append(f"- shape `{cid}`: {label(cid)}" + (f" · in: {container}" if container else "") + (f" · style: {hint}" if hint else ""))
        out += ["", "### Connectors", ""]
        for cid, c in cells.items():
            if c.get("edge") == "1":
                out.append(f"- `{label(c.get('source'))}` -> `{label(c.get('target'))}`" + (f" : {label(cid)}" if (c.get('value') or '').strip() else ""))
        out.append("")
    return out


def vsdx(path: Path) -> list[str]:
    z = read_zip(path)
    names = {}
    if "visio/pages/pages.xml" in z.namelist():
        for i, p in enumerate(safe_xml(z.read("visio/pages/pages.xml")).iter(), 0):
            if lname(p.tag) == "Page":
                names[len(names) + 1] = p.get("Name") or p.get("NameU") or f"page {len(names) + 1}"
    out = header(path, "Visio diagram")
    page_files = sorted(n for n in z.namelist() if re.match(r"visio/pages/page\d+\.xml$", n))
    for n, pf in enumerate(page_files, 1):
        root = safe_xml(z.read(pf))
        shapes = {}
        for sh in root.iter():
            if lname(sh.tag) == "Shape":
                txt = " ".join(t.strip() for el in sh.iter() if lname(el.tag) == "Text" for t in el.itertext() if t.strip())
                shapes[sh.get("ID")] = strip_html(txt) or (sh.get("NameU") or sh.get("Name") or f"#{sh.get('ID')}")
        conns = {}
        for c in root.iter():
            if lname(c.tag) == "Connect":
                conns.setdefault(c.get("FromSheet"), {})[c.get("FromCell")] = c.get("ToSheet")
        out += [f"## Page: {names.get(n, pf)}", "", "### Shapes", ""]
        connector_ids = set(conns)
        for sid, txt in shapes.items():
            if sid not in connector_ids:
                out.append(f"- shape `{sid}`: {txt}")
        out += ["", "### Connectors", ""]
        for cid, ends in conns.items():
            a, b = ends.get("BeginX"), ends.get("EndX")
            out.append(f"- `{shapes.get(a, a)}` -> `{shapes.get(b, b)}`" + (f" : {shapes.get(cid)}" if shapes.get(cid) and not shapes[cid].startswith("#") and not re.match(r"^(Dynamic connector|Connector)", shapes[cid]) else ""))
        out.append("")
    return out


def svg(path: Path) -> list[str]:
    root = safe_xml(path.read_bytes())
    texts = [" ".join(t.itertext()).strip() for t in root.iter() if lname(t.tag) in ("text", "title", "desc")]
    return header(path, "SVG diagram (text labels only; layout/arrows not interpreted)") + ["## Labels", ""] + [f"- {strip_html(t)}" for t in texts if t]


# ------------------------------------------------------------------ documents

def docx(path: Path) -> list[str]:
    z = read_zip(path)
    root = safe_xml(z.read("word/document.xml"))
    out = header(path, "Word document")
    body = next((e for e in root if lname(e.tag) == "body"), root)
    for el in body:
        t = lname(el.tag)
        if t == "p":
            style = next((s.get(next(iter(s.attrib), "")) for s in el.iter() if lname(s.tag) == "pStyle"), "") or ""
            text = "".join(x.text or "" for x in el.iter() if lname(x.tag) == "t").strip()
            if not text:
                continue
            m = re.match(r"(?i)heading\s*(\d)", style.replace("Heading", "Heading "))
            out.append(("#" * min(6, int(m.group(1)) + 1) + " " + text) if m else text)
            out.append("")
        elif t == "tbl":
            rows = []
            for tr in el.iter():
                if lname(tr.tag) == "tr":
                    cells = ["".join(x.text or "" for x in tc.iter() if lname(x.tag) == "t").strip().replace("|", "\\|")
                             for tc in tr if lname(tc.tag) == "tc"]
                    rows.append("| " + " | ".join(cells) + " |")
            if rows:
                ncol = rows[0].count("|") - 1
                out += [rows[0], "|" + " --- |" * ncol] + rows[1:] + [""]
    return out


def pptx(path: Path) -> list[str]:
    z = read_zip(path)
    slides = sorted((n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                    key=lambda n: int(re.search(r"(\d+)", n.rsplit("/", 1)[-1]).group(1)))
    out = header(path, "PowerPoint deck", f"{len(slides)} slide(s)")
    for n in slides:
        root = safe_xml(z.read(n))
        paras = []
        for p in root.iter():
            if lname(p.tag) == "p":
                t = "".join(x.text or "" for x in p.iter() if lname(x.tag) == "t").strip()
                if t:
                    paras.append(t)
        out += [f"## Slide {re.search(r'(\d+)', n.rsplit('/', 1)[-1]).group(1)}", ""] + [f"- {t}" for t in paras] + [""]
    return out


def pdf(path: Path) -> tuple[list[str] | None, str | None]:
    exe = shutil.which("pdftotext")
    if not exe:
        return None, "pdftotext not installed: read this PDF with Claude's Read tool (pages parameter) and write notes"
    r = subprocess.run([exe, "-layout", "-enc", "UTF-8", str(path), "-"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not r.stdout.strip():
        return None, "pdftotext produced no text (scanned PDF?): read it with Claude's Read tool"
    pages = r.stdout.split("\f")
    out = header(path, "PDF (pdftotext)", f"{len(pages)} page(s)")
    for i, pg in enumerate(pages, 1):
        if pg.strip():
            out += [f"## Page {i}", ""] + [ln.rstrip() for ln in pg.splitlines()] + [""]
    return out, None


def html_doc(path: Path) -> list[str]:
    raw = path.read_text(errors="replace")
    raw = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", "", raw)
    raw = re.sub(r"(?i)<(h[1-6])[^>]*>", lambda m: "\n" + "#" * (int(m.group(1)[1]) + 1) + " ", raw)
    raw = re.sub(r"(?i)<(br|/p|/div|/li|/tr)[^>]*>", "\n", raw)
    text = html.unescape(re.sub(r"<[^>]+>", "", raw))
    return header(path, "HTML document") + [ln.rstrip() for ln in text.splitlines() if ln.strip()]


# ------------------------------------------------------------------ CSPM

def sev(v) -> str:
    s = str(v or "").strip().lower()
    return {"informational": "info", "information": "info", "moderate": "medium", "important": "high",
            "error": "high", "warning": "medium", "note": "low", "none": "info"}.get(s, s or "unknown")


def first(d: dict, *paths, default=""):
    for p in paths:
        cur = d
        for k in p.split("."):
            if isinstance(cur, list):
                cur = cur[0] if cur else None
            cur = cur.get(k) if isinstance(cur, dict) else None
            if cur is None:
                break
        if cur not in (None, "", []):
            return cur
    return default


def cspm_rows(data, name: str):
    """Return (tool, rows) or (None, None). rows: dicts provider/id/severity/status/resource/title."""
    rows = []
    if isinstance(data, dict) and isinstance(data.get("Findings"), list) and data["Findings"] and "ProductArn" in data["Findings"][0]:
        for f in data["Findings"]:
            rows.append({"provider": "aws", "id": f.get("Id", ""), "severity": sev(first(f, "Severity.Label", "Severity.Normalized")),
                         "status": first(f, "Compliance.Status", "Workflow.Status", "RecordState"),
                         "resource": first(f, "Resources.Id"), "title": f.get("Title", "")})
        return "AWS Security Hub (ASFF)", rows
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        tool = "SARIF"
        for run in data["runs"]:
            tool = first(run, "tool.driver.name", default="SARIF")
            for r in run.get("results", []):
                loc = first(r, "locations.physicalLocation.artifactLocation.uri")
                line = first(r, "locations.physicalLocation.region.startLine")
                rows.append({"provider": "iac/sarif", "id": r.get("ruleId", ""), "severity": sev(r.get("level") or first(r, "properties.severity")),
                             "status": first(r, "kind", default="fail"), "resource": f"{loc}:{line}" if line else loc,
                             "title": first(r, "message.text")})
        return f"SARIF ({tool})", rows
    checkov = data if isinstance(data, list) else [data]
    if all(isinstance(x, dict) and isinstance(x.get("results"), dict) and "failed_checks" in x["results"] for x in checkov if x):
        for x in checkov:
            for f in x["results"].get("failed_checks", []):
                rng = f.get("file_line_range") or []
                rows.append({"provider": x.get("check_type", "iac"), "id": f.get("check_id", ""), "severity": sev(f.get("severity")),
                             "status": "FAILED", "resource": f"{f.get('resource', '')} ({f.get('file_path', '')}:{rng[0] if rng else ''})",
                             "title": f.get("check_name", "")})
        return "Checkov", rows
    if isinstance(data, list) and data and isinstance(data[0], dict):
        d0 = data[0]
        if "status_code" in d0 and ("finding_info" in d0 or "metadata" in d0):
            for f in data:
                rows.append({"provider": first(f, "cloud.provider", "metadata.product.vendor_name"), "id": first(f, "finding_info.uid", "metadata.event_code"),
                             "severity": sev(f.get("severity")), "status": f.get("status_code", ""),
                             "resource": first(f, "resources.uid", "resources.name"), "title": first(f, "finding_info.title", "message")})
            return "Prowler (OCSF)", rows
        if "CheckID" in d0 and "Status" in d0:
            for f in data:
                rows.append({"provider": f.get("Provider", ""), "id": f.get("CheckID", ""), "severity": sev(f.get("Severity")),
                             "status": f.get("Status", ""), "resource": f.get("ResourceArn") or f.get("ResourceId", ""),
                             "title": f.get("CheckTitle", "")})
            return "Prowler (JSON)", rows
        if "properties" in d0 and isinstance(d0["properties"], dict) and "status" in d0["properties"]:
            for f in data:
                p = f["properties"]
                rows.append({"provider": "azure", "id": f.get("name", ""), "severity": sev(first(p, "metadata.severity")),
                             "status": first(p, "status.code"), "resource": first(p, "resourceDetails.Id", "resourceDetails.id"),
                             "title": p.get("displayName", "")})
            return "Microsoft Defender for Cloud", rows
        if "finding" in d0 or ("category" in d0 and "resourceName" in d0):
            for f in data:
                g = f.get("finding", f)
                rows.append({"provider": "gcp", "id": g.get("name", "").rsplit("/", 1)[-1], "severity": sev(g.get("severity")),
                             "status": g.get("state", ""), "resource": g.get("resourceName", ""), "title": g.get("category", "")})
            return "GCP Security Command Center", rows
    if isinstance(data, dict) and isinstance(data.get("services"), dict):
        for svc, sd in data["services"].items():
            for fid, f in (sd.get("findings") or {}).items():
                if f.get("flagged_items"):
                    rows.append({"provider": data.get("provider_code", "cloud"), "id": f"{svc}.{fid}", "severity": sev(f.get("level")),
                                 "status": f"{f.get('flagged_items')} flagged", "resource": ", ".join((f.get("items") or [])[:3]),
                                 "title": f.get("description", "")})
        return "ScoutSuite", rows
    return None, None


def cspm_csv(text: str):
    rd = csv.DictReader(io.StringIO(text))
    cols = {c.lower(): c for c in (rd.fieldnames or [])}
    pick = lambda *ks: next((cols[c] for c in cols for k in ks if k in c), None)
    s, r, t = pick("severity", "risk"), pick("resource", "arn", "asset"), pick("title", "check", "rule", "control", "finding", "description")
    if not (s and (r or t)):
        return None, None
    st, i, pv = pick("status", "result", "state"), pick("check_id", "checkid", "rule_id", "control_id", "id"), pick("provider", "cloud")
    rows = [{"provider": row.get(pv, "") if pv else "", "id": row.get(i, "") if i else "", "severity": sev(row.get(s)),
             "status": row.get(st, "") if st else "", "resource": row.get(r, "") if r else "", "title": row.get(t, "") if t else ""}
            for row in rd]
    return "CSV export", rows


def cspm_md(src: Path, tool: str, rows: list[dict]) -> list[str]:
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    fails = [r for r in rows if not re.match(r"(?i)^(pass|passed|compliant|healthy|resolved|inactive|archived|success)", str(r["status"]))]
    out = header(src, f"CSPM/IaC scan results: {tool}", f"{len(rows)} finding(s), {len(fails)} not passing")
    out += ["## Severity counts", ""] + [f"- {k}: {v}" for k, v in sorted(counts.items())] + ["",
            "## Findings (one per line; cite this file:line)", "",
            "| # | Provider | Check/ID | Severity | Status | Resource | Title |", "| --- | --- | --- | --- | --- | --- | --- |"]
    esc = lambda v: redact_text(str(v)).replace("|", "\\|").replace("\n", " ")[:200]
    for n, r in enumerate(rows, 1):
        out.append(f"| {n} | {esc(r['provider'])} | {esc(r['id'])} | {esc(r['severity'])} | {esc(r['status'])} | {esc(r['resource'])} | {esc(r['title'])} |")
    return out


# ------------------------------------------------------------------ dispatcher

def is_iac(path: Path, text: str | None) -> str | None:
    ext = path.suffix.lower()
    if ext in IAC_EXT:
        return {".bicep": "Azure Bicep", ".jinja": "GCP Deployment Manager template", ".j2": "template"}.get(ext, "Terraform/HCL")
    if text is None:
        return None
    if "AWSTemplateFormatVersion" in text or re.search(r"(?m)^\s*Type:\s*['\"]?AWS::", text) or "Transform: AWS::Serverless" in text:
        return "AWS CloudFormation/SAM"
    if "deploymentTemplate.json" in text or re.search(r'"type"\s*:\s*"Microsoft\.[A-Za-z]+/', text):
        return "Azure ARM template"
    if re.search(r"(?m)^\s*-?\s*type:\s*['\"]?(compute|storage|sqladmin|container|iam|pubsub|cloudfunctions)\.v\d", text):
        return "GCP Deployment Manager"
    if re.search(r"(?m)^\s*apiVersion:\s*\S+\s*$", text) and re.search(r"(?m)^\s*kind:\s*\S+", text):
        return "Kubernetes manifest"
    if re.search(r"(?m)^\s*(runtime|name):\s*(nodejs|python|go|yaml)", text) and "Pulumi" in path.name:
        return "Pulumi"
    return None


def convert(path: Path, dest_dir: Path, rel: str):
    ext = path.suffix.lower()
    name = path.name.lower()
    safe = SAFE_NAME.sub("_", rel)
    if path.stat().st_size > MAX_FILE:
        return {"source": rel, "status": "skipped", "reason": "file too large"}
    if ext in IMG_EXT:
        return {"source": rel, "status": "needs_reading", "kind": "image",
                "reason": "diagram/image: view it with Claude's Read tool and record shapes, connectors and boundaries"}
    text = None
    if ext not in (".docx", ".pptx", ".vsdx", ".pdf", ".xlsx", ".doc", ".vsd", ".ppt"):
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            text = None
    iac = is_iac(path, text)
    if iac:
        out = dest_dir / safe
        out.write_text(redact_text(text or ""))
        return {"source": rel, "status": "copied", "kind": f"iac: {iac}", "file": out.name,
                "note": "verbatim copy; cite by original line numbers"}
    lines, kind, reason = None, None, None
    if name.endswith((".drawio", ".drawio.xml", ".dio")) or (ext == ".xml" and text and "<mxfile" in text[:2000]):
        lines, kind = drawio(path), "diagram: draw.io"
    elif ext == ".vsdx":
        lines, kind = vsdx(path), "diagram: visio"
    elif ext == ".svg":
        lines, kind = svg(path), "diagram: svg"
    elif ext == ".docx":
        lines, kind = docx(path), "document: word"
    elif ext == ".pptx":
        lines, kind = pptx(path), "document: powerpoint"
    elif ext == ".pdf":
        lines, reason = pdf(path)
        kind = "document: pdf"
        if lines is None:
            return {"source": rel, "status": "needs_reading", "kind": kind, "reason": reason}
    elif ext in (".doc", ".vsd", ".ppt", ".xlsx", ".xls"):
        return {"source": rel, "status": "unsupported", "kind": ext,
                "reason": "legacy/binary Office format: export to .docx/.vsdx/.pdf/.csv first"}
    elif ext in (".html", ".htm"):
        lines, kind = html_doc(path), "document: html"
    elif ext in (".json", ".sarif") or name.endswith(".js") and text and text.lstrip().startswith("scoutsuite_results"):
        raw = text or ""
        if raw.lstrip().startswith("scoutsuite_results"):
            raw = raw.split("=", 1)[1].strip().rstrip(";")
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        tool, rows = cspm_rows(data, rel) if data is not None else (None, None)
        if tool:
            lines, kind = cspm_md(path, tool, rows), f"cspm: {tool}"
        else:
            lines, kind = header(path, "JSON (unrecognized format; pretty-printed)") + ["```json"] + json.dumps(data, indent=2).splitlines()[:5000] + ["```"] if data is not None else None, "data: json"
    elif ext == ".csv":
        tool, rows = cspm_csv(text or "")
        if tool:
            lines, kind = cspm_md(path, tool, rows), f"cspm: {tool}"
        else:
            lines, kind = header(path, "CSV") + ["```"] + (text or "").splitlines()[:5000] + ["```"], "data: csv"
    elif ext in TEXT_EXT or ext in (".yaml", ".yml", ".ini", ".cfg", ".conf", ".toml") or text is not None:
        lines, kind = header(path, "text") + (text or "").splitlines(), "document: text"
    if lines is None:
        return {"source": rel, "status": "unsupported", "kind": ext or "unknown", "reason": "unrecognized binary format"}
    out = dest_dir / (safe + ".md")
    out.write_text(redact_text("\n".join(lines)) + "\n")
    return {"source": rel, "status": "converted", "kind": kind, "file": out.name}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--key", default="ctx")
    a = ap.parse_args()
    key = SAFE_NAME.sub("-", a.key)
    if not key.startswith("ctx"):
        key = "ctx-" + key
    out = Path(a.out).expanduser().resolve()
    dest = out / "evidence" / "context" / key
    dest.mkdir(parents=True, exist_ok=True)
    items = []
    for p in map(lambda x: Path(x).expanduser(), a.paths):
        files = [(f, f.relative_to(p).as_posix()) for f in sorted(p.rglob("*")) if f.is_file() and not f.is_symlink()] if p.is_dir() else [(p, p.name)]
        for f, rel in files:
            if any(part.startswith(".") for part in Path(rel).parts[:-1]):
                continue
            try:
                item = convert(f, dest, rel)
            except (Refused, zipfile.BadZipFile, ET.ParseError, KeyError, ValueError, OSError) as e:
                item = {"source": rel, "status": "refused", "reason": f"{type(e).__name__}: {e}"[:200]}
            item["original"] = str(f.resolve())
            items.append(item)
    manifest = {"key": key, "generated": now_iso(), "items": items}
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    # Protect original context folders (e.g. supplied IaC) with the guard: register them read-only too.
    for x in a.paths:
        px = Path(x).expanduser().resolve()
        if px.is_dir():
            register_target(f"{key}-src", px, out, {"kind": "context-source", "source": str(px), "revision": "context-snapshot", "dirty": None})
    register_target(key, dest, out, {"kind": "context", "source": ", ".join(str(Path(x).resolve()) for x in a.paths),
                                     "revision": "context-snapshot", "dirty": None})
    summary = {}
    for it in items:
        summary[it["status"]] = summary.get(it["status"], 0) + 1
    print(json.dumps({"key": key, "root": str(dest), "summary": summary, "items": items}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
