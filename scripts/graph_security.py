"""Security layer for the ckb knowledge graph (imported by graph_build.py).

- cloud_resource nodes from IaC (Terraform, CloudFormation, ARM/Bicep, Deployment Manager, k8s) with block ranges
- sc_finding nodes from <out>/evidence/sc-*.json, linked with finding_at to the innermost function/resource
- cspm_finding nodes from ingested CSPM tables (ctx-* keys), linked with affects to matching cloud resources

Reads files only.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import load_json, read_text, repo_excludes, repo_roots_for_output, walk_files  # noqa: E402
from graph_common import cite, make_edge, make_node, node_id  # noqa: E402
from inventory import IAC_FILE, IAC_RESOURCES  # noqa: E402

NAME_ATTR = re.compile(r'''^\s*["']?(name|bucket|identifier|broker_name|QueueName|BucketName|TableName|DBInstanceIdentifier|FunctionName)["']?\s*[:=]\s*["']([^"'$\{]+)["']''')
SEV_KEEP = {"critical", "high", "medium", "low"}


def block_end(lines, start_idx, kind):
    """1-based end line of an IaC block starting at start_idx (0-based)."""
    if kind in ("terraform", "azure-bicep", "terraform-module"):
        depth, opened = 0, False
        for j in range(start_idx, min(len(lines), start_idx + 2000)):
            depth += lines[j].count("{") - lines[j].count("}")
            opened = opened or "{" in lines[j]
            if opened and depth <= 0:
                return j + 1
        return start_idx + 1
    ind = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    for j in range(start_idx + 1, min(len(lines), start_idx + 500)):
        s = lines[j]
        if s.strip() and (len(s) - len(s.lstrip())) <= max(0, ind - 2) and not s.lstrip().startswith(("-", "#")):
            return j
    return min(len(lines), start_idx + 1)


def iac_resources(link):
    added = 0
    excl = repo_excludes(link.out)
    for key, root in link.repos.items():
        for p, rel in walk_files(Path(root), excl.get(key, [])):
            if not IAC_FILE.search(rel):
                continue
            text = read_text(p, max_bytes=2_000_000)
            if not text:
                continue
            lines = text.splitlines()
            fid = node_id("file", key, rel, "")
            for i, ln in enumerate(lines):
                for kind, pat in IAC_RESOURCES:
                    m = pat.search(ln)
                    if not m or (kind == "azure-arm" and not rel.endswith(".json")):
                        continue
                    typ, nm = (m.group(2), m.group(1)) if kind == "azure-bicep" else (m.group(1), m.group(2) or "")
                    if kind == "cloudformation" and not nm:
                        k = i - 1
                        while k >= 0 and not lines[k].strip():
                            k -= 1
                        mm = re.match(r"^\s*([A-Za-z0-9]+):\s*$", lines[k]) if k >= 0 else None
                        nm = mm.group(1) if mm else f"L{i + 1}"
                    if kind == "kubernetes":
                        nmm = next((re.search(r"^\s*name:\s*(\S+)", lines[j]) for j in range(i, min(len(lines), i + 8))
                                    if re.search(r"^\s*name:\s*\S+", lines[j])), None)
                        nm = nmm.group(1) if nmm else nm
                    end = block_end(lines, i, kind)
                    names = {nm} | {mm.group(2) for j in range(i, end) for mm in [NAME_ATTR.match(lines[j])] if mm}
                    n = make_node("cloud_resource", key, rel, f"{typ}.{nm}" if nm else typ, f"{typ} {nm}".strip(), i + 1, end,
                                  extractor="regex", attrs={"iac": kind, "type": typ, "names": sorted(x for x in names if x)})
                    if n["id"] in link.nodes:
                        continue
                    if fid not in link.nodes:
                        fn = make_node("file", key, rel, "", rel, 1, max(1, len(lines)), extractor="regex", attrs={"language": "iac"})
                        link.add_node(fn)
                        parent = node_id("repo", key, "", key)
                        link.add_edge(make_edge(parent, "contains", fid, cite(key, rel, 1)))
                    link.add_node(n)
                    link.add_edge(make_edge(fid, "contains", n["id"], cite(key, rel, i + 1)))
                    added += 1
                    break
    return added


def innermost(link, repo, path, line):
    best, size = None, 10 ** 9
    for n in link.nodes.values():
        if n.get("repo") == repo and n.get("path") == path and n["kind"] in ("function", "method", "class", "cloud_resource"):
            r = n.get("range", {})
            if r.get("start", 0) <= line <= r.get("end", 0) and r["end"] - r["start"] < size:
                best, size = n["id"], r["end"] - r["start"]
    return best or (node_id("file", repo, path, "") if node_id("file", repo, path, "") in link.nodes else None)


def sc_findings(link, out: Path):
    n_added = 0
    for p in sorted((out / "evidence").glob("sc-*.json")):
        data = load_json(p, {})
        repo = data.get("repo")
        if repo not in link.repos:
            continue
        for f in data.get("findings", []):
            if f.get("severity") not in SEV_KEEP:
                continue
            fid = node_id("sc_finding", repo, "", f"{f['check']}:{f['path']}:{hashlib.sha1((f.get('excerpt') or f.get('message','')).encode()).hexdigest()[:8]}")
            target = innermost(link, repo, f["path"], int(f.get("line", 1)))
            n = make_node("sc_finding", repo, "", fid.split("::", 1)[1], f"{f['check']} {f.get('message', '')}"[:200], f.get("line", 1),
                          extractor="scanner", confidence=f.get("confidence", "medium"), citation=f["citation"],
                          attrs={"check": f["check"], "severity": f["severity"], "class": f.get("class"), "category": f.get("category"),
                                 "remediation": f.get("remediation", "")[:200]})
            n["id"] = fid
            link.add_node(n)
            if target:
                link.add_edge(make_edge(fid, "finding_at", target, f["citation"], extractor="scanner", confidence=f.get("confidence", "medium")))
            n_added += 1
    return n_added


ROW = re.compile(r"^\|\s*(\d+)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|\s*$")
PASSING = re.compile(r"(?i)^(pass|passed|compliant|healthy|resolved|inactive|archived|success)")


def cspm_findings(link, out: Path):
    added, linked = 0, 0
    resources = [n for n in link.nodes.values() if n["kind"] == "cloud_resource"]
    for ctx_dir in sorted((out / "evidence" / "context").glob("ctx*")):
        man = load_json(ctx_dir / "manifest.json", {})
        key = man.get("key", ctx_dir.name)
        for item in man.get("items", []):
            if not str(item.get("kind", "")).startswith("cspm:") or not item.get("file"):
                continue
            fpath = ctx_dir / item["file"]
            for i, ln in enumerate(fpath.read_text(errors="replace").splitlines(), 1):
                m = ROW.match(ln)
                if not m:
                    continue
                _, provider, cid, sev, status, resource, title = (x.strip() for x in m.groups())
                if PASSING.match(status) or sev.lower() not in SEV_KEEP:
                    continue
                q = f"{item['file']}:{i}"
                n = make_node("cspm_finding", key, "", q, f"{cid or title}"[:200], i, extractor="context", confidence="high",
                              citation=cite(key, item["file"], i), attrs={"provider": provider, "severity": sev.lower(), "status": status,
                                                                         "resource": resource[:200], "title": title[:200], "tool": item["kind"][6:]})
                link.add_node(n)
                added += 1
                hay = f"{resource} {title}".lower()
                for r in resources:
                    names = [x for x in (r.get("attrs") or {}).get("names", []) if x and len(x) >= 4]
                    if any(x.lower() in hay for x in names):
                        link.add_edge(make_edge(n["id"], "affects", r["id"], cite(key, item["file"], i), extractor="context",
                                                confidence="medium", label="inferred", dst_citation=r["citation"]))
                        linked += 1
    return added, linked


def attach(link, out: Path) -> dict:
    res = iac_resources(link)
    sc = sc_findings(link, out)
    cs, cl = cspm_findings(link, out)
    return {"cloud_resources": res, "sc_findings": sc, "cspm_findings": cs, "cspm_linked": cl}
