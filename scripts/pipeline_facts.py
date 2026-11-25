#!/usr/bin/env python3
"""Structured facts about CI/CD pipeline files in every registered repo. Reads files only; never runs a pipeline.

Usage:
  pipeline_facts.py --out OUT_DIR [--repo KEY]

Covers GitHub Actions, Azure Pipelines (YAML and templates), GitLab CI, Jenkinsfile / shared libraries, CircleCI and
Bitbucket/other YAML pipelines at a basic level. For each pipeline file it records, with line citations:
  triggers (push / PR / fork-reachable / schedule / manual), runners (hosted or self-hosted), permissions,
  secret and variable names (never values), service connections and credentials ids, third-party actions /
  templates / libraries and whether they are pinned, deploy-like commands and whether an environment or approval
  gates them, and the repos/images the pipeline names (used to link pipelines to the repos they deploy).
It also reports findings for platforms the supply-chain scanner does not cover (the scanner already handles GitHub
Actions SC-C01..C05 and GitLab CI):
  PF01 external template/library/include referenced by a mutable ref
  PF02 untrusted build variable expanded inside a script (script injection)
  PF03 self-hosted runner reachable from a pull-request trigger
  PF04 deploy-like command with no environment, approval or protected-branch gate
  PF05 secret-like variable echoed

Writes <out>/evidence/pipeline-facts-<repo>.json. Heuristic, line-based (no YAML parser); results are [inferred].
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import read_text, repo_excludes, repo_roots_for_output, walk_files  # noqa: E402
from graph_common import atomic_write, safe_quote  # noqa: E402
from roles import classify  # noqa: E402

DEPLOY_RX = re.compile(r"(?i)\b(kubectl\s+(apply|set\s+image|rollout)|helm\s+(upgrade|install)|terraform\s+apply|tofu\s+apply|az\s+(deployment|webapp|functionapp|aks|containerapp)\b[^\n]*(create|deploy|up)|"
                       r"aws\s+(cloudformation\s+deploy|ecs\s+update-service|lambda\s+update-function|s3\s+(sync|cp)\b[^\n]*s3://)|gcloud\s+[^\n]*\bdeploy\b|docker\s+push|npm\s+publish|twine\s+upload|"
                       r"gh\s+release\s+create|cdk\s+deploy|pulumi\s+up|serverless\s+deploy|ansible-playbook|argocd\s+app\s+sync|flux\s+reconcile)")
SECRETISH = re.compile(r"(?i)(secret|token|passw|pwd|apikey|api_key|key\b|credential|pat\b)")
ADO_INJECT = re.compile(r"\$\((Build\.SourceBranchName|Build\.SourceBranch|Build\.SourceVersionMessage|System\.PullRequest\.(SourceBranch|SourceBranchName|TargetBranch)|Build\.RequestedFor(Email)?)\)")
JENKINS_INJECT = re.compile(r"\$\{?(params\.\w+|env\.(CHANGE_\w+|BRANCH_NAME|GIT_BRANCH|TAG_NAME))\}?")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def facts_for(rel: str, text: str, sub: str) -> dict:
    lines = text.splitlines()
    f = {"path": rel, "platform": sub, "triggers": [], "runners": [], "self_hosted": False, "pr_trigger": False, "fork_privileged": False,
         "permissions": [], "secrets": [], "service_connections": [], "credentials": [], "third_party": [], "deploy_steps": [], "environments": [],
         "approvals": False, "targets": [], "findings": []}
    findings = f["findings"]

    def finding(fid, sev, line, msg):
        findings.append({"id": fid, "severity": sev, "line": line, "quote": safe_quote(lines[line - 1] if 0 < line <= len(lines) else ""), "message": msg})

    secrets = set()
    in_script, script_indent = False, 0
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        ind = len(ln) - len(ln.lstrip())
        # script blocks (for injection and deploy detection)
        if re.match(r"-?\s*(script|bash|powershell|pwsh|run|sh|cmd|inlineScript|scriptBlock)\s*:", s):
            in_script, script_indent = True, ind
            body = s.split(":", 1)[1]
        elif in_script and ind <= script_indent and not s.startswith("-"):
            in_script, body = False, ""
        else:
            body = s if in_script else ""
        text_for_cmd = body or ""
        if text_for_cmd and DEPLOY_RX.search(text_for_cmd):
            f["deploy_steps"].append({"line": i, "command": safe_quote(text_for_cmd.strip())[:100]})
        if sub == "azure-pipelines":
            if re.match(r"(trigger|pr)\s*:", s) and ind == 0:
                f["triggers"].append(s.split(":")[0])
                if s.startswith("pr"):
                    f["pr_trigger"] = True
            if re.match(r"schedules\s*:", s):
                f["triggers"].append("schedule")
            m = re.match(r"-?\s*(?:name|vmImage)\s*:\s*['\"]?([^'\"#]+)", s)
            if m and re.search(r"(?m)^\s*pool\s*:", "\n".join(lines[max(0, i - 4):i])):
                f["runners"].append(m.group(1).strip())
                if s.lstrip("- ").startswith("name"):
                    f["self_hosted"] = True
            m = re.match(r"-?\s*(azureSubscription|connectedServiceName\w*|serviceConnection|dockerRegistryServiceConnection|kubernetesServiceConnection|backendServiceArm|"
                         r"azureResourceManagerConnection|endpoint)\s*:\s*['\"]?([^'\"#\s]+)", s)
            if m:
                f["service_connections"].append({"line": i, "name": m.group(2)})
            m = re.match(r"-?\s*group\s*:\s*['\"]?([^'\"#\s]+)", s)
            if m:
                f["credentials"].append({"line": i, "name": f"variable group {m.group(1)}"})
            m = re.match(r"-?\s*template\s*:\s*['\"]?([^'\"#\s]+)@([\w.-]+)", s)
            if m and m.group(2) != "self":
                f["third_party"].append({"line": i, "ref": f"{m.group(1)}@{m.group(2)}", "kind": "template", "pinned": None, "alias": m.group(2)})
            m = re.match(r"-?\s*task\s*:\s*([\w.]+@\w+)", s)
            if m:
                f["third_party"].append({"line": i, "ref": m.group(1), "kind": "task", "pinned": True})
            m = re.match(r"-?\s*(environment|deployment)\s*:\s*['\"]?([^'\"#\s]*)", s)
            if m:
                f["environments"].append({"line": i, "name": m.group(2) or m.group(1)})
            if re.match(r"-?\s*(ManualValidation@|approval)", s):
                f["approvals"] = True
            for mm in ADO_INJECT.finditer(body):
                finding("PF02", "high", i, f"build variable {mm.group(1)} is expanded into a script before the shell runs (script injection if an attacker controls it)")
            for mm in re.finditer(r"\$\(([A-Za-z_][\w.]*)\)", body):
                if SECRETISH.search(mm.group(1)):
                    secrets.add(mm.group(1))
                    if re.match(r"\s*(echo|Write-Host|Write-Output|printf)\b", body):
                        finding("PF05", "high", i, f"secret-like variable {mm.group(1)} is printed")
            m = re.match(r"-?\s*checkout\s*:\s*(\S+)", s)
            if m and m.group(1) not in ("self", "none"):
                f["targets"].append(m.group(1))
        elif sub == "github-actions":
            if re.match(r"(on|['\"]on['\"])\s*:", s) and ind == 0:
                rest = s.split(":", 1)[1]
                ev = re.findall(r"\b(push|pull_request_target|pull_request|workflow_dispatch|schedule|workflow_call|release|issue_comment|workflow_run|repository_dispatch|create|delete)\b", rest)
                j = i
                while j < len(lines) and (j == i or not lines[j].strip() or lines[j].startswith((" ", "\t", "-", "#"))):
                    ev += re.findall(r"^\s{1,4}(push|pull_request_target|pull_request|workflow_dispatch|schedule|workflow_call|release|issue_comment|workflow_run|repository_dispatch|create|delete)\s*:", lines[j]) if j > i - 1 else []
                    j += 1
                f["triggers"] = sorted(set(f["triggers"]) | set(ev))
            if re.match(r"runs-on\s*:", s):
                v = s.split(":", 1)[1].strip()
                f["runners"].append(v[:60])
                if "self-hosted" in v:
                    f["self_hosted"] = True
            if re.match(r"permissions\s*:", s):
                f["permissions"].append(s.split(":", 1)[1].strip() or "(block)")
            for mm in re.finditer(r"secrets\.([A-Za-z_]\w*)", ln):
                if mm.group(1) != "GITHUB_TOKEN":
                    secrets.add(mm.group(1))
            m = re.search(r"uses\s*:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)", s)
            if m and not m.group(1).startswith(("./", "docker://")):
                first = m.group(1).split("/")[0] in ("actions", "github")
                f["third_party"].append({"line": i, "ref": f"{m.group(1)}@{m.group(2)}", "kind": "action", "pinned": bool(HEX40.match(m.group(2))), "first_party": first})
                if ".github/workflows/" in m.group(1):
                    f["targets"].append("/".join(m.group(1).split("/")[:2]))
            m = re.match(r"-?\s*repository\s*:\s*['\"]?([\w./-]+)", s)
            if m:
                f["targets"].append(m.group(1))
            m = re.match(r"environment\s*:\s*['\"]?([^'\"#\s{]+)", s)
            if m:
                f["environments"].append({"line": i, "name": m.group(1)})
        elif sub == "gitlab-ci":
            m = re.match(r"-?\s*(only|except)\s*:|-?\s*rules\s*:|workflow\s*:", s)
            if m and "rules" in s:
                f["triggers"].append("rules")
            if re.search(r"merge_requests|\$CI_PIPELINE_SOURCE\s*==\s*['\"]merge_request_event", s):
                f["pr_trigger"] = True
            m = re.match(r"-?\s*tags\s*:\s*\[?([^\]#]*)", s)
            if m:
                f["runners"].append(m.group(1).strip())
            m = re.match(r"-?\s*environment\s*:\s*['\"]?([^'\"#\s{]+)", s)
            if m:
                f["environments"].append({"line": i, "name": m.group(1)})
            m = re.match(r"-?\s*(?:project|remote|template)\s*:\s*['\"]?(\S+)", s)
            if m:
                ref = next((re.match(r"\s*ref\s*:\s*['\"]?([^'\"#\s]+)", x).group(1) for x in lines[i:i + 3] if re.match(r"\s*ref\s*:", x)), None)
                f["third_party"].append({"line": i, "ref": m.group(1) + (f"@{ref}" if ref else ""), "kind": "include",
                                         "pinned": bool(ref and (HEX40.match(ref) or re.match(r"v?\d+\.\d+", ref)))})
                if not s.startswith("remote"):
                    f["targets"].append(m.group(1).split("@")[0])
            if re.search(r"\$\{?CI_(JOB_TOKEN|REGISTRY_PASSWORD)", ln):
                secrets.add("CI_JOB_TOKEN")
        elif sub == "jenkins":
            m = re.match(r"agent\s+(any|none)|agent\s*\{\s*label\s+['\"]([^'\"]+)|label\s+['\"]([^'\"]+)", s)
            if m:
                f["runners"].append(next((g for g in m.groups() if g), "any"))
                f["self_hosted"] = True
            if re.match(r"triggers\s*\{|cron\(|pollSCM\(", s):
                f["triggers"].append("cron/poll")
            m = re.search(r"@Library\(\s*\[?\s*['\"]([^'\"]+)['\"]", s)
            if m:
                ref = m.group(1)
                f["third_party"].append({"line": i, "ref": ref, "kind": "shared-library", "pinned": "@" in ref and bool(HEX40.match(ref.split("@")[1]) or re.match(r"v?\d", ref.split("@")[1]))})
            for mm in re.finditer(r"credentials\(\s*['\"]([^'\"]+)['\"]|credentialsId\s*:\s*['\"]([^'\"]+)['\"]", s):
                f["credentials"].append({"line": i, "name": mm.group(1) or mm.group(2)})
            if re.match(r"input\s*(message|\{)|input\s*\(", s):
                f["approvals"] = True
            if re.match(r"(sh|bat|powershell)\s*(\(|['\"])", s) and re.search(r'(sh|bat)\s*\(?\s*("""|")', s):
                mm = JENKINS_INJECT.search(s)
                if mm:
                    finding("PF02", "high", i, f"{mm.group(0)} is interpolated into a Groovy double-quoted shell string (script injection if attacker-controlled)")
            if DEPLOY_RX.search(s):
                f["deploy_steps"].append({"line": i, "command": safe_quote(s)[:100]})
        elif sub == "circleci":
            m = re.match(r"([\w-]+)\s*:\s*([\w-]+/[\w-]+)@([\w.]+)\s*$", s)
            if m:
                f["third_party"].append({"line": i, "ref": f"{m.group(2)}@{m.group(3)}", "kind": "orb", "pinned": bool(re.match(r"\d+\.\d+\.\d+", m.group(3)))})
            if re.match(r"context\s*:", s):
                f["credentials"].append({"line": i, "name": "context " + s.split(":", 1)[1].strip()})
            if re.match(r"type\s*:\s*approval", s):
                f["approvals"] = True
            if DEPLOY_RX.search(s):
                f["deploy_steps"].append({"line": i, "command": safe_quote(s)[:100]})
        if sub in ("github-actions", "gitlab-ci") and body is None:
            pass
    f["secrets"] = sorted(secrets)[:40]
    f["target_lines"] = {}
    for t in {t for t in f["targets"] if t}:
        f["target_lines"][t] = next((i for i, ln in enumerate(lines, 1) if t in ln), 1)
    f["targets"] = sorted({t for t in f["targets"] if t})[:20]
    f["pr_trigger"] = f["pr_trigger"] or any(t in ("pull_request", "pull_request_target") for t in f["triggers"])
    f["fork_privileged"] = "pull_request_target" in f["triggers"]
    # ---- findings
    if sub in ("azure-pipelines", "jenkins", "circleci", "gitlab-ci", "github-actions"):
        for tp in f["third_party"]:
            if sub in ("azure-pipelines",) and tp["kind"] == "template":
                tp["pinned"] = None  # decided from resources.repositories below
        repos = {}
        if sub == "azure-pipelines":
            for m in re.finditer(r"(?m)^\s*-\s*repository\s*:\s*(\S+)\s*\n((?:\s+.*\n?){1,6})", text):
                block = m.group(2)
                ref = re.search(r"ref\s*:\s*['\"]?([^'\"#\s]+)", block)
                repos[m.group(1)] = {"ref": ref.group(1) if ref else None, "line": _line(text, m.start()),
                                     "name": (re.search(r"name\s*:\s*['\"]?([^'\"#\s]+)", block) or [None, None])[1]}
            for alias, r in repos.items():
                mutable = not r["ref"] or r["ref"].startswith("refs/heads/") or not (HEX40.match(r["ref"] or "") or (r["ref"] or "").startswith("refs/tags/"))
                if r["name"]:
                    f["targets"].append(r["name"])
                if any(tp.get("alias") == alias for tp in f["third_party"]) and mutable:
                    finding("PF01", "medium", r["line"], f"templates are pulled from repository resource '{alias}' at {r['ref'] or 'the default branch'} (a mutable ref): whoever can push there controls this pipeline")
                for tp in f["third_party"]:
                    if tp.get("alias") == alias:
                        tp["pinned"] = not mutable
        for tp in f["third_party"]:
            if sub == "jenkins" and tp["kind"] == "shared-library" and not tp["pinned"]:
                finding("PF01", "medium", tp["line"], f"shared library {tp['ref']} is loaded without a pinned version")
            if sub == "circleci" and tp["kind"] == "orb" and not tp["pinned"]:
                finding("PF01", "medium", tp["line"], f"orb {tp['ref']} is not pinned to an exact version")
            if sub == "gitlab-ci" and tp["kind"] == "include" and tp["pinned"] is False and "@" not in tp["ref"]:
                finding("PF01", "medium", tp["line"], f"include {tp['ref']} has no pinned ref")
        if f["self_hosted"] and f["pr_trigger"]:
            finding("PF03", "high", 1, "a pull-request trigger can run on a self-hosted runner/agent (fork or contributor code executes on your infrastructure)")
        if f["deploy_steps"] and not f["environments"] and not f["approvals"]:
            d = f["deploy_steps"][0]
            finding("PF04", "medium", d["line"], "deploy-like command with no environment, approval or manual gate in this file (a branch rule elsewhere may still protect it)")
    return f


def run(out: Path, only: str | None = None) -> dict:
    stats = {}
    for repo, root in repo_roots_for_output(out).items():
        if repo.startswith("ctx") or (only and repo != only):
            continue
        pipes = []
        for p, rel in walk_files(Path(root), repo_excludes(out).get(repo, [])):
            if len(pipes) >= 200:
                break
            suffix = p.suffix.lower()
            head = read_text(p, max_bytes=2500) if suffix in (".yaml", ".yml", ".groovy", "") or p.name.startswith("Jenkinsfile") else ""
            info = classify(rel, head or "")
            if info["role"] != "pipeline":
                continue
            text = read_text(p, max_bytes=400_000)
            if text:
                sub = info.get("sub") or "pipeline"
                if sub == "pipeline" and re.search(r"(?m)^(trigger|pr|stages|jobs|steps)\s*:", text):
                    sub = "azure-pipelines"
                pipes.append(facts_for(rel, text, sub))
        if not pipes:
            continue
        findings = [{**x, "path": pf["path"]} for pf in pipes for x in pf["findings"]]
        doc = {"repo": repo, "pipelines": pipes, "findings": findings,
               "note": "line-based facts, [inferred]; GitHub Actions and GitLab CI checks SC-C01..C05 are in the supply-chain report"}
        atomic_write(out / "evidence" / f"pipeline-facts-{repo}.json", json.dumps(doc, indent=1))
        stats[repo] = {"pipelines": len(pipes), "findings": len(findings)}
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo")
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve(), a.repo), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
