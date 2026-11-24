#!/usr/bin/env python3
"""Read-only probe of the local environment: which tools, logins and tokens ckb can use.

Usage:
  env_probe.py [--scratch DIR] [--check-network HOST ...] [--token-env NAME ...]

Reports names and booleans only. Secret values are never read into the output; `az` is asked only
whether a login exists. Network checks are a plain TCP connect to host:443 (no request, no data) and
only for hosts you pass. Nothing is installed or changed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

TOKEN_GROUPS = {
    "github": ["GITHUB_TOKEN", "GH_TOKEN"],
    "gitlab": ["GITLAB_TOKEN"],
    "azure_devops": ["AZURE_DEVOPS_EXT_PAT", "ADO_PAT", "SYSTEM_ACCESSTOKEN"],
    "snyk": ["SNYK_TOKEN", "SNYK_ORG_ID"],
    "neo4j": ["NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"],
}
CI_FLAGS = {"CI": "generic", "GITHUB_ACTIONS": "github-actions", "GITLAB_CI": "gitlab-ci", "TF_BUILD": "azure-pipelines",
            "JENKINS_URL": "jenkins", "CIRCLECI": "circleci"}


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def tool(name, version_args=None):
    path = shutil.which(name)
    out = {"available": bool(path)}
    if path and version_args:
        rc, txt = run([name, *version_args])
        out["version"] = (txt.splitlines() or [""])[0][:80] if rc == 0 else None
    return out


def probe(scratch: str | None = None, hosts: list[str] | None = None, extra_token_envs: list[str] | None = None) -> dict:
    tools = {"git": tool("git", ["--version"]), "python3": {"available": True, "version": sys.version.split()[0]},
             "pdftotext": tool("pdftotext", ["-v"]), "node": tool("node", ["--version"]), "gh": tool("gh", ["--version"]),
             "glab": tool("glab", ["--version"]), "az": tool("az")}
    ts = next((m for m in ("tree_sitter_language_pack", "tree_sitter_languages") if importlib.util.find_spec(m)), None)
    tools["tree_sitter"] = {"available": bool(ts), "module": ts}
    az = {"available": tools["az"]["available"], "logged_in": False}
    if az["available"]:
        rc, _ = run(["az", "account", "show", "--output", "none"], timeout=20)
        az["logged_in"] = rc == 0
    tools["az"] = az
    groups = dict(TOKEN_GROUPS)
    if extra_token_envs:
        groups["extra"] = list(extra_token_envs)
    tokens = {g: {n: bool(os.environ.get(n)) for n in names} for g, names in groups.items()}
    scratch = scratch or tempfile.gettempdir()
    try:
        free_gb = round(shutil.disk_usage(scratch).free / 1024 ** 3, 1)
    except OSError:
        free_gb = None
    ci = next((v for k, v in CI_FLAGS.items() if os.environ.get(k) and k != "CI"), None) or ("generic" if os.environ.get("CI") else None)
    net = {}
    for h in hosts or []:
        try:
            with socket.create_connection((h, 443), timeout=3):
                net[h] = True
        except OSError:
            net[h] = False
    return {"tools": tools, "tokens": tokens, "runtime": {"ci": ci, "interactive": sys.stdin.isatty() and not ci, "cpus": os.cpu_count() or 1,
                                                          "scratch": scratch, "scratch_free_gb": free_gb, "network": net}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scratch")
    ap.add_argument("--check-network", nargs="*", default=[])
    ap.add_argument("--token-env", action="append", default=[])
    a = ap.parse_args()
    print(json.dumps(probe(a.scratch, a.check_network, a.token_env), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
