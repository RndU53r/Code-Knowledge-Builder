#!/usr/bin/env python3
"""List the repositories of an Azure DevOps project, GitHub org, or GitLab group (read-only API calls).

Usage:
  enumerate_sources.py SPEC [SPEC ...] [--include GLOB ...] [--exclude GLOB ...] [--max-repos N]
                       [--include-forks] [--include-archived] [--token-env VAR] [--api-base URL]
                       [--gitlab-base URL] [--ado-auth auto|az|pat|none]

SPEC is one of:
  ado:ORG/PROJECT          Azure DevOps project (dev.azure.com; Azure DevOps Server via --api-base)
  github-org:NAME          GitHub organization (GitHub Enterprise via --api-base)
  gitlab-group:PATH        GitLab group incl. subgroups (self-hosted via --gitlab-base)

Prints JSON: {"sources": [{"spec", "source", "key", "default_branch", "branch", "skipped": false, ...}],
              "skipped": [...], "capped": bool}
`source` is a shorthand fetch_source.py accepts. `branch` follows the ckb rule: main, else master, else
the repo's default branch. Archived/disabled repos and forks are skipped unless asked for.

Tokens are read from env vars (never printed or put in URLs): GitHub GITHUB_TOKEN/GH_TOKEN, GitLab
GITLAB_TOKEN, Azure DevOps an `az` login or AZURE_DEVOPS_EXT_PAT / ADO_PAT / SYSTEM_ACCESSTOKEN.
Plain http:// API bases are refused unless they point at localhost.
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_source import ADO_PAT_ENVS, az_token  # noqa: E402

DEFAULT_BRANCHES = ("main", "master")
SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")


class ApiError(Exception):
    pass


def check_base(base: str, has_token: bool):
    u = urllib.parse.urlparse(base)
    if u.scheme == "https":
        return
    if u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1"):
        return
    raise SystemExit(f"refusing API base {base!r}: use https (http only for localhost)")


def http_json(url: str, headers: dict, secrets: list[str]):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ckb-enumerate", **headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"null"), r.headers
    except HTTPError as e:
        msg = f"HTTP {e.code} for {urllib.parse.urlparse(url).path}"
        if e.code in (401, 403):
            msg += " (token missing/insufficient?)"
        raise ApiError(msg)
    except (URLError, ValueError, OSError) as e:
        text = str(e)
        for s in secrets:
            text = text.replace(s, "[REDACTED]")
        raise ApiError(f"request failed: {type(e).__name__}: {text[:200]}")


def pick_branch(default_branch: str | None, heads: set[str] | None):
    """main, else master (when we can see the branch list), else the repo default."""
    if heads is not None:
        for b in DEFAULT_BRANCHES:
            if b in heads:
                return b, b
    if default_branch:
        d = default_branch.replace("refs/heads/", "")
        if heads is None and d in DEFAULT_BRANCHES:
            return d, d
        return d, "repo-default"
    return None, "unknown"


# ---------------------------------------------------------------- providers

def github_org(name, base, token_env, include_forks, include_archived):
    tok = os.environ.get(token_env or "") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    check_base(base, bool(tok))
    headers = {"X-GitHub-Api-Version": "2022-11-28", "Accept": "application/vnd.github+json"}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    url = f"{base.rstrip('/')}/orgs/{urllib.parse.quote(name)}/repos?per_page=100&type=all"
    out, skipped = [], []
    while url:
        data, hdrs = http_json(url, headers, [tok or ""])
        for r in data or []:
            row = {"spec": f"github-org:{name}", "source": f"github:{r['full_name']}", "key": SAFE_KEY.sub("-", r["name"]),
                   "default_branch": r.get("default_branch")}
            if r.get("archived") and not include_archived:
                skipped.append({**row, "reason": "archived"})
            elif r.get("fork") and not include_forks:
                skipped.append({**row, "reason": "fork"})
            elif r.get("disabled"):
                skipped.append({**row, "reason": "disabled"})
            else:
                out.append(row)
        m = re.search(r'<([^>]+)>;\s*rel="next"', hdrs.get("Link", "") or "")
        url = m.group(1) if m else None
    return out, skipped


def gitlab_group(path, base, token_env, include_forks, include_archived, gitlab_base):
    tok = os.environ.get(token_env or "") or os.environ.get("GITLAB_TOKEN")
    check_base(base, bool(tok))
    headers = {"PRIVATE-TOKEN": tok} if tok else {}
    url = f"{base.rstrip('/')}/api/v4/groups/{urllib.parse.quote(path, safe='')}/projects?include_subgroups=true&per_page=100"
    out, skipped = [], []
    page = 1
    while True:
        data, hdrs = http_json(f"{url}&page={page}", headers, [tok or ""])
        for r in data or []:
            row = {"spec": f"gitlab-group:{path}", "source": f"gitlab:{r['path_with_namespace']}", "key": SAFE_KEY.sub("-", r["path"]),
                   "default_branch": r.get("default_branch"), "gitlab_base": gitlab_base}
            if r.get("archived") and not include_archived:
                skipped.append({**row, "reason": "archived"})
            elif r.get("forked_from_project") and not include_forks:
                skipped.append({**row, "reason": "fork"})
            else:
                out.append(row)
        nxt = hdrs.get("X-Next-Page") or ""
        if not nxt or not data:
            break
        page = int(nxt)
    return out, skipped


def ado_headers(auth: str, token_env: str | None):
    """Return (headers, secrets, how). az bearer token, else PAT basic auth, else anonymous."""
    if auth in ("auto", "az"):
        t = az_token()
        if t:
            return {"Authorization": f"Bearer {t}"}, [t], "az"
    if auth in ("auto", "pat"):
        for n in ([token_env] if token_env else []) + list(ADO_PAT_ENVS):
            if n and os.environ.get(n):
                pat = os.environ[n]
                b = base64.b64encode(f":{pat}".encode()).decode()
                return {"Authorization": f"Basic {b}"}, [pat, b], "pat"
    if auth in ("az", "pat"):
        raise SystemExit(f"Azure DevOps auth '{auth}' not available (no az login / no PAT env var)")
    return {}, [], "anonymous"


def ado_project(spec, base, token_env, auth, include_archived):
    org, _, project = spec.partition("/")
    if not org or not project:
        raise SystemExit("ado spec is ado:ORG/PROJECT")
    headers, secrets, how = ado_headers(auth, token_env)
    check_base(base, bool(headers))
    url = f"{base.rstrip('/')}/{urllib.parse.quote(org)}/{urllib.parse.quote(project)}/_apis/git/repositories?api-version=7.1"
    data, _ = http_json(url, headers, secrets)
    out, skipped = [], []
    for r in (data or {}).get("value", []):
        row = {"spec": f"ado:{org}/{project}", "source": f"ado:{org}/{project}/{r['name']}", "key": SAFE_KEY.sub("-", r["name"]),
               "default_branch": r.get("defaultBranch"), "auth": how}
        if r.get("isDisabled"):
            skipped.append({**row, "reason": "disabled"})
        else:
            out.append(row)
    return out, skipped


# ---------------------------------------------------------------- main

def matches(name: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(name.lower(), g.lower()) for g in globs)


def enumerate_spec(spec: str, a) -> tuple[list, list]:
    kind, _, rest = spec.partition(":")
    if kind == "github-org":
        return github_org(rest, a.api_base or "https://api.github.com", a.token_env, a.include_forks, a.include_archived)
    if kind == "gitlab-group":
        gb = a.gitlab_base.rstrip("/")
        return gitlab_group(rest, a.api_base or gb, a.token_env, a.include_forks, a.include_archived, gb)
    if kind == "ado":
        return ado_project(rest, a.api_base or "https://dev.azure.com", a.token_env, a.ado_auth, a.include_archived)
    raise SystemExit(f"unknown spec {spec!r}; use ado:ORG/PROJECT, github-org:NAME or gitlab-group:PATH")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("specs", nargs="+")
    ap.add_argument("--include", action="append", default=[])
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--max-repos", type=int, default=50)
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--token-env")
    ap.add_argument("--api-base")
    ap.add_argument("--gitlab-base", default=os.environ.get("CKB_GITLAB_BASE", "https://gitlab.com"))
    ap.add_argument("--ado-auth", default="auto", choices=["auto", "az", "pat", "none"])
    a = ap.parse_args()
    sources, skipped = [], []
    for spec in a.specs:
        try:
            s, k = enumerate_spec(spec, a)
        except ApiError as e:
            skipped.append({"spec": spec, "reason": f"enumeration failed: {e}"})
            continue
        sources += s
        skipped += k
    keep = []
    for r in sources:
        name = r["key"]
        if a.include and not matches(name, a.include):
            skipped.append({**r, "reason": "not in --include"})
        elif a.exclude and matches(name, a.exclude):
            skipped.append({**r, "reason": "--exclude"})
        else:
            keep.append(r)
    seen, uniq = set(), []
    for r in keep:  # unique keys (same repo name in two projects)
        k = r["key"]
        n = 2
        while k in seen:
            k = f"{r['key']}-{n}"
            n += 1
        seen.add(k)
        uniq.append({**r, "key": k})
    capped = len(uniq) > a.max_repos
    for r in uniq:
        r["branch"], r["branch_source"] = pick_branch(r.get("default_branch"), None)
        r["note"] = "fetch_source.py applies main, else master, else default when cloning"
    print(json.dumps({"sources": uniq[: a.max_repos], "skipped": skipped, "capped": capped, "total_found": len(uniq)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
