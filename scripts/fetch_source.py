#!/usr/bin/env python3
"""Acquire a source for ckb analysis, safely and read-only.

Usage:
  fetch_source.py --out OUT_DIR [--key name] [--scratch dir] [--ref BRANCH] [--working-tree]
                  [--token-env VAR] [--auth auto|az|pat|none] [--gitlab-base URL] [--exclude GLOB ...] SOURCE

SOURCE is a local directory, an https:// or ssh:// git URL, a git@host:org/repo URL, or a shorthand:
  github:org/repo   gitlab:group/sub/repo   ado:org/project/repo
  https://dev.azure.com/ORG/PROJECT/_git/REPO   https://ORG.visualstudio.com/PROJECT/_git/REPO

Branch rule (when --ref is not given): main, else master, else the remote's default branch.
- Remote: shallow clone of that branch (hooks off, no submodules, no LFS smudge, file:// and ext::
  refused) into a fresh scratch dir.
- Local git repo: if the repo's current branch is not main/master, a READ-ONLY snapshot of main (else
  master) is exported with `git archive` into scratch; your checkout and working tree are never touched.
  Uncommitted work is not in a snapshot; use --working-tree to analyze the folder as it is on disk.
  Service sub-directories of a repo are resolved inside the same snapshot. Folders that are not git
  repos, or repos with no main/master, are analyzed in place.

Auth (never printed, never in a URL or argv): --token-env VAR reads a token from that env var.
For Azure DevOps, --auth auto uses a logged-in `az` CLI session (Entra access token) if available,
otherwise a PAT from AZURE_DEVOPS_EXT_PAT / ADO_PAT / SYSTEM_ACCESSTOKEN. GitHub/GitLab tokens come
from --token-env. Tokens reach git through environment variables only.

The target is registered (evidence/targets.json + the per-user registry) so the ckb guard hook
protects it. Prints one JSON object describing the registered source.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import now_iso, register_target  # noqa: E402

ALLOWED_URL = re.compile(r"^(https://|ssh://|git@[A-Za-z0-9.\-]+:)")
SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_BRANCHES = ("main", "master")
ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"  # Azure DevOps Entra resource id
ADO_PAT_ENVS = ("AZURE_DEVOPS_EXT_PAT", "ADO_PAT", "SYSTEM_ACCESSTOKEN")
MAX_SNAPSHOT_BYTES = 2 * 1024 ** 3

GIT_SAFE = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "submodule.recurse=false",
    "-c", "core.symlinks=false",
    "-c", "core.fsmonitor=false",
    "-c", "credential.helper=",
]


def git(args, cwd=None, env=None, check=True):
    return subprocess.run(["git", *GIT_SAFE, *args], cwd=cwd, env=env, check=check, capture_output=True, text=True)


def expand_shorthand(src: str, gitlab_base: str) -> str:
    if src.startswith("github:"):
        return f"https://github.com/{src[7:]}.git"
    if src.startswith("gitlab:"):
        return f"{gitlab_base.rstrip('/')}/{src[7:]}.git"
    if src.startswith("ado:"):
        parts = src[4:].strip("/").split("/")
        if len(parts) == 3:
            org, project, repo = (urllib.parse.quote(x, safe="") for x in parts)
            return f"https://dev.azure.com/{org}/{project}/_git/{repo}"
        raise SystemExit("ado shorthand is ado:ORG/PROJECT/REPO (use enumerate_sources.py for a whole project)")
    return src


def key_from(src: str) -> str:
    name = src.rstrip("/").split("/")[-1].split(":")[-1]
    name = name[:-4] if name.endswith(".git") else name
    return SAFE_KEY.sub("-", name) or "repo"


def strip_credentials(url: str) -> str:
    return re.sub(r"//[^/@]+@", "//", url)


def is_ado(url: str) -> bool:
    """Decide on the parsed hostname (never a regex over the raw string): the host git connects to is the host checked."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.query or u.fragment or u.username or u.password:
        return False
    host = (u.hostname or "").rstrip(".").lower()
    return host == "dev.azure.com" or (host.endswith(".visualstudio.com") and host.count(".") >= 2)


# ---------------------------------------------------------------- auth (env-only)

def az_token() -> str | None:
    if not shutil.which("az"):
        return None
    try:
        r = subprocess.run(["az", "account", "get-access-token", "--resource", ADO_RESOURCE, "--query", "accessToken", "-o", "tsv"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    t = r.stdout.strip()
    return t if r.returncode == 0 and t and "\n" not in t else None


def auth_env(url: str, token_env: str | None, auth: str) -> tuple[dict, list[str], list[str]]:
    """Return (extra env vars, extra `git -c` args, secrets to redact). Tokens only ever live in env vars."""
    env: dict = {}
    extra: list[str] = []
    secrets: list[str] = []
    if is_ado(url) and auth in ("auto", "az", "pat"):
        tok = None
        if auth in ("auto", "az"):
            tok = az_token()
            if tok:
                # bearer token via GIT_CONFIG_* env vars (git >= 2.31): not visible in argv or process list
                env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraheader",
                            "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {tok}"})
                secrets.append(tok)
                return env, extra, secrets
        if auth in ("auto", "pat"):
            names = ([token_env] if token_env else []) + list(ADO_PAT_ENVS)
            for n in names:
                if n and os.environ.get(n):
                    env["CKB_GIT_TOKEN"] = os.environ[n]
                    secrets.append(os.environ[n])
                    extra = ["-c", 'credential.helper=!f() { echo username=ckb; echo "password=$CKB_GIT_TOKEN"; }; f']
                    return env, extra, secrets
        if auth in ("az", "pat"):
            raise SystemExit(f"Azure DevOps auth '{auth}' not available (no az login / no PAT env var set)")
        return env, extra, secrets  # anonymous (public project)
    if token_env:
        if not os.environ.get(token_env):
            raise SystemExit(f"token env var {token_env} is not set")
        env["CKB_GIT_TOKEN"] = os.environ[token_env]
        secrets.append(os.environ[token_env])
        extra = ["-c", 'credential.helper=!f() { echo username=oauth2; echo "password=$CKB_GIT_TOKEN"; }; f']
    return env, extra, secrets


def clean_env(extra_env: dict) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/echo"})
    env.update(extra_env)
    return env


def redact(msg: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            msg = msg.replace(s, "[REDACTED]")
    return msg


# ---------------------------------------------------------------- branch rule

def pick_branch(heads: set[str], explicit: str | None) -> tuple[str | None, str]:
    if explicit:
        return explicit, "explicit"
    for b in DEFAULT_BRANCHES:
        if b in heads:
            return b, b
    return None, "default"


def remote_branch(url: str, env: dict, extra: list[str], secrets: list[str], explicit: str | None) -> tuple[str | None, str]:
    if explicit:
        return explicit, "explicit"
    r = subprocess.run(["git", *GIT_SAFE, *extra, "ls-remote", "--heads", "--", url, *DEFAULT_BRANCHES], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot list branches: {redact(r.stderr, secrets).strip()[:300]}")
    heads = {ln.split("refs/heads/", 1)[1] for ln in r.stdout.splitlines() if "refs/heads/" in ln}
    b, how = pick_branch(heads, None)
    return (b, how) if b else (None, "remote-default")


def clone(url: str, dest: Path, ref: str | None, token_env: str | None, auth: str) -> dict:
    if not ALLOWED_URL.match(url):
        raise SystemExit(f"refused: only https://, ssh:// and git@host: URLs are allowed (got {strip_credentials(url)!r})")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0] and url.startswith("https://"):
        raise SystemExit("refused: credentials embedded in URL; use --token-env instead")
    if url.startswith("https://") and (urllib.parse.urlsplit(url).query or urllib.parse.urlsplit(url).fragment):
        raise SystemExit("refused: https URL with a query string or fragment")
    extra_env, extra, secrets = auth_env(url, token_env, auth)
    env = clean_env(extra_env)
    branch, how = remote_branch(url, env, extra, secrets, ref)
    args = [*extra, "clone", "--depth", "1", "--no-recurse-submodules", "--no-tags", "--single-branch"]
    if branch:
        args += ["--branch", branch]
    args += ["--", url, str(dest)]
    r = subprocess.run(["git", *GIT_SAFE, *args], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"clone failed: {redact(r.stderr, secrets).strip()[:500]}")
    rev = git(["rev-parse", "HEAD"], cwd=dest).stdout.strip()
    cur = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dest, check=False).stdout.strip()
    return {"kind": "remote", "source": strip_credentials(url), "revision": rev, "dirty": False, "ref": branch or cur,
            "ref_source": how, "shallow": True, "source_mode": "clone"}


# ---------------------------------------------------------------- local repos

def toplevel(p: Path) -> Path | None:
    r = git(["rev-parse", "--show-toplevel"], cwd=p, check=False)
    return Path(r.stdout.strip()).resolve() if r.returncode == 0 and r.stdout.strip() else None


def local_meta(root: Path) -> dict:
    meta = {"kind": "local", "source": str(root), "revision": "unversioned", "dirty": None, "source_mode": "in-place"}
    r = git(["rev-parse", "HEAD"], cwd=root, check=False)
    if r.returncode == 0:
        meta["revision"] = r.stdout.strip()
        st = git(["status", "--porcelain", "--untracked-files=no"], cwd=root, check=False)
        meta["dirty"] = bool(st.stdout.strip())
        br = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root, check=False).stdout.strip()
        meta["ref"] = br
        rem = git(["remote", "get-url", "origin"], cwd=root, check=False)
        if rem.returncode == 0:
            meta["remote"] = strip_credentials(rem.stdout.strip())
    return meta


def local_heads(top: Path) -> set[str]:
    r = git(["for-each-ref", "--format=%(refname:short)", "refs/heads/"], cwd=top, check=False)
    return set(r.stdout.split())


def safe_extract(data: bytes, dest: Path) -> int:
    """Extract a git-archive tar without trusting member paths; symlinks and special files are skipped."""
    dest = dest.resolve()
    n, total = 0, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        for m in tf:
            if not (m.isreg() or m.isdir()):
                continue  # never materialize symlinks, hardlinks, devices
            target = (dest / m.name).resolve()
            if dest != target and dest not in target.parents:
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += m.size
            if total > MAX_SNAPSHOT_BYTES:
                raise SystemExit("snapshot too large (> 2 GiB); narrow the source")
            target.parent.mkdir(parents=True, exist_ok=True)
            f = tf.extractfile(m)
            if f is not None:
                target.write_bytes(f.read())
                n += 1
    return n


def snapshot(top: Path, branch: str, scratch_parent: Path) -> tuple[Path, str]:
    rev = git(["rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"], cwd=top).stdout.strip()
    snap = scratch_parent / f"ckb-snap-{hashlib.sha1((str(top) + rev).encode()).hexdigest()[:12]}"
    if not (snap / ".ckb-snapshot-complete").is_file():
        if snap.exists():
            shutil.rmtree(snap)
        snap.mkdir(parents=True)
        r = subprocess.run(["git", *GIT_SAFE, "archive", "--format=tar", f"refs/heads/{branch}"], cwd=top, capture_output=True)
        if r.returncode != 0:
            raise SystemExit(f"git archive failed: {r.stderr.decode(errors='replace')[:300]}")
        safe_extract(r.stdout, snap)
        (snap / ".ckb-snapshot-complete").write_text(rev + "\n")
    return snap, rev


def resolve_local(local: Path, ref: str | None, working_tree: bool, scratch_parent: Path) -> tuple[Path, dict]:
    root = local.resolve()
    meta = local_meta(root)
    top = toplevel(root)
    if working_tree or top is None:
        meta["source_mode"] = "working-tree" if working_tree and top else "in-place"
        return root, meta
    cur = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=top, check=False).stdout.strip()
    heads = local_heads(top)
    branch, how = pick_branch(heads, ref)
    if branch is None or (ref is None and cur == branch):
        meta["ref_source"] = "current" if cur in DEFAULT_BRANCHES else "no main/master; analyzed in place"
        return root, meta
    if branch not in heads:
        raise SystemExit(f"branch {branch!r} not found in {top}")
    if ref and cur == ref:
        meta["ref_source"] = "explicit (current)"
        return root, meta
    snap, rev = snapshot(top, branch, scratch_parent)
    rel = root.relative_to(top) if root != top else Path(".")
    new_root = (snap / rel).resolve()
    meta.update({"source_mode": "snapshot", "ref": branch, "ref_source": how, "revision": rev, "dirty": False,
                 "snapshot_of": str(root), "checked_out_branch": cur, "scratch": str(snap),
                 "note": "read-only snapshot via git archive; the checkout was not touched; uncommitted work is not included"})
    return new_root, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("--out", required=True, help="ckb output directory (e.g. <target>/.ckb)")
    ap.add_argument("--key")
    ap.add_argument("--scratch", help="parent dir for clones and snapshots (default: system temp)")
    ap.add_argument("--ref", help="branch to analyze (default: main, else master)")
    ap.add_argument("--working-tree", action="store_true", help="local repos: analyze the folder as it is on disk")
    ap.add_argument("--token-env")
    ap.add_argument("--auth", default="auto", choices=["auto", "az", "pat", "none"], help="Azure DevOps auth source")
    ap.add_argument("--gitlab-base", default=os.environ.get("CKB_GITLAB_BASE", "https://gitlab.com"))
    ap.add_argument("--exclude", action="append", default=[], help="glob to skip in this source (e.g. a service dir registered separately)")
    a = ap.parse_args()

    src = expand_shorthand(a.source, a.gitlab_base)
    key = SAFE_KEY.sub("-", a.key) if a.key else key_from(src)
    out = Path(a.out).expanduser()
    scratch_parent = Path(a.scratch).expanduser() if a.scratch else Path(tempfile.gettempdir())
    scratch_parent.mkdir(parents=True, exist_ok=True)

    local = Path(src).expanduser()
    if local.exists():
        if not local.is_dir():
            raise SystemExit("local source must be a directory")
        root, meta = resolve_local(local, a.ref, a.working_tree, scratch_parent)
    else:
        scratch = Path(tempfile.mkdtemp(prefix=f"ckb-{key}-", dir=scratch_parent))
        root = scratch / key
        meta = clone(src, root, a.ref, a.token_env, a.auth)
        meta["scratch"] = str(scratch)

    meta["fetched"] = now_iso()
    if a.exclude:
        meta["exclude"] = a.exclude
    register_target(key, root, out, meta)
    print(json.dumps({"key": key, "root": str(root), **meta}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
