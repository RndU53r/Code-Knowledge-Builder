#!/usr/bin/env python3
"""Acquire a source for ckb analysis, safely and read-only.

Usage:
  fetch_source.py --out <output_dir> [--key name] [--scratch dir] [--ref branch_or_tag]
                  [--token-env GITHUB_TOKEN] [--gitlab-base https://gitlab.example.com] SOURCE

SOURCE is a local directory, an https:// or ssh:// git URL, a git@host:org/repo URL,
or a shorthand: github:org/repo, gitlab:group/sub/repo.

Remote clones: hooks disabled, depth 1, no submodules, no LFS smudge, file:// and
ext:: transports refused, into a fresh empty scratch directory. Tokens are read from
the named env var and passed through a one-shot credential helper (never in the URL,
never printed). The target is registered so the ckb guard hook protects it.

Prints one JSON object describing the registered source.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import now_iso, register_target  # noqa: E402

ALLOWED_URL = re.compile(r"^(https://|ssh://|git@[A-Za-z0-9.\-]+:)")
SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")

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
    return subprocess.run(["git", *GIT_SAFE, *args], cwd=cwd, env=env, check=check,
                          capture_output=True, text=True)


def expand_shorthand(src: str, gitlab_base: str) -> str:
    if src.startswith("github:"):
        return f"https://github.com/{src[7:]}.git"
    if src.startswith("gitlab:"):
        return f"{gitlab_base.rstrip('/')}/{src[7:]}.git"
    return src


def key_from(src: str) -> str:
    name = src.rstrip("/").split("/")[-1].split(":")[-1]
    name = name[:-4] if name.endswith(".git") else name
    return SAFE_KEY.sub("-", name) or "repo"


def local_meta(root: Path) -> dict:
    meta = {"kind": "local", "source": str(root), "revision": "unversioned", "dirty": None}
    r = git(["rev-parse", "HEAD"], cwd=root, check=False)
    if r.returncode == 0:
        meta["revision"] = r.stdout.strip()
        st = git(["status", "--porcelain", "--untracked-files=no"], cwd=root, check=False)
        meta["dirty"] = bool(st.stdout.strip())
        rem = git(["remote", "get-url", "origin"], cwd=root, check=False)
        if rem.returncode == 0:
            meta["remote"] = strip_credentials(rem.stdout.strip())
    return meta


def strip_credentials(url: str) -> str:
    return re.sub(r"//[^/@]+@", "//", url)


def clone(url: str, dest: Path, ref: str | None, token_env: str | None) -> dict:
    if not ALLOWED_URL.match(url):
        raise SystemExit(f"refused: only https://, ssh:// and git@host: URLs are allowed (got {strip_credentials(url)!r})")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0] and url.startswith("https://"):
        raise SystemExit("refused: credentials embedded in URL; use --token-env instead")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/echo"})
    extra = []
    if token_env:
        if not os.environ.get(token_env):
            raise SystemExit(f"token env var {token_env} is not set")
        # One-shot helper reads the token from the environment at call time; the value
        # never appears in argv, the URL, or output.
        env["CKB_GIT_TOKEN"] = os.environ[token_env]
        helper = '!f() { echo username=oauth2; echo "password=$CKB_GIT_TOKEN"; }; f'
        extra = ["-c", f"credential.helper={helper}"]
    args = [*extra, "clone", "--depth", "1", "--no-recurse-submodules", "--no-tags", "--single-branch"]
    if ref:
        args += ["--branch", ref]
    args += ["--", url, str(dest)]
    r = subprocess.run(["git", *GIT_SAFE, *args], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        msg = r.stderr.replace(os.environ.get(token_env or "", "\0") or "\0", "[REDACTED]")
        raise SystemExit(f"clone failed: {msg.strip()[:500]}")
    rev = git(["rev-parse", "HEAD"], cwd=dest).stdout.strip()
    return {"kind": "remote", "source": strip_credentials(url), "revision": rev, "dirty": False,
            "ref": ref, "shallow": True}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("--out", required=True, help="ckb output directory (e.g. <target>/.ckb)")
    ap.add_argument("--key")
    ap.add_argument("--scratch", help="parent dir for remote clones (default: system temp)")
    ap.add_argument("--ref")
    ap.add_argument("--token-env")
    ap.add_argument("--gitlab-base", default=os.environ.get("CKB_GITLAB_BASE", "https://gitlab.com"))
    ap.add_argument("--exclude", action="append", default=[], help="glob to skip in this source (e.g. a service dir already registered separately)")
    a = ap.parse_args()

    src = expand_shorthand(a.source, a.gitlab_base)
    key = SAFE_KEY.sub("-", a.key) if a.key else key_from(src)
    out = Path(a.out).expanduser()

    local = Path(src).expanduser()
    if local.exists():
        if not local.is_dir():
            raise SystemExit("local source must be a directory")
        root = local.resolve()
        meta = local_meta(root)
    else:
        parent = Path(a.scratch).expanduser() if a.scratch else Path(tempfile.gettempdir())
        parent.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix=f"ckb-{key}-", dir=parent))
        root = scratch / key
        meta = clone(src, root, a.ref, a.token_env)
        meta["scratch"] = str(scratch)

    meta["fetched"] = now_iso()
    if a.exclude:
        meta["exclude"] = a.exclude
    register_target(key, root, out, meta)
    print(json.dumps({"key": key, "root": str(root), **meta}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
