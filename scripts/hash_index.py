#!/usr/bin/env python3
"""Content-hash index for incremental refresh (/ckb:update).

Usage:
  hash_index.py snapshot --out OUT_DIR          # record hashes for every registered repo
  hash_index.py diff --out OUT_DIR [--json]     # compare current files with the snapshot

The diff reports, per repo: added/removed/changed files, and which ckb stages are
stale, using a simple dependency map (manifests/CI/Docker → supply-chain; contracts
→ cross-repo flows; any source change → analysis, outputs, threat model, context).
Remote clones are refreshed by re-running fetch_source.py before diffing.
Idea inspired by arden/Codebase-Knowledge-Builder (incremental cache); independent code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import load_json, now_iso, repo_excludes, repo_roots_for_output, save_json, walk_files  # noqa: E402

SUPPLY = re.compile(r"(^|/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|pyproject\.toml|"
                    r"poetry\.lock|uv\.lock|setup\.py|go\.(mod|sum)|Cargo\.(toml|lock)|pom\.xml|[^/]*\.gradle(\.kts)?|"
                    r"Gemfile(\.lock)?|composer\.json|\.npmrc|Dockerfile[^/]*|Makefile|\.gitlab-ci\.yml)$|^\.github/workflows/")
CONTRACT = re.compile(r"(?i)(openapi|swagger|asyncapi)[^/]*\.(ya?ml|json)$|\.(proto|graphql|gql|avsc)$")
INFRA = re.compile(r"(?i)(k8s|helm|kustomiz|terraform|\.tf$|compose|ingress|gateway)")
DOC = re.compile(r"\.(md|txt|rst|adoc)$")


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(out: Path) -> dict:
    data = {"generated": now_iso(), "repos": {}}
    for key, root in repo_roots_for_output(out).items():
        data["repos"][key] = {rel: sha(p) for p, rel in walk_files(root, repo_excludes(out).get(key, []))}
    save_json(out / "evidence" / "hashes.json", data)
    return {k: len(v) for k, v in data["repos"].items()}


def stages_for(paths: list[str]) -> list[str]:
    st = set()
    for p in paths:
        if SUPPLY.search(p):
            st.add("supply-chain")
        if CONTRACT.search(p):
            st |= {"cross-repo-flows", "threat-model", "context"}
        if INFRA.search(p):
            st |= {"hld", "threat-model", "context"}
        if DOC.search(p):
            st.add("supply-chain")  # agent-injection checks cover docs
        else:
            st |= {"analysis", "outputs-and-conditions", "threat-model", "context", "cross-repo-flows", "graph"}
        if SUPPLY.search(p) or INFRA.search(p):
            st.add("graph")
    return sorted(st)


def diff(out: Path) -> dict:
    old = load_json(out / "evidence" / "hashes.json", {"repos": {}})["repos"]
    res = {}
    for key, root in repo_roots_for_output(out).items():
        cur = {rel: sha(p) for p, rel in walk_files(root, repo_excludes(out).get(key, []))}
        prev = old.get(key)
        if prev is None:
            res[key] = {"status": "new", "stale_stages": ["all"]}
            continue
        added = sorted(set(cur) - set(prev))
        removed = sorted(set(prev) - set(cur))
        changed = sorted(k for k in set(cur) & set(prev) if cur[k] != prev[k])
        touched = added + removed + changed
        res[key] = {"status": "changed" if touched else "unchanged", "added": added, "removed": removed,
                    "changed": changed, "stale_stages": stages_for(touched)}
    for key in set(old) - set(res):
        res[key] = {"status": "unregistered", "stale_stages": ["system"]}
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["snapshot", "diff"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    r = snapshot(out) if a.mode == "snapshot" else diff(out)
    print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
