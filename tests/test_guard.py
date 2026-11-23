#!/usr/bin/env python3
"""Tests for scripts/guard.py. Run: python3 tests/test_guard.py

Uses a temporary CKB_HOME and a temporary fake target; touches nothing else.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "guard.py"


def run(mode: str, event: dict, env: dict) -> dict | None:
    r = subprocess.run([sys.executable, str(GUARD), mode], input=json.dumps(event), capture_output=True,
                       text=True, env=env)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout) if r.stdout.strip() else None


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="ckb-guard-test-"))
    target = tmp / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.py").write_text("print('hi')\n")
    (target / "run.sh").write_text("echo hi\n")
    elsewhere = tmp / "elsewhere"
    elsewhere.mkdir()
    env = {**os.environ, "CKB_HOME": str(tmp / "home"), "CLAUDE_PLUGIN_ROOT": str(ROOT)}
    sys.path.insert(0, str(ROOT / "scripts"))
    os.environ["CKB_HOME"] = env["CKB_HOME"]
    from ckb_common import register_target
    register_target("target", target, target / ".ckb", {"kind": "local"})

    T = str(target)
    deny_cases = [
        ("npm install", T), ("npm ci", T), ("yarn", T), ("pnpm i", T), ("npx something", T),
        ("pip install -r requirements.txt", T), ("poetry install", T), ("go build ./...", T), ("go test ./...", T),
        ("cargo build", T), ("make", T), ("./gradlew build", T), ("mvn package", T), ("docker build .", T),
        ("python3 src/app.py", T), ("bash run.sh", T), ("./run.sh", T), ("node -e 'x'", T),
        (f"cd {T} && npm install", str(elsewhere)), (f"npm --prefix {T} install", str(elsewhere)),
        (f"python3 {T}/src/app.py", str(elsewhere)), (f"make -C {T}", str(elsewhere)),
        ("git checkout main", T), ("git pull", T), ("git commit -m x", T), ("source run.sh", T),
        ("echo ok; npm install", T), ("timeout 60 npm install", T), ("sudo make install", T),
        (f"bash -c 'cd {T} && npm i'", str(elsewhere)), (f"pushd {T} && make", str(elsewhere)),
        ("rm -rf src", T), (f"echo x > {T}/src/app.py", str(elsewhere)), ("sed -i '' s/a/b/ src/app.py", T),
        (f"cp /etc/hosts {T}/src/", str(elsewhere)), ("chmod 755 run.sh", T), ("chmod g+x run.sh", T),
        (f"mv {T}/run.sh /tmp/x", str(elsewhere)), ("echo hi >> src/app.py", T),
    ]
    allow_cases = [
        ("ls -la", T), ("grep -rn TODO .", T), ("cat src/app.py", T), ("git log -5", T), ("git show HEAD", T),
        ("git blame src/app.py", T), ("git ls-files", T), ("git -c core.hooksPath=/dev/null checkout main", T),
        (f"python3 {ROOT}/scripts/inventory.py --root {T} --key target", T),
        (f"python3 {ROOT}/scripts/scan_supply_chain.py --root . --key target", T),
        ("npm install", str(elsewhere)), ("make", str(elsewhere)), ("python3 x.py", str(elsewhere)),
        (f"wc -l {T}/src/app.py", str(elsewhere)),
        (f"cp {T}/src/app.py /tmp/ckb-copy.py", str(elsewhere)), ("grep -rn x . > /dev/null", T),
        (f"echo x > {T}/.ckb/evidence/note.md", str(elsewhere)), ("sed -n 1,5p src/app.py", T),
        ("bash -c 'ls -la'", T),
    ]
    fails = 0
    for cmd, cwd in deny_cases:
        out = run("bash", {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}, env)
        ok = out and out["hookSpecificOutput"]["permissionDecision"] == "deny"
        fails += not ok
        print(("PASS" if ok else "FAIL"), "deny ", repr(cmd), "@", Path(cwd).name)
    for cmd, cwd in allow_cases:
        out = run("bash", {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}, env)
        ok = out is None
        fails += not ok
        print(("PASS" if ok else "FAIL"), "allow", repr(cmd), "@", Path(cwd).name, "" if ok else out)

    w_deny = run("write", {"tool_name": "Write", "tool_input": {"file_path": f"{T}/src/app.py"}, "cwd": T}, env)
    w_allow = run("write", {"tool_name": "Write", "tool_input": {"file_path": f"{T}/.ckb/index.md"}, "cwd": T}, env)
    w_else = run("write", {"tool_name": "Write", "tool_input": {"file_path": f"{elsewhere}/x.md"}, "cwd": T}, env)
    for name, ok in (("write into target denied", bool(w_deny)), ("write into .ckb allowed", w_allow is None),
                     ("write elsewhere allowed", w_else is None)):
        fails += not ok
        print("PASS" if ok else "FAIL", name)

    out_dir = target / ".ckb"
    (out_dir / "repos" / "target").mkdir(parents=True, exist_ok=True)
    good = out_dir / "repos" / "target" / "overview.md"
    good.write_text("# t\n\n> **ckb provenance**\n\n## Purpose\nPrints hi `target/src/app.py:1` «print('hi')»\n")
    bad = out_dir / "repos" / "target" / "hld.md"
    bad.write_text("# t\n\n> **ckb provenance**\n\n## Components\nA thing `target/src/app.py:99`\nkey AKIAABCDEFGHIJKLMNOP\n")
    p_good = run("post", {"tool_name": "Write", "tool_input": {"file_path": str(good)}, "cwd": T}, env)
    p_bad = run("post", {"tool_name": "Write", "tool_input": {"file_path": str(bad)}, "cwd": T}, env)
    for name, ok in (("post: valid output passes", p_good is None),
                     ("post: bad line + secret blocked", bool(p_bad) and "E3" in p_bad["reason"] and "S1" in p_bad["reason"]),
                     ("post: secret value not echoed", bool(p_bad) and "AKIAABCDEFGHIJKLMNOP" not in p_bad["reason"])):
        fails += not ok
        print("PASS" if ok else "FAIL", name)
    print(f"\n{fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
