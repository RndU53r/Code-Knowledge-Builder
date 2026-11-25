#!/usr/bin/env python3
"""ckb hook logic. Reads the hook event JSON on stdin.

  guard.py bash   PreToolUse(Bash): deny commands that would install, build, run, or
                  test code inside a registered target, or run its git hooks.
  guard.py write  PreToolUse(Write|Edit|MultiEdit|NotebookEdit): deny writes inside a
                  registered target except under its ckb output directory.
  guard.py post   PostToolUse(Write|Edit|MultiEdit): when a ckb output .md is written,
                  verify citations, provenance, Mermaid, links, and redaction; block
                  (send feedback to Claude) on errors.

Targets are registered by fetch_source.py in ~/.ckb/targets.json (CKB_HOME overrides).
Commands are only restricted when they touch a registered target, so the guard does
not interfere with unrelated work.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import registered_targets, within  # noqa: E402

PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", HERE.parent)).resolve()

# command name -> subcommands that execute target code (None = any use executes)
EXEC_CMDS = {
    "npm": {"install", "i", "ci", "run", "run-script", "test", "t", "start", "exec", "rebuild", "pack", "publish", "add", "update", "link", "explore", "restart", "stop", "x"},
    "yarn": None, "pnpm": None, "bun": None, "npx": None, "pnpx": None, "bunx": None, "corepack": None,
    "pip": {"install", "download", "wheel"}, "pip3": {"install", "download", "wheel"},
    "poetry": {"install", "run", "build", "shell", "add", "update", "lock"},
    "uv": {"run", "sync", "pip", "add", "build", "tool"}, "uvx": None, "pipenv": {"install", "run", "sync", "shell"},
    "pdm": {"install", "run", "sync", "build"}, "hatch": None, "tox": None, "nox": None, "pytest": None,
    "go": {"run", "build", "test", "generate", "install", "get", "vet", "mod"},
    "cargo": {"build", "run", "test", "install", "bench", "check", "fetch", "publish"},
    "mvn": None, "mvnw": None, "./mvnw": None, "gradle": None, "gradlew": None, "./gradlew": None, "ant": None, "sbt": None,
    "make": None, "gmake": None, "cmake": None, "ninja": None, "bazel": None, "bazelisk": None, "just": None, "task": None,
    "docker": {"build", "run", "compose", "buildx", "exec", "create", "start"}, "docker-compose": None, "podman": {"build", "run"},
    "bundle": None, "gem": {"install", "build"}, "rake": None, "composer": None, "php": None, "mix": None,
    "dotnet": {"build", "run", "test", "restore", "publish"}, "deno": {"run", "task", "test", "install", "compile"},
    "terraform": {"init", "plan", "apply", "destroy"}, "helm": {"install", "upgrade", "template", "dependency"},
    "pre-commit": None, "husky": None, "lefthook": None,
}
INTERPRETERS = {"python", "python3", "python2", "node", "ruby", "perl", "php", "bash", "sh", "zsh", "dash", "ksh",
                "pwsh", "powershell", "deno", "bun", "tsx", "ts-node", "lua", "Rscript", "java"}
GIT_HOOK_SUBCMDS = {"commit", "merge", "checkout", "switch", "pull", "rebase", "am", "push", "cherry-pick", "revert",
                    "worktree", "clone", "submodule", "stash", "reset", "gc", "fetch"}
GIT_READONLY = {"log", "show", "blame", "ls-files", "ls-tree", "rev-parse", "status", "diff", "grep", "cat-file",
                "describe", "shortlog", "rev-list", "for-each-ref", "branch", "tag", "remote", "config"}
WRITE_ALL_ARGS = {"rm", "rmdir", "mv", "touch", "truncate", "tee", "chown", "chgrp", "shred", "unlink", "chmod"}
WRITE_LAST_ARG = {"cp", "install", "ln", "rsync", "scp"}
INPLACE = {"sed", "perl", "gsed"}
REDIRECT = re.compile(r"(?:^|[^<>&0-9])(?:\d|&)?>>?\|?\s*([^\s;&|]+)")
WRAPPERS = {"sudo", "env", "time", "nice", "nohup", "timeout", "command", "exec", "xargs", "caffeinate"}


_DENIED = []


def deny(reason: str) -> int:
    _DENIED.append(reason)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": f"ckb guard: {reason}"}}))
    return 0


def targets():
    out = []
    for t in registered_targets():
        try:
            out.append((Path(t["root"]).resolve(), Path(t.get("out_dir", Path(t["root"]) / ".ckb")).resolve()))
        except (KeyError, OSError):
            continue
    return out


def split_segments(cmd: str) -> list[str]:
    # split on ; && || | & and newlines (outside quotes, best effort)
    parts, buf, q = [], "", None
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if q:
            buf += c
            if c == q:
                q = None
        elif c in "'\"":
            q = c
            buf += c
        elif c in ";\n" or c == "|" or c == "&":
            parts.append(buf)
            buf = ""
            if cmd[i:i + 2] in ("&&", "||"):
                i += 1
        elif cmd[i:i + 2] == "$(" or c == "`":
            parts.append(buf)
            buf = ""
            i += 1 if c == "$" else 0
        else:
            buf += c
        i += 1
    parts.append(buf)
    return [p.strip().strip("()") for p in parts if p.strip()]


def tokens(seg: str) -> list[str]:
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def resolve(p: str, cwd: Path) -> Path:
    p = os.path.expandvars(os.path.expanduser(p))
    return (cwd / p).resolve() if not os.path.isabs(p) else Path(p).resolve()


def touches(tok_paths: list[Path], cwd: Path, tgts) -> tuple[Path, Path] | None:
    for root, out in tgts:
        if within(cwd, root) and not within(cwd, out):
            return root, out
        for p in tok_paths:
            if within(p, root) and not within(p, out) and not within(p, PLUGIN_ROOT):
                return root, out
    return None


def in_target_not_out(p: Path, tgts):
    for root, out in tgts:
        if within(p, root) and not within(p, out):
            return root
    return None


def check_bash(ev: dict) -> int:
    cmd = (ev.get("tool_input") or {}).get("command", "")
    cwd = Path(ev.get("cwd") or os.getcwd()).resolve()
    tgts = targets()
    if not tgts or not cmd.strip():
        return 0
    return check_command(cmd, cwd, tgts, depth=0)


def check_command(cmd: str, cwd: Path, tgts, depth: int) -> int:
    if depth > 3:
        return deny("nested shell command too deep to verify")
    for seg in split_segments(cmd):
        # shell redirections that write into a target
        for m in REDIRECT.finditer(seg):
            if m.group(1) in ("/dev/null", "/dev/stderr", "/dev/stdout"):
                continue
            root = in_target_not_out(resolve(m.group(1).strip("'\""), cwd), tgts)
            if root:
                return deny(f"shell redirection writes into target {root}. ckb only writes under the output dir.")
        toks = tokens(seg)
        # track `cd X` / `pushd X` so later segments are evaluated in the right directory
        if toks[:1] in (["cd"], ["pushd"]) and len(toks) > 1:
            cwd = resolve(toks[1], cwd)
            continue
        while toks and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]) or toks[0] in WRAPPERS or toks[0].startswith("-") or toks[0].isdigit()):
            toks = toks[1:]
        if not toks:
            continue
        name = os.path.basename(toks[0])
        args = toks[1:]
        # nested shells: check the -c string as its own command
        if name in ("bash", "sh", "zsh", "dash", "ksh") and "-c" in args:
            i = args.index("-c")
            if i + 1 < len(args):
                r = check_command(args[i + 1], cwd, tgts, depth + 1)
                if r or _DENIED:
                    return r
                continue
        # file-modifying commands
        plain = [a for a in args if not a.startswith("-")]
        if name in WRITE_ALL_ARGS or (name in INPLACE and any(a.startswith("-i") for a in args)):
            check = plain if name not in INPLACE else plain[1:]
            if name == "chmod":
                check = plain[1:]
            for a in check:
                root = in_target_not_out(resolve(a, cwd), tgts)
                if root:
                    return deny(f"`{name}` would modify {a} inside target {root}. Targets are read-only for ckb.")
        if name in WRITE_LAST_ARG and plain:
            root = in_target_not_out(resolve(plain[-1], cwd), tgts)
            if root:
                return deny(f"`{name}` would write into target {root}. Targets are read-only for ckb.")
        paths = [resolve(t, cwd) for t in toks if ("/" in t or t.startswith(".")) and not t.startswith("-")]
        # -C/--prefix/--cwd style dir arguments
        for i, t in enumerate(toks[:-1]):
            if t in ("-C", "--prefix", "--cwd", "--dir", "--directory", "-f", "--file", "--project-dir", "--manifest-path"):
                paths.append(resolve(toks[i + 1], cwd))
        hit = touches(paths, cwd, tgts)
        if not hit:
            continue
        root = hit[0]
        if name == "git":
            sub = next((a for a in args if not a.startswith("-") and "=" not in a), "")
            hooks_off = "core.hooksPath=/dev/null" in seg
            if sub in GIT_HOOK_SUBCMDS and not hooks_off:
                return deny(f"`git {sub}` can run repository hooks in target {root}. Use read-only git "
                            f"({', '.join(sorted(GIT_READONLY))}) or pass -c core.hooksPath=/dev/null.")
            continue
        if name in EXEC_CMDS:
            subs = EXEC_CMDS[name]
            sub = next((a for a in args if subs and a in subs), next((a for a in args if not a.startswith("-")), ""))
            if subs is None or sub in subs:
                return deny(f"`{name} {sub}`. Target {root} is read-only for ckb: no install, build, run, or test. "
                            "Use static analysis (Read/Grep/Glob) and the ckb scripts instead.")
        if name in INTERPRETERS or re.match(r"python\d", name):
            script_args = [resolve(a, cwd) for a in args if not a.startswith("-")]
            if args[:1] and args[0] in ("-c", "-e", "-m", "--eval", "-r") and within(cwd, root):
                return deny(f"`{name} {args[0]}` executes code with cwd inside target {root}.")
            for p in script_args[:1]:
                if within(p, PLUGIN_ROOT):
                    break
                if within(p, root):
                    return deny(f"`{name}` would execute target file {p}. ckb never runs target code.")
            if not script_args and within(cwd, root) and name in ("bash", "sh", "zsh", "python", "python3", "node"):
                return deny(f"interactive `{name}` inside target {root}.")
        if name in ("source", "."):
            return deny(f"`{name}` would execute a target file in {root}.")
        if toks[0].startswith("./") or (os.sep in toks[0] and within(resolve(toks[0], cwd), root)):
            return deny(f"would execute target file {toks[0]} in {root}.")
    return 0


def check_write(ev: dict) -> int:
    ti = ev.get("tool_input") or {}
    fp = ti.get("file_path") or ti.get("notebook_path")
    if not fp:
        return 0
    cwd = Path(ev.get("cwd") or os.getcwd())
    p = resolve(fp, cwd)
    if p.name.startswith("seed-") and p.suffix == ".jsonl" and p.parent.name == "proposals":
        return deny("graph/proposals/seed-*.jsonl are written by ckb's deterministic rule engines only; agents write <stage>-<repo>.jsonl.")
    for root, out in targets():
        if within(p, root) and not within(p, out):
            return deny(f"write to {p} is inside target {root}. ckb only writes under {out}.")
    return 0


def check_proposal(p: Path, out_dir: Path) -> int:
    r = subprocess.run([sys.executable or "python3", str(HERE / "graph_merge.py"), "--out", str(out_dir), "--check", str(p)],
                       capture_output=True, text=True)
    try:
        rej = json.loads(r.stdout).get("rejected", [])
    except ValueError:
        return 0
    if rej:
        msg = (f"ckb graph proposal check failed for {p.name} ({len(rej)} line(s) rejected). Fix them:\n- "
               + "\n- ".join(f"line {x.get('line')}: {x.get('reason')}" for x in rej[:25])
               + "\nEvery proposal needs a real `repo/path:line` citation and an exact quote from that line.")
        print(json.dumps({"decision": "block", "reason": msg}))
    return 0


def autoupdate(ev: dict) -> int:
    """Opt-in (graph_autoupdate: on): structural graph refresh after a git commit. Never dispatches agents."""
    cmd = (ev.get("tool_input") or {}).get("command", "")
    if not re.search(r"\bgit\b[^|;&]*\b(commit|merge|cherry-pick|rebase|pull)\b", cmd):
        return 0
    cwd = Path(ev.get("cwd") or os.getcwd())
    settings = cwd / ".claude" / "code-knowledge-builder.local.md"
    if not settings.is_file() or not re.search(r"(?m)^graph_autoupdate:\s*on\b", settings.read_text()):
        return 0
    m = re.search(r"(?m)^output_dir:\s*(\S+)", settings.read_text())
    out = (cwd / m.group(1)).resolve() if m else cwd / ".ckb"
    if not (out / "graph" / "graph.json").is_file():
        return 0
    subprocess.Popen([sys.executable or "python3", str(HERE / "graph_build.py"), "--out", str(out), "--extract", "--incremental",
                      "--structural-only"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return 0


def check_post(ev: dict) -> int:
    ti = ev.get("tool_input") or {}
    fp = ti.get("file_path")
    if fp and fp.endswith(".jsonl") and "/graph/proposals/" in fp:
        p = resolve(fp, Path(ev.get("cwd") or os.getcwd()))
        out_dir = next((out for _, out in targets() if within(p, out)), None)
        return check_proposal(p, out_dir) if out_dir else 0
    if not fp or not fp.endswith(".md"):
        return 0
    p = resolve(fp, Path(ev.get("cwd") or os.getcwd()))
    out_dir = next((out for _, out in targets() if within(p, out)), None)
    if out_dir is None:
        return 0
    rel = p.relative_to(out_dir).as_posix()
    if rel.startswith("evidence/"):
        return 0
    py = sys.executable or "python3"
    problems = []
    v = subprocess.run([py, str(HERE / "verify_citations.py"), "--out", str(out_dir), "--json", str(p)],
                       capture_output=True, text=True)
    try:
        for r in json.loads(v.stdout).get("results", []):
            problems += [f"{e['code']} L{e['line']}: {e['message']}" for e in r["errors"]]
    except ValueError:
        problems.append("citation verifier failed to run")
    c = subprocess.run([py, str(HERE / "check_outputs.py"), "--json", str(p)], capture_output=True, text=True)
    try:
        for probs in json.loads(c.stdout).get("results", {}).values():
            problems += [f"{x['code']} L{x['line']}: {x['message']}" for x in probs]
    except ValueError:
        pass
    if problems:
        msg = (f"ckb output check failed for {rel} ({len(problems)} problem(s)). Fix before continuing:\n- "
               + "\n- ".join(problems[:25]) + ("\n- …" if len(problems) > 25 else "")
               + "\nCitations must be `repo/path:line` with a registered repo key and a real line; secrets must be redacted.")
        print(json.dumps({"decision": "block", "reason": msg}))
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        ev = json.load(sys.stdin)
    except ValueError:
        return 0
    try:
        return {"bash": check_bash, "write": check_write, "post": check_post, "autoupdate": autoupdate}.get(mode, lambda e: 0)(ev)
    except Exception as e:  # noqa: BLE001 - never crash the session; report and allow
        print(f"ckb guard internal error ({type(e).__name__}): {e}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
