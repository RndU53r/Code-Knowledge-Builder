"""Shared helpers for ckb scripts. Python 3 standard library only.

Nothing here executes, imports, or builds target code. Targets are only read
as bytes/text.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

VERSION = "0.1.0"

# Directories never walked (vendored, generated, caches, VCS internals).
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "bower_components",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "dist", "build", "out", "target", ".gradle", ".idea", ".vscode", ".next", ".nuxt",
    "coverage", ".terraform", ".ckb", "site-packages",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".tar", ".jar", ".war", ".class", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".o", ".a", ".pyc", ".wasm", ".woff", ".woff2", ".ttf", ".otf",
    ".mp3", ".mp4", ".mov", ".db", ".sqlite", ".parquet",
}
SECRET_FILE_PATTERNS = [
    re.compile(p) for p in (
        r"(^|/)\.env(\..*)?$", r"\.pem$", r"\.key$", r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$",
        r"\.p12$", r"\.pfx$", r"\.keystore$", r"\.jks$", r"(^|/)\.npmrc$", r"(^|/)\.pypirc$",
        r"(^|/)credentials(\.json)?$", r"(^|/)\.netrc$",
    )
]
# Value patterns (used to REDACT, never to print the value).
SECRET_VALUE_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
    ("Credentials in URL", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'\"]+:[^/\s@'\"]+@")),
    ("Generic assigned secret", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
]


def ckb_home() -> Path:
    return Path(os.environ.get("CKB_HOME", Path.home() / ".ckb"))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def redact(value: str) -> str:
    return (value[:4] if len(value) > 4 else "") + "…[REDACTED]"


def redact_text(text: str) -> str:
    """Return text with every secret-looking value replaced by its first 4 chars + …[REDACTED]."""
    for _, a, b in sorted(find_secret_values(text), key=lambda t: -t[1]):
        text = text[:a] + redact(text[a:b]) + text[b:]
    return text


def find_secret_values(text: str):
    """Yield (type, start, end) for secret-looking values. Never return the value itself."""
    for name, pat in SECRET_VALUE_PATTERNS:
        for m in pat.finditer(text):
            yield name, m.start(), m.end()


def is_secret_file(rel: str) -> bool:
    return any(p.search(rel) for p in SECRET_FILE_PATTERNS)


_CTRL_NAME = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\x85]")


def walk_files(root: Path, extra_excludes: list[str] | None = None):
    """Yield (abs_path, rel_posix) for regular files under root.

    Never follows symlinks; symlinks are yielded via walk_symlinks instead.
    """
    root = root.resolve()
    extra = [re.compile(fnmatch_to_re(g)) for g in (extra_excludes or [])]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in EXCLUDED_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if _CTRL_NAME.search(rel):  # newlines/control characters in a path would forge lines in citations and reports
                continue
            if any(r.search(rel) for r in extra):
                continue
            yield p, rel


def walk_symlinks(root: Path):
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink():
                yield p.relative_to(root).as_posix()


def fnmatch_to_re(glob: str) -> str:
    out = ""
    i = 0
    while i < len(glob):
        c = glob[i]
        if glob[i:i + 2] == "**":
            out += ".*"
            i += 2
            continue
        out += {"*": "[^/]*", "?": "[^/]"}.get(c, re.escape(c))
        i += 1
    return "(^|/)" + out + "$"


def is_binary(path: Path, sniff: int = 4096) -> bool:
    if path.suffix.lower() in BINARY_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sniff)
    except OSError:
        return True
    return b"\x00" in chunk


def read_text(path: Path, max_bytes: int = 2_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------- targets registry

def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def user_registry_path() -> Path:
    return ckb_home() / "targets.json"


def register_target(key: str, root: Path, out_dir: Path, meta: dict) -> None:
    """Record a target in the run's evidence/targets.json and the per-user registry."""
    root = root.resolve()
    out_dir = out_dir.resolve()
    run_reg = out_dir / "evidence" / "targets.json"
    data = load_json(run_reg, {"repos": {}})
    data.setdefault("repos", {})[key] = {"root": str(root), **meta}
    data["out_dir"] = str(out_dir)
    save_json(run_reg, data)

    ureg = load_json(user_registry_path(), {"targets": []})
    entries = [t for t in ureg.get("targets", []) if t.get("root") != str(root)]
    entries.append({"root": str(root), "out_dir": str(out_dir), "key": key, "registered": now_iso()})
    ureg["targets"] = entries
    save_json(user_registry_path(), ureg)


def repo_excludes(out_dir: Path) -> dict[str, list[str]]:
    data = load_json(out_dir / "evidence" / "targets.json", {"repos": {}})
    return {k: v.get("exclude", []) for k, v in data.get("repos", {}).items()}


def registered_targets() -> list[dict]:
    return load_json(user_registry_path(), {"targets": []}).get("targets", [])


def repo_roots_for_output(out_dir: Path) -> dict[str, Path]:
    data = load_json(out_dir / "evidence" / "targets.json", {"repos": {}})
    return {k: Path(v["root"]) for k, v in data.get("repos", {}).items()}


def find_out_dir(path: Path) -> Path | None:
    """Walk up from a file inside an output dir to the dir holding evidence/targets.json."""
    for parent in [path] + list(path.parents):
        if (parent / "evidence" / "targets.json").is_file():
            return parent
    return None


def within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False
