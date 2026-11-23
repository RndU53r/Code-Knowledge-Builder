#!/usr/bin/env python3
"""Static supply-chain and injection scanner for one repo. Reads files only.

Usage:
  scan_supply_chain.py --root REPO_ROOT --key REPO_KEY [--json-out F] [--md-out F]
                       [--osv] [--exclude GLOB ...]

Emits JSON (stdout or --json-out) and optionally a markdown findings table whose
evidence column uses ckb citations (`key/path:line`). Never executes target code.
--advisories osv,snyk queries api.osv.dev and/or the Snyk REST API (SNYK_TOKEN + SNYK_ORG_ID)
with package names and exact versions (opt-in; sends data off-machine). Without it, advisory
status is "not checked". Every registry dependency always gets a security.snyk.io page link
(no network call) so a human can check it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import (find_secret_values, is_binary, is_secret_file, now_iso,  # noqa: E402
                        read_text, walk_files, walk_symlinks)

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SUSPICIOUS, RISKY, INFO = "confirmed-suspicious", "risky-practice", "informational"

REMEDIATION = {
    "SC-M01": "Pin exact versions and commit a lockfile; let a bot (Renovate/Dependabot) raise update PRs.",
    "SC-M02": "Commit the ecosystem lockfile and install with the frozen/locked mode in CI.",
    "SC-M03": "Replace git/URL dependencies with registry releases, or pin to a full commit SHA and vendor-review it.",
    "SC-M04": "Confirm the package name is intended; typosquats imitate popular names by one or two characters.",
    "SC-M05": "Use only approved registries; scope internal registries per package scope; avoid --extra-index-url.",
    "SC-M06": "Reserve internal names on public registries or map the scope to the private registry explicitly.",
    "SC-M07": "Regenerate the lockfile from the manifest and review the diff.",
    "SC-I01": "Remove install lifecycle scripts or audit them; install with --ignore-scripts in CI.",
    "SC-I02": "Move build logic to declarative config (pyproject); remove network/exec from setup.py.",
    "SC-I03": "Download to a file, verify a pinned checksum or signature, then execute.",
    "SC-I04": "Remove remote script includes and exec tasks from the build, or pin and verify them.",
    "SC-C01": "Pin actions to a full 40-character commit SHA (with a version comment).",
    "SC-C02": "Avoid pull_request_target; if required, never check out or run PR head code in it.",
    "SC-C03": "Pass untrusted ${{ }} values through env: variables and quote them in the script.",
    "SC-C04": "Declare least-privilege `permissions:` at workflow or job level (default contents: read).",
    "SC-C05": "Never echo secrets; avoid `secrets: inherit`; scope secrets to the job that needs them.",
    "SC-D01": "Pin base images by digest (image@sha256:...).",
    "SC-D02": "Replace remote ADD with a verified download (checksum) or COPY of a vetted artifact.",
    "SC-D03": "Add a non-root USER and drop privileges.",
    "SC-D04": "Verify downloaded binaries with a pinned sha256 or signature before use.",
    "SC-D05": "Avoid privileged containers, host networking, and running as UID 0.",
    "SC-D06": "Pin module sources to an immutable ref and providers to a version constraint.",
    "SC-D07": "Block public access (S3 Block Public Access, Azure allowBlobPublicAccess=false, no allUsers bindings); front with authenticated access.",
    "SC-D08": "Replace wildcard IAM actions/roles with least-privilege, resource-scoped permissions.",
    "SC-D09": "Enable encryption at rest and enforce TLS 1.2+ / HTTPS-only.",
    "SC-S01": "Decode and review the blob; remove it if it is not a legitimate asset.",
    "SC-S02": "Never eval/exec content fetched at runtime or decoded from opaque strings.",
    "SC-S03": "Remove network access from import- and build-time code paths.",
    "SC-S04": "Remove hidden/bidirectional Unicode and homoglyphs; add a CI check that rejects them.",
    "SC-S05": "Review recent changes to build and CI files for unexpected behavior.",
    "SC-S06": "Remove committed binaries or document and checksum them; build from source in CI.",
    "SC-S07": "Review repository git hooks before enabling them; never auto-install hooks from untrusted repos.",
    "SC-S08": "Rotate the credential, remove it from history, and load it from a secret manager.",
    "SC-S09": "Remove secret-bearing files from the repo and add them to .gitignore.",
    "SC-A01": "Remove text that addresses AI agents; treat it as a possible injection attempt and investigate its origin.",
    "SC-A02": "Review agent instruction files; keep them free of commands that fetch, execute, or exfiltrate.",
}

POPULAR = {
    "npm": ["lodash", "express", "react", "axios", "request", "chalk", "commander", "debug", "moment",
            "webpack", "typescript", "eslint", "jest", "dotenv", "uuid", "async", "underscore", "colors",
            "cross-env", "node-fetch", "event-stream", "jquery", "vue", "next", "mongoose", "body-parser",
            "kafkajs", "amqplib", "pg", "redis", "ws", "socket.io", "yargs", "babel-core", "electron"],
    "pypi": ["requests", "numpy", "pandas", "django", "flask", "fastapi", "urllib3", "boto3", "pyyaml",
             "setuptools", "cryptography", "pillow", "sqlalchemy", "pydantic", "jinja2", "click", "six",
             "python-dateutil", "certifi", "idna", "colorama", "beautifulsoup4", "scipy", "matplotlib",
             "uvicorn", "httpx", "aiohttp", "celery", "kafka-python", "pika", "psycopg2", "redis"],
}

AGENT_PHRASES = re.compile(
    r"(?i)(ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts?|rules)"
    r"|disregard\s+(all\s+|any\s+|your\s+)?(previous\s+|prior\s+)?(instructions|guidelines|rules)"
    r"|(note|message|instructions?)\s+(to|for)\s+(the\s+)?(ai|llm|claude|copilot|chatgpt|gpt|assistant|agent|codex|cursor)s?\b"
    r"|\b(ai|llm)\s+(agents?|assistants?|tools?|models?)\s*(must|should|shall|are\s+required\s+to|need\s+to)\b"
    r"|\byou\s+are\s+(now\s+)?(an?\s+|the\s+)?(ai|assistant|agent|llm|language\s+model)\b"
    r"|\b(claude|copilot|chatgpt|cursor|codex|gemini)\s*[,:]\s*(please\s+)?(run|execute|ignore|delete|send|upload|curl|add|install|disable)\b"
    r"|<\s*/?\s*(system|assistant|instructions?)\s*>"
    r"|\bsystem\s+prompt\s*(override|:)"
    r"|do\s+not\s+(tell|inform|alert|mention\s+(this\s+)?to)\s+the\s+user"
    r"|without\s+(asking|telling|informing)\s+the\s+user)")
DANGEROUS_IMPERATIVE = re.compile(r"(?i)\b(curl|wget|rm\s+-rf|chmod\s+\+x|base64\s+-d|nc\s+-|bash\s+-c|sh\s+-c|"
                                  r"exfiltrat|upload|send\s+(the\s+)?(env|secrets?|tokens?|keys?)|\.ssh|"
                                  r"disable\s+(the\s+)?(hook|guard|check|safety))")
AGENT_FILES = re.compile(r"(?i)(^|/)(claude\.md|agents\.md|gemini\.md|\.cursorrules|\.cursor/rules/.*|"
                         r"\.clinerules(/.*)?|\.windsurf/rules/.*|\.windsurfrules|\.github/copilot-instructions\.md|"
                         r"\.agents/.*\.md|\.claude/(settings.*\.json|commands/.*|agents/.*))$")
BIDI = re.compile("[‪-‮⁦-⁩]")
ZERO_WIDTH = re.compile("[​-‍⁠᠎]")
CURL_PIPE = re.compile(r"(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|"
                       r"\b(bash|sh)\s+<\(\s*(curl|wget)|\biex\s*\(\s*(new-object|iwr|invoke-webrequest)")
NET_CALL = re.compile(r"(?i)(requests\.(get|post)|urllib\.request|urlopen\(|http\.client|socket\.connect|"
                      r"fetch\(|https?\.get\(|axios\.|child_process|net\.connect|curl\s|wget\s|Invoke-WebRequest)")
EVAL_FETCH = re.compile(r"(?i)(eval|exec|Function|execSync|spawn|compile)\s*\(\s*[^)]{0,200}"
                        r"(fetch|requests\.get|urlopen|http\.get|https\.get|axios|b64decode|atob|base64|Buffer\.from|decode\()")
BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}|(?:[0-9a-fA-F]{2}){120,}|(?:\\x[0-9a-fA-F]{2}){60,}")
SOURCE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".kt",
              ".rs", ".sh", ".bash", ".ps1", ".pl", ".lua", ".cs", ".c", ".cc", ".cpp", ".h", ".swift",
              ".gradle", ".kts", ".groovy", ".scala"}
DOC_EXT = {".md", ".txt", ".rst", ".adoc", ".html", ".mdx"}
CONF_EXT = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".xml", ".env", ".properties"}
BIN_COMMIT_EXT = {".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".class", ".bin", ".o", ".a", ".whl", ".pyc", ".node"}


def safe_excerpt(s: str, n: int = 80) -> str:
    s = s.strip()
    for name, a, b in sorted(find_secret_values(s), key=lambda t: -t[1]):
        s = s[:a] + s[a:a + 4] + "…[REDACTED]" + s[b:]
    s = "".join(f"<U+{ord(c):04X}>" if (BIDI.match(c) or ZERO_WIDTH.match(c)) else c for c in s)
    s = s.replace("`", "'").replace("|", "\\|").replace("«", "<").replace("»", ">")
    return s[:n] + ("…" if len(s) > n else "")


def levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    d = prev[-1]
    # adjacent transposition counts as one edit (Damerau), e.g. lodahs -> lodash
    if d == 2 and len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]:
            return 1
    return d


class Scanner:
    def __init__(self, root: Path, key: str, excludes: list[str]):
        self.root, self.key = root.resolve(), key
        self.excludes = excludes
        self.findings: list[dict] = []
        self.deps: list[dict] = []
        self.checks_run: dict[str, int] = {}
        self.limitations: list[str] = []
        self.files = list(walk_files(self.root, excludes))

    # ------------------------------------------------------------------ helpers
    def add(self, check, category, cls, severity, confidence, rel, line, text, message):
        self.findings.append({
            "check": check, "category": category, "class": cls, "severity": severity,
            "confidence": confidence, "path": rel, "line": line,
            "citation": f"{self.key}/{rel}:{line}", "excerpt": safe_excerpt(text or ""),
            "message": message, "remediation": REMEDIATION.get(check, ""),
        })

    def ran(self, name):
        self.checks_run[name] = self.checks_run.get(name, 0) + 1

    @staticmethod
    def line_of(text: str, idx: int) -> int:
        return text.count("\n", 0, idx) + 1

    def grep(self, text, pattern, rel, check, category, cls, sev, conf, msg):
        for m in pattern.finditer(text):
            ln = self.line_of(text, m.start())
            self.add(check, category, cls, sev, conf, rel, ln, text.splitlines()[ln - 1], msg)

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        names = {rel for _, rel in self.files}
        for path, rel in self.files:
            base = rel.rsplit("/", 1)[-1]
            ext = Path(base).suffix.lower()
            if is_secret_file(rel):
                self.ran("secret-files")
                self.add("SC-S09", "secrets", RISKY, "medium", "high", rel, 1, "", "secret-bearing file committed (contents not read)")
                continue
            if ext in BIN_COMMIT_EXT or (ext not in DOC_EXT | CONF_EXT | SOURCE_EXT and is_binary(path)):
                self.ran("committed-binaries")
                if ext in BIN_COMMIT_EXT:
                    self.add("SC-S06", "source-indicators", RISKY, "medium", "high", rel, 1, "", f"committed binary ({ext})")
                continue
            text = read_text(path)
            if text is None:
                self.limitations.append(f"skipped (too large or unreadable): {rel}")
                continue
            self.scan_text_generic(rel, base, ext, text)
            if base == "package.json":
                self.npm_manifest(rel, text, names)
            elif base == "package-lock.json":
                self.npm_lock(rel, text)
            elif base == ".npmrc" or base == ".yarnrc" or base == ".yarnrc.yml":
                self.registry_config(rel, text)
            elif re.match(r"requirements.*\.(txt|in)$", base) or base == "constraints.txt":
                self.requirements(rel, text, names)
            elif base == "pyproject.toml":
                self.pyproject(rel, text, names)
            elif base == "setup.py":
                self.setup_py(rel, text)
            elif base == "go.mod":
                self.go_mod(rel, text, names)
            elif base == "Cargo.toml":
                self.cargo(rel, text, names)
            elif base in ("pom.xml",):
                self.maven(rel, text)
            elif base.endswith((".gradle", ".gradle.kts")):
                self.gradle(rel, text)
            elif base == "Gemfile":
                self.gemfile(rel, text, names)
            elif base == "composer.json":
                self.composer(rel, text, names)
            if base.startswith("Dockerfile") or base.endswith(".Dockerfile") or base == "Containerfile":
                self.dockerfile(rel, text)
            if rel.startswith(".github/workflows/") and ext in (".yml", ".yaml"):
                self.gha(rel, text)
            if base in (".gitlab-ci.yml",) or rel.startswith(".gitlab/ci/"):
                self.gitlab_ci(rel, text)
            if ext in (".yml", ".yaml") and re.search(r"(?m)^\s*kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob)\b", text):
                self.k8s(rel, text)
            if ext == ".tf" or base.endswith(".tf.json"):
                self.terraform(rel, text)
            if ext == ".bicep" or (ext == ".json" and '"Microsoft.' in text):
                self.azure(rel, text)
            if ext in (".yml", ".yaml", ".json", ".template") and ("AWSTemplateFormatVersion" in text or re.search(r"Type:\s*['\"]?AWS::", text)):
                self.cloudformation(rel, text)
            if ext in (".yml", ".yaml", ".jinja") and re.search(r"type:\s*['\"]?compute\.v\d\.firewall|type:\s*['\"]?storage\.v\d", text):
                self.gcp_dm(rel, text)
            if base in ("Makefile", "makefile", "GNUmakefile") or ext in (".sh", ".bash", ".ps1"):
                self.ran("install-time-shell")
        self.symlinks()
        self.git_hooks(names)
        self.history()
        self.findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["class"] != SUSPICIOUS,
                                          f["check"], f["path"], f["line"]))
        for i, f in enumerate(self.findings, 1):
            f["id"] = f"{self.key.upper()}-SC-{i:03d}"
        return {
            "repo": self.key, "root": str(self.root), "generated": now_iso(),
            "files_scanned": len(self.files), "findings": self.findings, "dependencies": self.deps,
            "checks_run": self.checks_run, "limitations": self.limitations,
        }

    # ------------------------------------------------------------------ generic text checks
    def scan_text_generic(self, rel, base, ext, text):
        lines = text.splitlines()
        # Hidden unicode (Trojan Source, zero-width) and homoglyphs
        self.ran("hidden-unicode")
        for i, ln in enumerate(lines, 1):
            if BIDI.search(ln):
                self.add("SC-S04", "source-indicators", SUSPICIOUS, "high", "high", rel, i, ln,
                         "bidirectional control character (Trojan Source pattern)")
            elif ZERO_WIDTH.search(ln) and ext in SOURCE_EXT | CONF_EXT:
                self.add("SC-S04", "source-indicators", RISKY, "medium", "medium", rel, i, ln, "zero-width character in code/config")
            elif ext in SOURCE_EXT and re.search(r"[A-Za-z_]", ln):
                for tok in re.findall(r"[^\W\d_][\w]*", ln):
                    scripts = {unicodedata.name(c, "").split(" ")[0] for c in tok if not c.isascii() and c.isalpha()}
                    if scripts & {"CYRILLIC", "GREEK"} and any(c.isascii() and c.isalpha() for c in tok):
                        self.add("SC-S04", "source-indicators", SUSPICIOUS, "high", "medium", rel, i, ln,
                                 "mixed-script identifier (homoglyph)")
                        break
        # Secrets (values never stored)
        self.ran("secret-values")
        for name, a, _ in find_secret_values(text):
            ln = self.line_of(text, a)
            if name == "Credentials in URL":
                self.add("SC-S08", "secrets", RISKY, "medium", "medium", rel, ln, lines[ln - 1],
                         "credentials embedded in a URL (may be a default like guest:guest; still a hardcoded credential)")
            else:
                self.add("SC-S08", "secrets", SUSPICIOUS, "high", "medium", rel, ln, lines[ln - 1], f"possible {name} committed")
        # curl | sh anywhere (scripts, Makefiles, Dockerfiles, CI, docs install lines)
        self.ran("curl-pipe-sh")
        for m in CURL_PIPE.finditer(text):
            ln = self.line_of(text, m.start())
            line = lines[ln - 1]
            sus = re.search(r"(?i)https?://(\d{1,3}\.){3}\d{1,3}|\.invalid\b|pastebin|ngrok|transfer\.sh|raw\.githubusercontent\.com/[^/]+/[^/]+/(main|master)/", line)
            in_docs = Path(rel).suffix.lower() in DOC_EXT and not AGENT_FILES.search(rel)
            self.add("SC-I03", "install-time", SUSPICIOUS if sus else RISKY,
                     "low" if in_docs else ("high" if sus else "medium"), "high", rel, ln, line,
                     "remote script piped to a shell" + (" (untrusted host)" if sus else ""))
        # Agent-targeted injection
        self.ran("agent-injection")
        is_agent_file = bool(AGENT_FILES.search(rel))
        for m in AGENT_PHRASES.finditer(text):
            ln = self.line_of(text, m.start())
            window = " ".join(lines[max(0, ln - 2):ln + 2])
            dangerous = bool(DANGEROUS_IMPERATIVE.search(window))
            self.add("SC-A01", "prompt-injection", SUSPICIOUS if (dangerous or not is_agent_file) else RISKY,
                     "critical" if dangerous else "high", "high" if dangerous else "medium", rel, ln, lines[ln - 1],
                     "text addressed to AI agents" + (" with a dangerous imperative" if dangerous else ""))
        if is_agent_file:
            self.ran("agent-instruction-files")
            hits = [i for i, ln in enumerate(lines, 1) if DANGEROUS_IMPERATIVE.search(ln)]
            if hits:
                worst = any(CURL_PIPE.search(lines[i - 1]) or re.search(r"(?i)\.ssh|exfiltrat|upload|disable", lines[i - 1]) for i in hits)
                self.add("SC-A02", "prompt-injection", SUSPICIOUS if worst else RISKY, "high" if worst else "medium",
                         "high" if worst else "medium", rel, hits[0], lines[hits[0] - 1],
                         f"agent instruction file contains {len(hits)} command-like line(s)"
                         + (" that fetch-and-execute or exfiltrate" if worst else "") + "; agents that auto-load it would be instructed to run them")
            else:
                self.add("SC-A02", "prompt-injection", INFO, "info", "high", rel, 1, "",
                         "agent instruction file present (treated as data, not followed)")
        # HTML comments in docs that hide agent phrases
        if ext in DOC_EXT:
            for m in re.finditer(r"<!--(.*?)-->", text, re.S):
                if AGENT_PHRASES.search(m.group(1)) or DANGEROUS_IMPERATIVE.search(m.group(1)):
                    ln = self.line_of(text, m.start())
                    self.add("SC-A01", "prompt-injection", SUSPICIOUS, "high", "high", rel, ln, lines[ln - 1],
                             "hidden HTML comment with agent-directed or command-like text")
        if ext in SOURCE_EXT:
            self.ran("eval-of-fetched")
            self.grep(text, EVAL_FETCH, rel, "SC-S02", "source-indicators", SUSPICIOUS, "high", "medium",
                      "dynamic code execution of fetched or decoded content")
            self.ran("encoded-blobs")
            for m in BLOB.finditer(text):
                ln = self.line_of(text, m.start())
                near = " ".join(lines[max(0, ln - 3):ln + 3])
                sus = re.search(r"(?i)\b(eval|exec|Function|atob|b64decode|base64\s*-d|Buffer\.from|unhexlify|fromCharCode)\b", near)
                self.add("SC-S01", "source-indicators", SUSPICIOUS if sus else RISKY, "high" if sus else "low",
                         "medium" if sus else "low", rel, ln, lines[ln - 1][:60],
                         f"encoded blob ({len(m.group(0))} chars)" + (" near a decoder/eval" if sus else ""))
            if base in ("setup.py", "__init__.py", "conftest.py", "build.gradle", "build.gradle.kts", "build.rs") \
                    or rel.endswith(("/install.js", "/postinstall.js", "/preinstall.js")):
                self.ran("import-time-network")
                for m in NET_CALL.finditer(text):
                    ln = self.line_of(text, m.start())
                    if not lines[ln - 1].startswith((" ", "\t")) or base in ("build.rs",) or "install" in base:
                        self.add("SC-S03", "source-indicators", RISKY, "medium", "low", rel, ln, lines[ln - 1],
                                 f"network or process call in import/build-time file ({base})")

    # ------------------------------------------------------------------ manifests
    def dep(self, eco, name, spec, source, rel, line, pinned):
        self.deps.append({"ecosystem": eco, "name": name, "spec": spec, "source": source, "pinned": pinned,
                          "manifest": rel, "line": line, "citation": f"{self.key}/{rel}:{line}",
                          "advisory": "not checked", "snyk_url": None})

    def typosquat(self, eco, name, rel, line, raw):
        self.ran("typosquat")
        n = name.lower().split("/")[-1]
        for pop in POPULAR.get(eco, []):
            if n != pop and levenshtein(n, pop) == 1 and len(pop) >= 4:
                self.add("SC-M04", "manifests", RISKY, "medium", "low", rel, line, raw,
                         f"package name '{name}' is one edit from popular '{pop}'")

    def line_for(self, text, needle):
        idx = text.find(needle)
        return self.line_of(text, idx) if idx >= 0 else 1

    def npm_manifest(self, rel, text, names):
        self.ran("npm-manifest")
        try:
            pj = json.loads(text)
        except ValueError:
            self.limitations.append(f"invalid JSON: {rel}")
            return
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        if not any(d + lf in names for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb")):
            if pj.get("dependencies") or pj.get("devDependencies"):
                self.add("SC-M02", "manifests", RISKY, "medium", "high", rel, 1, "", "package.json without a lockfile")
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, spec in (pj.get(section) or {}).items():
                ln = self.line_for(text, f'"{name}"')
                raw = f'"{name}": "{spec}"'
                src = "registry"
                if re.match(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:)", str(spec)) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", str(spec)):
                    src = "git/url"
                    self.add("SC-M03", "manifests", RISKY, "high" if str(spec).startswith("http") else "medium", "high",
                             rel, ln, raw, f"{section} '{name}' resolved from {spec.split(':')[0]} instead of the registry")
                pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+([-+][\w.]+)?", str(spec)))
                if src == "registry" and not pinned and section != "peerDependencies":
                    sev = "medium" if re.search(r"^\*$|latest|^>=|^x$|\|\|", str(spec)) else "low"
                    self.add("SC-M01", "manifests", RISKY, sev, "high", rel, ln, raw, f"floating version range '{spec}' for {name}")
                if name.startswith("@") and section != "peerDependencies":
                    self.ran("dependency-confusion")
                    scope = name.split("/")[0]
                    if not any(f"{scope}:registry" in (read_text(self.root / n) or "") for n in names if n.endswith(".npmrc")):
                        if scope not in ("@types", "@babel", "@angular", "@vue", "@nestjs", "@aws-sdk", "@google-cloud",
                                         "@azure", "@typescript-eslint", "@testing-library", "@reduxjs", "@mui",
                                         "@emotion", "@octokit", "@anthropic-ai", "@opentelemetry", "@grpc"):
                            self.add("SC-M06", "manifests", RISKY, "low", "low", rel, ln, raw,
                                     f"scoped package {scope} has no scope→registry mapping; if internal, it may resolve from the public registry")
                self.typosquat("npm", name, rel, ln, raw)
                self.dep("npm", name, str(spec), src, rel, ln, pinned)
        scripts = pj.get("scripts") or {}
        self.ran("npm-lifecycle-scripts")
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare"):
            if hook in scripts:
                body = str(scripts[hook])
                ln = self.line_for(text, f'"{hook}"')
                sus = re.search(r"(?i)curl|wget|https?://|node\s+-e|base64|eval|\|\s*(ba)?sh|powershell|nc\s|/dev/tcp", body)
                self.add("SC-I01", "install-time", SUSPICIOUS if sus else RISKY,
                         "critical" if sus else ("low" if hook == "prepare" else "medium"), "high", rel, ln,
                         f'"{hook}": "{body}"',
                         f"npm {hook} script runs at install time" + (" and fetches/executes remote or encoded content" if sus else ""))

    def npm_lock(self, rel, text):
        self.ran("npm-lockfile")
        try:
            lock = json.loads(text)
        except ValueError:
            return
        pkgs = lock.get("packages") or {}
        for path, meta in pkgs.items():
            res = str(meta.get("resolved", ""))
            if res and not res.startswith("https://registry.npmjs.org/") and not res.startswith("file:"):
                ln = self.line_for(text, res)
                self.add("SC-M05", "manifests", RISKY, "medium", "medium", rel, ln, res, f"{path or 'root'} resolved from a non-default registry/URL")
        root_meta = pkgs.get("", {})
        mpath = self.root / (rel.rsplit("/", 1)[0] + "/package.json" if "/" in rel else "package.json")
        try:
            pj = json.loads(mpath.read_text())
        except (OSError, ValueError):
            return
        self.ran("lockfile-drift")
        for section in ("dependencies", "devDependencies"):
            want = pj.get(section) or {}
            have = root_meta.get(section) or {}
            for name, spec in want.items():
                if have and name not in have:
                    self.add("SC-M07", "manifests", RISKY, "medium", "high", rel, 1, name,
                             f"{name} is in package.json {section} but not in the lockfile root")
                elif have and str(have.get(name)) != str(spec):
                    self.add("SC-M07", "manifests", RISKY, "low", "high", rel, self.line_for(text, f'"{name}"'),
                             f"{name}: {have.get(name)} vs {spec}", f"lockfile root spec for {name} differs from package.json")

    def registry_config(self, rel, text):
        self.ran("registry-config")
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.search(r"(?i)registry\s*[=:]\s*['\"]?(\S+)", ln)
            if m and "registry.npmjs.org" not in m.group(1) and "registry.yarnpkg.com" not in m.group(1):
                self.add("SC-M05", "manifests", RISKY, "low", "high", rel, i, ln, f"custom registry configured: {m.group(1)}")
            if re.search(r"_authToken\s*=\s*[^$\s{]", ln):
                self.add("SC-S08", "secrets", SUSPICIOUS, "high", "medium", rel, i, ln, "registry auth token committed")

    def requirements(self, rel, text, names):
        self.ran("pip-requirements")
        hashed = "--hash=" in text
        for i, raw in enumerate(text.splitlines(), 1):
            ln = raw.split("#", 1)[0].strip()
            if not ln:
                continue
            if ln.startswith("--extra-index-url"):
                self.add("SC-M06", "manifests", RISKY, "high", "high", rel, i, raw,
                         "--extra-index-url lets public PyPI shadow internal package names (dependency confusion)")
                continue
            if ln.startswith(("--index-url", "-i ")):
                self.add("SC-M05", "manifests", RISKY, "low", "high", rel, i, raw, "custom package index")
                continue
            if ln.startswith(("-r", "-c", "--")):
                continue
            if re.match(r"(?i)^(git\+|hg\+|svn\+|https?://)|\s@\s*(git\+|https?://)", ln):
                self.add("SC-M03", "manifests", RISKY, "medium", "high", rel, i, raw, "dependency installed from VCS/URL")
                self.dep("pypi", ln.split("@")[0].strip() or ln, ln, "git/url", rel, i, "@" in ln and re.search(r"@[0-9a-f]{40}", ln) is not None)
                continue
            m = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*(.*)$", ln)
            if not m:
                continue
            name, spec = m.group(1).split("[")[0], m.group(2).split(";")[0].strip()
            pinned = spec.startswith("==") and "*" not in spec
            if not pinned:
                self.add("SC-M01", "manifests", RISKY, "medium" if not spec else "low", "high", rel, i, raw,
                         f"{name} not pinned with == ({spec or 'no version'})")
            self.typosquat("pypi", name, rel, i, raw)
            self.dep("pypi", name, spec or "*", "registry", rel, i, pinned)
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        if not hashed and not any(d + lf in names for lf in ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")):
            self.add("SC-M02", "manifests", RISKY, "low", "medium", rel, 1, "",
                     "requirements without --hash pins or a lockfile (installs are not reproducible)")

    def pyproject(self, rel, text, names):
        self.ran("pyproject")
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        block = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", text)
        if block:
            start = self.line_of(text, block.start(1))
            for off, raw in enumerate(block.group(1).splitlines()):
                m = re.search(r"['\"]([A-Za-z0-9._\-]+)(\[[^\]]*\])?\s*([^'\"]*)['\"]", raw)
                if m:
                    name, spec = m.group(1), m.group(3).strip()
                    pinned = spec.startswith("==")
                    self.typosquat("pypi", name, rel, start + off, raw)
                    self.dep("pypi", name, spec or "*", "registry", rel, start + off, pinned)
                    if "@" in spec and ("git+" in spec or "http" in spec):
                        self.add("SC-M03", "manifests", RISKY, "medium", "high", rel, start + off, raw, "dependency from VCS/URL")
        for m in re.finditer(r"(?m)^([A-Za-z0-9._\-]+)\s*=\s*\{[^}\n]*\b(git|url|path)\s*=", text):
            ln = self.line_of(text, m.start())
            self.add("SC-M03", "manifests", RISKY, "medium", "high", rel, ln, m.group(0), f"poetry dependency {m.group(1)} from {m.group(2)}")
        if (block or "[tool.poetry.dependencies]" in text) and not any(d + lf in names for lf in ("poetry.lock", "uv.lock", "pdm.lock")):
            self.add("SC-M02", "manifests", RISKY, "low", "medium", rel, 1, "", "pyproject dependencies without a lockfile")

    def setup_py(self, rel, text):
        self.ran("setup-py")
        lines = text.splitlines()
        hits = [(i, ln) for i, ln in enumerate(lines, 1)
                if re.search(r"(?i)urlopen|requests\.|subprocess|os\.system|exec\(|eval\(|b64decode|socket|urllib", ln)]
        for i, ln in hits:
            self.add("SC-I02", "install-time", SUSPICIOUS if re.search(r"(?i)urlopen|requests\.|socket|b64decode|exec\(|eval\(", ln) else RISKY,
                     "high", "medium", rel, i, ln, "setup.py performs network/process/dynamic execution at install time")
        if "cmdclass" in text and not hits:
            self.add("SC-I02", "install-time", RISKY, "low", "medium", rel, self.line_for(text, "cmdclass"), "cmdclass",
                     "setup.py overrides install commands (cmdclass)")

    def go_mod(self, rel, text, names):
        self.ran("go-mod")
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        if "require" in text and d + "go.sum" not in names:
            self.add("SC-M02", "manifests", RISKY, "medium", "high", rel, 1, "", "go.mod without go.sum")
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]{2,}[^\s]*)\s+(v[^\s]+)", ln)
            if m and not ln.strip().startswith(("module", "go ", "//")):
                self.dep("go", m.group(1), m.group(2), "registry", rel, i, True)
            if ln.strip().startswith("replace") or "=>" in ln:
                self.add("SC-M03", "manifests", RISKY, "low", "high", rel, i, ln, "go replace directive redirects a module")

    def cargo(self, rel, text, names):
        self.ran("cargo")
        sect = None
        for i, ln in enumerate(text.splitlines(), 1):
            h = re.match(r"^\s*\[([^\]]+)\]", ln)
            if h:
                sect = h.group(1)
                continue
            if sect and sect.endswith("dependencies"):
                m = re.match(r'^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+)$', ln)
                if m:
                    spec = m.group(2)
                    if re.search(r"\b(git|path)\s*=", spec):
                        self.add("SC-M03", "manifests", RISKY, "medium", "high", rel, i, ln, f"crate {m.group(1)} from git/path")
                    self.dep("crates", m.group(1), spec.strip(), "git/url" if "git" in spec else "registry", rel, i, "=" in spec.strip('"')[:1])
        if "[[bin]]" in text or "src/main.rs" in names:
            d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
            if d + "Cargo.lock" not in names:
                self.add("SC-M02", "manifests", RISKY, "low", "medium", rel, 1, "", "binary crate without Cargo.lock")

    def maven(self, rel, text):
        self.ran("maven")
        for m in re.finditer(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?", text):
            ln = self.line_of(text, m.start())
            v = m.group(3) or "(managed)"
            self.dep("maven", f"{m.group(1)}:{m.group(2)}", v, "registry", rel, ln, bool(m.group(3)) and "SNAPSHOT" not in v and "[" not in v)
            if "SNAPSHOT" in v or "LATEST" in v or "RELEASE" in v or v.startswith("["):
                self.add("SC-M01", "manifests", RISKY, "medium", "high", rel, ln, m.group(0)[:80], f"non-reproducible Maven version {v}")
        for m in re.finditer(r"<url>\s*http://", text):
            self.add("SC-M05", "manifests", RISKY, "high", "high", rel, self.line_of(text, m.start()), m.group(0), "Maven repository over plain HTTP")
        if "exec-maven-plugin" in text or "maven-antrun-plugin" in text:
            ln = self.line_for(text, "exec-maven-plugin") if "exec-maven-plugin" in text else self.line_for(text, "maven-antrun-plugin")
            self.add("SC-I04", "install-time", RISKY, "medium", "medium", rel, ln, "", "build executes arbitrary commands (exec/antrun plugin)")

    def gradle(self, rel, text):
        self.ran("gradle")
        for i, ln in enumerate(text.splitlines(), 1):
            if re.search(r"apply\s+from\s*:?\s*['\"]https?://", ln):
                self.add("SC-I04", "install-time", SUSPICIOUS, "high", "high", rel, i, ln, "Gradle applies a remote script")
            if re.search(r"\b(exec\s*\{|commandLine|ProcessBuilder|\.execute\(\))", ln):
                self.add("SC-I04", "install-time", RISKY, "medium", "medium", rel, i, ln, "Gradle build executes a process")
            if re.search(r"url\s*[=(]?\s*['\"]http://", ln):
                self.add("SC-M05", "manifests", RISKY, "high", "high", rel, i, ln, "repository over plain HTTP")
            m = re.search(r"(implementation|api|compile|runtimeOnly|testImplementation)\s*\(?\s*['\"]([^:'\"]+:[^:'\"]+):?([^'\"]*)['\"]", ln)
            if m:
                v = m.group(3) or "(managed)"
                self.dep("maven", m.group(2), v, "registry", rel, i, bool(m.group(3)) and "+" not in v)
                if "+" in v or "latest" in v:
                    self.add("SC-M01", "manifests", RISKY, "medium", "high", rel, i, ln, f"dynamic Gradle version {v}")

    def gemfile(self, rel, text, names):
        self.ran("gemfile")
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"](.*)", ln)
            if m:
                self.dep("rubygems", m.group(1), m.group(2).strip(", ") or "*", "git/url" if "git" in m.group(2) else "registry", rel, i, "'=" in m.group(2))
                if re.search(r"\b(git|github)\s*:", m.group(2)):
                    self.add("SC-M03", "manifests", RISKY, "medium", "high", rel, i, ln, "gem from git")
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        if d + "Gemfile.lock" not in names:
            self.add("SC-M02", "manifests", RISKY, "low", "medium", rel, 1, "", "Gemfile without Gemfile.lock")

    def composer(self, rel, text, names):
        self.ran("composer")
        try:
            cj = json.loads(text)
        except ValueError:
            return
        for sect in ("require", "require-dev"):
            for name, spec in (cj.get(sect) or {}).items():
                self.dep("packagist", name, spec, "registry", rel, self.line_for(text, f'"{name}"'), bool(re.fullmatch(r"\d+\.\d+\.\d+", spec)))
        for hook in ("post-install-cmd", "post-update-cmd", "pre-install-cmd"):
            if hook in (cj.get("scripts") or {}):
                self.add("SC-I01", "install-time", RISKY, "medium", "high", rel, self.line_for(text, hook), hook, f"composer {hook} script")

    # ------------------------------------------------------------------ CI/CD
    def gha(self, rel, text):
        self.ran("github-actions")
        lines = text.splitlines()
        has_prt = re.search(r"(?m)^\s*(on:\s*\[?[^\n]*pull_request_target|pull_request_target\s*:)", text)
        if has_prt:
            ln = self.line_of(text, has_prt.start())
            checkout_head = re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/", text)
            self.add("SC-C02", "ci-cd", SUSPICIOUS if checkout_head else RISKY, "critical" if checkout_head else "medium",
                     "high", rel, ln, lines[ln - 1],
                     "pull_request_target" + (" checks out untrusted PR code with a privileged token" if checkout_head else " runs with write token and secrets for fork PRs"))
        if not re.search(r"(?m)^\s*permissions\s*:", text):
            self.add("SC-C04", "ci-cd", RISKY, "low", "high", rel, 1, "", "no permissions: block (token gets repository default scopes)")
        for i, ln in enumerate(lines, 1):
            m = re.search(r"uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)", ln)
            if m and not m.group(1).startswith(("./", "docker://")):
                if not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                    first = m.group(1).split("/")[0] in ("actions", "github")
                    self.add("SC-C01", "ci-cd", RISKY, "low" if first else "high", "high", rel, i, ln,
                             f"action {m.group(1)} pinned to mutable ref '{m.group(2)}'" + ("" if first else " (third-party)"))
            if re.search(r"permissions\s*:\s*write-all", ln):
                self.add("SC-C04", "ci-cd", RISKY, "high", "high", rel, i, ln, "permissions: write-all")
            elif re.search(r"^\s*(contents|packages|id-token|actions|pull-requests|deployments|security-events)\s*:\s*write", ln):
                self.add("SC-C04", "ci-cd", RISKY, "low", "medium", rel, i, ln, "write scope granted; confirm it is required")
            if re.search(r"secrets\s*:\s*inherit", ln):
                self.add("SC-C05", "ci-cd", RISKY, "medium", "high", rel, i, ln, "secrets: inherit passes all secrets to a called workflow")
            if re.search(r"(echo|printf|print)\b[^\n]*\$\{\{\s*secrets\.", ln):
                self.add("SC-C05", "ci-cd", SUSPICIOUS, "high", "high", rel, i, ln, "secret printed in a run step")
            if CURL_PIPE.search(ln):
                pass  # already reported by generic check
        # script injection: untrusted contexts inside run: blocks
        in_run, run_indent = False, 0
        for i, ln in enumerate(lines, 1):
            s = ln.lstrip()
            ind = len(ln) - len(s)
            if re.match(r"-?\s*run\s*:", s):
                in_run, run_indent = True, ind
                body = s.split(":", 1)[1]
            elif in_run and s and ind <= run_indent:
                in_run = False
                body = ""
            else:
                body = ln if in_run else ""
            if body and re.search(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|head_commit|commits|discussion|pages|workflow_run)"
                                  r"[^}]*(title|body|message|name|label|ref|email|head_branch|default_branch|page_name)|github\.head_ref)[^}]*\}\}", body):
                self.add("SC-C03", "ci-cd", SUSPICIOUS, "high", "high", rel, i, ln,
                         "untrusted event data interpolated into a shell script (script injection)")

    def gitlab_ci(self, rel, text):
        self.ran("gitlab-ci")
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*image\s*:\s*['\"]?([^\s'\"]+)", ln)
            if m and "@sha256:" not in m.group(1):
                self.add("SC-D01", "containers-iac", RISKY, "medium" if (":latest" in m.group(1) or ":" not in m.group(1).split("/")[-1]) else "low",
                         "high", rel, i, ln, f"CI image {m.group(1)} not pinned by digest")
            if re.search(r"(?i)include\s*:\s*\n?\s*-?\s*remote\s*:", ln) or re.search(r"^\s*-?\s*remote\s*:\s*['\"]?https?://", ln):
                self.add("SC-I04", "ci-cd", RISKY, "high", "high", rel, i, ln, "remote CI include")
            if re.search(r"\$CI_(MERGE_REQUEST_TITLE|MERGE_REQUEST_DESCRIPTION|COMMIT_MESSAGE|COMMIT_TITLE|COMMIT_BRANCH|MERGE_REQUEST_SOURCE_BRANCH_NAME)", ln) \
                    and not re.search(r"['\"]\$CI_", ln):
                self.add("SC-C03", "ci-cd", RISKY, "medium", "medium", rel, i, ln, "user-controlled CI variable used unquoted in a script")

    # ------------------------------------------------------------------ containers / IaC
    def dockerfile(self, rel, text):
        self.ran("dockerfile")
        lines = text.splitlines()
        user_set, last_user = False, None
        stages: set[str] = set()
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            m = re.match(r"(?i)FROM\s+(--platform=\S+\s+)?(\S+)(\s+AS\s+(\S+))?", s)
            if m:
                img = m.group(2)
                if m.group(4):
                    stages.add(m.group(4).lower())
                if img.lower() != "scratch" and img.lower() not in stages and "@sha256:" not in img:
                    tagless = ":" not in img.split("/")[-1]
                    self.add("SC-D01", "containers-iac", RISKY, "medium" if (tagless or img.endswith(":latest")) else "low",
                             "high", rel, i, ln, f"base image {img} not pinned by digest")
            if re.match(r"(?i)ADD\s+(--\S+\s+)*https?://", s):
                self.add("SC-D02", "containers-iac", RISKY, "high", "high", rel, i, ln, "ADD from a remote URL (no integrity check)")
            if re.match(r"(?i)USER\s+", s):
                user_set, last_user = True, s.split(None, 1)[1].strip()
            if re.match(r"(?i)RUN\b", s) and re.search(r"(?i)\b(curl|wget)\b[^\n]*(-o|-O|>)", s):
                block = s
                j = i
                while block.endswith("\\") and j < len(lines):
                    block += lines[j]
                    j += 1
                if not re.search(r"(?i)sha256sum|sha512sum|shasum|gpg\s+--verify|cosign\s+verify|--checksum", block):
                    self.add("SC-D04", "containers-iac", RISKY, "medium", "medium", rel, i, ln, "binary downloaded without checksum/signature verification")
        if not user_set or (last_user and last_user in ("root", "0", "0:0")):
            self.add("SC-D03", "containers-iac", RISKY, "medium", "high", rel, 1 if not user_set else self.line_for(text, "USER"),
                     "", "container runs as root (no non-root USER)")

    def k8s(self, rel, text):
        self.ran("kubernetes")
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*-?\s*image\s*:\s*['\"]?([^\s'\"]+)", ln)
            if m and "@sha256:" not in m.group(1):
                img = m.group(1)
                bad = img.endswith(":latest") or ":" not in img.split("/")[-1]
                self.add("SC-D01", "containers-iac", RISKY, "medium" if bad else "low", "high", rel, i, ln, f"workload image {img} not pinned by digest")
            if re.search(r"privileged\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true|runAsUser\s*:\s*0\b|allowPrivilegeEscalation\s*:\s*true", ln):
                self.add("SC-D05", "containers-iac", RISKY, "high", "high", rel, i, ln, "privileged pod setting")

    def iac_common(self, rel, lines, provider):
        """Cloud misconfiguration patterns shared by Terraform/CloudFormation/ARM/Bicep/DM."""
        for i, ln in enumerate(lines, 1):
            if re.search(r'"Action"\s*:\s*"\*"|Action:\s*["\']?\*["\']?\s*$|actions\s*=\s*\[\s*"\*"\s*\]|"actions"\s*:\s*\[\s*"\*"', ln):
                self.add("SC-D08", "containers-iac", RISKY, "high", "medium", rel, i, ln, f"{provider}: wildcard IAM action")
            if re.search(r'(?i)acl\s*[=:]\s*["\']?public-read(-write)?|PublicRead(Write)?\b|block_public_acls\s*=\s*false|'
                         r'allowBlobPublicAccess["\']?\s*[:=]\s*true|publicNetworkAccess["\']?\s*[:=]\s*["\']?Enabled|'
                         r'"allUsers"|"allAuthenticatedUsers"|members\s*=\s*\[[^\]]*"allUsers"', ln):
                self.add("SC-D07", "containers-iac", RISKY, "high", "medium", rel, i, ln, f"{provider}: storage or service publicly accessible")
            if re.search(r'(?i)(encrypted|storage_encrypted|enable_encryption|encryption_enabled|supportsHttpsTrafficOnly|enableHttpsTrafficOnly)["\']?\s*[:=]\s*["\']?false|'
                         r'minimumTlsVersion["\']?\s*[:=]\s*["\']?TLS1_0|ssl_enforcement_enabled\s*=\s*false|require_ssl\s*=\s*false', ln):
                self.add("SC-D09", "containers-iac", RISKY, "medium", "medium", rel, i, ln, f"{provider}: encryption or TLS disabled")
            if re.search(r'(?i)source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"|sourceAddressPrefix["\']?\s*[:=]\s*["\']?(\*|Internet|0\.0\.0\.0/0)|'
                         r'CidrIp:\s*["\']?0\.0\.0\.0/0|"CidrIp"\s*:\s*"0\.0\.0\.0/0"|sourceRanges:\s*\[?\s*["\']?0\.0\.0\.0/0', ln):
                self.add("SC-D05", "containers-iac", RISKY, "medium", "medium", rel, i, ln, f"{provider}: ingress open to the internet")
            if re.search(r'(?i)(password|admin_password|administratorLoginPassword|secret|MasterUserPassword)["\']?\s*[:=]\s*["\'][^"\'$\{\[]{6,}["\']', ln):
                self.add("SC-S08", "secrets", RISKY, "high", "medium", rel, i, ln, f"{provider}: literal password/secret in IaC")

    def azure(self, rel, text):
        self.ran("azure-iac")
        self.iac_common(rel, text.splitlines(), "Azure")

    def cloudformation(self, rel, text):
        self.ran("cloudformation")
        self.iac_common(rel, text.splitlines(), "AWS CloudFormation")

    def gcp_dm(self, rel, text):
        self.ran("gcp-deployment-manager")
        self.iac_common(rel, text.splitlines(), "GCP Deployment Manager")

    def terraform(self, rel, text):
        self.ran("terraform")
        prov = "Terraform/" + ("AWS" if "aws_" in text else "Azure" if "azurerm_" in text else "GCP" if "google_" in text else "IaC")
        self.iac_common(rel, text.splitlines(), prov)
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.search(r'source\s*=\s*"(git::[^"]+|github\.com/[^"]+|https?://[^"]+)"', ln)
            if m and "?ref=" not in m.group(1):
                self.add("SC-D06", "containers-iac", RISKY, "medium", "high", rel, i, ln, "module source without a pinned ref")
            if re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"', ln):
                self.add("SC-D05", "containers-iac", RISKY, "medium", "medium", rel, i, ln, "ingress open to 0.0.0.0/0")

    # ------------------------------------------------------------------ repo-level
    def symlinks(self):
        self.ran("symlinks")
        for rel in walk_symlinks(self.root):
            self.limitations.append(f"symlink not followed: {rel}")

    def git_hooks(self, names):
        self.ran("git-hooks")
        for n in sorted(names):
            if re.match(r"^(\.husky/[^_][^/]*|\.githooks/.+|lefthook\.ya?ml|\.pre-commit-config\.ya?ml|\.git-hooks/.+)$", n):
                self.add("SC-S07", "source-indicators", RISKY if n.startswith((".husky", ".githooks", ".git-hooks")) else INFO,
                         "low" if n.startswith((".husky", ".githooks", ".git-hooks")) else "info", "high", n, 1, "",
                         "repository-managed git hook configuration")
        hooks_dir = self.root / ".git" / "hooks"
        if hooks_dir.is_dir():
            live = [p.name for p in hooks_dir.iterdir() if p.is_file() and not p.name.endswith(".sample")]
            if live:
                self.limitations.append(f"local .git/hooks contains active hooks: {', '.join(sorted(live))} (not executed; ckb clones disable hooks)")

    def history(self):
        self.ran("recent-build-ci-commits")
        if not (self.root / ".git").exists():
            self.limitations.append("not a git checkout: commit history checks skipped")
            return
        shallow = (self.root / ".git" / "shallow").exists()
        r = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(self.root), "log", "-n", "30",
                            "--format=@@%h|%cI|%s", "--name-only"], capture_output=True, text=True)
        if r.returncode != 0:
            self.limitations.append("git log unavailable")
            return
        if shallow:
            self.limitations.append("shallow clone: only the latest commit's history was available")
        commit = None
        for line in r.stdout.splitlines():
            if line.startswith("@@"):
                commit = line[2:].split("|", 2)
                continue
            if commit and re.match(r"^(\.github/workflows/|\.gitlab-ci\.yml|Jenkinsfile|Makefile|package\.json|setup\.py|"
                                   r"pyproject\.toml|build\.gradle|pom\.xml|Dockerfile|\.npmrc|\.husky/)", line):
                self.add("SC-S05", "source-indicators", INFO, "info", "low", line, 1, f"{commit[0]} {commit[2][:50]}",
                         f"recent commit {commit[0]} ({commit[1][:10]}) touched build/CI file")


SNYK_SITE_ECO = {"npm": "npm", "pypi": "pip", "go": "golang", "maven": "maven", "crates": "cargo",
                 "rubygems": "rubygems", "packagist": "composer"}
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "maven": "maven", "crates": "cargo",
             "rubygems": "gem", "packagist": "composer"}
OSV_ECO = {"npm": "npm", "pypi": "PyPI", "go": "Go", "crates": "crates.io", "maven": "Maven",
           "rubygems": "RubyGems", "packagist": "Packagist"}


def exact_version(d: dict) -> str | None:
    if not d["pinned"]:
        return None
    v = re.sub(r"^(==|=|v(?=\d))", "", d["spec"].strip().strip('"'))
    return v if re.match(r"^\d[\w.+-]*$", v) else None


def snyk_link(d: dict) -> str | None:
    """Public security.snyk.io page for the package (no network call; for humans to check)."""
    import urllib.parse
    eco = SNYK_SITE_ECO.get(d["ecosystem"])
    if not eco or d["source"] != "registry":
        return None
    url = f"https://security.snyk.io/package/{eco}/{urllib.parse.quote(d['name'], safe='@')}"
    v = exact_version(d)
    return url + (f"/{urllib.parse.quote(v)}" if v else "")


def add_advisory(d: dict, source: str, ids: list[str], url_fmt: str) -> None:
    prev = d.get("advisories", [])
    prev += [{"source": source, "id": i, "url": url_fmt.format(i)} for i in ids]
    d["advisories"] = prev
    d.setdefault("checked_by", []).append(source)


def osv_lookup(deps: list[dict]) -> str:
    import urllib.request
    queries, idx = [], []
    for i, d in enumerate(deps):
        v = exact_version(d)
        if v and d["ecosystem"] in OSV_ECO:
            queries.append({"package": {"name": d["name"], "ecosystem": OSV_ECO[d["ecosystem"]]}, "version": v})
            idx.append(i)
    if not queries:
        return "OSV: no exactly pinned dependencies to check"
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps({"queries": queries}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            results = json.loads(resp.read()).get("results", [])
    except Exception as e:  # noqa: BLE001
        return f"OSV lookup failed: {type(e).__name__}"
    for i, res in zip(idx, results):
        add_advisory(deps[i], "osv", [v["id"] for v in res.get("vulns", [])], "https://osv.dev/vulnerability/{}")
    return f"OSV: checked {len(queries)} pinned dependencies"


def snyk_lookup(deps: list[dict], token_env: str, org_env: str) -> str:
    """Snyk REST API 'list issues for a package' (needs a Snyk token and org id; opt-in)."""
    import urllib.parse
    import urllib.request
    import os
    token, org = os.environ.get(token_env), os.environ.get(org_env)
    if not token or not org:
        return f"Snyk: not checked ({token_env} and {org_env} must be set)"
    checked = failed = 0
    for d in deps:
        v = exact_version(d)
        t = PURL_TYPE.get(d["ecosystem"])
        if not v or not t or d["source"] != "registry":
            continue
        name = d["name"]
        if t == "maven" and ":" in name:
            name = name.replace(":", "/", 1)
        elif t == "npm" and name.startswith("@"):
            name = "%40" + name[1:]
        purl = f"pkg:{t}/{name}@{v}"
        url = (f"https://api.snyk.io/rest/orgs/{urllib.parse.quote(org)}/packages/{urllib.parse.quote(purl, safe='')}"
               f"/issues?version=2024-10-15&limit=100")
        req = urllib.request.Request(url, headers={"Authorization": f"token {token}",
                                                   "Accept": "application/vnd.api+json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read()).get("data", [])
        except Exception as e:  # noqa: BLE001
            failed += 1
            d.setdefault("lookup_errors", []).append(f"snyk: {type(e).__name__}")
            continue
        ids = [(it.get("attributes") or {}).get("key") or it.get("id") for it in data]
        add_advisory(d, "snyk", [i for i in ids if i], "https://security.snyk.io/vuln/{}")
        checked += 1
    return f"Snyk: checked {checked} pinned dependencies" + (f", {failed} lookups failed" if failed else "")


def finalize_advisories(deps: list[dict]) -> None:
    for d in deps:
        d["snyk_url"] = snyk_link(d)
        adv = d.get("advisories") or []
        by = d.get("checked_by") or []
        if adv:
            d["advisory"] = "vulnerable: " + ", ".join(f"{a['id']} ({a['url']})" for a in adv)
        elif by:
            d["advisory"] = "no known advisory (" + "+".join(sorted(set(by))) + ")"
        elif not d["pinned"]:
            d["advisory"] = "not checked (unpinned)"
        else:
            d["advisory"] = "not checked"


def to_markdown(rep: dict) -> str:
    out = ["| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |",
           "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for f in rep["findings"]:
        if f["severity"] == "info":
            continue
        out.append(f"| {f['id']} | {f['check']} | {f['class']} | {f['severity']} | {f['confidence']} | `{f['citation']}` | "
                   f"{f['message']}{(' — ' + chr(96) + f['excerpt'] + chr(96)) if f['excerpt'] else ''} | {f['remediation']} |")
    out += ["", "| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Snyk page | Manifest |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for d in rep["dependencies"]:
        out.append(f"| {d['ecosystem']} | {d['name']} | {safe_excerpt(d['spec'], 40)} | {'yes' if d['pinned'] else 'no'} | "
                   f"{d['source']} | {d['advisory']} | {('<' + d['snyk_url'] + '>') if d.get('snyk_url') else 'n/a'} | `{d['citation']}` |")
    info = [f for f in rep["findings"] if f["severity"] == "info"]
    if info:
        out += ["", "Informational:", ""] + [f"- {f['message']} `{f['citation']}`" for f in info]
    if rep["limitations"]:
        out += ["", "Limitations:", ""] + [f"- {safe_excerpt(x, 200)}" for x in rep["limitations"]]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--md-out")
    ap.add_argument("--osv", action="store_true", help="alias for --advisories osv")
    ap.add_argument("--advisories", default="", help="comma list: osv,snyk (opt-in; sends package names+versions off-machine)")
    ap.add_argument("--snyk-token-env", default="SNYK_TOKEN")
    ap.add_argument("--snyk-org-env", default="SNYK_ORG_ID")
    ap.add_argument("--exclude", action="append", default=[])
    a = ap.parse_args()
    s = Scanner(Path(a.root), a.key, a.exclude)
    rep = s.run()
    sources = {x.strip().lower() for x in a.advisories.split(",") if x.strip()} | ({"osv"} if a.osv else set())
    notes = []
    if "osv" in sources:
        notes.append(osv_lookup(rep["dependencies"]))
    if "snyk" in sources:
        notes.append(snyk_lookup(rep["dependencies"], a.snyk_token_env, a.snyk_org_env))
    finalize_advisories(rep["dependencies"])
    rep["advisory_lookup"] = "; ".join(notes) if notes else "not checked (advisory_lookup off)"
    js = json.dumps(rep, indent=2)
    if a.json_out:
        Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json_out).write_text(js + "\n")
    else:
        print(js)
    if a.md_out:
        Path(a.md_out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.md_out).write_text(to_markdown(rep))
    counts = {}
    for f in rep["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(json.dumps({"repo": a.key, "findings": counts, "dependencies": len(rep["dependencies"])}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
