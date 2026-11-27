#!/usr/bin/env python3
"""Deterministic draft threat model from the ckb knowledge graph (so every run, even headless/CI, gets one).

Usage:
  threat_seed.py --out OUT_DIR [--force]

Reads graph.json (+ supply-chain JSON, CSPM/IaC nodes, drift nodes) and applies fixed rules:
  injection paths (taint candidates to unsafe SQL/command/SSRF/code/deserialization sinks), endpoints with
  no authentication evidence, security switches an env var can turn off, plaintext or identity-header trust
  between services, unauthenticated message channels and requeue-forever consumers, tables written by
  several repos, outbound calls with no timeout, cloud misconfigurations (IaC + CSPM), confirmed-suspicious
  supply-chain findings, documented-vs-observed drift, and LLM integrations (OWASP LLM Top 10).

Writes
  <out>/system/threat-model.md          draft (carries <!-- ckb:threat-seed -->; never overwrites a refined
                                        file that lacks the marker unless --force)
  <out>/graph/proposals/seed-threats.jsonl   threat / trust_boundary nodes + threatens / crosses_boundary
                                        edges, extractor "rule", verified by graph_merge.py like any proposal
Every threat cites code, IaC, or scan evidence. Ratings follow skills/threat-modeling/references/rating-rubric.md.
The threat-modeler agent then confirms, refines, or removes each draft threat.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import now_iso, read_text, repo_roots_for_output  # noqa: E402
from graph_common import atomic_write, graph_dir, md_safe, safe_quote, safe_str  # noqa: E402
from graph_query import GraphStore  # noqa: E402

MARK = "<!-- ckb:threat-seed -->"
RANK = {"low": 1, "medium": 2, "high": 3}
INV = {1: "low", 2: "medium", 3: "high"}
AUTH_RX = re.compile(r"(?i)(require_?auth|requires?_?login|login_required|authenticate|authorize|authorized|jwt|bearer|oauth|\bauth\b|current_?user|get_current|"
                     r"depends\(.*(user|auth|token)|verify_?token|check_?permission|has_?role|require_?role|@secured|@preauthorize|@rolesallowed|isauthenticated|passport\.|session\.user|"
                     r"authori[sz]ation|auth\w*(middleware|guard|layer|filter|interceptor)|\[authorize|before_action\s*:\s*authenticate|authenticate_user!|->middleware\(\s*['\"](auth|can|verified)|auth:(api|sanctum)|@useguards|permission_classes|"
                     r"isauthenticated|requires_auth|verify_jwt|jwt_required|@permission_required|@loginrequired|hasauthority|hasrole|\.authorizerequests|\.authenticated\(\)|"
                     r"authority-check|check_user_roles|require_login|->under\b|\bunder\s+sub|authmiddleware|shelf_auth|authenticated\s*\(|sap_authorized|ssf_|cl_http_server=>authenticate)")
CLASS_AUTH_RX = re.compile(r"(?i)(before_action\s*:\s*authenticate|@PreAuthorize|\[Authorize[\](]|@UseGuards|->middleware\(\s*['\"]auth|permission_classes|@Secured|@RolesAllowed|authenticate_user!|\.authenticated\(\))")
ANON_RX = re.compile(r"(?i)(\[AllowAnonymous\]|skip_before_action\s*:\s*authenticate|@PermitAll|permitAll\(\)|@Public\(\)|AllowAny)")
HEALTH_RX = re.compile(r"(?i)/(health|healthz|ready|readyz|live|livez|ping|metrics|favicon|static|docs|openapi|swagger)")
SWITCH_RX = re.compile(r"(?i)((AUTH|SECURITY|VERIFY|TLS|SSL|CSRF|SIGNATURE|CERT)\w*(DISABLE|OFF|SKIP|BYPASS|INSECURE|NOVERIFY)|(DISABLE|SKIP|BYPASS|NO|INSECURE)_?(AUTH|VERIFY|TLS|SSL|CSRF|SIGNATURE|CERT)\w*|\bDEBUG\b|ALLOW_ALL|TRUST_ALL)")
IDHEADER_RX = re.compile(r"(?i)['\"`](x-(request-)?user(-id)?|x-forwarded-user|x-tenant(-id)?|x-auth-user|x-userid)['\"`]")
SIGN_RX = re.compile(r"(?i)(hmac|signature|sign\(|verify\(|jwt|checksum|schema\.validate|jsonschema|validate\()")
REQUEUE_RX = re.compile(r"(?i)(Nack\([^)]*,\s*true\)|requeue\s*[=:]\s*(true|True)|basic_nack\([^)]*requeue\s*=\s*True|\.nack\([^)]*true|reject\([^)]*true)")
DLQ_RX = re.compile(r"(?i)(dead[-_ ]?letter|\bdlq\b|x-dead-letter|deadletter)")
SECRET_ENV_BENIGN = re.compile(r"(?i)(_FILE|_PATH|_URL|_URI|_NAME|_HEADER|_ENABLED|_TTL|_EXPIRY|_ENDPOINT|_ARN|_SECRET_ID|_REF)$")
SECRET_ENV = re.compile(r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)")
CWE = {"sql": ("CWE-89", "A03:2021 Injection"), "command": ("CWE-78", "A03:2021 Injection"), "ssrf": ("CWE-918", "A10:2021 SSRF"),
       "code": ("CWE-94", "A03:2021 Injection"), "deserialization": ("CWE-502", "A08:2021 Software and Data Integrity Failures"),
       "template": ("CWE-1336", "A03:2021 Injection"), "xss": ("CWE-79", "A03:2021 Injection"), "path": ("CWE-22", "A01:2021 Broken Access Control"),
       "redirect": ("CWE-601", "A01:2021 Broken Access Control"), "nosql": ("CWE-943", "A03:2021 Injection"), "ldap": ("CWE-90", "A03:2021 Injection"),
       "xpath": ("CWE-643", "A03:2021 Injection"), "xxe": ("CWE-611", "A05:2021 Security Misconfiguration"),
       "memory": ("CWE-787", "A04:2021 Insecure Design"), "format": ("CWE-134", "A03:2021 Injection"),
       "tls": ("CWE-295", "A07:2021 Identification and Authentication Failures"), "unsafe_code": ("CWE-119", "A04:2021 Insecure Design")}
SINK_TITLE = {"sql": "SQL injection", "command": "COMMAND injection", "ssrf": "SSRF injection", "code": "CODE injection", "deserialization": "DESERIALIZATION injection",
              "template": "Template injection", "xss": "Cross-site scripting", "path": "Path traversal", "redirect": "Open redirect", "nosql": "NoSQL injection",
              "ldap": "LDAP injection", "xpath": "XPath injection", "xxe": "XML external entity processing", "memory": "Memory-unsafe operation",
              "format": "Format string", "tls": "Disabled TLS verification", "unsafe_code": "Unsafe code block"}
SINK_STRIDE = {"sql": "Tampering / Information disclosure", "deserialization": "Tampering / Information disclosure", "command": "Elevation of privilege",
               "code": "Elevation of privilege", "template": "Elevation of privilege", "xss": "Spoofing / Information disclosure", "path": "Information disclosure / Tampering",
               "redirect": "Spoofing", "nosql": "Tampering / Information disclosure", "ldap": "Tampering / Information disclosure", "xpath": "Information disclosure",
               "xxe": "Information disclosure", "ssrf": "Information disclosure", "memory": "Elevation of privilege", "format": "Information disclosure",
               "tls": "Spoofing / Information disclosure", "unsafe_code": "Elevation of privilege"}
SINK_CONTROL = {"sql": "Use parameterized queries / ORM bindings; validate id formats.", "command": "Avoid shells; pass argument arrays; allowlist inputs.",
                "ssrf": "Allowlist destination hosts; block link-local/metadata addresses; do not take URLs from requests.",
                "code": "Remove eval/exec on inputs; use safe parsers.", "deserialization": "Use safe formats (JSON) and type allowlists.",
                "template": "Never build templates from user input; pass data as template variables.", "xss": "Encode output for its context; avoid raw HTML sinks; set a CSP.",
                "path": "Resolve and check the final path stays under an allowed base directory; use generated file ids, not client paths.",
                "redirect": "Redirect only to allowlisted or relative targets.", "nosql": "Validate operator-free input types; use typed query builders.",
                "ldap": "Escape filter and DN values or use parameterized LDAP APIs.", "xpath": "Use parameterized XPath or escape values.",
                "xxe": "Disable DTDs and external entities in the parser.", "memory": "Use bounded APIs (snprintf, strncpy, std::string) and validate lengths.",
                "format": "Pass untrusted data as an argument, never as the format string.", "tls": "Keep certificate and hostname verification on.",
                "unsafe_code": "Keep unsafe blocks minimal, audited and covered by tests."}
CLOUD_CHECK = {"SC-D07": ("CWE-284", "Information disclosure", "Public cloud storage or service", "Block public access; require authenticated access",
                          "A01:2021 Broken Access Control", "high", "high"),
               "SC-D08": ("CWE-269", "Elevation of privilege", "Wildcard IAM permissions", "Replace wildcard actions with least-privilege, resource-scoped permissions",
                          "A01:2021 Broken Access Control", "medium", "high"),
               "SC-D09": ("CWE-311", "Information disclosure", "Encryption or TLS disabled", "Enable encryption at rest and require TLS 1.2+",
                          "A02:2021 Cryptographic Failures", "medium", "medium"),
               "SC-D05": ("CWE-284", "Elevation of privilege", "Ingress open to the internet", "Restrict ingress to required sources; put services behind a gateway/WAF",
                          "A05:2021 Security Misconfiguration", "high", "medium")}
SC_CWE = {"install-time": ("CWE-829", "Install-time code execution from a dependency or script"), "ci-cd": ("CWE-829", "Untrusted input or code reaches a privileged CI/CD job"),
          "source-indicators": ("CWE-506", "Embedded malicious or obfuscated code"), "prompt-injection": ("CWE-1427", "Text aimed at AI agents (prompt injection)"),
          "secrets": ("CWE-798", "Hardcoded credential"), "manifests": ("CWE-1357", "Risky dependency source"), "containers-iac": ("CWE-250", "Insecure container/IaC configuration")}


def prio(l: str, i: str) -> str:
    a, b = RANK[l], RANK[i]
    if a == 3 and b == 3:
        return "critical"
    if a <= 1 and b <= 1:
        return "low"
    return INV[max(a, b)]


class Ctx:
    def __init__(self, out: Path):
        self.out = out
        self.store = GraphStore(out)
        self.g = self.store
        self.roots = {k: v for k, v in repo_roots_for_output(out).items()}
        self.cache = {}
        self.nodes = self.store.nodes
        self.in_http = defaultdict(list)
        for e in self.store.edges:
            if e["kind"] in ("http_calls", "grpc_calls"):
                self.in_http[e["dst"]].append(e)
        self.handler = {}
        for e in self.store.edges:
            if e["kind"] == "routes_to":
                self.handler.setdefault(e["src"], []).append(e["dst"])
        self.deploy, self.deploy_all = {}, {}  # app repo -> workloads that run it; deploy repo -> its facts
        for p in sorted((out / "evidence").glob("deploy-facts-*.json")):
            try:
                d = json.loads(p.read_text())
            except (ValueError, OSError):
                EVIDENCE_PROBLEMS.append(p.name)
                continue
            self.deploy_all[d["repo"]] = d
            for w in d.get("workloads", []):
                if w.get("app_repo"):
                    self.deploy.setdefault(w["app_repo"], []).append({**w, "deploy_repo": d["repo"]})

    def lines(self, repo: str, path: str):
        key = (repo, path)
        if key not in self.cache:
            root = self.roots.get(repo)
            t = read_text(root / path) if root and path else None
            self.cache[key] = t.splitlines() if t else []
        return self.cache[key]

    def line(self, citation: str):
        m = re.match(r"^([^/]+)/(.+):(\d+)(?:-\d+)?$", citation or "")
        if not m:
            return None
        ls = self.lines(m.group(1), m.group(2))
        i = int(m.group(3))
        for j in range(i - 1, min(len(ls), i + 2)):
            if 0 <= j < len(ls) and ls[j].strip():
                return ls[j].strip()
        return None

    def window(self, citation: str, before=2, after=4) -> str:
        m = re.match(r"^([^/]+)/(.+):(\d+)", citation or "")
        if not m:
            return ""
        ls = self.lines(m.group(1), m.group(2))
        i = int(m.group(3))
        return "\n".join(ls[max(0, i - 1 - before): i + after])

    def file_text(self, repo: str, path: str) -> str:
        return "\n".join(self.lines(repo, path))

    def repo_of_entry(self, node_id: str) -> str:
        n = self.nodes.get(node_id, {})
        return n.get("repo") if n.get("repo") not in (None, "_system", "") else (n.get("citation", "").split("/", 1)[0])

    def external_auth(self, endpoint_id: str):
        """An authentication control outside the code (gateway/ingress auth, mesh policy, API gateway authorizer) in front of the workload that runs this endpoint."""
        for w in self.deploy.get(self.repo_of_entry(endpoint_id), []):
            for ctl in w.get("external_controls", []):
                if ctl["kind"] in ("gateway-auth", "mesh-auth", "jwt-auth", "mtls"):
                    return {**ctl, "workload": w["name"]}
        return None

    def exposure(self, endpoint_id: str) -> tuple[str, str]:
        ws_all = self.deploy.get(self.repo_of_entry(endpoint_id), [])
        ws = [w for w in ws_all if w.get("source") != "dockerfile"] or ws_all  # a Dockerfile only declares ports; Services/Ingresses decide exposure
        pub = [w for w in ws if (w.get("exposure") or {}).get("public")]
        if pub:
            ex = pub[0]["exposure"]
            via = ("ingress " + ", ".join(ex.get("hosts", [])[:2])) if ex.get("hosts") else ex.get("kind", "public")
            return "public", f"deployed as {pub[0]['name']} ({via}; {ex.get('citation') or pub[0]['citation']})"
        if ws and all((w.get("exposure") or {}).get("kind") in ("cluster-internal", "none", "container-ports") for w in ws) and any(w.get("deploy_repo") == self.repo_of_entry(endpoint_id) or w.get("resolved_by") in ("image", "build context", "chart") for w in ws):
            return "internal", f"deployed as {ws[0]['name']} with no public Service/Ingress ({ws[0]['citation']})"
        callers = [e for e in self.in_http.get(endpoint_id, []) if self.nodes.get(e["src"], {}).get("repo") != self.nodes[endpoint_id].get("repo")]
        if callers:
            names = sorted({self.nodes[e["src"]]["repo"] for e in callers if e["src"] in self.nodes})
            return "internal", f"called by {', '.join(names)}"
        return "public-candidate", "no other service calls it (may be internet-facing)"

    def fn_of(self, node_id: str):
        return node_id


def add(threats, **t):
    t.setdefault("mitigations", [])
    t.setdefault("gaps", "")
    t.setdefault("label", "inferred")
    t.setdefault("confidence", "medium")
    t["priority"] = prio(t["likelihood"], t["impact"])
    threats.append(t)


# ---------------------------------------------------------------- rules

def rule_taint(c: Ctx, threats):
    safe_by = defaultdict(list)
    for n in c.nodes.values():
        if n["kind"] == "sink" and (n.get("attrs") or {}).get("safe"):
            safe_by[((n.get("attrs") or {}).get("sink_type"), n["repo"])].append(n)
    seen = set()
    for p in c.store.taint(max_depth=10, limit=60)["paths"]:
        sink = c.nodes[p["sink"]["id"]]
        stype = p["sink_type"]
        key = (p["source"]["id"], sink["id"])
        if key in seen or stype not in CWE:
            continue
        seen.add(key)
        src = c.nodes[p["source"]["id"]]
        if src["kind"] == "endpoint":
            exp, why = c.exposure(src["id"])
        elif src["kind"] in ("agent", "command"):
            exp, why = "internal", "LLM-directed agent: its input and tool arguments can be shaped by untrusted text"
        elif src["kind"] == "consumer":
            exp, why = "internal", "message consumer"
        elif src["kind"] in ("cli_command", "cron_job"):
            exp, why = "internal", "local command or scheduled job"
        else:
            exp, why = "internal", "input read inside a handler"
        lik = "high" if exp in ("public-candidate", "public") and p["label"] == "observed-path" else "medium"
        safe = safe_by.get((stype, sink["repo"]), [])
        hop_cites = [h["citation"] for h in p["hops"]][:6]
        add(threats, component=f"{src['name']} → {sink['name']}", stride=SINK_STRIDE.get(stype, "Information disclosure"),
            title=f"{SINK_TITLE.get(stype, stype)} path from {src['name']} to an unsafe sink",
            cwe=CWE[stype][0], owasp=CWE[stype][1] + ("; OWASP LLM Top 10: LLM05 improper output handling, LLM06 excessive agency" if src["kind"] in ("agent", "command") else ""), likelihood=lik, impact="high",
            evidence=[sink["citation"]] + hop_cites[:2], primary=sink["citation"], target=sink["id"],
            mitigations=[f"A safe pattern exists elsewhere in {sink['repo']}: `{s['citation']}` ({(s.get('attrs') or {}).get('reason')})" for s in safe[:1]],
            gaps=f"{(sink.get('attrs') or {}).get('reason', 'unsafe construction')}; endpoint exposure: {exp} ({why}). Taint is a candidate path: confirm the input reaches the sink.",
            control=SINK_CONTROL[stype],
            label="observed" if p["label"] == "observed-path" else "inferred", confidence="high" if p["label"] == "observed-path" else "medium")


ROUTE_DECL_RX = re.compile(r"(?i)Route::|^\s*@\w*(Get|Post|Put|Delete|Patch|Request)Mapping|^\s*\[Http(Get|Post|Put|Delete|Patch)|\b(app|router)\.(get|post|put|patch|delete|all)\(|^\s*(get|post|put|patch|delete)\s+['\"]|^\s*@(app|router|bp|blueprint)\.|^\s*resources?\s+:")


def route_window(c: Ctx, citation: str) -> str:
    """The route declaration plus its own decorators/chain, without the neighbouring routes' middleware."""
    m = re.match(r"^([^/]+)/(.+):(\d+)", citation or "")
    if not m:
        return ""
    ls = c.lines(m.group(1), m.group(2))
    i = int(m.group(3)) - 1
    if not 0 <= i < len(ls):
        return ""
    before = []
    for j in range(i - 1, max(-1, i - 3), -1):
        if ls[j].rstrip().endswith((";", "}")) or ROUTE_DECL_RX.search(ls[j]) and ls[j].lstrip().startswith(("Route::", "get ", "post ")):
            break
        before.append(ls[j])
    after = []
    for j in range(i + 1, min(len(ls), i + 4)):
        if ROUTE_DECL_RX.search(ls[j]) and not ls[j].lstrip().startswith(("@PreAuthorize", "@Secured")):
            break
        after.append(ls[j])
    return "\n".join(list(reversed(before)) + [ls[i]] + after)


def has_auth_evidence(c: Ctx, ep: dict) -> bool:
    """True if the route line, handler signature, or handler's callees show authentication/authorization."""
    hs = c.handler.get(ep["id"], [])
    chain = ""
    window = route_window(c, ep["citation"])
    for h in hs:
        hn = c.nodes.get(h, {})
        window += "\n" + c.window(f"{hn.get('repo')}/{hn.get('path')}:{hn.get('range', {}).get('start', 1)}", 1, 3)
        for e in c.store.out_adj.get(h, []):
            if e["kind"] == "calls":
                chain += " " + c.nodes.get(e["dst"], {}).get("name", "")
    if ANON_RX.search(window):
        return False
    if AUTH_RX.search(window) or AUTH_RX.search(chain):
        return True
    for h in hs:  # class-level annotation / controller filter: everything before the first function of the handler's file
        hn = c.nodes.get(h, {})
        key = ("first-fn", hn.get("repo"), hn.get("path"))
        if key not in c.cache:
            starts = [x["range"]["start"] for x in c.nodes.values() if x["kind"] in ("function", "method") and x.get("repo") == hn.get("repo")
                      and x.get("path") == hn.get("path") and not (x.get("attrs") or {}).get("inline_handler")]
            c.cache[key] = min(starts) if starts else 1
        head = "\n".join(c.lines(hn.get("repo", ""), hn.get("path", ""))[: max(0, c.cache[key] - 1)])
        if CLASS_AUTH_RX.search(head) and not ANON_RX.search(head):
            return True
    return False


def rule_auth(c: Ctx, threats):
    n_added = 0
    for ep in sorted((n for n in c.nodes.values() if n["kind"] == "endpoint"), key=lambda n: n["citation"]):
        if HEALTH_RX.search(ep.get("attrs", {}).get("path", "")) or ep.get("attrs", {}).get("protocol") in ("ui", "signal"):
            continue  # app screens and signal handlers are not network entry points
        hs = c.handler.get(ep["id"], [])
        if has_auth_evidence(c, ep):
            continue
        if n_added >= 25:
            break
        exp, why = c.exposure(ep["id"])
        ext = c.external_auth(ep["id"])
        if ext:
            add(threats, component=ep["name"], stride="Spoofing / Elevation of privilege", title=f"Authentication for {ep['name']} lives outside the application code ({ext['kind']})",
                cwe="CWE-306", owasp="A07:2021 Identification and Authentication Failures", likelihood="low", impact="medium", evidence=[ep["citation"], ext["citation"]], primary=ep["citation"],
                target=hs[0] if hs else ep["id"], mitigations=[f"{ext['kind']} on workload {ext['workload']}: {ext['detail']} ({ext['citation']})"],
                gaps="No authentication was found in the code. An external control provides it at the edge; confirm it covers this route, that internal callers cannot bypass it, and that the service rejects requests that did not pass through it.",
                control="Defence in depth: verify the identity assertion in the service as well (signed token), and block direct access to the workload.", label="inferred", confidence="medium")
            n_added += 1
            continue
        reaches_sink = any(e["kind"] == "reaches_sink" for h in hs for e in c.store.out_adj.get(h, []))
        add(threats, component=ep["name"], stride="Spoofing / Elevation of privilege", title=f"No authentication evidence on {ep['name']}",
            cwe="CWE-306", owasp="A07:2021 Identification and Authentication Failures", likelihood="high" if exp in ("public-candidate", "public") else "medium",
            impact="high" if reaches_sink else "medium", evidence=[ep["citation"]], primary=ep["citation"], target=hs[0] if hs else ep["id"],
            gaps=f"No auth middleware, decorator, or role check found on the route or its handler chain (exposure: {exp}: {why}). Global middleware or gateway-level auth would not be seen here.",
            control="Authenticate and authorize in the service itself (do not rely on network position); deny by default.", confidence="medium")
        n_added += 1


def rule_switches(c: Ctx, threats):
    for n in sorted((n for n in c.nodes.values() if n["kind"] == "env_var"), key=lambda n: n["citation"]):
        if not SWITCH_RX.search(n["name"]):
            continue
        line = c.line(n["citation"]) or ""
        users = [e["src"] for e in c.store.in_adj.get(n["id"], []) if e["kind"] == "reads_env"]
        dep = [e for e in c.store.out_adj.get(n["id"], []) if e["kind"] == "configured_by"]
        dval = next(((e.get("attrs") or {}).get("value"), e["citation"]) for e in dep[:1]) if dep and (dep[0].get("attrs") or {}).get("value") is not None else None
        on = bool(dval and str(dval[0]).strip().lower() in ("true", "1", "yes", "on") and re.search(r"(?i)DISABLE|SKIP|BYPASS|INSECURE|DEBUG|NO_|ALLOW_ALL|TRUST_ALL", n["name"]))
        add(threats, component=f"{n['repo']} env {n['name']}", stride="Elevation of privilege",
            title=f"Security control is switched off in deployment by {n['name']}={dval[0]}" if on else f"Security control can be switched off by environment variable {n['name']}",
            cwe="CWE-1188", owasp="A05:2021 Security Misconfiguration", likelihood="high" if on else "medium", impact="high", evidence=[n["citation"]] + ([dval[1]] if dval else []), primary=n["citation"],
            target=users[0] if users else None,
            gaps=(f"`{safe_str(line, 120)}` toggles a protection. Deployed value: `{dval[0]}` ({dval[1]})." if dval else f"`{safe_str(line, 120)}` toggles a protection; a mis-set variable in any environment disables it. Default: see the cited line."),
            control="Remove the bypass from production builds, or fail closed and alert when it is set outside local development.", label="observed", confidence="high")


def rule_deploy(c: Ctx, threats):
    """Threats from deployment facts: secrets in env, elevated privileges, missing network policy, public workloads without any authentication
    control, plain-HTTP listeners."""
    for drepo, d in sorted(c.deploy_all.items()):
        has_np = any(x["kind"] == "network-policy" for x in d.get("controls", []))
        for w in d.get("workloads", []):
            cite = w["citation"]
            secrets = [e for e in w.get("env", []) if SECRET_ENV.search(e["name"]) and not SECRET_ENV_BENIGN.search(e["name"]) and e["source"] == "literal"]
            if secrets:
                add(threats, component=f"{drepo} workload {w['name']}", stride="Information disclosure", title=f"Secret-like variable set as a literal in deployment config ({w['name']}: {', '.join(e['name'] for e in secrets[:3])})",
                    cwe="CWE-798", owasp="A07:2021 Identification and Authentication Failures", likelihood="high", impact="high", evidence=[cite], primary=cite, target=None,
                    gaps="The value is committed with the deployment definition (visible to anyone who can read the repo or the cluster spec).", control="Inject from a secret store (secretKeyRef, Key Vault, Secrets Manager) and rotate the value.", label="observed", confidence="high")
            sec = w.get("security") or {}
            flags = [k for k in ("privileged", "host_network", "host_path", "run_as_root") if sec.get(k)]
            if flags:
                add(threats, component=f"{drepo} workload {w['name']}", stride="Elevation of privilege", title=f"Workload {w['name']} runs with elevated privileges ({', '.join(flags)})",
                    cwe="CWE-250", owasp="A05:2021 Security Misconfiguration", likelihood="medium", impact="high", evidence=[cite], primary=cite, target=None,
                    gaps="A compromise of the container gives the attacker the node or root inside the container.", control="Drop privileges, run as non-root, avoid host namespaces and hostPath mounts.", label="observed", confidence="high")
            if w["source"] == "kubernetes" and not has_np and not w.get("network_policy") and w["kind"] in ("Deployment", "StatefulSet", "DaemonSet"):
                add(threats, component=f"{drepo} workload {w['name']}", stride="Lateral movement / Information disclosure", title=f"No NetworkPolicy restricts traffic to or from {w['name']}",
                    cwe="CWE-284", owasp="A05:2021 Security Misconfiguration", likelihood="medium", impact="medium", evidence=[cite], primary=cite, target=None,
                    gaps="No NetworkPolicy was found in this repo; the cluster may apply a default-deny elsewhere.", control="Add default-deny ingress/egress and allow only the required peers.", confidence="low")
            app = w.get("app_repo")
            ex = w.get("exposure") or {}
            if app and ex.get("public") and not w.get("external_controls") and any(n["kind"] == "endpoint" and c.repo_of_entry(n["id"]) == app and not has_auth_evidence(c, n) and not HEALTH_RX.search((n.get("attrs") or {}).get("path", ""))
                                                                                  for n in c.nodes.values()):
                add(threats, component=f"{app} (deployed as {w['name']})", stride="Spoofing / Elevation of privilege", title=f"Publicly exposed workload {w['name']} has no authentication control in code or in front of it",
                    cwe="CWE-306", owasp="A07:2021 Identification and Authentication Failures", likelihood="high", impact="high", evidence=[ex.get("citation") or cite, cite], primary=ex.get("citation") or cite, target=None,
                    gaps=f"Exposure: {ex.get('kind')} ({', '.join(ex.get('hosts', [])[:2]) or ex.get('service_type') or 'public'}). No gateway authorizer, ingress auth, mesh policy or in-code check was found for its endpoints.",
                    control="Put authentication at the edge (gateway/ingress/mesh) and in the service; deny by default.", label="inferred", confidence="medium")
        for ctl in d.get("controls", []):
            if ctl["kind"] == "listener" and ctl.get("insecure"):
                add(threats, component=f"{drepo} listener {ctl['scope']}", stride="Information disclosure / Tampering", title=f"HTTP listener without a redirect to HTTPS ({ctl['scope']})",
                    cwe="CWE-319", owasp="A02:2021 Cryptographic Failures", likelihood="medium", impact="medium", evidence=[ctl["citation"]], primary=ctl["citation"], target=None,
                    gaps="Plain HTTP is accepted at the load balancer.", control="Redirect HTTP to HTTPS or remove the listener.", label="observed", confidence="high")
            if ctl["kind"] == "gateway-no-auth":
                add(threats, component=f"{drepo} API gateway route {ctl['scope']}", stride="Spoofing", title=f"API Gateway route {ctl['scope']} has no authorizer",
                    cwe="CWE-306", owasp="A07:2021 Identification and Authentication Failures", likelihood="high", impact="medium", evidence=[ctl["citation"]], primary=ctl["citation"], target=None,
                    gaps="Authorization is NONE for this method/route.", control="Attach an authorizer (IAM, Cognito, JWT, Lambda).", label="observed", confidence="high")


EVIDENCE_PROBLEMS: list[str] = []


def _evidence_json(c: Ctx, pattern: str):
    for p in sorted((c.out / "evidence").glob(pattern)):
        try:
            yield json.loads(p.read_text())
        except (ValueError, OSError):
            EVIDENCE_PROBLEMS.append(p.name)  # reported in the threat model so a missing threat is never mistaken for a clean result


def rule_agents(c: Ctx, threats):
    """OWASP LLM Top 10 threats grounded in the agent graph: excessive agency, tools no hook guards, broken control chains."""
    hooks = [n for n in c.nodes.values() if n["kind"] == "hook"]
    covered = set()
    for h in hooks:
        m_ = ((h.get("attrs") or {}).get("matcher") or "*").strip()
        for tool in re.split(r"[|,]", m_):
            tool = tool.strip()
            covered.add("*" if tool in ("", "*", ".*") else tool)
    covered_all = "*" in covered
    for d in _evidence_json(c, "agent-graph-*.json"):
        for f in d.get("risk_flags", []):
            if f["reads_untrusted"]:
                add(threats, component=f"{d['repo']} {f['kind']} {f['node']}", stride="Elevation of privilege / Tampering", title=f"{f['kind'].capitalize()} {f['node']} can read untrusted content and also use {', '.join(f['risky_tools'])}",
                    cwe="CWE-1427", owasp="OWASP LLM Top 10: LLM01 prompt injection, LLM06 excessive agency", likelihood="medium", impact="high", evidence=[f["citation"]], primary=f["citation"], target=None,
                    gaps="Text it reads (repo files, web pages, tool output) can carry instructions; with write, shell or network tools those instructions become actions.",
                    control="Give reading agents no write/shell/network tools; split them from the agent that acts, and require approval for destructive actions.", label="inferred", confidence="medium")
            unguarded = [t for t in f["risky_tools"] if not covered_all and t not in covered and not any(t in x for x in covered)]
            if unguarded and hooks:
                add(threats, component=f"{d['repo']} {f['kind']} {f['node']}", stride="Elevation of privilege", title=f"Tool(s) {', '.join(unguarded)} used by {f['node']} are not covered by any hook",
                    cwe="CWE-693", owasp="OWASP LLM Top 10: LLM06 excessive agency", likelihood="medium", impact="medium", evidence=[f["citation"]], primary=f["citation"], target=None,
                    gaps=f"Hooks guard: {', '.join(sorted(x for x in covered if x)) or 'nothing'}.", control="Add a PreToolUse hook for these tools or remove them from the agent.", label="inferred", confidence="medium")
        for dg in d.get("dangling", [])[:5]:
            add(threats, component=f"{d['repo']} control chain", stride="Repudiation / false assurance", title=f"Reference to a missing agent, skill or command: {dg['ref']}",
                cwe="CWE-1059", owasp="OWASP LLM Top 10: LLM06 excessive agency", likelihood="low", impact="low", evidence=[dg["citation"]], primary=dg["citation"], target=None,
                gaps="A step that should dispatch another agent or skill points at a name that does not exist, so that control silently does not run.", control="Fix the name or remove the step.", label="observed", confidence="high")


def rule_library(c: Ctx, threats):
    """Dependencies with advisories or risky sources, rated by whether the code actually calls them (calls_lib edges)."""
    called = defaultdict(list)
    for e in c.store.edges:
        if e["kind"] == "calls_lib" and e["dst"] in c.nodes:
            called[(c.nodes[e["dst"]].get("repo"), re.sub(r"[-_.]+", "-", c.nodes[e["dst"]]["name"].lower()))].append(e)
    for d in _evidence_json(c, "sc-*.json"):
        repo = d.get("repo")
        for dep in d.get("dependencies", []):
            adv = dep.get("advisories") or []
            if not adv:
                continue
            nm = re.sub(r"[-_.]+", "-", str(dep.get("name", "")).lower())
            hits = called.get((repo, nm)) or called.get((repo, nm.split("/")[-1])) or called.get((repo, nm.replace("-", "_"))) or []
            ids = ", ".join(a if isinstance(a, str) else str(a.get("id", "")) for a in adv[:3])
            apis = sorted({x for e in hits for x in (e.get("attrs") or {}).get("apis", [])})[:5]
            cite = (hits[0]["citation"] if hits else f"{repo}/{dep.get('path', dep.get('manifest', ''))}:{dep.get('line', 1)}")
            add(threats, component=f"{repo} dependency {dep.get('name')}", stride="Tampering / Elevation of privilege",
                title=(f"Vulnerable dependency {dep.get('name')} is called by the code ({', '.join(apis) or 'API not resolved'})" if hits else f"Vulnerable dependency {dep.get('name')} is declared but no call into it was resolved"),
                cwe="CWE-1395", owasp="A06:2021 Vulnerable and Outdated Components", likelihood="high" if hits else "low", impact="high" if hits else "medium", evidence=[cite], primary=cite, target=None,
                gaps=f"Advisories: {ids}. " + ("The code calls it, so the advisory is reachable until shown otherwise." if hits else "No call was resolved: it may be used only by tests, transitively, or through dynamic loading (see the coverage report)."),
                control="Upgrade to a fixed version; if the vulnerable API is unused, record that decision.", label="observed" if hits else "inferred", confidence="medium")


def rule_coverage(c: Ctx, threats):
    """What static analysis could not see: dynamic-dispatch hotspots and unsafe sinks no entry point reaches are listed as unknown risk, never silence."""
    cov = next(_evidence_json(c, "coverage.json"), None)
    if not cov:
        return
    hot = [(repo, h) for repo, v in cov["repos"].items() for h in v.get("dynamic_hotspots", [])][:5]
    for repo, h in hot:
        add(threats, component=f"{repo} dynamic dispatch", stride="Tampering", title=f"Dynamic dispatch at {h['citation'].split('/', 1)[1]} ({h['what']}) is invisible to the call graph",
            cwe="CWE-470", owasp="A03:2021 Injection", likelihood="low", impact="medium", evidence=[h["citation"]], primary=h["citation"], target=None,
            gaps="A path that goes through reflection, eval or a dynamic lookup cannot be followed statically; review whether attacker-influenced data picks the target.",
            control="Replace dynamic lookup with an allowlist of targets; validate names against it.", label="inferred", confidence="low")
    for repo, v in cov["repos"].items():
        for s_ in v.get("dormant_sinks", [])[:3]:
            add(threats, component=f"{repo} {s_['name']}", stride="Information disclosure / Tampering", title=f"Unsafe sink not reached by any entry point (dormant): {s_['name']}",
                cwe="CWE-1164", owasp="A04:2021 Insecure Design", likelihood="low", impact="medium", evidence=[s_["citation"]], primary=s_["citation"], target=None,
                gaps="No entry point reaches it statically; it becomes live if a caller is added or reached dynamically.", control="Remove dead code or fix the sink before it is wired up.", label="inferred", confidence="low")


def attack_paths(c: Ctx, limit: int = 12):
    """Entry point -> ... -> sink paths over every edge kind (calls, class/object calls, references, library, agents, FFI, HTTP, queues, spawns),
    ranked by exposure, controls, confidence and the coverage of the repos crossed."""
    cov = next(_evidence_json(c, "coverage.json"), {"repos": {}})
    rows = []
    for p in c.store.taint(max_depth=14, limit=400)["paths"]:
        src, sink = c.nodes[p["source"]["id"]], c.nodes[p["sink"]["id"]]
        if p["sink_type"] not in CWE:
            continue
        if src["kind"] == "endpoint":
            exp, _ = c.exposure(src["id"])
            ext = c.external_auth(src["id"])
        else:
            exp, ext = "internal", None
        base = {"public": 3, "public-candidate": 2, "internal": 1}.get(exp, 1)
        score = base * 2 - (1 if ext else 0) + (2 if p["label"] == "observed-path" else 1) + (1 if p["sink_type"] in ("sql", "command", "code", "deserialization") else 0)
        names = [c.nodes.get(p["source"]["id"], {}).get("name", "?")] + [c.nodes[h["dst"]]["name"] if h["dst"] in c.nodes else h["dst"] for h in p["hops"]]
        repos = []
        for h in p["hops"]:
            r_ = c.nodes.get(h["dst"], {}).get("repo")
            if r_ and r_ not in repos and r_ != "_system":
                repos.append(r_)
        cov_pct = min([(cov["repos"].get(r_, {}).get("call_resolution") or {}).get("resolved_pct") if (cov["repos"].get(r_, {}).get("call_resolution") or {}).get("resolved_pct") is not None else 100 for r_ in (repos or [src.get("repo")])] or [100])
        rows.append({"score": score, "entry": src["name"], "kind": src["kind"], "exposure": exp, "control": f"{ext['kind']}" if ext else "-", "hops": " → ".join(f"{n}" for n in names[:7]) + (" → …" if len(names) > 7 else ""),
                     "via": ", ".join(sorted({h["kind"] for h in p["hops"]})), "sink": f"{p['sink_type']} ({CWE[p['sink_type']][0]})", "confidence": p["label"], "repos": ", ".join(repos) or src.get("repo", ""),
                     "coverage": cov_pct, "citation": sink["citation"]})
    rows.sort(key=lambda r: -r["score"])
    return rows[:limit]


def rule_trust(c: Ctx, threats):
    done = set()
    for e in c.store.edges:
        if e["kind"] != "http_calls" or not e.get("dst_citation"):
            continue
        s, d = c.nodes.get(e["src"]), c.nodes.get(e["dst"])
        if not s or not d or s["repo"] == d["repo"]:
            continue
        win = c.window(e["citation"], 3, 6)
        sfile = c.file_text(s["repo"], s["path"])
        if IDHEADER_RX.search(win) and (s["repo"], d["repo"], "hdr") not in done:
            done.add((s["repo"], d["repo"], "hdr"))
            m = IDHEADER_RX.search(win)
            add(threats, component=f"{s['repo']} → {d['repo']} ({d['name']})", stride="Spoofing", title=f"{d['repo']} may trust a caller-supplied identity header ({m.group(1)})",
                cwe="CWE-290", owasp="A07:2021 Identification and Authentication Failures", likelihood="medium", impact="high", evidence=[e["citation"], e["dst_citation"]],
                primary=e["citation"], target=e["src"],
                gaps="The caller sets an identity header; unless the callee authenticates the caller (mTLS/signed token) and strips client-supplied copies at the edge, any in-network caller can impersonate a user.",
                control="Propagate a signed identity token (JWT/mTLS) and verify it in the callee; never trust plain headers.", confidence="medium")
        pm = re.search(r"['\"`](http://(?!localhost|127\.0\.0\.1)[A-Za-z0-9_.-]+(:\d+)?)", sfile)
        if pm and (s["repo"], d["repo"], "plain") not in done:
            ln = next((i for i, x in enumerate(c.lines(s["repo"], s["path"]), 1) if pm.group(1) in x), None)
            if ln:
                done.add((s["repo"], d["repo"], "plain"))
                cite = f"{s['repo']}/{s['path']}:{ln}"
                add(threats, component=f"{s['repo']} → {d['repo']} (service-to-service HTTP)", stride="Information disclosure / Tampering", title=f"Plain HTTP between {s['repo']} and {d['repo']}",
                    cwe="CWE-319", owasp="A02:2021 Cryptographic Failures", likelihood="medium", impact="medium", evidence=[cite, e["citation"]], primary=cite, target=e["src"],
                    gaps=f"The default destination is `{pm.group(1)}` (no TLS). Deployment config may override it; none was found in scope.",
                    control="Use TLS (ideally mTLS via a service mesh) for service-to-service traffic.", label="observed", confidence="medium")


def rule_messaging(c: Ctx, threats):
    topics = [n for n in c.nodes.values() if n["kind"] == "topic"]
    for t in sorted(topics, key=lambda n: n["name"]):
        prods = [e for e in c.store.in_adj.get(t["id"], []) if e["kind"] == "publishes"]
        cons = [e for e in c.store.in_adj.get(t["id"], []) if e["kind"] == "consumes"]
        if not prods or not cons:
            continue
        pw = c.window(prods[0]["citation"], 8, 3)
        cw = c.window(cons[0]["citation"], 3, 25)
        if not SIGN_RX.search(pw) and not SIGN_RX.search(cw):
            fn_c = cons[0]["src"]
            add(threats, component=f"topic {t['name']}", stride="Tampering / Spoofing", title=f"No integrity or authenticity check on messages from topic {t['name']}",
                cwe="CWE-345", owasp="A08:2021 Software and Data Integrity Failures", likelihood="medium", impact="high", evidence=[prods[0]["citation"], cons[0]["citation"]],
                primary=cons[0]["citation"], target=fn_c,
                gaps="Neither side signs or validates payloads against a schema; anyone who can publish to the broker can trigger consumer actions.",
                control="Authenticate producers at the broker, sign or validate messages, and restrict publish permissions per service.", confidence="medium")
        for cn in cons:
            fnode = c.nodes.get(cn["src"], {})
            text = c.file_text(fnode.get("repo", ""), fnode.get("path", ""))
            rm = REQUEUE_RX.search(text)
            if rm:
                ln = next((i for i, x in enumerate(c.lines(fnode["repo"], fnode["path"]), 1) if REQUEUE_RX.search(x)), None)
                repo_has_dlq = any(DLQ_RX.search(c.file_text(fnode["repo"], n["path"])) for n in c.nodes.values()
                                   if n["kind"] == "file" and n.get("repo") == fnode["repo"] and n.get("path"))
                if ln:
                    cite = f"{fnode['repo']}/{fnode['path']}:{ln}"
                    add(threats, component=f"consumer of {t['name']}", stride="Denial of service", title=f"Failed messages are requeued without a dead-letter path ({t['name']})",
                        cwe="CWE-400", owasp="A04:2021 Insecure Design", likelihood="medium", impact="medium", evidence=[cite], primary=cite, target=cn["src"],
                        mitigations=[f"A dead-letter reference exists in {fnode['repo']}"] if repo_has_dlq else [],
                        gaps="A poison message is retried forever and may repeat side effects (duplicates)." + ("" if repo_has_dlq else " No dead-letter configuration found."),
                        control="Add a retry limit and dead-letter queue; make handlers idempotent.", label="observed", confidence="high")
                    break
    tables = [n for n in c.nodes.values() if n["kind"] == "table"]
    for t in sorted(tables, key=lambda n: n["name"]):
        ws = [e for e in c.store.in_adj.get(t["id"], []) if e["kind"] == "writes"]
        repos = sorted({c.nodes[e["src"]]["repo"] for e in ws if e["src"] in c.nodes})
        if len(repos) >= 2:
            add(threats, component=f"table {t['name']}", stride="Tampering", title=f"Table {t['name']} is written by several services ({', '.join(repos)})",
                cwe="CWE-653", owasp="A04:2021 Insecure Design", likelihood="medium", impact="medium", evidence=[w["citation"] for w in ws][:3], primary=ws[0]["citation"],
                target=ws[0]["src"], gaps="Shared writers couple services to one schema and make it hard to enforce per-service invariants and least privilege.",
                control="Give each table one owning service, or enforce per-service DB roles and constraints.", confidence="medium")


def rule_timeouts(c: Ctx, threats):
    flagged = 0
    for e in c.store.edges:
        if e["kind"] != "http_calls" or flagged >= 6:
            continue
        s = c.nodes.get(e["src"], {})
        text = c.file_text(s.get("repo", ""), s.get("path", ""))
        if text and not re.search(r"(?i)timeout", text):
            add(threats, component=f"{s['repo']} outbound call", stride="Denial of service", title=f"Outbound HTTP call without a timeout in {s['path']}",
                cwe="CWE-400", owasp="A04:2021 Insecure Design", likelihood="medium", impact="low", evidence=[e["citation"]], primary=e["citation"], target=e["src"],
                gaps="No timeout setting appears anywhere in the calling file; a slow dependency can exhaust workers.", control="Set connect and read timeouts and a circuit breaker.", confidence="low")
            flagged += 1


def rule_cloud(c: Ctx, threats):
    by_res = defaultdict(list)
    for e in c.store.edges:
        if e["kind"] == "finding_at":
            f = c.nodes.get(e["src"], {})
            chk = (f.get("attrs") or {}).get("check")
            if chk in CLOUD_CHECK and c.nodes.get(e["dst"], {}).get("kind") == "cloud_resource":
                by_res[(e["dst"], chk)].append(f)
    cspm = defaultdict(list)
    for e in c.store.edges:
        if e["kind"] == "affects":
            cspm[e["dst"]].append(c.nodes.get(e["src"], {}))
    for (res_id, chk), fs in sorted(by_res.items()):
        cwe, stride, what, ctrl, owasp, l, i = CLOUD_CHECK[chk]
        res = c.nodes[res_id]
        corro = cspm.get(res_id, [])
        add(threats, component=f"{res['name']}", stride=stride, title=f"{what}: {res['name']}", cwe=cwe, owasp=owasp, likelihood=l, impact=i,
            evidence=[fs[0]["citation"]] + [x["citation"] for x in corro[:2]], primary=fs[0]["citation"], target=res_id,
            gaps=f"IaC declares it ({chk}). " + (f"A CSPM scan also reports it open ({', '.join(sorted({(x.get('attrs') or {}).get('tool', 'scan') for x in corro}))}): observed at scan time." if corro else "No CSPM result corroborates it."),
            control=ctrl, label="observed", confidence="high" if corro else "medium")


def rule_supply(c: Ctx, threats):
    seen = set()
    for n in sorted((n for n in c.nodes.values() if n["kind"] == "sc_finding"), key=lambda n: n["citation"]):
        a = n.get("attrs") or {}
        if a.get("check") in CLOUD_CHECK or a.get("class") != "confirmed-suspicious":
            continue
        k = (a.get("check"), n["citation"].rsplit(":", 1)[0])
        if k in seen or len(seen) >= 15:
            continue
        seen.add(k)
        cwe, what = SC_CWE.get(a.get("category"), ("CWE-829", "Supply-chain risk"))
        add(threats, component=n["citation"].rsplit(":", 1)[0], stride="Tampering / Elevation of privilege", title=f"{what}: {n['name'][:90]}", cwe=cwe,
            owasp="A08:2021 Software and Data Integrity Failures", likelihood="high", impact="high", evidence=[n["citation"]], primary=n["citation"],
            target=next((e["dst"] for e in c.store.out_adj.get(n["id"], []) if e["kind"] == "finding_at"), None),
            gaps=f"Scanner class `{a.get('class')}`, severity {a.get('severity')} ({a.get('check')}). " + (a.get("remediation") or ""),
            control=a.get("remediation") or "See the supply-chain report.", label="observed", confidence="medium")


PIPE_CWE = {"SC-C01": ("CWE-829", "A08:2021 Software and Data Integrity Failures", "Tampering", "Pipeline pulls actions/templates by a mutable reference", "Pin to a full commit SHA or immutable tag; review updates."),
            "SC-C02": ("CWE-829", "A08:2021 Software and Data Integrity Failures", "Elevation of privilege", "Privileged pull_request_target workflow", "Avoid pull_request_target; never check out or run PR head code in it."),
            "SC-C03": ("CWE-77", "A03:2021 Injection", "Elevation of privilege", "Untrusted event data interpolated into a pipeline script", "Pass untrusted values through environment variables and quote them."),
            "SC-C04": ("CWE-250", "A05:2021 Security Misconfiguration", "Elevation of privilege", "Pipeline token has broad permissions", "Declare least-privilege permissions per workflow/job."),
            "SC-C05": ("CWE-532", "A09:2021 Security Logging and Monitoring Failures", "Information disclosure", "Secrets exposed to scripts or logs", "Never echo secrets; scope them to the job that needs them; avoid secrets: inherit.")}
PF_CWE = {"PF01": ("CWE-829", "A08:2021 Software and Data Integrity Failures", "Tampering", "Pipeline code is loaded from a mutable reference", "Pin templates/libraries/orbs to a tag or commit and protect the source repo branch."),
          "PF02": ("CWE-77", "A03:2021 Injection", "Elevation of privilege", "Untrusted build variable expanded inside a pipeline script", "Pass the value as an environment variable and quote it; never expand branch names or commit messages inline."),
          "PF03": ("CWE-250", "A05:2021 Security Misconfiguration", "Elevation of privilege", "Pull-request builds can run on a self-hosted runner", "Use ephemeral hosted runners for PR builds, or require approval before running fork/contributor code."),
          "PF04": ("CWE-693", "A04:2021 Insecure Design", "Elevation of privilege", "Deploy step without an environment, approval or manual gate", "Deploy through a protected environment with required reviewers and branch rules."),
          "PF05": ("CWE-532", "A09:2021 Security Logging and Monitoring Failures", "Information disclosure", "Secret-like variable printed to the build log", "Do not echo secrets; rely on masked variables and avoid printing them.")}


def rule_pipeline(c: Ctx, threats):
    """CI/CD pipeline threats: supply-chain scanner findings for CI (SC-C01..C05) plus pipeline_facts findings (PF01..PF05)."""
    kinds = {n["repo"]: (n.get("attrs") or {}).get("repo_kind") for n in c.nodes.values() if n["kind"] == "repo"}
    sec = defaultdict(list)
    for n in sorted((n for n in c.nodes.values() if n["kind"] == "sc_finding"), key=lambda n: n["citation"]):
        a = n.get("attrs") or {}
        if a.get("check") in PIPE_CWE:
            sec[(n["repo"], a["check"])].append(n)
    for (repo, chk), ns in sorted(sec.items()):
        pipeline_repo = kinds.get(repo) in ("cicd-pipeline", "gitops-config", "mixed")
        ns = [n for n in ns if pipeline_repo or (n.get("attrs") or {}).get("severity") in ("high", "critical")]
        if not ns:
            continue
        cwe, owasp, stride, what, ctrl = PIPE_CWE[chk]
        worst = any((n.get("attrs") or {}).get("severity") in ("high", "critical") for n in ns)
        add(threats, component=f"{repo} CI/CD pipeline", stride=stride, title=f"{what} ({repo}, {len(ns)} place(s))", cwe=cwe, owasp=owasp,
            likelihood="high" if worst else "medium", impact="high" if pipeline_repo else "medium", evidence=[n["citation"] for n in ns[:3]], primary=ns[0]["citation"],
            target=next((e["dst"] for e in c.store.out_adj.get(ns[0]["id"], []) if e["kind"] == "finding_at"), None),
            gaps=f"Supply-chain scanner {chk}: {safe_str((ns[0].get('attrs') or {}).get('remediation') or ns[0]['name'], 160)}",
            control=ctrl, label="observed", confidence="high" if worst else "medium")
    for p in sorted((c.out / "evidence").glob("pipeline-facts-*.json")):
        try:
            d = json.loads(p.read_text())
        except ValueError:
            continue
        repo = d.get("repo")
        by = defaultdict(list)
        for fnd in d.get("findings", []):
            by[fnd["id"]].append(fnd)
        for fid, fs in sorted(by.items()):
            if fid not in PF_CWE:
                continue
            cwe, owasp, stride, what, ctrl = PF_CWE[fid]
            cites = [f"{repo}/{x['path']}:{x['line']}" for x in fs[:3]]
            high = any(x["severity"] == "high" for x in fs)
            add(threats, component=f"{repo} CI/CD pipeline", stride=stride, title=f"{what} ({repo}, {len(fs)} place(s))", cwe=cwe, owasp=owasp,
                likelihood="high" if high else "medium", impact="high", evidence=cites, primary=cites[0], target=None,
                gaps=safe_str(fs[0]["message"], 220), control=ctrl, label="inferred", confidence="medium")


def rule_drift(c: Ctx, threats):
    for n in sorted((n for n in c.nodes.values() if n["kind"] == "drift"), key=lambda n: n["citation"]):
        a = n.get("attrs") or {}
        add(threats, component=n["name"][:60], stride="Repudiation / false assurance", title=f"Documented control not found in code or IaC: {n['name'][:80]}",
            cwe="CWE-1059", owasp="A04:2021 Insecure Design", likelihood="medium", impact="medium" if a.get("security", "yes") != "yes" else "high",
            evidence=[n["citation"]] + ([a["doc_citation"]] if a.get("doc_citation") else []), primary=n["citation"], target=None,
            gaps=safe_str(a.get("claim", "") + " vs " + a.get("observed", ""), 240), control="Fix the code/IaC to match the claim, or correct the document; record the decision.",
            label="inferred", confidence="medium")


def rule_llm(c: Ctx, threats):
    pk = [n for n in c.nodes.values() if n["kind"] == "package" and re.search(r"(?i)^(anthropic|openai|langchain|llama.?index|cohere|mistralai|vertexai|ollama|@anthropic-ai)", n["name"])]
    if not pk:
        return
    p = sorted(pk, key=lambda n: n["citation"])[0]
    for lid, title, ctrl in (("LLM01", "Prompt injection via user or retrieved content", "Separate trusted instructions from untrusted data; filter and constrain outputs."),
                             ("LLM05", "Improper handling of model output", "Treat model output as untrusted: validate before use in SQL, shell, HTML, or tool calls."),
                             ("LLM06", "Excessive agency of tools/actions", "Least-privilege tools, human approval for destructive actions.")):
        add(threats, component=f"LLM integration ({p['name']})", stride="Tampering / Elevation of privilege", title=f"{lid}: {title}", cwe="CWE-1427" if lid == "LLM01" else "CWE-20",
            owasp=f"OWASP LLM Top 10: {lid}", likelihood="medium", impact="medium", evidence=[p["citation"]], primary=p["citation"], target=None,
            gaps="An LLM SDK is imported; how untrusted text and outputs flow was not traced by this draft rule. Confirm against the prompt and tool code.", control=ctrl, label="inferred", confidence="low")


# ---------------------------------------------------------------- boundaries, output

def boundaries(c: Ctx):
    tbs, seen = [], set()

    def add_tb(tid, name, kind, cite, crossed):
        if tid in seen or not cite:
            return
        seen.add(tid)
        tbs.append({"id": tid, "name": name, "kind": kind, "citation": cite, "crossed_by": crossed})
    for e in c.store.edges:
        s = c.nodes.get(e["src"], {})
        if e["kind"] == "http_calls" and e.get("dst_citation"):
            d = c.nodes.get(e["dst"], {})
            add_tb(f"TB-{s.get('repo')}-{d.get('repo')}-http", f"{s.get('repo')} → {d.get('repo')} (service boundary, HTTP)", "service", e["citation"], e["src"])
        elif e["kind"] == "http_calls" and c.nodes.get(e["dst"], {}).get("kind") == "external":
            add_tb(f"TB-{s.get('repo')}-external", f"{s.get('repo')} → third parties", "third-party", e["citation"], e["src"])
        elif e["kind"] in ("publishes", "consumes") and c.nodes.get(e["dst"], {}).get("kind") == "topic":
            add_tb(f"TB-broker-{c.nodes[e['dst']]['name']}", f"message broker topic {c.nodes[e['dst']]['name']}", "messaging", e["citation"], e["src"])
        elif e["kind"] in ("reads", "writes") and c.nodes.get(e["dst"], {}).get("kind") == "table":
            add_tb(f"TB-data-{c.nodes[e['dst']]['name']}", f"data store: table {c.nodes[e['dst']]['name']}", "data", e["citation"], e["src"])
    pub = [n for n in c.nodes.values() if n["kind"] == "endpoint" and c.exposure(n["id"])[0] in ("public-candidate", "public")]
    if pub:
        p = sorted(pub, key=lambda n: n["citation"])[0]
        add_tb("TB-internet", "internet → public-facing endpoints (candidates)", "internet", p["citation"], (c.handler.get(p["id"]) or [p["id"]])[0])
    for n in c.nodes.values():
        if n["kind"] == "cloud_resource" and re.search(r"(?i)ingress|load.?balancer|api.?gateway|front.?door", n["name"]):
            add_tb(f"TB-edge-{re.sub(r'[^A-Za-z0-9]+', '-', n['name'])[:40]}", f"edge: {n['name']}", "edge", n["citation"], n["id"])
    return tbs


def esc(s) -> str:
    return md_safe(s)


def quote_of(c: Ctx, citation: str):
    q = c.line(citation)
    q = safe_quote(q) if q else None
    return q or None


def write_proposals(c: Ctx, out: Path, threats, tbs):
    lines = []
    for t in threats:
        q = quote_of(c, t["primary"])
        if not q:
            continue
        qn = f"{t['id']}-{re.sub(r'[^a-z0-9]+', '-', t['title'].lower())[:40].strip('-')}"
        t["qualname"] = qn
        lines.append({"op": "node", "extractor": "rule", "kind": "threat", "repo": "_system", "qualname": qn, "name": f"{t['id']} {t['title']}"[:200],
                      "citation": t["primary"], "quote": q, "confidence": t["confidence"], "label": t["label"],
                      "attrs": {"stride": t["stride"], "cwe": t["cwe"], "owasp": t["owasp"], "likelihood": t["likelihood"], "impact": t["impact"],
                                "priority": t["priority"], "draft": True, "component": t["component"][:120]}})
        if t.get("target") and t["target"] in c.nodes:
            lines.append({"op": "edge", "extractor": "rule", "src": f"threat:_system::{qn}", "kind": "threatens", "dst": t["target"], "citation": t["primary"],
                          "quote": q, "confidence": t["confidence"], "label": t["label"], "rationale": t["title"][:200]})
    for b in tbs:
        q = quote_of(c, b["citation"])
        if not q:
            continue
        lines.append({"op": "node", "extractor": "rule", "kind": "trust_boundary", "repo": "_system", "qualname": b["id"], "name": b["name"][:200], "citation": b["citation"],
                      "quote": q, "confidence": "medium", "label": "inferred", "attrs": {"boundary_kind": b["kind"], "draft": True}})
        if b["crossed_by"] in c.nodes:
            lines.append({"op": "edge", "extractor": "rule", "src": b["crossed_by"], "kind": "crosses_boundary", "dst": f"trust_boundary:_system::{b['id']}",
                          "citation": b["citation"], "quote": q, "confidence": "medium", "label": "inferred"})
    p = graph_dir(out) / "proposals" / "seed-threats.jsonl"
    atomic_write(p, "".join(json.dumps(x) + "\n" for x in lines))
    return len(lines)


def dfd(c: Ctx) -> str:
    from callgraph import compute, label as lab
    g = {"nodes": list(c.nodes.values()), "edges": c.store.edges}
    cg = compute(g, {k: v for k, v in c.roots.items() if not k.startswith("ctx")})
    rows = cg["repo"]["edges"][:40]
    names = {n["id"]: n["name"] for n in cg["repo"]["nodes"]}
    pub = set()
    for n in c.nodes.values():
        if n["kind"] == "endpoint" and c.exposure(n["id"])[0] in ("public-candidate", "public"):
            pub.add(n["repo"])
    ids, groups = {}, {"internet": [], "internal": [], "third": []}
    for r in rows:
        for x in (r["src"], r["dst"]):
            if x not in ids:
                ids[x] = f"N{len(ids) + 1}"
                kind = c.nodes.get(x, {}).get("kind", "repo")
                rep = names.get(x, "")
                groups["third" if kind == "external" else "internet" if rep in pub else "internal"].append(x)
    out = ["flowchart LR", '  U(("Internet users"))']
    titles = {"internet": "Trust boundary: public-facing candidates", "internal": "Trust boundary: internal services", "third": "Trust boundary: third parties"}
    for g, members in groups.items():
        if members:
            out.append(f'  subgraph TB_{g}["{titles[g]}"]')
            out += [f'    {ids[m]}["{lab(names[m])}"]' for m in members]
            out.append("  end")
    for m in groups["internet"]:
        out.append(f"  U -->|\"requests\"| {ids[m]}")
    for r in rows:
        out.append(f'  {ids[r["src"]]} {"-.->" if r["label"] == "inferred" else "-->"}|"{lab(r["mechanism"], 24)}"| {ids[r["dst"]]}')
    return "\n".join(out)


def render(c: Ctx, threats, tbs, prop_lines) -> str:
    targets = json.loads((c.out / "evidence" / "targets.json").read_text()).get("repos", {}) if (c.out / "evidence" / "targets.json").is_file() else {}
    srcs = ", ".join(f"`{k}` @ `{str(v.get('revision') or 'local')[:12]}`" for k, v in targets.items() if not k.startswith("ctx"))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threats.sort(key=lambda t: (order[t["priority"]], t["primary"]))
    for i, t in enumerate(threats, 1):
        t["id"] = f"T-{i:02d}"
    write_proposals(c, c.out, threats, tbs)
    L = ["# System threat model (draft)", "", "> **ckb provenance**", f"> - Sources: {srcs}", f"> - Generated: {now_iso()} by ckb threat_seed, stage `threat-model-draft`",
         "> - Scope: registered repos, IaC, supplied CSPM/docs · Excluded: vendored, generated, binaries, symlinks",
         "> - Method: deterministic rules over the knowledge graph; no target code executed; ratings per the ckb rubric",
         "> - Verification: threats are mirrored as graph proposals (graph/proposals/seed-threats.jsonl) and verified by graph_merge", "",
         f"> **DRAFT** [inferred]: produced by rules, not by a reviewer. The threat-modeler agent confirms, refines, or removes each threat below; until then treat every item as a lead to check in the cited code. {MARK}", "",
         "## Scope", "", f"Registered repos: {', '.join(f'`{k}`' for k in targets if not k.startswith('ctx')) or '[unknown]'}. Threats come from {len(threats)} rule hits. Rules cover injection paths, authentication evidence, security switches, service-to-service trust, messaging, shared state, timeouts, cloud posture, supply chain, documentation drift, and LLM use. [inferred]", ""]
    assets = []
    for n in sorted(c.nodes.values(), key=lambda n: n["citation"] or ""):
        if n["kind"] == "table":
            assets.append((n["name"], "data store (table)", "high", n["citation"]))
        elif n["kind"] == "env_var" and SECRET_ENV.search(n["name"]):
            assets.append((n["name"], "secret/credential configuration (name only)", "high", n["citation"]))
        elif n["kind"] == "cloud_resource" and re.search(r"(?i)bucket|storage|db_instance|database|queue|mq_broker|secret|kms|sqs|sns", n["name"]):
            assets.append((n["name"], "cloud data/messaging resource", "medium", n["citation"]))
        elif n["kind"] == "topic":
            assets.append((n["name"], "message topic", "medium", n["citation"]))
    L += ["## Assets", "", "| Asset | Kind | Sensitivity | Source |", "| --- | --- | --- | --- |"]
    L += [f"| {esc(a[0])} | {a[1]} | {a[2]} | `{a[3]}` |" for a in assets[:40] if a[3]] or ["| [unknown] none identified | | | |"]
    L += ["", "## Actors", "", "| Actor | Trust level | Capabilities |", "| --- | --- | --- |",
          "| Anonymous internet user | untrusted | reach public-facing endpoints [inferred] |", "| Authenticated user | low | call authenticated endpoints [inferred] |",
          "| Internal service | medium | call internal endpoints, publish/consume topics, read/write shared stores [inferred] |",
          "| Operator / CI system | high | deploy, configure environment variables, run pipelines [inferred] |",
          "| Third-party API / SaaS | untrusted | receive outbound calls and data [inferred] |", ""]
    L += ["## Entry points", "", "| Entry point | Exposure | AuthN evidence | Source |", "| --- | --- | --- | --- |"]
    auth_missing = {t["primary"] for t in threats if t["cwe"] == "CWE-306"}
    eps = sorted((n for n in c.nodes.values() if n["kind"] == "endpoint"), key=lambda n: n["citation"])
    L += [f"| {esc(n['name'])} | {c.exposure(n['id'])[0]} | {'none found' if n['citation'] in auth_missing else 'found or exempt'} | `{n['citation']}` |" for n in eps[:60]] \
        or ["| [unknown] none | | | |"]
    L += ["", "## Trust boundaries", "", "| ID | Boundary | Crossed by | Source |", "| --- | --- | --- | --- |"]
    L += [f"| {b['id']} | {esc(b['name'])} | {esc(c.nodes.get(b['crossed_by'], {}).get('name', ''))} | `{b['citation']}` |" for b in tbs] or ["| [unknown] none | | | |"]
    L += ["", "## Data flow diagram", "", "```mermaid", dfd(c), "```", ""]
    L += ["## STRIDE", "", "| ID | Component or flow | STRIDE | Threat | CWE/OWASP | Likelihood | Impact | Existing mitigations | Gaps | Recommended controls | Confidence | Source |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for t in threats:
        mit = "; ".join(esc(m) for m in t["mitigations"]) or "none found"
        src = " ".join(f"`{x}`" for x in dict.fromkeys(t["evidence"]))
        L.append(f"| {t['id']} [draft] | {esc(t['component'])[:70]} | {esc(t['stride'])} | {esc(t['title'])} | {t['cwe']} · {esc(t['owasp'])} | {t['likelihood']} | {t['impact']} | {mit} | {esc(t['gaps'])[:300]} | {esc(t['control'])[:200]} | {t['confidence']} ({t['label']}) | {src} |")
    if not threats:
        L.append("| [unknown] no rule matched | | | | | | | | | | | |")
    cats = [("AuthN/AuthZ", "CWE-306"), ("Secrets handling", "CWE-798"), ("Inter-service trust", "CWE-290"), ("Injection sinks (SQL, cmd, template, deser, SSRF, path)", None), ("Data sensitivity", "CWE-284")]
    L += ["", "## Focus checks", "", "| Area | Finding | Source |", "| --- | --- | --- |"]
    for area, cwe in cats:
        hits = [t for t in threats if (t["cwe"] == cwe if cwe else t["cwe"] in ("CWE-89", "CWE-78", "CWE-918", "CWE-94", "CWE-502"))]
        if area == "Secrets handling":
            hits += [t for t in threats if t["cwe"] == "CWE-798"]
        L.append(f"| {area} | " + (f"{len(hits)} draft threat(s): " + ", ".join(h['id'] for h in hits[:6]) if hits else "none detected by the rules [inferred]") + " | " + (" ".join(f"`{h['primary']}`" for h in hits[:2]) if hits else "[n/a]") + " |")
    L += ["| LLM (OWASP LLM Top 10) | " + ("LLM SDK imported: see LLM entries" if any(t['owasp'].startswith('OWASP LLM') for t in threats) else "no LLM SDK detected") + " | " + (next((f"`{t['primary']}`" for t in threats if t['owasp'].startswith('OWASP LLM')), "[n/a]")) + " |"]
    aps = attack_paths(c)
    L += ["", "## Attack paths", "",
          "Entry point to sink over every resolved edge kind (calls, class and object calls, references, library calls, agent dispatch, FFI, HTTP, queues, spawns). Exposure comes from deployment facts when present; a control in front of the entry point lowers the rank; coverage is the resolved-call percentage of the repos crossed. Paths are candidates, not proven dataflow. [inferred]", "",
          "| # | Entry point | Exposure | Control in front | Path | Via | Sink | Evidence | Repos | Coverage | Source |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    L += [f"| {i} | {esc(r['entry'])} | {r['exposure']} | {r['control']} | {esc(r['hops'])} | {r['via']} | {r['sink']} | {r['confidence']} | {esc(r['repos'])} | {r['coverage']}% | `{r['citation']}` |" for i, r in enumerate(aps, 1)] or ["| - | [unknown] no entry-to-sink path found | | | | | | | | | |"]
    cov = next(_evidence_json(c, "coverage.json"), None)
    L += ["", "## Analysis coverage and blind spots", ""]
    if cov:
        L += ["| Repo | Calls resolved or library | Entry points | Functions no entry point reaches | Dynamic-dispatch hotspots | Dormant unsafe sinks |", "| --- | --- | --- | --- | --- | --- |"]
        L += [f"| {esc(r_)} | {((v.get('call_resolution') or {}).get('resolved_pct') if (v.get('call_resolution') or {}).get('resolved_pct') is not None else '[n/a]')}{'%' if (v.get('call_resolution') or {}).get('resolved_pct') is not None else ''} | {v['entry_points']} | {v['unreachable_count']} | {len(v['dynamic_hotspots'])} | {len(v['dormant_sinks'])} |" for r_, v in cov["repos"].items()]
        L += ["", "Low coverage lowers confidence in every path above; see `system/coverage.md` for the unresolved names and hotspots. Static analysis cannot prove that every path was found. [inferred]"]
    else:
        L += ["[unknown] no coverage report was generated (run `coverage_report.py`)."]
    L += ["", "## Prioritized risks", ""]
    L += [f"{i}. **{t['id']}** ({t['priority']}): {esc(t['title'])}: `{t['primary']}`" for i, t in enumerate(threats[:10], 1)] or ["[unknown] none"]
    L += ["", "## Assumptions", ""] + ([f"- [unknown] Evidence file(s) unreadable, so the rules that depend on them did not run: {', '.join(sorted(set(EVIDENCE_PROBLEMS)))}. Re-run the graph build."] if EVIDENCE_PROBLEMS else []) + [""]
    L += [ "- Exposure labels are inferred from the call graph (an endpoint nobody else calls is a public candidate); confirm against ingress/gateway configuration. [inferred]",
          "- Authentication evidence is looked for on the route line and handler chain only: global middleware and gateway-level auth are not visible to these rules. [inferred]",
          "- Taint paths are candidate reachability over call/route edges, not a full data-flow proof. [inferred]", ""]
    return "\n".join(L)


def run(out: Path, force=False) -> dict:
    EVIDENCE_PROBLEMS.clear()
    c = Ctx(out)
    threats = []
    for rule in (rule_taint, rule_auth, rule_switches, rule_deploy, rule_agents, rule_library, rule_coverage, rule_trust, rule_messaging, rule_timeouts, rule_cloud, rule_supply, rule_pipeline, rule_drift, rule_llm):
        rule(c, threats)
    tbs = boundaries(c)
    md = render(c, threats, tbs, 0)
    p = out / "system" / "threat-model.md"
    wrote = True
    if p.is_file() and MARK not in p.read_text() and not force:
        p = out / "system" / "threat-model.draft.md"
        wrote = False  # a refined (agent-written) model exists: keep it, write the draft alongside
    atomic_write(p, md)
    return {"threats": len(threats), "boundaries": len(tbs), "file": str(p.relative_to(out)), "overwrote_refined": False, "wrote_primary": wrote,
            "by_priority": {k: sum(1 for t in threats if t["priority"] == k) for k in ("critical", "high", "medium", "low")}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve(), a.force), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
