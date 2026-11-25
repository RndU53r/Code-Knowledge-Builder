#!/usr/bin/env python3
"""Deployment, configuration and controls outside application code, from IaC, containers, Kubernetes, compose and gateway config.
Reads files only; never runs a deployment tool or contacts a cluster.

Usage:
  deploy_facts.py --out OUT_DIR [--repo KEY]

Per repo that holds deployment content it records, with citations:
  workloads   compose services, Kubernetes Deployment/StatefulSet/DaemonSet/Job/CronJob, Helm values and templates, ECS task
              definitions, Lambda functions, Dockerfiles: image, ports, injected environment (name + where the value comes from;
              literal values only for non-secret names), identity (service account / IAM role), replicas, security context
  exposure    Service type, Ingress hosts and TLS, load balancers and listeners, security-group rules, API gateway routes
  controls    gateway/ingress authentication (authorizers, auth-url, oauth2-proxy), WAF, mTLS / mesh policy, NetworkPolicy,
              private endpoints, rate limits and IP allowlists, TLS settings, secret stores
Each workload is linked to the application repo it runs (image name, build context, chart name, name equality) when that repo is
registered. Writes evidence/deploy-facts-<repo>.json and graph/proposals/seed-deploy.jsonl (service nodes, `deploys` and
`configured_by` edges, extractor "rule"). Line-based and heuristic: results are [inferred].
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import read_text, redact_text, repo_excludes, repo_roots_for_output, walk_files  # noqa: E402
from graph_common import atomic_write, graph_dir, safe_quote  # noqa: E402
from roles import classify  # noqa: E402

SECRETISH = re.compile(r"(?i)(PASS|PWD|SECRET|TOKEN|KEY|CREDENTIAL|CONN(ECTION)?_?STRING|DSN|COOKIE|SALT|SIGN|AUTH|CERT|URL|URI|HOST_?KEY|SESSION)")


def safe_value(name: str, v: str):
    """A literal env value is kept only for names that are clearly not secret and values that do not look like credentials."""
    v = (v or "").strip()
    if re.fullmatch(r"(?i)true|false|0|1|yes|no|on|off|enabled|disabled", v):
        return v  # a boolean switch value is not a secret, whatever the variable is called
    if not v or SECRETISH.search(name or "") or len(v) > 60 or re.search(r"://[^/\s]*@|[A-Za-z0-9+/=_-]{32,}", v):
        return None
    return v
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}
PUBLIC_CIDR = re.compile(r"0\.0\.0\.0/0|::/0|\"\*\"|'\*'")


def _cite(repo, rel, line):
    return f"{repo}/{rel}:{line}"


def docs_of(text: str):
    """Yield (start_line, doc_text) for each YAML document."""
    start, buf = 1, []
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.strip() == "---":
            if buf:
                yield start, "\n".join(buf)
            start, buf = i + 1, []
        else:
            buf.append(ln)
    if buf:
        yield start, "\n".join(buf)


def _first(rx, text, default=None, flags=re.M):
    m = re.search(rx, text, flags)
    return m.group(1).strip().strip("'\"") if m else default


def env_entries(block: str, base_line: int):
    """env: lists (- name: X / value: Y / valueFrom: ...) and maps (KEY: value / - KEY=value) found in a text block."""
    out = []
    lines = block.splitlines()
    for i, ln in enumerate(lines):
        m = re.match(r"^[ \t]*-\s*name:\s*['\"]?([A-Za-z_][\w.]*)['\"]?\s*$", ln)
        if m:
            nxt_lines = []
            for x in lines[i + 1:i + 8]:
                if re.match(r"^[ \t]*-\s*name:", x):
                    break
                nxt_lines.append(x)
            nxt = " ".join(nxt_lines)
            vf = re.search(r"valueFrom:\s*(?:\n\s*)?(secretKeyRef|configMapKeyRef|fieldRef|resourceFieldRef)", nxt) or re.search(r"\b(secretKeyRef|configMapKeyRef|fieldRef)\b", nxt)
            val = re.match(r"\s*value:\s*['\"]?([^'\"#\n]*)['\"]?", nxt_lines[0]) if nxt_lines else None
            src = vf.group(1) if vf else ("literal" if val else "unknown")
            out.append({"name": m.group(1), "source": src, "line": base_line + i, **({"value": safe_value(m.group(1), val.group(1))} if val and src == "literal" and safe_value(m.group(1), val.group(1)) is not None else {})})
            continue
        m = re.match(r"^[ \t]*-\s*([A-Za-z_][\w]*)=(.*)$", ln)  # compose list form
        if m:
            out.append({"name": m.group(1), "source": "literal" if m.group(2) and "${" not in m.group(2) else "variable", "line": base_line + i,
                        **({"value": safe_value(m.group(1), m.group(2).strip("'\""))} if m.group(2) and "${" not in m.group(2) and safe_value(m.group(1), m.group(2).strip("'\"")) is not None else {})})
            continue
        m = re.match(r"^\s{2,}([A-Z_][A-Z0-9_]*):\s*(.*)$", ln)  # compose / helm map form
        if m:
            v = m.group(2).strip().strip("'\"")
            out.append({"name": m.group(1), "source": "variable" if "${" in v or "{{" in v else ("literal" if v else "unknown"), "line": base_line + i,
                        **({"value": safe_value(m.group(1), v)} if v and "${" not in v and "{{" not in v and safe_value(m.group(1), v) is not None else {})})
    return out


def parse_k8s(repo, rel, text, facts):
    for start, doc in docs_of(text):
        kind = _first(r"^kind:\s*(\w+)", doc)
        name = _first(r"^metadata:[ \t]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+name:[ \t]*(\S+)", doc + "\n") or _first(r"^[ \t]+name:\s*(\S+)", doc)
        if not kind:
            continue
        cite = _cite(repo, rel, start + (next((i for i, ln in enumerate(doc.splitlines()) if ln.startswith("kind:")), 0)))
        if kind in WORKLOAD_KINDS:
            images = [re.sub(r"//[^/@\s]*@", "//", i)[:200] for i in re.findall(r"^[ \t]*-?[ \t]*image:[ \t]*['\"]?([^\s'\"#]{1,300})", doc, re.M)]
            ports = [int(p) for p in re.findall(r"containerPort:[ \t]*(\d{1,5})", doc)]
            envs = env_entries(doc[doc.find("env:"):] if "env:" in doc else "", start + (doc[:doc.find("env:")].count("\n") if "env:" in doc else 0))
            envfrom = re.findall(r"(?:secretRef|configMapRef):\s*\n\s*name:\s*(\S+)", doc)
            sec = {"privileged": bool(re.search(r"privileged:\s*true", doc)), "host_network": bool(re.search(r"hostNetwork:\s*true", doc)),
                   "host_path": bool(re.search(r"\bhostPath:", doc)), "run_as_non_root": bool(re.search(r"runAsNonRoot:\s*true", doc)),
                   "run_as_root": bool(re.search(r"runAsUser:\s*0\b", doc)), "limits": bool(re.search(r"\blimits:", doc))}
            facts["workloads"].append({"name": name or kind, "kind": kind, "source": "kubernetes", "namespace": _first(r"^[ \t]+namespace:\s*(\S+)", doc), "images": images[:6], "ports": ports[:8],
                                       "env": envs[:60], "env_from": envfrom[:6], "service_account": _first(r"serviceAccountName:\s*(\S+)", doc),
                                       "replicas": int(_first(r"replicas:\s*(\d+)", doc, "0") or 0) or None, "security": sec, "citation": cite,
                                       "exposure": {"kind": "none"}})
        elif kind == "Service":
            facts["_services"].append({"name": name, "type": _first(r"^[ \t]+type:\s*(\w+)", doc, "ClusterIP"), "selector": re.findall(r"^\s{4,}(?:app|app\.kubernetes\.io/name):\s*(\S+)", doc, re.M),
                                       "ports": [int(p) for p in re.findall(r"^[ \t]*-?\s*port:\s*(\d+)", doc, re.M)][:6], "citation": cite,
                                       "annotations": re.findall(r"^[ \t]+([\w./-]*(?:internal|load-balancer|ssl|cert|auth)[\w./-]*):\s*(.*)$", doc, re.M)[:6]})
        elif kind == "Ingress":
            hosts = re.findall(r"^[ \t]*-?\s*host:\s*['\"]?([^\s'\"]+)", doc, re.M)
            backends = re.findall(r"(?:service:\s*\n\s*name:|serviceName:)\s*['\"]?([\w.-]+)", doc)
            ann = dict(re.findall(r"^[ \t]+([\w./-]+):\s*['\"]?([^'\"\n#]*)['\"]?\s*$", doc[doc.find("annotations:"):doc.find("spec:")] if "annotations:" in doc else "", re.M))
            facts["_ingresses"].append({"name": name, "hosts": hosts[:6], "backends": backends[:8], "tls": bool(re.search(r"^[ \t]*tls:", doc, re.M)), "annotations": ann, "citation": cite})
            for k, v in ann.items():
                if re.search(r"auth-url|auth-signin|oauth2|auth-type|auth-secret|jwt|authorizer", k, re.I):
                    facts["controls"].append({"kind": "gateway-auth", "scope": f"ingress {name}", "detail": f"{k}: {v}"[:120], "citation": cite, "hosts": hosts[:3], "backends": backends[:8]})
                if re.search(r"waf|modsecurity|owasp", k, re.I):
                    facts["controls"].append({"kind": "waf", "scope": f"ingress {name}", "detail": f"{k}: {v}"[:120], "citation": cite, "backends": backends[:8]})
                if re.search(r"whitelist|allowlist|source-range", k, re.I):
                    facts["controls"].append({"kind": "ip-allowlist", "scope": f"ingress {name}", "detail": f"{k}: {v}"[:120], "citation": cite, "backends": backends[:8]})
                if re.search(r"limit-(rps|rpm|connections)|rate-limit", k, re.I):
                    facts["controls"].append({"kind": "rate-limit", "scope": f"ingress {name}", "detail": f"{k}: {v}"[:120], "citation": cite, "backends": backends[:8]})
        elif kind == "NetworkPolicy":
            facts["controls"].append({"kind": "network-policy", "scope": name or "networkpolicy", "detail": "policyTypes: " + ",".join(re.findall(r"^[ \t]*-\s*(Ingress|Egress)\s*$", doc, re.M)) + ("; default-deny" if re.search(r"podSelector:\s*\{\}", doc) else ""),
                                      "citation": cite})
        elif kind == "PeerAuthentication":
            facts["controls"].append({"kind": "mtls", "scope": name or "peerauthentication", "detail": "mode: " + (_first(r"mode:\s*(\w+)", doc) or "?"), "citation": cite})
        elif kind in ("AuthorizationPolicy", "RequestAuthentication"):
            facts["controls"].append({"kind": "mesh-auth" if kind == "AuthorizationPolicy" else "jwt-auth", "scope": name or kind, "detail": kind + (" (jwt issuer)" if "issuer" in doc else ""), "citation": cite,
                                      "selector": re.findall(r"^\s{4,}(?:app|app\.kubernetes\.io/name):\s*(\S+)", doc, re.M)[:3]})
        elif kind == "ServiceAccount":
            role = _first(r"(?:eks\.amazonaws\.com/role-arn|iam\.gke\.io/gcp-service-account|azure\.workload\.identity/client-id):\s*(\S+)", doc)
            facts["_serviceaccounts"][name] = {"identity": role, "citation": cite}


def parse_compose(repo, rel, text, facts):
    lines = text.splitlines()
    in_services, cur = False, None
    blocks = {}
    for i, ln in enumerate(lines, 1):
        if re.match(r"^services:[ \t]*$", ln):
            in_services = True
            continue
        if in_services and re.match(r"^\S", ln) and not ln.startswith("#"):
            in_services = False
        if in_services:
            m = re.match(r"^  ([\w.-]+):\s*$", ln)
            if m:
                cur = m.group(1)
                blocks[cur] = [i, []]
            elif cur:
                blocks[cur][1].append(ln)
    for name, (start, body) in blocks.items():
        b = "\n".join(body)
        image = re.sub(r"//[^/@\s]*@", "//", (_first(r"^[ \t]+image:[ \t]*(\S+)", b) or ""))[:200] or None
        build = _first(r"^[ \t]+build:\s*(\S+)", b) or _first(r"^[ \t]+context:\s*(\S+)", b)
        ports = re.findall(r"^[ \t]*-\s*['\"]?(?:(\d+(?:\.\d+\.\d+\.\d+)?):)?(\d{1,5})(?:/\w+)?['\"]?\s*$", b[b.find("ports:"):] if "ports:" in b else "", re.M)
        published = [p for p in re.findall(r"^[ \t]*-\s*['\"]?(?:[\d.]+:)?(\d{1,5}):(\d{1,5})", b[b.find("ports:"):] if "ports:" in b else "", re.M)]
        inline = re.search(r"^[ \t]+ports:\s*\[([^\]]*)\]", b, re.M)  # ports: ["3000:3000", "9000:9000"]
        if inline:
            published += [p for p in re.findall(r"['\"]?(?:[\d.]+:)?(\d+):(\d+)['\"]?", inline.group(1))]
            ports += [(None, c) for h, c in re.findall(r"['\"]?(?:[\d.]+:)?(\d+):(\d+)['\"]?", inline.group(1))]
        envs = env_entries(b[b.find("environment:"):b.find("environment:") + 2000] if "environment:" in b else "", start + b[:b.find("environment:")].count("\n") + 1 if "environment:" in b else start)
        facts["workloads"].append({"name": name, "kind": "compose-service", "source": "compose", "images": [image] if image else [], "build": build, "ports": [int(c) for _, c in ports][:8],
                                   "published_ports": [int(h) for h, c in published][:8], "env": envs[:60], "env_file": _first(r"^[ \t]+env_file:\s*(\S+)", b), "security": {"privileged": bool(re.search(r"privileged:\s*true", b)),
                                   "run_as_root": bool(re.search(r"user:\s*['\"]?(0|root)\b", b))},
                                   "exposure": {"kind": "host-ports" if published else "none", "published": [int(h) for h, c in published][:6], "public": bool(published)}, "citation": _cite(repo, rel, start)})


def parse_helm_values(repo, rel, text, facts):
    chart = Path(rel).parent.name
    img = _first(r"^image:[ \t]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+repository:[ \t]*(\S+)", text + "\n") or _first(r"^[ \t]*repository:\s*(\S+)", text)
    env = env_entries(text[text.find("env:"):text.find("env:") + 2000] if re.search(r"^[ \t]*env:", text, re.M) else "", text[:max(0, text.find("env:"))].count("\n") + 1)
    ing = re.search(r"^ingress:[ \t]*\n((?:[ \t]+[^\n]*\n?)+)", text, re.M)
    enabled = bool(ing and re.search(r"enabled:\s*true", ing.group(1)))
    hosts = re.findall(r"host:\s*['\"]?([^\s'\"]+)", ing.group(1)) if ing else []
    stype = _first(r"^service:[ \t]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+type:[ \t]*(\w+)", text + "\n")
    facts["workloads"].append({"name": chart, "kind": "helm-release", "source": "helm", "images": [img] if img else [], "ports": [], "env": env[:60], "security": {},
                               "exposure": {"kind": "ingress" if enabled else ("service-" + stype.lower() if stype else "none"), "hosts": hosts[:4], "service_type": stype}, "citation": _cite(repo, rel, 1), "chart": chart})
    for m in re.finditer(r"^[ \t]*(?:oauth2Proxy|authUrl|auth_url|auth)\s*:", text, re.M):
        facts["controls"].append({"kind": "gateway-auth", "scope": f"helm {chart}", "detail": m.group(0).strip()[:80], "citation": _cite(repo, rel, text[:m.start()].count("\n") + 1), "hosts": hosts[:3], "backends": [chart]})


def parse_dockerfile(repo, rel, text, facts):
    ports = [int(p) for p in re.findall(r"^[ \t]*EXPOSE\s+(\d+)", text, re.M | re.I)]
    user = _first(r"^[ \t]*USER\s+(\S+)", text, None, re.M | re.I)
    facts["workloads"].append({"name": Path(rel).parent.name or repo, "kind": "dockerfile", "source": "dockerfile", "images": [], "ports": ports[:8], "env": [], "build": str(Path(rel).parent) or ".",
                               "security": {"run_as_root": user in (None, "root", "0")}, "healthcheck": bool(re.search(r"^[ \t]*HEALTHCHECK\b", text, re.M | re.I)),
                               "exposure": {"kind": "container-ports" if ports else "none"}, "citation": _cite(repo, rel, 1)})


TF_BLOCK = re.compile(r'^[ \t]*resource\s+"(?P<type>[\w-]+)"\s+"(?P<name>[\w-]+)"\s*\{', re.M)


def parse_terraform(repo, rel, text, facts):
    lines = text.splitlines()
    for m in TF_BLOCK.finditer(text):
        typ, name = m.group("type"), m.group("name")
        start = text[:m.start("type")].count("\n") + 1
        depth, end = 0, start
        for j in range(start - 1, min(len(lines), start + 400)):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth <= 0 and j >= start - 1:
                end = j + 1
                break
        body = "\n".join(lines[start - 1:end])
        cite = _cite(repo, rel, start)
        if typ in ("aws_lb", "aws_alb"):
            internal = bool(re.search(r"internal\s*=\s*true", body))
            facts["_lbs"].append({"name": name, "public": not internal, "citation": cite})
            facts["controls"].append({"kind": "load-balancer", "scope": name, "detail": "internal" if internal else "internet-facing", "citation": cite})
        elif typ in ("aws_lb_listener", "aws_alb_listener"):
            proto = _first(r"protocol\s*=\s*\"(\w+)\"", body, "HTTP")
            port = _first(r"port\s*=\s*\"?(\d+)", body, "?")
            facts["controls"].append({"kind": "listener", "scope": name, "detail": f"{proto}:{port}" + (" redirect" if "redirect" in body else ""), "citation": cite,
                                      "insecure": proto == "HTTP" and "redirect" not in body})
        elif typ in ("aws_security_group", "aws_security_group_rule", "azurerm_network_security_rule", "google_compute_firewall"):
            if PUBLIC_CIDR.search(body) or re.search(r"source_address_prefix\s*=\s*\"(\*|Internet)\"", body):
                ports = re.findall(r"(?:from_port|to_port|destination_port_range)\s*=\s*\"?(\d{1,5})", body)
                facts["controls"].append({"kind": "open-ingress", "scope": name, "detail": "open to the internet" + (f" on {','.join(sorted(set(ports)))}" if ports else ""), "citation": cite})
        elif typ.startswith("aws_wafv2") or typ in ("azurerm_web_application_firewall_policy", "azurerm_cdn_frontdoor_firewall_policy"):
            facts["controls"].append({"kind": "waf", "scope": name, "detail": typ, "citation": cite})
        elif typ in ("aws_api_gateway_method", "aws_apigatewayv2_route"):
            auth = _first(r"authori[sz](?:ation|er_type)\s*=\s*\"(\w+)\"", body, "NONE") or "NONE"
            facts["controls"].append({"kind": "gateway-auth" if auth.upper() != "NONE" else "gateway-no-auth", "scope": name, "detail": f"authorization {auth}", "citation": cite})
        elif typ in ("aws_ecs_task_definition",):
            images = re.findall(r"\"image\"\s*[:=]\s*\"([^\"]+)\"", body)
            envn = [(a, b) for a, b in re.findall(r"\"?name\"?\s*[:=]\s*\"([A-Z_][A-Z0-9_]*)\"\s*,?\s*\"?value\"?\s*[:=]\s*\"([^\"]*)\"", body)]
            ports = [int(p) for p in re.findall(r"containerPort\"?\s*[:=]\s*(\d{1,5})", body)]
            facts["workloads"].append({"name": name, "kind": "ecs-task", "source": "ecs", "images": images[:4], "ports": ports[:6], "security": {}, "citation": cite,
                                       "env": [{"name": a, "source": "literal", "line": start, **({"value": safe_value(a, b)} if safe_value(a, b) is not None else {})} for a, b in envn][:40],
                                       "service_account": _first(r"task_role_arn\s*=\s*(\S+)", body), "exposure": {"kind": "none"}})
        elif typ in ("aws_lambda_function", "google_cloudfunctions_function", "azurerm_linux_function_app", "azurerm_function_app"):
            envn = re.findall(r"^[ \t]*([A-Z_][A-Z0-9_]*)\s*=\s*(\"[^\"]*\"|var\.\w+|\S+)", body[body.find("variables"):] if "variables" in body else body, re.M)
            facts["workloads"].append({"name": name, "kind": "function", "source": "terraform", "images": [], "ports": [], "security": {}, "citation": cite,
                                       "env": [{"name": a, "source": "literal" if b.startswith('"') else "variable", "line": start, **({"value": safe_value(a, b.strip('"'))} if b.startswith('"') and safe_value(a, b.strip('"')) is not None else {})} for a, b in envn][:30],
                                       "service_account": _first(r"role\s*=\s*(\S+)", body), "exposure": {"kind": "none"}})
        elif typ in ("azurerm_container_app",):
            ext = bool(re.search(r"external_enabled\s*=\s*true", body))
            facts["workloads"].append({"name": name, "kind": "container-app", "source": "terraform", "images": re.findall(r"image\s*=\s*\"([^\"]+)\"", body)[:3], "ports": [], "env": [], "security": {}, "citation": cite,
                                       "exposure": {"kind": "ingress" if ext else "none", "public": ext}})
        elif typ in ("google_cloud_run_service", "google_cloud_run_v2_service"):
            pub = bool(re.search(r"allUsers", body)) or "INGRESS_TRAFFIC_ALL" in body
            facts["workloads"].append({"name": name, "kind": "cloud-run", "source": "terraform", "images": re.findall(r"image\s*=\s*\"([^\"]+)\"", body)[:3], "ports": [], "env": [], "security": {}, "citation": cite,
                                       "exposure": {"kind": "ingress" if pub else "none", "public": pub}})


NGINX_CTL = [("auth_request", "gateway-auth"), ("limit_req", "rate-limit"), ("ssl_protocols", "tls"), ("modsecurity", "waf"), (r"\ballow\s+[\d.]+", "ip-allowlist"), (r"\bdeny\s+all", "ip-allowlist")]


def parse_gateway(repo, rel, text, facts):
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.strip()
        for rx, kind in NGINX_CTL:
            if re.search(rx, s):
                facts["controls"].append({"kind": kind, "scope": rel, "detail": s[:100], "citation": _cite(repo, rel, i)})
        m = re.search(r"proxy_pass\s+https?://([\w.-]+)", s)
        if m:
            facts["controls"].append({"kind": "proxy", "scope": rel, "detail": f"proxies to {m.group(1)}", "citation": _cite(repo, rel, i), "backends": [m.group(1)]})
        if re.search(r"(?i)\b(jwt|oidc|oauth2|basic-auth|key-auth|openid)\b", s) and ("plugin" in s.lower() or "filter" in s.lower() or "name" in s.lower()):
            facts["controls"].append({"kind": "gateway-auth", "scope": rel, "detail": s[:100], "citation": _cite(repo, rel, i)})


def scan_repo(repo: str, root: Path, excludes: list[str]) -> dict:
    facts = {"repo": repo, "workloads": [], "controls": [], "_services": [], "_ingresses": [], "_serviceaccounts": {}, "_lbs": []}
    for p, rel in walk_files(root, excludes):
        suffix = p.suffix.lower()
        name = p.name
        if suffix not in (".yaml", ".yml", ".tf", ".json", ".conf", ".tpl") and not name.startswith(("Dockerfile", "nginx", "envoy", "kong", "traefik")) and name != "Containerfile":
            continue
        text = read_text(p, max_bytes=600_000)
        if not text:
            continue
        try:
            if name.startswith("Dockerfile") or name == "Containerfile":
                parse_dockerfile(repo, rel, text, facts)
            elif suffix == ".tf":
                parse_terraform(repo, rel, text, facts)
            elif re.match(r"(docker-)?compose[^/]*\.ya?ml$", name) or (suffix in (".yaml", ".yml") and re.search(r"(?m)^services:[ \t]*$", text) and re.search(r"(?m)^[ \t]+(image|build):", text)):
                parse_compose(repo, rel, text, facts)
            elif suffix in (".yaml", ".yml", ".tpl") and re.search(r"(?m)^values.*\.ya?ml$", name) and ("/templates/" not in rel):
                parse_helm_values(repo, rel, text, facts)
            elif suffix in (".yaml", ".yml", ".tpl") and re.search(r"(?m)^kind:[ \t]*\w+", text) and "apiVersion" in text:
                parse_k8s(repo, rel, text, facts)
            elif re.search(r"(?i)nginx|envoy|kong|traefik|haproxy", name) or (suffix == ".conf" and re.search(r"proxy_pass|server_name", text)):
                parse_gateway(repo, rel, text, facts)
        except Exception as e:  # noqa: BLE001 - one hostile or odd file must not stop the other files or repos; it is listed, not hidden
            facts.setdefault("skipped", []).append({"path": rel, "reason": f"{type(e).__name__}: {str(e)[:80]}"})
    # exposure per workload from Services, Ingresses, load balancers
    svcs = {s["name"]: s for s in facts["_services"]}
    for w in facts["workloads"]:
        if w["source"] != "kubernetes":
            continue
        matching = [s for s in facts["_services"] if w["name"] in s["selector"] or s["name"] == w["name"]]
        ing = [i for i in facts["_ingresses"] if any(b in {s["name"] for s in matching} or b == w["name"] for b in i["backends"])]
        stype = next((s["type"] for s in matching if s["type"] in ("LoadBalancer", "NodePort")), matching[0]["type"] if matching else None)
        ext_ctl = [c for c in facts["controls"] if c["kind"] in ("gateway-auth", "mesh-auth", "jwt-auth", "mtls") and (w["name"] in c.get("backends", []) or any(s["name"] in c.get("backends", []) for s in matching) or w["name"] in c.get("selector", []))]
        w["exposure"] = {"kind": "ingress" if ing else ("loadbalancer" if stype == "LoadBalancer" else ("nodeport" if stype == "NodePort" else ("cluster-internal" if matching else "none"))),
                         "service_type": stype, "hosts": sorted({h for i in ing for h in i["hosts"]})[:4], "tls": any(i["tls"] for i in ing), "public": bool(ing) or stype in ("LoadBalancer", "NodePort"),
                         "citation": (ing[0]["citation"] if ing else matching[0]["citation"] if matching else None)}
        w["external_controls"] = [{"kind": c["kind"], "detail": c["detail"], "citation": c["citation"]} for c in ext_ctl]
        sa = facts["_serviceaccounts"].get(w.get("service_account") or "", {})
        if sa:
            w["identity"] = sa.get("identity")
    if any(c["kind"] == "network-policy" for c in facts["controls"]):
        for w in facts["workloads"]:
            if w["source"] == "kubernetes":
                w["network_policy"] = True
    public_sg = [c for c in facts["controls"] if c["kind"] == "open-ingress"]
    public_lb = [x for x in facts["_lbs"] if x["public"]]
    for w in facts["workloads"]:
        if w["source"] in ("ecs", "terraform") and w["kind"] in ("ecs-task", "function") and (public_lb or public_sg):
            w["exposure"] = {"kind": "loadbalancer" if public_lb else "open-security-group", "public": True, "citation": (public_lb or public_sg)[0]["citation"]}
    for k in ("_services", "_ingresses", "_serviceaccounts", "_lbs"):
        facts.pop(k, None)
    return facts


def link_workloads(all_facts: dict, repos: list[str]) -> None:
    """Resolve each workload to the application repo it runs: image name, build context, chart name, then name equality."""
    low = {r.lower(): r for r in repos}
    for repo, facts in all_facts.items():
        for w in facts["workloads"]:
            cands = []
            for img in w.get("images", []):
                nm = re.split(r"[:@]", img.split("/")[-1])[0].lower()
                cands.append((nm, "image"))
            if w.get("build"):
                cands.append((Path(str(w["build"]).strip("./") or ".").name.lower(), "build context"))
            if w.get("chart"):
                cands.append((w["chart"].lower(), "chart"))
            cands.append((w["name"].lower(), "name"))
            for nm, how in cands:
                tgt = low.get(nm) or next((low[k] for k in low if nm.startswith(k + "-") or nm.endswith("-" + k)), None)
                if tgt:
                    w["app_repo"], w["resolved_by"] = tgt, how
                    break
            else:
                if w["source"] == "dockerfile" or (w["source"] in ("compose",) and not w.get("images")):
                    w["app_repo"], w["resolved_by"] = repo, "same repo"


def run(out: Path, only: str | None = None) -> dict:
    roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
    all_facts = {}
    for repo, root in roots.items():
        f = scan_repo(repo, Path(root), repo_excludes(out).get(repo, []))
        if f["workloads"] or f["controls"]:
            all_facts[repo] = f
    link_workloads(all_facts, list(roots))
    lines, stats = [], {}
    if not only:  # evidence of repos that no longer hold deployment content must not feed the threat model
        for p in (out / "evidence").glob("deploy-facts-*.json"):
            if p.name[len("deploy-facts-"):-len(".json")] not in all_facts:
                p.unlink()
    gp = graph_dir(out) / "graph.json"
    graph = json.loads(gp.read_text()) if gp.is_file() else {"nodes": []}
    envnodes = {(n["repo"], n["name"]): n["id"] for n in graph["nodes"] if n["kind"] == "env_var"}
    for repo, facts in all_facts.items():
        if only and repo != only:
            continue
        atomic_write(out / "evidence" / f"deploy-facts-{repo}.json", redact_text(json.dumps(facts, indent=1)))
        stats[repo] = {"workloads": len(facts["workloads"]), "controls": len(facts["controls"]), "linked": sum(1 for w in facts["workloads"] if w.get("app_repo")), "dropped_unverifiable": 0}
        for w in facts["workloads"]:
            ar = w.get("app_repo")
            if not ar:
                continue
            nid = f"service:{repo}::{w['name']}"
            cite = w["citation"]
            rel_line = cite.split("/", 1)[1] if "/" in cite else cite
            quote = safe_quote(_line_at(roots[repo], rel_line))
            if not quote:
                stats[repo]["dropped_unverifiable"] += 1  # its source line could not be re-read: listed in the evidence JSON but not added to the graph
                continue
            lines.append({"op": "node", "kind": "service", "repo": repo, "qualname": w["name"], "name": w["name"], "citation": cite, "quote": quote, "confidence": "medium", "label": "inferred",
                          "extractor": "rule", "attrs": {"workload_kind": w["kind"], "source": w["source"], "exposure": (w.get("exposure") or {}).get("kind"), "public": (w.get("exposure") or {}).get("public"),
                                                          "images": w.get("images", [])[:3], "app_repo": ar, "resolved_by": w.get("resolved_by")}})
            app_cite = next((n["citation"] for n in graph["nodes"] if n["kind"] == "file" and n["repo"] == ar and n.get("citation")), None)
            lines.append({"op": "edge", "src": nid, "kind": "deploys", "dst": f"repo:{ar}::{ar}", "citation": cite, "quote": quote, "confidence": "medium" if w.get("resolved_by") in ("image", "build context", "chart", "same repo") else "low",
                          "label": "inferred", "extractor": "rule", "dst_citation": app_cite if ar != repo else None, "attrs": {"via": w.get("resolved_by")}})
            for e in w.get("env", []):
                ev = envnodes.get((ar, e["name"]))
                eline = f"{repo}/{rel_line.rsplit(':', 1)[0]}:{e['line']}"
                eq = safe_quote(_line_at(roots[repo], f"{rel_line.rsplit(':', 1)[0]}:{e['line']}"))
                if eq and (SECRETISH.search(e["name"]) or safe_value(e["name"], re.split(r"[:=]", eq, 1)[-1].strip(" '\"-")) is None):
                    eq = e["name"]  # never copy a value line for a secret-like name: quote only the name (it appears in the cited line)
                if ev and eq:
                    lines.append({"op": "edge", "src": ev, "kind": "configured_by", "dst": nid, "citation": eline, "quote": eq, "confidence": "medium", "label": "observed", "extractor": "rule",
                                  "dst_citation": cite if ar != repo else None, "attrs": {"source": e["source"], **({"value": e["value"]} if "value" in e else {})}})
    pp = graph_dir(out) / "proposals" / "seed-deploy.jsonl"
    if lines:
        pp.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(pp, "\n".join(json.dumps(x) for x in lines) + "\n")
    elif pp.exists():
        pp.unlink()
    return stats


def _line_at(root, rel_line: str) -> str:
    rel, _, ln = rel_line.rpartition(":")
    try:
        txt = (Path(root) / rel).read_text(errors="replace").splitlines()
        i = int(ln)
        return txt[i - 1].strip() if 0 < i <= len(txt) else ""
    except (OSError, ValueError):
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo")
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve(), a.repo), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
