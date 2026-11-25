"""Entry-point, taint-source and sink patterns for the regex extractor (every language except the Python AST path).

Pure functions over text lines; nothing here reads files or executes anything. Used by graph_extract.py.

  find_entries(lang, rel, lines)  -> entry points (http endpoints, consumers, cron jobs, CLI commands, gRPC services)
  line_sources(lang, line)        -> [(source_type, label)] user-controlled inputs read on this line
  line_sinks(lang, line, text)    -> [(sink_type, safe, reason, confidence)] dangerous operations on this line

Everything is a heuristic over single lines (plus a few lines of look-ahead for annotations). The extractor labels
results medium/low confidence; flows between a source and a sink are only ever candidate paths.
"""
from __future__ import annotations

import re

HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")


# ---------------------------------------------------------------- shared helpers

def join_path(prefix: str, path: str) -> str:
    p = "/" + "/".join(x for x in (prefix or "").strip("/").split("/") + (path or "").strip("/").split("/") if x)
    return p if p != "" else "/"


def arg_kind(arg: str, lang: str = "") -> str:
    """'literal' (constant string), 'inline' (string built with concatenation/interpolation), or 'variable' (non-literal)."""
    a = (arg or "").strip()
    if not a:
        return "variable"
    if re.match(r"^&?(?:format!|String::from\(.*\)\s*\+|\w+\.to_string\(\)\s*\+)", a):
        return "inline"
    m = re.match(r'^(?:@|\$|f|r|b|F)?("""|\'\'\'|"|\'|`)', a)
    if not m:
        return "variable"
    q = m.group(1)
    end = a.find(q, m.end())
    body = a[m.end(): end if end != -1 else None]
    rest = a[end + len(q):] if end != -1 else ""
    interp = bool(re.search(r"\$\{|#\{|%s|%d|%\(|\{\w", body)) and not (a[0] == "'" and lang in ("php",))
    if lang == "php" and q == '"' and re.search(r"\$\w|\{\$", body):
        interp = True
    if a[0] in "$fF" and "{" in body:
        interp = True
    concat = bool(re.match(r"\s*(\+|\.\s|\.\$|&\s|\|\|)", rest))
    return "inline" if interp or concat else "literal"


class Groups:
    """Indentation-scoped path prefixes (Laravel Route::prefix()->group, Rails namespace/scope blocks)."""

    def __init__(self):
        self.stack: list[tuple[int, str]] = []

    def enter(self, indent: int, prefix: str):
        self.stack.append((indent, prefix))

    def at(self, indent: int, line: str) -> str:
        s = line.lstrip()
        while self.stack and indent <= self.stack[-1][0] and (s.startswith(("}", "end", ")")) or indent < self.stack[-1][0]):
            self.stack.pop()
        return "/".join(p for _, p in self.stack)


def _indent(ln: str) -> int:
    return len(ln) - len(ln.lstrip())


def _entry(kind, line, name, **kw):
    e = {"kind": kind, "line": line, "name": name, "near": kw.pop("near", True), "method": kw.pop("method", None), "path": kw.pop("path", None),
         "handler": kw.pop("handler", None), "proto": kw.pop("proto", "http"), "queue": kw.pop("queue", None),
         "inline": kw.pop("inline", False), "defer": kw.pop("defer", False)}
    e.update(kw)
    return e


def _next_is_class(lines, i, span=5):
    for j in range(i, min(len(lines), i + span)):
        s = lines[j].strip()
        if re.search(r"\b(class|interface|object|struct)\s+\w+", s) and "(" not in s.split("class")[0]:
            m = re.search(r"\b(?:class|interface|object|struct)\s+(\w+)", s)
            return m.group(1) if m else ""
        if s and not s.startswith(("@", "[", "#[", "/", "*", "//")) and not s.endswith(("]", ",")):
            return None
    return None


# ---------------------------------------------------------------- entry points

SPRING_METHOD = re.compile(r"@(Get|Post|Put|Patch|Delete)Mapping\b(?:\(([^)]*)\))?")
SPRING_RM = re.compile(r"@RequestMapping\b(?:\(([^)]*)\))?")
JAXRS_VERB = re.compile(r"@(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
JAXRS_PATH = re.compile(r"@Path\(\s*\"([^\"]*)\"\s*\)")
LISTENER = re.compile(r"@(KafkaListener|RabbitListener|SqsListener|JmsListener|ServiceBusListener|PubSubListener)\b(?:\(([^)]*)\))?")
SCHEDULED = re.compile(r"@Scheduled\b(?:\(([^)]*)\))?")


def _str_arg(args: str | None, keys=("value", "path", "name", "topics", "queues", "destination")) -> str | None:
    if not args:
        return None
    for k in keys:
        m = re.search(rf'\b{k}\s*=\s*\{{?\s*"([^"]*)"', args)
        if m:
            return m.group(1)
    m = re.match(r'\s*\{?\s*"([^"]*)"', args)
    return m.group(1) if m else None


def _java_entries(lines):
    out, prefix = [], ""
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        m = SPRING_RM.search(ln)
        if m:
            cls = _next_is_class(lines, i - 1)
            path = _str_arg(m.group(1), ("value", "path")) or ""
            if cls is not None:
                prefix = path
            else:
                meth = re.search(r"RequestMethod\.(\w+)", m.group(1) or "")
                out.append(_entry("endpoint", i, f"{(meth.group(1) if meth else 'ANY')} {join_path(prefix, path)}",
                                  method=(meth.group(1) if meth else "ANY"), path=join_path(prefix, path)))
            continue
        m = SPRING_METHOD.search(ln)
        if m:
            path = _str_arg(m.group(2), ("value", "path")) or ""
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {join_path(prefix, path)}", method=m.group(1).upper(), path=join_path(prefix, path)))
            continue
        m = JAXRS_PATH.search(ln)
        if m:
            cls = _next_is_class(lines, i - 1)
            if cls is not None:
                prefix = m.group(1)
                continue
            verb = next((JAXRS_VERB.search(lines[j]).group(1) for j in range(max(0, i - 4), min(len(lines), i + 3)) if JAXRS_VERB.search(lines[j])), "ANY")
            out.append(_entry("endpoint", i, f"{verb} {join_path(prefix, m.group(1))}", method=verb, path=join_path(prefix, m.group(1))))
            continue
        m = JAXRS_VERB.search(ln)
        if m and not any(JAXRS_PATH.search(lines[j]) for j in range(max(0, i - 4), min(len(lines), i + 3))) and _next_is_class(lines, i - 1) is None \
                and re.search(r"\w+\s*\(", "".join(lines[i:i + 3])):
            out.append(_entry("endpoint", i, f"{m.group(1)} {join_path(prefix, '')}", method=m.group(1), path=join_path(prefix, "")))
            continue
        m = LISTENER.search(ln)
        if m:
            q = _str_arg(m.group(2), ("topics", "queues", "destination", "value", "name"))
            out.append(_entry("consumer", i, f"consume {q or m.group(1)}", queue=q, proto=m.group(1)))
            continue
        m = SCHEDULED.search(ln)
        if m:
            spec = re.search(r'cron\s*=\s*"([^"]+)"', m.group(1) or "") or re.search(r"(fixed(?:Rate|Delay)\s*=\s*[\w.]+)", m.group(1) or "")
            out.append(_entry("cron_job", i, f"schedule {spec.group(1) if spec else 'unspecified'}"))
            continue
        m = re.search(r"@Controller\(\s*\"([^\"]*)\"\s*\)", ln)  # Micronaut/Quarkus-style class prefix
        if m and _next_is_class(lines, i - 1) is not None:
            prefix = m.group(1)
            continue
        m = re.search(r"@(Get|Post|Put|Patch|Delete)\(\s*(?:value\s*=\s*)?\"([^\"]*)\"", ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {join_path(prefix, m.group(2))}", method=m.group(1).upper(), path=join_path(prefix, m.group(2))))
            continue
        m = re.search(r"@WebServlet\(\s*(?:urlPatterns\s*=\s*|value\s*=\s*)?\{?\s*\"([^\"]+)\"", ln)
        if m:
            prefix = m.group(1)
            continue
        m = re.search(r"\bvoid\s+do(Get|Post|Put|Delete)\s*\(\s*(?:final\s+)?HttpServletRequest", ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {join_path(prefix, '')}", method=m.group(1).upper(), path=join_path(prefix, "")))
            continue
        m = re.search(r"\b(?:router|r)\.(get|post|put|patch|delete)\(\s*\"([^\"]+)\"\s*\)\.handler\(\s*([\w:.]+)", ln)
        if m:
            h = m.group(3).split("::")[-1].split(".")[-1]
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=m.group(1).upper(), path=m.group(2), handler=h, defer=True, near=False))
    return out


CS_HTTP = re.compile(r'\[Http(Get|Post|Put|Patch|Delete|Head|Options)(?:\(\s*"([^"]*)"[^)]*\))?\]')
CS_ROUTE = re.compile(r'\[Route\(\s*"([^"]*)"\s*\)\]')
CS_MIN = re.compile(r'\.Map(Get|Post|Put|Patch|Delete)\(\s*"([^"]+)"\s*,\s*([\w.]+)?')
CS_FUNC = re.compile(r'\[Function(?:Name)?\(\s*"([^"]+)"\s*\)\]')
CS_HTTPTRIG = re.compile(r"\[HttpTrigger\(([^)]*)\)")
CS_TRIG = re.compile(r'\[(TimerTrigger|QueueTrigger|ServiceBusTrigger|EventHubTrigger|KafkaTrigger|BlobTrigger|EventGridTrigger)\(\s*"?([^",)]*)')


def _cs_entries(lines):
    out, prefix, cls_name = [], "", ""
    func_name = None
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        m = re.search(r"\bclass\s+(\w+)", ln)
        if m:
            cls_name = m.group(1)
        m = CS_ROUTE.search(ln)
        if m:
            cls = _next_is_class(lines, i - 1)
            tmpl = m.group(1)
            if cls is not None:
                prefix = tmpl.replace("[controller]", re.sub(r"Controller$", "", cls).lower())
            else:
                verb = next((CS_HTTP.search(lines[j]).group(1).upper() for j in range(max(0, i - 4), min(len(lines), i + 3)) if CS_HTTP.search(lines[j])), "ANY")
                out.append(_entry("endpoint", i, f"{verb} {join_path(prefix, tmpl)}", method=verb, path=join_path(prefix, tmpl)))
            continue
        m = CS_HTTP.search(ln)
        if m:
            tmpl = m.group(2) or ""
            pfx = prefix.replace("[controller]", re.sub(r"Controller$", "", cls_name).lower())
            if m.group(2) is None and any(CS_ROUTE.search(lines[j]) for j in range(max(0, i - 3), min(len(lines), i + 3)) if j != i - 1):
                continue
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {join_path(pfx, tmpl)}", method=m.group(1).upper(), path=join_path(pfx, tmpl)))
            continue
        m = CS_MIN.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=m.group(1).upper(), path=m.group(2),
                              handler=m.group(3), inline=not m.group(3)))
            continue
        m = CS_FUNC.search(ln)
        if m:
            func_name = m.group(1)
            continue
        m = CS_HTTPTRIG.search(ln)
        if m:
            rt = re.search(r'Route\s*=\s*"([^"]*)"', m.group(1))
            meths = re.findall(r'"(get|post|put|patch|delete)"', m.group(1), re.I)
            path = "/api/" + (rt.group(1) if rt else (func_name or "function")).lstrip("/")
            out.append(_entry("endpoint", i, f"{(meths[0].upper() if len(meths) == 1 else 'ANY')} {path}", method=(meths[0].upper() if len(meths) == 1 else "ANY"), path=path))
            continue
        m = CS_TRIG.search(ln)
        if m:
            if m.group(1) == "TimerTrigger":
                out.append(_entry("cron_job", i, f"schedule {m.group(2)}"))
            else:
                out.append(_entry("consumer", i, f"consume {m.group(2) or m.group(1)}", queue=m.group(2), proto=m.group(1)))
    return out


RB_SINATRA = re.compile(r"^\s*(get|post|put|patch|delete|options|head)\s+['\"](/?[^'\"]*)['\"].*\b(?:do|\{)\s*(\|.*\|)?\s*$")
RB_VERB = re.compile(r"^\s*(get|post|put|patch|delete|match|any)\s+['\"]?:?([\w/:.\-*]+)['\"]?(.*)$")
RB_TO = re.compile(r"(?:to:|=>)\s*['\"](\w+(?:/\w+)*)#(\w+)['\"]")
RB_RES = re.compile(r"^\s*resources?\s+:(\w+)(?:\s*,\s*(.*))?")
RB_SCOPE = re.compile(r"^\s*(?:namespace|scope)\s+(?::|['\"])(\w[\w/]*)['\"]?.*\bdo\b")
RB_REST = [("GET", ""), ("POST", ""), ("GET", "/:id"), ("PUT", "/:id"), ("PATCH", "/:id"), ("DELETE", "/:id")]


def _rb_entries(rel, lines):
    out, g = [], Groups()
    is_routes = rel.endswith("routes.rb") or "/routes/" in rel
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400 or ln.lstrip().startswith("#"):
            continue
        if not is_routes:
            m = RB_SINATRA.match(ln)
            if m:
                out.append(_entry("endpoint", i, f"{m.group(1).upper()} {join_path('', m.group(2))}", method=m.group(1).upper(), path=join_path("", m.group(2)), inline=True))
                continue
            m = re.match(r"^\s*include\s+Sidekiq::(?:Worker|Job)\b", ln)
            if m:
                cls = next((re.match(r"^\s*class\s+(\w+)", lines[j]).group(1) for j in range(i - 2, max(-1, i - 6), -1) if re.match(r"^\s*class\s+\w+", lines[j])), "worker")
                out.append(_entry("consumer", i, f"consume job {cls}", queue=cls, proto="sidekiq", handler="perform", near=True))
            continue
        ind = _indent(ln)
        pfx = g.at(ind, ln)
        m = RB_SCOPE.match(ln)
        if m:
            g.enter(ind, m.group(1))
            continue
        m = RB_RES.match(ln)
        if m:
            name, opts = m.group(1), m.group(2) or ""
            only = re.search(r"only:\s*\[([^\]]*)\]", opts)
            allowed = {x.strip(" :'\"") for x in only.group(1).split(",")} if only else None
            act = {("GET", ""): "index", ("POST", ""): "create", ("GET", "/:id"): "show", ("PUT", "/:id"): "update", ("PATCH", "/:id"): "update", ("DELETE", "/:id"): "destroy"}
            for meth, suffix in RB_REST:
                if allowed is not None and act[(meth, suffix)] not in allowed:
                    continue
                path = join_path(pfx, name + suffix)
                out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=act[(meth, suffix)], defer=True,
                                  controller=name))
            continue
        m = RB_VERB.match(ln)
        if m and m.group(1) not in ("get",) or (m and m.group(1) == "get"):
            to = RB_TO.search(m.group(3))
            meth = m.group(1).upper() if m.group(1) not in ("match", "any") else "ANY"
            path = join_path(pfx, m.group(2))
            out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=to.group(2) if to else None, defer=bool(to),
                              controller=to.group(1) if to else None))
    return out


PHP_ROUTE = re.compile(r"Route::(get|post|put|patch|delete|options|any|match)\(\s*(?:\[[^\]]*\]\s*,\s*)?['\"]([^'\"]*)['\"]\s*(?:,\s*(.*))?")
PHP_PREFIX = re.compile(r"(?:Route::prefix\(\s*['\"]([^'\"]*)['\"]\s*\)|->prefix\(\s*['\"]([^'\"]*)['\"]\s*\)|['\"]prefix['\"]\s*=>\s*['\"]([^'\"]*)['\"]).*(?:group|function)")
PHP_SYMFONY = re.compile(r"(?:#\[Route\(\s*['\"]([^'\"]*)['\"]|@Route\(\s*\"([^\"]*)\")(.*)")
PHP_CRON = re.compile(r"\$schedule->(command|job|call)\(([^)]*)\)")


def _php_entries(lines):
    out, g, cls_prefix = [], Groups(), ""
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        ind = _indent(ln)
        pfx = g.at(ind, ln)
        m = PHP_PREFIX.search(ln)
        if m:
            g.enter(ind, next(x for x in m.groups() if x is not None))
            continue
        m = PHP_ROUTE.search(ln)
        if m:
            rest = m.group(3) or ""
            meth = m.group(1).upper() if m.group(1) not in ("any", "match") else "ANY"
            hm = re.search(r"\[\s*[\w\\]+::class\s*,\s*['\"](\w+)['\"]\s*\]", rest) or re.search(r"['\"][\w\\]+@(\w+)['\"]", rest)
            inline = "function" in rest or "fn" in rest.split("(")[0]
            path = join_path(pfx, m.group(2))
            out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=hm.group(1) if hm else None, inline=inline and not hm, defer=bool(hm)))
            continue
        m = PHP_SYMFONY.search(ln)
        if m:
            path = m.group(1) or m.group(2)
            cls = _next_is_class(lines, i - 1)
            if cls is not None:
                cls_prefix = path
                continue
            mm = re.search(r"methods[:=]\s*[\[{]\s*['\"](\w+)['\"]", m.group(3) or "")
            meth = mm.group(1).upper() if mm else "ANY"
            out.append(_entry("endpoint", i, f"{meth} {join_path(cls_prefix, path)}", method=meth, path=join_path(cls_prefix, path)))
            continue
        m = PHP_CRON.search(ln)
        if m:
            out.append(_entry("cron_job", i, f"schedule {m.group(2).strip()[:40]}"))
            continue
        m = re.search(r"\badd_action\(\s*['\"]wp_ajax(?:_nopriv)?_(\w+)['\"]\s*,\s*(?:['\"]([\w:]+)['\"]|\[[^,\]]+,\s*['\"](\w+)['\"]\s*\])", ln)
        if m:
            h = m.group(2) or m.group(3)
            out.append(_entry("endpoint", i, f"POST /wp-admin/admin-ajax.php?action={m.group(1)}", method="POST", path=f"/wp-admin/admin-ajax.php?action={m.group(1)}", handler=h.split("::")[-1], defer=True, near=False))
            continue
        m = re.search(r"\bregister_rest_route\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*(.*)", ln)
        if m:
            tail = " ".join(lines[i - 1:i + 6])
            vm = re.search(r"['\"]methods['\"]\s*=>\s*['\"]?(?:WP_REST_Server::)?([A-Za-z]+)", tail)
            hm = re.search(r"['\"]callback['\"]\s*=>\s*(?:['\"]([\w:]+)['\"]|\[[^,\]]+,\s*['\"](\w+)['\"]\s*\])", tail)
            meth = {"READABLE": "GET", "CREATABLE": "POST", "EDITABLE": "PUT", "DELETABLE": "DELETE"}.get((vm.group(1) if vm else "").upper(), (vm.group(1) if vm else "ANY").upper())
            path = join_path("wp-json/" + m.group(1), m.group(2))
            out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=(hm.group(1) or hm.group(2)).split("::")[-1] if hm else None, defer=bool(hm), near=False))
            continue
        m = re.search(r"\$\w+->(get|post|put|patch|delete)\(\s*['\"](/[^'\"]*)['\"]\s*,\s*(.*)", ln)  # Slim
        if m:
            hm = re.search(r"\[\s*[\w\\]+::class\s*,\s*['\"](\w+)['\"]\s*\]|['\"][\w\\]+:(\w+)['\"]", m.group(3))
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=m.group(1).upper(), path=m.group(2), handler=(hm.group(1) or hm.group(2)) if hm else None,
                              defer=bool(hm), inline=not hm and "function" in m.group(3), near=False))
            continue
        m = re.search(r"Route::(?:api)?[Rr]esource\(\s*['\"]([\w./-]+)['\"]\s*,\s*([\w\\]+)::class", ln)
        if m:
            base = join_path(pfx, m.group(1))
            for meth_, suffix, act in (("GET", "", "index"), ("POST", "", "store"), ("GET", "/{id}", "show"), ("PUT", "/{id}", "update"), ("DELETE", "/{id}", "destroy")):
                out.append(_entry("endpoint", i, f"{meth_} {base}{suffix}", method=meth_, path=base + suffix, handler=act, defer=True, near=False, controller=m.group(2).split("\\")[-1]))
            continue
    return out


JS_RECV_SKIP = {"axios", "http", "https", "request", "got", "superagent", "fetch", "client", "$http", "ky", "cache", "map", "headers",
                "req", "res", "localStorage", "sessionStorage", "session", "Reflect", "Object", "params", "searchParams", "config",
                "settings", "store", "this", "process", "env", "formData", "form", "url", "URLSearchParams", "memo", "redis", "storage"}
JS_ROUTE = re.compile(r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all|head|options)\(\s*['\"`](/[^'\"`]*)['\"`]\s*(?:,\s*(.*))?")
JS_ROUTE_CHAIN = re.compile(r"\.route\(\s*['\"`]([^'\"`]*)['\"`]\s*\)")
JS_CHAIN_VERB = re.compile(r"\.(get|post|put|patch|delete|all)\(")
HAPI = re.compile(r"method\s*:\s*['\"](\w+)['\"].*path\s*:\s*['\"]([^'\"]+)['\"]|path\s*:\s*['\"]([^'\"]+)['\"].*method\s*:\s*['\"](\w+)['\"]")
NEST_CTRL = re.compile(r"@Controller\(\s*(?:['\"]([^'\"]*)['\"])?\s*\)")
NEST_VERB = re.compile(r"@(Get|Post|Put|Patch|Delete|All|Options|Head)\(\s*(?:['\"]([^'\"]*)['\"])?\s*\)")
NEST_MSG = re.compile(r"@(MessagePattern|EventPattern)\(\s*['\"]([^'\"]+)['\"]")
NEST_CRON = re.compile(r"@(Cron|Interval|Timeout)\(\s*['\"]?([^'\")]*)")
JS_CRON = re.compile(r"\b(?:cron\.schedule|schedule\.scheduleJob|agenda\.define|new CronJob)\(\s*['\"]([^'\"]+)['\"]")
JS_CLI = re.compile(r"\b(program|cli|yargs|argv|cmd|app)\.command\(\s*['\"]([^'\"]+)['\"]")
JS_WORKER = re.compile(r"new Worker\(\s*['\"]([^'\"]+)['\"]|\.process\(\s*['\"]([^'\"]+)['\"]")


def _js_entries(rel, lines):
    out, prefix, in_chain = [], "", None
    for i, ln in enumerate(lines, 1):
        if len(ln) > 500:
            continue
        m = NEST_CTRL.search(ln)
        if m:
            prefix = m.group(1) or ""
            continue
        m = NEST_VERB.search(ln)
        if m:
            meth = m.group(1).upper() if m.group(1) != "All" else "ANY"
            out.append(_entry("endpoint", i, f"{meth} {join_path(prefix, m.group(2) or '')}", method=meth, path=join_path(prefix, m.group(2) or "")))
            continue
        m = NEST_MSG.search(ln)
        if m:
            out.append(_entry("consumer", i, f"consume {m.group(2)}", queue=m.group(2), proto=m.group(1)))
            continue
        m = NEST_CRON.search(ln)
        if m:
            out.append(_entry("cron_job", i, f"schedule {m.group(2) or m.group(1)}"))
            continue
        m = JS_ROUTE.search(ln)
        if m and m.group(1) not in JS_RECV_SKIP:
            meth = m.group(2).upper() if m.group(2) != "all" else "ANY"
            out.append(_entry("endpoint", i, f"{meth} {m.group(3)}", method=meth, path=m.group(3), inline=True, recv=m.group(1)))
            continue
        m = JS_ROUTE_CHAIN.search(ln)
        if m:
            verbs = JS_CHAIN_VERB.findall(ln)
            j = i
            while not verbs and j < min(len(lines), i + 6):  # chained on the following lines
                verbs = JS_CHAIN_VERB.findall(lines[j])
                j += 1
            for v in verbs or ["all"]:
                meth = v.upper() if v != "all" else "ANY"
                out.append(_entry("endpoint", i, f"{meth} {m.group(1)}", method=meth, path=m.group(1), inline=True))
            continue
        m = HAPI.search(ln)
        if m:
            meth, path = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))
            out.append(_entry("endpoint", i, f"{meth.upper()} {path}", method=meth.upper(), path=path, inline=True))
            continue
        m = JS_CRON.search(ln)
        if m:
            out.append(_entry("cron_job", i, f"schedule {m.group(1)}"))
            continue
        m = JS_CLI.search(ln)
        if m:
            out.append(_entry("cli_command", i, f"command {m.group(2)}"))
            continue
        m = JS_WORKER.search(ln)
        if m:
            q = m.group(1) or m.group(2)
            out.append(_entry("consumer", i, f"consume {q}", queue=q, proto="bull"))
    mounts = {}
    for ln in lines:  # app.use('/api', router) in the same file prefixes the router's routes
        mm_ = re.search(r"\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*(?:[\w$.]+\s*,\s*)*([A-Za-z_$][\w$]*)\s*\)", ln)
        if mm_:
            mounts[mm_.group(2)] = mm_.group(1)
    for e in out:
        if e["kind"] == "endpoint" and e.get("recv") in mounts:
            e["path"] = join_path(mounts[e["recv"]], e["path"])
            e["name"] = f"{e['method']} {e['path']}"
    for i, ln in enumerate(lines, 1):  # tRPC procedures
        m = re.match(r"^\s*(\w+)\s*:\s*(?:\w+\.)*(?:publicProcedure|protectedProcedure|procedure|authedProcedure)\b", ln)
        if m:
            tail = " ".join(lines[i - 1:i + 6])
            meth = "POST" if re.search(r"\.mutation\(", tail) else "GET"
            out.append(_entry("endpoint", i, f"{meth} /trpc/{m.group(1)}", method=meth, path=f"/trpc/{m.group(1)}", proto="trpc", near=False, enclosing=True))
    # Next.js file-based routing
    mm = re.match(r"^(?:src/)?(pages/api|app)/(.*)\.(?:[jt]sx?)$", rel)
    if mm:
        parts = [re.sub(r"^\[\.\.\.(\w+)\]$|^\[(\w+)\]$", "{p}", p) for p in mm.group(2).split("/") if not re.match(r"^\(.*\)$", p)]
        if mm.group(1) == "pages/api":
            path = "/api/" + "/".join(x for x in parts if x != "index")
            out.append(_entry("endpoint", 1, f"ANY {path.rstrip('/') or '/api'}", method="ANY", path=path.rstrip("/") or "/api", defer=False, handler="handler"))
        elif parts and parts[-1] == "route":
            path = "/" + "/".join(parts[:-1])
            for i, ln in enumerate(lines, 1):
                m = re.match(r"^\s*export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", ln)
                if m:
                    out.append(_entry("endpoint", i, f"{m.group(1)} {path or '/'}", method=m.group(1), path=path or "/", handler=m.group(1)))
    return out


GO_ROUTE = re.compile(r"\.(HandleFunc|Handle|MethodFunc|Method|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Get|Post|Put|Patch|Delete|Head|Options|Any)\(\s*(?:\"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\"\s*,\s*)?\"([^\"]+)\"\s*(?:,\s*([A-Za-z_][\w.]*))?")
GO_METHODS = re.compile(r"\.Methods\(\s*\"(\w+)\"")
GO_GRPC = re.compile(r"\bRegister(\w+)Server\(")
GO_COBRA = re.compile(r"cobra\.Command\{")
GO_CRON = re.compile(r"\.(?:AddFunc|Every|Cron)\(\s*\"([^\"]+)\"(?:\s*,\s*([\w.]+))?")


def _go_entries(lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        m = GO_ROUTE.search(ln)
        if m:
            name, meth, path, h = m.groups()
            if name in ("HandleFunc", "Handle", "Method", "MethodFunc"):
                if name in ("Method", "MethodFunc"):
                    continue
                parts = path.split(" ", 1)
                if len(parts) == 2 and parts[0] in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    meth, path = parts
                gm = GO_METHODS.search(ln)
                meth = meth or (gm.group(1).upper() if gm else "ANY")
            else:
                meth = name.upper() if name.upper() != "ANY" else "ANY"
            if path.startswith("/") or " " in path:
                out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=h, defer=bool(h) and h != "func", near=False))
            continue
        m = GO_GRPC.search(ln)
        if m and m.group(1) not in ("Reflection", "Health", "Channelz"):
            out.append(_entry("endpoint", i, f"GRPC /{m.group(1)}", method="GRPC", path=f"/{m.group(1)}", proto="grpc", near=False))
            continue
        if GO_COBRA.search(ln):
            use = next((re.search(r'Use:\s*"([^"]+)"', lines[j]) for j in range(i - 1, min(len(lines), i + 8)) if re.search(r'Use:\s*"', lines[j])), None)
            run = next((re.search(r"RunE?:\s*([A-Za-z_][\w.]*)", lines[j]) for j in range(i - 1, min(len(lines), i + 10)) if re.search(r"RunE?:\s*[A-Za-z_]", lines[j])), None)
            if use:
                out.append(_entry("cli_command", i, f"command {use.group(1).split()[0]}", handler=run.group(1) if run else None, defer=bool(run), inline=not run))
            continue
        m = GO_CRON.search(ln)
        if m and re.search(r"\b(cron|c|scheduler|s)\.", ln):
            out.append(_entry("cron_job", i, f"schedule {m.group(1)}", handler=m.group(2), defer=bool(m.group(2))))
    return out


RS_ATTR = re.compile(r"#\[(get|post|put|patch|delete|head|options)\(\s*\"([^\"]*)\"")
RS_AXUM = re.compile(r"\.route\(\s*\"([^\"]+)\"\s*,\s*(.*)")
RS_VERB = re.compile(r"\b(get|post|put|patch|delete|any|head|options)\(\s*([\w:]+)\s*\)")
RS_ACTIX = re.compile(r"(?:web::resource\(\s*\"([^\"]+)\"\s*\)\s*)?\.route\(\s*(?:\"([^\"]+)\"\s*,\s*)?web::(get|post|put|patch|delete)\(\)\s*\.to\(\s*([\w:]+)")
RS_WARP = re.compile(r"warp::path!?\(\s*\"([^\"]+)\"")


def _rust_entries(lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        m = RS_ATTR.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=m.group(1).upper(), path=m.group(2)))
            continue
        m = RS_AXUM.search(ln)
        if m:
            for vm in RS_VERB.finditer(m.group(2)):
                meth = vm.group(1).upper() if vm.group(1) != "any" else "ANY"
                out.append(_entry("endpoint", i, f"{meth} {m.group(1)}", method=meth, path=m.group(1), handler=vm.group(2).split("::")[-1], defer=True, near=False))
            continue
        m = RS_ACTIX.search(ln)
        if m and (m.group(1) or m.group(2)):
            path = m.group(1) or m.group(2)
            out.append(_entry("endpoint", i, f"{m.group(3).upper()} {path}", method=m.group(3).upper(), path=path, handler=m.group(4).split("::")[-1], defer=True, near=False))
            continue
        m = RS_WARP.search(ln)
        if m:
            tail = " ".join(lines[i - 1:i + 3])
            vm = re.search(r"warp::(get|post|put|patch|delete)\(\)", tail)
            hm = re.search(r"\.(?:and_then|map|then)\(\s*([\w:]+)\s*\)", tail)
            meth = vm.group(1).upper() if vm else "ANY"
            out.append(_entry("endpoint", i, f"{meth} /{m.group(1).strip('/')}", method=meth, path="/" + m.group(1).strip("/"), handler=hm.group(1).split("::")[-1] if hm else None, defer=bool(hm), near=False))
            continue
        if re.search(r"#\[derive\([^)]*\bParser\b", ln) or re.search(r"\bCommand::new\(\s*\"([^\"]+)\"\s*\)\s*\.(?:about|version|arg|subcommand)", ln):
            out.append(_entry("cli_command", i, "command " + (re.search(r"Command::new\(\s*\"([^\"]+)\"", ln) or [None, "clap"])[1]))
            continue
        m = re.search(r"\bJob::new(?:_async|_repeated)?\(\s*\"([^\"]+)\"", ln)
        if m:
            out.append(_entry("cron_job", i, f"schedule {m.group(1)}"))
            continue
        m = re.search(r"\bservice_fn\(\s*([\w:]+)\s*\)", ln)
        if m:
            out.append(_entry("endpoint", i, f"ANY lambda/{m.group(1).split('::')[-1]}", method="ANY", path="/lambda", handler=m.group(1).split("::")[-1], defer=True, near=False, proto="lambda"))
        m = re.match(r"^\s*impl\s+(\w+)\s+for\s+(\w+)", ln)
        if m and any("async_trait" in lines[j] for j in range(max(0, i - 3), i)) and m.group(1)[0].isupper() and m.group(1) not in ("Drop", "Display", "Debug", "Clone"):
            depth = 0
            for j in range(i - 1, min(len(lines), i + 400)):
                depth += lines[j].count("{") - lines[j].count("}")
                fm = re.match(r"^\s*async\s+fn\s+(\w+)", lines[j])
                if fm:
                    out.append(_entry("endpoint", j + 1, f"GRPC /{m.group(1)}/{fm.group(1)}", method="GRPC", path=f"/{m.group(1)}/{fm.group(1)}", proto="grpc", handler=fm.group(1)))
                if j > i - 1 and depth <= 0:
                    break
    return out


SW_VAPOR = re.compile(r"\.(get|post|put|patch|delete)\(\s*((?:\"[^\"]*\"\s*,\s*)*\"[^\"]*\")(?:\s*,\s*use:\s*(.*))?\)\s*$")


def _swift_entries(lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        m = SW_VAPOR.search(ln)
        if m:
            segs = re.findall(r"\"([^\"]*)\"", m.group(2))
            path = "/" + "/".join(x.strip("/") for x in segs if x.strip("/"))
            h = None
            if m.group(3):
                rest = m.group(3).strip()
                while "(" in rest:
                    rest = re.sub(r"\([^()]*\)", "", rest)
                hm = re.findall(r"(\w+)\s*$", rest)
                h = hm[-1] if hm else None
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {path}", method=m.group(1).upper(), path=path, handler=h, defer=bool(h), near=False,
                              enclosing=not h))
    return out


KT_ROUTE = re.compile(r"^\s*(get|post|put|patch|delete|head|options)\s*\(\s*\"([^\"]*)\"\s*\)\s*\{")
SC_PATH = re.compile(r"\bpath(?:Prefix)?\(\s*\"([^\"]+)\"\s*\)")
SC_H4 = re.compile(r"case\s+(?:\w+\s*@\s*)?(GET|POST|PUT|PATCH|DELETE)\s*->\s*Root((?:\s*/\s*(?:\"[^\"]*\"|\w+))*)")


def _kt_scala_entries(lang, lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400:
            continue
        m = KT_ROUTE.match(ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2) or '/'}", method=m.group(1).upper(), path=m.group(2) or "/", near=False, enclosing=True))
            continue
        if lang == "scala":
            m = SC_PATH.search(ln)
            if m:
                tail = " ".join(lines[i - 1:i + 4])
                vm = re.search(r"\b(get|post|put|patch|delete)\b\s*[{(]", tail)
                meth = vm.group(1).upper() if vm else "ANY"
                out.append(_entry("endpoint", i, f"{meth} /{m.group(1).strip('/')}", method=meth, path="/" + m.group(1).strip("/"), near=False, enclosing=True))
                continue
            m = SC_H4.search(ln)
            if m:
                segs = [x.strip().strip('"') if x.strip().startswith('"') else "{p}" for x in re.split(r"/", m.group(2)) if x.strip()]
                path = "/" + "/".join(segs)
                out.append(_entry("endpoint", i, f"{m.group(1)} {path}", method=m.group(1), path=path, near=False, enclosing=True))
    return out


def find_entries(lang: str, rel: str, lines: list[str]) -> list[dict]:
    if lang == "rust":
        return _rust_entries(lines)
    if lang == "swift":
        return _swift_entries(lines)
    if lang in ("kotlin", "scala"):
        return _kt_scala_entries(lang, lines) + _java_entries(lines)
    if lang in ("java", "kotlin", "scala"):
        return _java_entries(lines)
    if lang == "csharp":
        return _cs_entries(lines)
    if lang == "ruby":
        return _rb_entries(rel, lines)
    if lang == "php":
        return _php_entries(lines)
    if lang in ("javascript", "typescript"):
        return _js_entries(rel, lines)
    if lang == "go":
        return _go_entries(lines)
    return []


# ---------------------------------------------------------------- taint sources

SOURCES = {
    "javascript": [
        ("http_param", re.compile(r"\b(?:req|request)\.(query|body|params|headers|cookies|files?)\b|\bctx\.(query|params|headers)\b|\bctx\.request\.body\b|\.searchParams\b|\brequest\.(json|formData)\(")),
        ("cli_arg", re.compile(r"\bprocess\.argv\b")),
        ("stdin", re.compile(r"\bprocess\.stdin\b")),
        ("file_read", re.compile(r"\bfs\.(?:promises\.)?(readFile|readFileSync|createReadStream)\(")),
        ("message_body", re.compile(r"\b(?:message|msg)\.(content|value|body|data)\b")),
        ("http_param", re.compile(r"@(Param|Body|Query|Headers|Req|UploadedFile)\(")),
    ],
    "go": [
        ("http_param", re.compile(r"\.(FormValue|PostFormValue|PathValue)\(|\.URL\.Query\(\)|\.Header\.Get\(|\.Cookie\(|\.PostForm\(|\.ShouldBind\w*\(|\.BodyParser\(|\.QueryParam\(|"
                                  r"\.DefaultQuery\(|\bchi\.URLParam\(|\bmux\.Vars\(|json\.NewDecoder\(\s*\w+\.Body\s*\)|(?:io|ioutil)\.ReadAll\(\s*\w+\.Body\s*\)|\.Param\(\s*\"")),
        ("cli_arg", re.compile(r"\bos\.Args\b|\bflag\.(String|Int|Bool|Parse|Args)\w*\(")),
        ("stdin", re.compile(r"\bos\.Stdin\b")),
        ("file_read", re.compile(r"\b(?:os\.ReadFile|ioutil\.ReadFile|os\.Open)\(")),
        ("message_body", re.compile(r"\b(?:d|msg|delivery|m)\.Body\b")),
    ],
    "java": [
        ("http_param", re.compile(r"\bcall\.(?:receive\w*|parameters|request\.(?:queryParameters|headers))|\bentity\(as\[|\bparameters?\(|\bformFields?\(|"
                                  r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|MatrixParam|Body|Header|QueryValue|PathVariable)\b|"
                                  r"\.getParameter\(|\.getHeader\(|\.getInputStream\(\)|\.getReader\(\)|\.getCookies\(\)|\.getQueryString\(\)")),
        ("stdin", re.compile(r"\bSystem\.in\b")),
        ("file_read", re.compile(r"\bFiles\.(readAllLines|readString|readAllBytes|newInputStream|lines)\(|new FileInputStream\(|new FileReader\(")),
        ("message_body", re.compile(r"@Payload\b|\bConsumerRecord\b|\.getBody\(\)|\.getPayload\(\)")),
    ],
    "csharp": [
        ("http_param", re.compile(r"\[(FromBody|FromQuery|FromRoute|FromForm|FromHeader)\]|\bRequest\.(Query|Form|Headers|Body|Cookies|RouteValues|ReadFormAsync)\b|\bHttpContext\.Request\b")),
        ("stdin", re.compile(r"\bConsole\.(In|ReadLine|OpenStandardInput)\b")),
        ("cli_arg", re.compile(r"\bEnvironment\.GetCommandLineArgs\(")),
        ("file_read", re.compile(r"\bFile\.(ReadAll\w*|OpenRead|ReadLines|OpenText)\(")),
        ("message_body", re.compile(r"\bmessage\.(Body|Value)\b|\.Message\.Body\b|\bmyQueueItem\b|\bBrokeredMessage\b")),
    ],
    "ruby": [
        ("http_param", re.compile(r"\bparams\[|\bparams\.(require|permit|fetch|to_unsafe_h)\b|\brequest\.(body|headers|params|raw_post|query_parameters)\b|\bcookies\[")),
        ("cli_arg", re.compile(r"\bARGV\b")),
        ("stdin", re.compile(r"\bSTDIN\b|\$stdin\b|\bgets\b")),
        ("file_read", re.compile(r"\bFile\.(read|readlines|open|foreach)\(|\bIO\.read\(")),
    ],
    "php": [
        ("http_param", re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$request->(input|query|get|post|all|header|file|cookie|json)\(|\bRequest::(input|query|get)\(|php://input")),
        ("cli_arg", re.compile(r"\$argv\b|\$_SERVER\[\s*['\"]argv['\"]\s*\]")),
        ("stdin", re.compile(r"php://stdin|\bSTDIN\b|\bfgets\(\s*STDIN")),
        ("file_read", re.compile(r"\b(file_get_contents|fopen|file)\(\s*\$")),
    ],
    "rust": [
        ("http_param", re.compile(r"\b(web::(Query|Json|Path|Form)|Query<|Json<|Path<|Form<|State<|Multipart|HttpRequest|CookieJar|TypedHeader)")),
        ("cli_arg", re.compile(r"\benv::args\(|\bClap::parse\b|\bArgs::parse\(")),
        ("stdin", re.compile(r"\bstdin\(\)")),
        ("file_read", re.compile(r"\bfs::read(?:_to_string)?\(|\bFile::open\(")),
    ],
    "swift": [
        ("http_param", re.compile(r"\breq\.(?:content|query|parameters|headers|body|cookies)\b|\brequest\.(?:content|query|parameters|headers|body)\b")),
        ("cli_arg", re.compile(r"\bCommandLine\.arguments\b")),
        ("stdin", re.compile(r"\breadLine\(")),
        ("file_read", re.compile(r"\bString\(contentsOfFile:|\bFileManager\.default\.contents\(")),
    ],
}
SOURCES["typescript"] = SOURCES["javascript"]
SOURCES["kotlin"] = SOURCES["java"]
SOURCES["scala"] = SOURCES["java"]


def line_sources(lang: str, line: str) -> list[tuple[str, str]]:
    out = []
    for stype, rx in SOURCES.get(lang, []):
        m = rx.search(line)
        if m:
            out.append((stype, m.group(0).strip()[:60]))
    return out


# ---------------------------------------------------------------- sinks
# rule = (languages, regex, sink_type, mode, reason). Named group `arg` is the call argument that decides safety.
# mode: 'dyn'    unsafe when `arg` is built from strings or is a variable; safe when it is a constant
#       'dynlit' like dyn but a variable only counts as low-confidence
#       'unsafe' the call is dangerous by itself

L = lambda *x: set(x)  # noqa: E731
ALL_JS = L("javascript", "typescript")
JVM = L("java", "kotlin", "scala")
SINK_RULES = [
    # --- SQL
    (JVM, re.compile(r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|queryForList|queryForObject|queryForMap|batchUpdate)\(\s*(?P<arg>[^;]*)"), "sql", "sql", "JDBC/JPA call"),
    (L("csharp"), re.compile(r"(?:new\s+(?:Sql|Npgsql|MySql|Oracle)Command|\.(?:ExecuteSqlRaw|FromSqlRaw|ExecuteSqlCommand|FromSql|SqlQuery|QueryAsync|Query|Execute|ExecuteAsync))\s*(?:<[^>]*>)?\(\s*(?P<arg>[^;]*)"), "sql", "sql", "ADO.NET/EF/Dapper call"),
    (L("ruby"), re.compile(r"\.(?:find_by_sql|exec_query|connection\.execute|execute|select_all|select_rows)\(\s*(?P<arg>.*)|\.(?:where|order|group|having|joins|pluck|select)\(\s*(?P<arg2>[\"'].*#\{.*)"), "sql", "sql", "ActiveRecord raw SQL"),
    (L("php"), re.compile(r"\b(?:mysqli_query|mysql_query|pg_query|sqlsrv_query)\(\s*(?:\$\w+\s*,\s*)?(?P<arg>[^;]*)|->(?:query|exec|prepare|whereRaw|selectRaw|orderByRaw|havingRaw)\(\s*(?P<arg2>[^;]*)|\bDB::(?:select|statement|raw|unprepared|insert|update|delete)\(\s*(?P<arg3>[^;]*)"), "sql", "sql", "PHP database call"),
    # --- command
    (JVM, re.compile(r"\bRuntime\.getRuntime\(\)\.exec\(\s*(?P<arg>[^;]*)|\bnew\s+ProcessBuilder\(\s*(?P<arg2>[^;]*)|\bProcessBuilder\(\s*(?P<arg3>[^;]*)"), "command", "dyn", "process execution"),
    (L("csharp"), re.compile(r"\bProcess\.Start\(\s*(?P<arg>[^;]*)|\bnew\s+ProcessStartInfo\(\s*(?P<arg2>[^;]*)"), "command", "dyn", "Process.Start"),
    (L("ruby"), re.compile(r"(?<![\w.])(?:system|exec|spawn)\(\s*(?P<arg>[^)]*)|\bOpen3\.\w+\(\s*(?P<arg2>[^)]*)|\bIO\.popen\(\s*(?P<arg3>[^)]*)|%x[({\[]\s*(?P<arg4>[^)\]}]*)|`(?P<arg5>[^`]*)`"), "command", "dyn", "shell command"),
    (L("php"), re.compile(r"\b(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\(\s*(?P<arg>[^;]*)|`(?P<arg2>[^`]*\$[^`]*)`"), "command", "dyn", "shell command"),
    # --- code evaluation
    (L("ruby"), re.compile(r"(?<![\w.])(?:eval|instance_eval|class_eval|module_eval)\(\s*(?P<arg>[^)]*)|\.constantize\b"), "code", "dyn", "dynamic code evaluation"),
    (L("php"), re.compile(r"\b(?:eval|assert|create_function)\(\s*(?P<arg>[^;]*)"), "code", "dyn", "dynamic code evaluation"),
    (JVM, re.compile(r"\bGroovyShell\b|\bScriptEngine\b.*\.eval\(|\bSpelExpressionParser\b|\.parseExpression\(\s*(?P<arg>[^)]*)|\bOgnl\.getValue\("), "code", "dyn", "expression/script evaluation"),
    (L("csharp"), re.compile(r"\bCSharpScript\.\w+\(\s*(?P<arg>[^;]*)|\bAssembly\.Load(?:From|File)?\(\s*(?P<arg2>[^;]*)"), "code", "dyn", "dynamic code load/evaluation"),
    (ALL_JS, re.compile(r"\bvm\.(?:runInNewContext|runInThisContext|runInContext|Script)\(\s*(?P<arg>[^)]*)|\brequire\(\s*(?P<arg2>[^'\"`)][^)]*)\)"), "code", "dyn", "dynamic code/module evaluation"),
    # --- deserialization
    (JVM, re.compile(r"\bnew\s+ObjectInputStream\(|\bXMLDecoder\b|\bnew\s+XStream\(|\.enableDefaultTyping\(|\bnew\s+Yaml\(\s*\)"), "deserialization", "unsafe", "Java deserialization"),
    (L("csharp"), re.compile(r"\b(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\b|TypeNameHandling\.(?:All|Auto|Objects|Arrays)"), "deserialization", "unsafe", ".NET deserialization"),
    (L("ruby"), re.compile(r"\bMarshal\.(?:load|restore)\(|\bYAML\.load\(|\bPsych\.load\(|\bYAML\.unsafe_load\("), "deserialization", "unsafe", "Marshal/YAML load"),
    (L("php"), re.compile(r"\bunserialize\((?P<arg>[^;]*)"), "deserialization", "dyn", "unserialize"),
    (ALL_JS, re.compile(r"\bnode-serialize\b|\bserialize\.unserialize\(|(?<![\w.])yaml\.load\(|\bjs-yaml\b.*\.load\("), "deserialization", "unsafe", "unsafe deserializer/YAML load"),
    # --- SSRF (outbound requests with a non-literal URL)
    (JVM, re.compile(r"\bnew\s+URL\(\s*(?P<arg>[^;]*)|\.openConnection\(|\brestTemplate\.\w+\(\s*(?P<arg2>[^;]*)|\bnew\s+Http(?:Get|Post|Put|Delete)\(\s*(?P<arg3>[^;]*)|\.uri\(\s*(?P<arg4>[^;]*)|\bURI\.create\(\s*(?P<arg5>[^;]*)"), "ssrf", "dynlit", "outbound request"),
    (L("csharp"), re.compile(r"\.(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync)\(\s*(?P<arg>[^;]*)|\bnew\s+Uri\(\s*(?P<arg2>[^;]*)|\bWebRequest\.Create\(\s*(?P<arg3>[^;]*)"), "ssrf", "dynlit", "outbound request"),
    (L("ruby"), re.compile(r"\bNet::HTTP\.(?:get|get_response|post|start|new)\(\s*(?P<arg>[^)]*)|\bURI\.open\(\s*(?P<arg2>[^)]*)|\b(?:HTTParty|RestClient|Faraday|Typhoeus)\.\w+\(\s*(?P<arg3>[^)]*)|\bURI\.parse\(\s*(?P<arg4>[^)]*)"), "ssrf", "dynlit", "outbound request"),
    (L("php"), re.compile(r"\bfile_get_contents\(\s*(?P<arg>\$[^;]*)|\bcurl_init\(\s*(?P<arg2>[^)]*)\)|CURLOPT_URL\s*,\s*(?P<arg3>[^)]*)|->request\(\s*['\"]\w+['\"]\s*,\s*(?P<arg4>[^,)]*)"), "ssrf", "dynlit", "outbound request"),
    (L("go"), re.compile(r"\bhttp\.(?:Get|Post|Head|PostForm)\(\s*(?P<arg>[^,)]*)|\bhttp\.NewRequest(?:WithContext)?\([^,]*,\s*(?:\"\w+\"|http\.\w+)\s*,\s*(?P<arg2>[^,)]*)"), "ssrf", "dynlit", "outbound request"),
    # --- path traversal
    (ALL_JS, re.compile(r"\bfs\.(?:promises\.)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|readdir|rm|createWriteStream)\(\s*(?P<arg>[^,)]*)|\bres\.(?:sendFile|download)\(\s*(?P<arg2>[^,)]*)"), "path", "dyn", "file access"),
    (L("go"), re.compile(r"\bos\.(?:Open|ReadFile|Create|OpenFile|Remove|RemoveAll|WriteFile)\(\s*(?P<arg>[^,)]*)|\bhttp\.ServeFile\(\s*[^,]*,\s*[^,]*,\s*(?P<arg2>[^,)]*)|\bioutil\.ReadFile\(\s*(?P<arg3>[^,)]*)"), "path", "dyn", "file access"),
    (JVM, re.compile(r"\bnew\s+File\(\s*(?P<arg>[^;]*)|\bPaths\.get\(\s*(?P<arg2>[^;]*)|\bnew\s+FileInputStream\(\s*(?P<arg3>[^;]*)|\.getResourceAsStream\(\s*(?P<arg4>[^;]*)"), "path", "dyn", "file access"),
    (L("csharp"), re.compile(r"\bFile\.(?:ReadAll\w*|WriteAll\w*|Open\w*|Delete|Copy|Move)\(\s*(?P<arg>[^;]*)|\bPhysicalFile\(\s*(?P<arg2>[^;]*)"), "path", "dyn", "file access"),
    (L("ruby"), re.compile(r"\bFile\.(?:read|open|write|delete|readlines)\(\s*(?P<arg>[^)]*)|\bsend_file\(\s*(?P<arg2>[^)]*)|\bDir\.glob\(\s*(?P<arg3>[^)]*)"), "path", "dyn", "file access"),
    (L("php"), re.compile(r"\b(?:include|require)(?:_once)?\s*\(?\s*(?P<arg>\$[^;]*)|\b(?:fopen|readfile|unlink|file_put_contents)\(\s*(?P<arg2>\$[^,;)]*)"), "path", "dyn", "file access/include"),
    # --- open redirect
    (ALL_JS, re.compile(r"\bres\.redirect\(\s*(?:\d+\s*,\s*)?(?P<arg>[^)]*)"), "redirect", "dyn", "redirect"),
    (JVM, re.compile(r"\.sendRedirect\(\s*(?P<arg>[^)]*)|\bnew\s+RedirectView\(\s*(?P<arg2>[^)]*)|return\s+\"redirect:\"\s*\+\s*(?P<arg3>[^;]*)"), "redirect", "dyn", "redirect"),
    (L("csharp"), re.compile(r"\bRedirect(?:Permanent)?\(\s*(?P<arg>[^)]*)|\bnew\s+RedirectResult\(\s*(?P<arg2>[^)]*)"), "redirect", "dyn", "redirect"),
    (L("ruby"), re.compile(r"\bredirect_to\s+(?P<arg>[^\n]*)"), "redirect", "dyn", "redirect"),
    (L("php"), re.compile(r"\bheader\(\s*(?P<arg>[\"']Location:[^)]*)"), "redirect", "dyn", "redirect"),
    (L("go"), re.compile(r"\bhttp\.Redirect\(\s*[^,]+,\s*[^,]+,\s*(?P<arg>[^,)]*)"), "redirect", "dyn", "redirect"),
    # --- Rust
    (L("rust"), re.compile(r"\bCommand::new\(\s*\"(?:sh|bash|cmd|powershell)\"\s*\)\s*\.args?\(\s*\[?\s*\"-c\"\s*,\s*(?P<arg>[^)\]]*)|\bCommand::new\(\s*(?P<arg2>[^)]*)\)"), "command", "dyn", "process execution"),
    (L("rust"), re.compile(r"\b(?:sqlx::query(?:_as|_scalar)?|diesel::sql_query|sql_query|\.execute|\.prepare)\(\s*(?P<arg>&?format!\(.*|[^)]*)"), "sql", "sql", "SQL call"),
    (L("rust"), re.compile(r"\breqwest::(?:blocking::)?(?:get|Client::new\(\)\.get|Client::new\(\)\.post)\(\s*(?P<arg>[^)]*)|\.(?:get|post|put|delete)\(\s*(?P<arg2>[^)]*)\)\s*\.send"), "ssrf", "dynlit", "outbound request"),
    (L("rust"), re.compile(r"\b(?:File::open|File::create|fs::read_to_string|fs::read|fs::write|fs::remove_file|fs::read_dir)\(\s*(?P<arg>[^)]*)"), "path", "dyn", "file access"),
    (L("rust"), re.compile(r"\bunsafe\s*\{"), "unsafe_code", "unsafe", "unsafe block (manual memory safety)"),
    # --- Swift
    (L("swift"), re.compile(r"\bsqlite3_exec\(\s*[^,]+,\s*(?P<arg>[^,)]*)|\.(?:execute|query|raw)\(\s*(?P<arg2>\"[^)]*\\\(|[^)]*)\)"), "sql", "sql", "SQL call"),
    (L("swift"), re.compile(r"\bProcess\(\)|\bNSTask\b|\bposix_spawn\(|\bsystem\(\s*(?P<arg>[^)]*)"), "command", "unsafe", "process execution"),
    (L("swift"), re.compile(r"\bURL\(string:\s*(?P<arg>[^)]*)\)|\bURLRequest\(url:\s*(?P<arg2>[^)]*)\)"), "ssrf", "dynlit", "outbound request"),
    (L("swift"), re.compile(r"\bcontentsOfFile:\s*(?P<arg>[^),]*)|\bFileManager\.default\.(?:contents|removeItem|createFile)\(\s*(?:atPath:\s*)?(?P<arg2>[^),]*)"), "path", "dyn", "file access"),
    (L("swift"), re.compile(r"\bloadHTMLString\(\s*(?P<arg>[^,)]*)|\bevaluateJavaScript\(\s*(?P<arg2>[^,)]*)"), "xss", "dyn", "HTML/JS loaded into a web view"),
    (L("swift"), re.compile(r"\bNSKeyedUnarchiver\.unarchiveObject\(|\bunarchiveTopLevelObjectWithData\("), "deserialization", "unsafe", "insecure unarchiving"),
    # --- XSS / template output
    (ALL_JS, re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|\bdangerouslySetInnerHTML\b|\bdocument\.write(?:ln)?\(|\bv-html\b|\bbypassSecurityTrust\w+\(|\$\([^)]*\)\.html\("), "xss", "unsafe", "raw HTML output"),
    (L("csharp"), re.compile(r"\bHtml\.Raw\(|\bnew\s+HtmlString\("), "xss", "unsafe", "raw HTML output"),
    (L("ruby"), re.compile(r"\.html_safe\b|\braw\s*\(?\s*[@\w]|<%=="), "xss", "unsafe", "raw HTML output"),
    (L("php"), re.compile(r"\becho\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b|\bprint\s+[^;]*\$_(?:GET|POST|REQUEST)\b|<\?=\s*\$_(?:GET|POST|REQUEST)"), "xss", "unsafe", "unescaped request data in output"),
    (JVM, re.compile(r"\.getWriter\(\)\.(?:print|println|write)\(\s*[^;]*getParameter|th:utext|escapeXml\s*=\s*\"false\""), "xss", "unsafe", "raw HTML output"),
    (ALL_JS, re.compile(r"\b(?:ejs|pug|nunjucks)\.(?:render|renderString|compile)\(\s*(?P<arg>[^,)]*)|\bHandlebars\.compile\(\s*(?P<arg2>[^,)]*)|\b_\.template\(\s*(?P<arg3>[^,)]*)"), "template", "dyn", "template compiled from a string"),
    (L("ruby"), re.compile(r"\bERB\.new\(\s*(?P<arg>[^,)]*)|\brender\s+(?:inline|plain):\s*(?P<arg2>[^\n]*)"), "template", "dyn", "template built from a string"),
    (L("php"), re.compile(r"->createTemplate\(\s*(?P<arg>[^)]*)|\bBlade::compileString\(\s*(?P<arg2>[^)]*)"), "template", "dyn", "template built from a string"),
    (JVM, re.compile(r"\bVelocity\.evaluate\([^,]*,[^,]*,[^,]*,\s*(?P<arg>[^)]*)|\bnew\s+Template\(\s*[^,]*,\s*new\s+StringReader\(\s*(?P<arg2>[^)]*)"), "template", "dyn", "template built from a string"),
    # --- XXE
    (JVM, re.compile(r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\(|\bnew\s+SAXReader\(|\bXMLReaderFactory\.createXMLReader\("), "xxe", "xxe", "XML parser"),
    (L("csharp"), re.compile(r"\bDtdProcessing\.Parse\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver"), "xxe", "unsafe", "DTD processing enabled"),
    (L("php"), re.compile(r"\blibxml_disable_entity_loader\(\s*false\s*\)|\bLIBXML_NOENT\b"), "xxe", "unsafe", "external entities enabled"),
    (L("ruby"), re.compile(r"Nokogiri::XML\([^)]*(?:NOENT|noent)|\.noent\b"), "xxe", "unsafe", "external entities enabled"),
    # --- NoSQL / LDAP / XPath
    (ALL_JS, re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|aggregate|countDocuments)\(\s*(?P<arg>[^;]*)|\$where\b"), "nosql", "nosql", "Mongo-style query"),
    (ALL_JS | JVM | L("php", "csharp"), re.compile(r"\b(?:ldap_search|ldap_list|ldap_read|DirectorySearcher|SearchControls)\b.*(?:\+|\$|\{)|\bctx\.search\(\s*(?P<arg>[^;]*)"), "ldap", "dyn", "LDAP search"),
    (ALL_JS | JVM | L("php", "csharp"), re.compile(r"\b(?:xpath\.(?:select|evaluate)|XPath(?:Expression)?\.(?:evaluate|compile)|SelectNodes|SelectSingleNode|->xpath)\(\s*(?P<arg>[^;]*)"), "xpath", "dyn", "XPath query"),
]
_ARG_GROUPS = re.compile(r"^arg\d*$")
MITIGATION = {
    "path": re.compile(r"\b(basename|realpath|normalize|filepath\.(Base|Clean)|path\.basename|path\.resolve|getCanonicalPath|toRealPath|GetFileName|secure_filename)\b"),
    "command": re.compile(r"\b(escapeshellarg|escapeshellcmd|shellescape|shlex|Shellwords\.escape|ProcessBuilder\([^)]*\"(?!sh|bash|cmd))"),
    "sql": re.compile(r"(?i)\b(prepareStatement|PreparedStatement|FromSqlInterpolated|sanitize_sql|parameterize|bindValue|bind_param|setString|setInt|\.bind\()\b"),
    "xss": re.compile(r"\b(escapeHtml|htmlspecialchars|htmlentities|DOMPurify|sanitize|h\(|ERB::Util|HtmlEncode|encodeForHTML)\b"),
    "redirect": re.compile(r"\b(allowlist|whitelist|isSafeUrl|IsLocalUrl|url_has_allowed_host|startsWith\(['\"]/)\b"),
}
XXE_HARDEN = re.compile(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|setExpandEntityReferences\(\s*false|ACCESS_EXTERNAL_DTD|XMLConstants\.|external-general-entities")
REQUEST_TAINT = re.compile(r"\b(req|request|ctx)\.(query|body|params|headers|cookies)\b|\$_(GET|POST|REQUEST|COOKIE)\b|\bparams\[|getParameter\(|\bRequest\.(Query|Form)\b|@RequestParam|"
                           r"\br\.(Form|URL|PostForm|Header)|\$request->(input|query|get|post|all|header)\(|request\.(GET|POST|args|form)\b|\bFormValue\(")


def line_sinks(lang: str, line: str, text: str = "") -> list[tuple[str, bool, str, str]]:
    """Dangerous operations on one source line. `text` is the whole file (used for XXE hardening hints). Returns
    (sink_type, safe, reason, confidence); safe=False means the call looks exploitable if its input is attacker-controlled."""
    out = []
    for langs, rx, stype, mode, reason in SINK_RULES:
        if lang not in langs:
            continue
        m = rx.search(line)
        if not m:
            continue
        mit = MITIGATION.get(stype)
        gd = m.groupdict()
        arg = next((gd[k] for k in gd if _ARG_GROUPS.match(k) and gd[k] is not None), None)
        if mode == "unsafe":
            out.append((stype, bool(mit and mit.search(line)), reason, "medium"))
        elif mode == "xxe":
            hardened = bool(XXE_HARDEN.search(text))
            out.append((stype, hardened, "parser factory with hardening features in file" if hardened else "XML parser without visible hardening (DTD/external entities)", "low" if hardened else "medium"))
        elif mode == "nosql":
            tainted = bool(REQUEST_TAINT.search(line))
            if "$where" in line or tainted:
                out.append((stype, False, "request input reaches the query" if tainted else "$where operator", "medium"))
        elif mode == "sql":
            k = arg_kind(arg or "", lang)
            if k == "literal":
                if re.search(r"(?i)\b(select|insert|update|delete|with|merge)\b", arg or ""):
                    safe = bool(re.search(r"\?|:\w+|\$\d|@\w+|%s", arg or "")) or not re.search(r"(?i)\bwhere\b", arg or "")
                    out.append((stype, safe, "constant query" + (" with placeholders" if safe else ""), "medium"))
            elif arg is not None:
                safe = bool(mit and mit.search(line)) and k != "inline"
                tainted = bool(REQUEST_TAINT.search(arg))
                out.append((stype, safe, "query built from strings" + (" with request data" if tainted else "") if k == "inline" else "non-literal query (variable)",
                            "high" if tainted and k == "inline" else ("medium" if k == "inline" else "low")))
        else:  # dyn / dynlit
            if arg is None:
                out.append((stype, False, reason, "low"))
                continue
            k = arg_kind(arg, lang)
            if k == "literal":
                continue  # constant argument: nothing attacker-controlled
            safe = bool(mit and mit.search(line)) if mit else False
            tainted = bool(REQUEST_TAINT.search(arg))
            conf = "high" if tainted else ("medium" if k == "inline" else "low")
            why = reason + (" with request data in the argument" if tainted else " built from strings" if k == "inline" else " with a non-literal argument")
            out.append((stype, safe, why + (" (mitigation visible)" if safe else ""), conf))
    # de-duplicate (same type reported by two rules on one line)
    seen, res = set(), []
    for x in out:
        if (x[0], x[2]) not in seen:
            seen.add((x[0], x[2]))
            res.append(x)
    return res
