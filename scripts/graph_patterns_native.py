"""Entry points, taint sources and sinks for C, C++, Dart/Flutter, Perl and ABAP (0.7.0).

Kept apart from graph_patterns.py so each language family can be read and reviewed on its own. graph_patterns imports `native_entries`,
`NATIVE_SOURCES` and `NATIVE_SINK_RULES` and merges them into its dispatch tables; the semantics (modes `dyn`, `dynlit`, `unsafe`, `sql`) are the
same as there. Everything is a line-level regex over source text: nothing is executed, results carry medium/low confidence and unresolved
dispatch is counted by the coverage report rather than guessed.
"""
from __future__ import annotations

import re


def _entry(kind, line, name, **kw):
    e = {"kind": kind, "line": line, "name": name, "near": kw.pop("near", True), "method": kw.pop("method", None), "path": kw.pop("path", None),
         "handler": kw.pop("handler", None), "proto": kw.pop("proto", "http"), "queue": kw.pop("queue", None),
         "inline": kw.pop("inline", False), "defer": kw.pop("defer", False)}
    e.update(kw)
    return e


def _verb(s: str | None) -> str:
    s = (s or "").upper().replace("_METHOD", "").strip(" \"'")
    m = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", s)
    return m.group(1) if m else "ANY"


def _dotted(h: str) -> str:
    return h.replace("::", ".").replace("->", ".").strip("&* ")


# ------------------------------------------------------------------ C and C++

C_MAIN = re.compile(r"^\s*(?:int|void)\s+main\s*\(")
C_CIVET = re.compile(r"\bmg_set_request_handler\(\s*\w+\s*,\s*\"([^\"]+)\"\s*,\s*&?([A-Za-z_]\w*)")
C_EVHTTP = re.compile(r"\bevhttp_set_cb\(\s*\w+\s*,\s*\"([^\"]+)\"\s*,\s*&?([A-Za-z_]\w*)")
C_MG_URI = re.compile(r"\bmg_http_match_uri\(\s*\w+\s*,\s*\"([^\"]+)\"")
C_MHD = re.compile(r"\bstrcmp\(\s*url\s*,\s*\"(/[^\"]*)\"\s*\)\s*==\s*0")
C_NGX = re.compile(r"->\s*handler\s*=\s*&?(ngx_\w+)")
C_SIGNAL = re.compile(r"\bsignal\(\s*SIG[A-Z0-9]+\s*,\s*&?([A-Za-z_]\w*)|\bsa_handler\s*=\s*&?([A-Za-z_]\w*)")
C_GETOPT = re.compile(r"\bgetopt(?:_long)?\(|\bargp_parse\(|\bCLI11_PARSE\(|\bCLI::App\b|\bcxxopts::Options\b")
CPP_PISTACHE = re.compile(r"\bRoutes::(Get|Post|Put|Delete|Patch|Options)\(\s*\w+\s*,\s*\"([^\"]+)\"\s*,\s*(?:Routes::bind\(\s*)?&?([\w:]+)")
CPP_HTTPLIB = re.compile(r"\b(?:svr|server|srv|app|s)\.(Get|Post|Put|Delete|Patch|Options)\(\s*(?:R\")?\"?([^\",)]+)\"\s*,\s*(\[|[A-Za-z_]\w*::[\w:]+\s*\))")
CPP_CROW = re.compile(r"\bCROW_ROUTE\(\s*\w+\s*,\s*\"([^\"]+)\"\s*\)(?:\s*\.methods\(([^)]*)\))?(.*)")
CPP_DROGON = re.compile(r"\b(?:ADD_METHOD_TO|METHOD_ADD)\(\s*([\w:]+)\s*,\s*\"([^\"]+)\"\s*,\s*([^)]*)\)")
CPP_DROGON2 = re.compile(r"\bregisterHandler\(\s*\"([^\"]+)\"\s*,\s*&?([\w:]+)\s*(?:,\s*\{([^}]*)\})?")
CPP_OATPP = re.compile(r"\bENDPOINT(?:_ASYNC)?\(\s*\"(\w+)\"\s*,\s*\"([^\"]+)\"\s*,\s*(\w+)")
CPP_GRPC = re.compile(r"^\s*(?:class|struct)\s+(\w+)\s+(?:final\s*)?:\s*(?:public\s+)?(?:\w+::)*(\w+)::(?:Service|AsyncService|CallbackService)\b")
CPP_GRPC_M = re.compile(r"^\s*(?:::)?(?:grpc::)?(?:Status|ServerUnaryReactor\s*\*|ServerWriteReactor<[^>]*>\s*\*)\s+(\w+)\s*\(")


def _c_entries(lang, lines):
    out = []
    grpc_until, grpc_name = -1, None
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400 or ln.lstrip().startswith(("//", "*", "/*", "#")):
            continue
        if C_MAIN.match(ln):
            out.append(_entry("cli_command", i, "main", handler="main", proto="cli"))
            continue
        m = C_CIVET.search(ln) or C_EVHTTP.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"ANY {m.group(1)}", method="ANY", path=m.group(1), handler=m.group(2), defer=True, near=False))
            continue
        m = C_MG_URI.search(ln) or C_MHD.search(ln)
        if m:
            meth = _verb(re.search(r"\"(GET|POST|PUT|PATCH|DELETE)\"", ln).group(1)) if re.search(r"\"(GET|POST|PUT|PATCH|DELETE)\"", ln) else "ANY"
            out.append(_entry("endpoint", i, f"{meth} {m.group(1)}", method=meth, path=m.group(1), near=False, enclosing=True))
            continue
        m = C_NGX.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"ANY /nginx/{m.group(1)}", method="ANY", path=f"/nginx/{m.group(1)}", handler=m.group(1), defer=True, near=False))
            continue
        m = C_SIGNAL.search(ln)
        if m and (m.group(1) or m.group(2)) not in ("SIG_IGN", "SIG_DFL"):
            h = m.group(1) or m.group(2)
            out.append(_entry("consumer", i, f"signal handler {h}", handler=h, defer=True, near=False, proto="signal", queue=f"signal:{h}"))
            continue
        if C_GETOPT.search(ln):
            out.append(_entry("cli_command", i, "command line options", near=False, proto="cli"))
            continue
        if lang != "cpp":
            continue
        m = CPP_PISTACHE.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=m.group(1).upper(), path=m.group(2), handler=_dotted(m.group(3)), defer=True, near=False))
            continue
        m = CPP_HTTPLIB.search(ln)
        if m and m.group(2).startswith("/"):
            meth, path, h = m.group(1).upper(), m.group(2), m.group(3)
            if h == "[":
                out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, inline=True))
            else:
                out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=_dotted(h.rstrip(") ")), defer=True, near=False))
            continue
        m = CPP_CROW.search(ln)
        if m:
            meth = _verb(m.group(2)) if m.group(2) else "GET"
            out.append(_entry("endpoint", i, f"{meth} {m.group(1)}", method=meth, path=m.group(1), inline=("[" in (m.group(3) or "")), near=("[" not in (m.group(3) or ""))))
            continue
        m = CPP_DROGON.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{_verb(m.group(3))} {m.group(2)}", method=_verb(m.group(3)), path=m.group(2), handler=_dotted(m.group(1)), defer=True, near=False))
            continue
        m = CPP_DROGON2.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{_verb(m.group(3))} {m.group(1)}", method=_verb(m.group(3)), path=m.group(1), handler=_dotted(m.group(2)), defer=True, near=False))
            continue
        m = CPP_OATPP.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=m.group(1).upper(), path=m.group(2), inline=True))
            continue
        m = CPP_GRPC.match(ln)
        if m:
            grpc_name, grpc_until = m.group(2), i + 600
            continue
        if grpc_name and i < grpc_until:
            mm = CPP_GRPC_M.match(ln)
            if mm:
                out.append(_entry("endpoint", i, f"GRPC /{grpc_name}/{mm.group(1)}", method="GRPC", path=f"/{grpc_name}/{mm.group(1)}", proto="grpc", handler=mm.group(1)))
            elif re.match(r"^\};?\s*$", ln):
                grpc_name = None
    return out


# ------------------------------------------------------------------ Dart / Flutter

D_MAIN = re.compile(r"^\s*(?:Future<void>\s+|void\s+)main\s*\(")
D_RUNAPP = re.compile(r"\brunApp\(")
D_SHELF = re.compile(r"\b(?:router|app|r|route|routes|api|server|handler)\.(get|post|put|patch|delete|head|options|all)\(\s*['\"](/[^'\"]*)['\"]\s*,\s*(.*)")
D_SHELF_ANNOT = re.compile(r"@Route\.(get|post|put|patch|delete|head|options|all)\(\s*['\"]([^'\"]+)['\"]")
D_NAMED_ROUTE = re.compile(r"['\"](/[\w/:.-]*)['\"]\s*:\s*\(\s*\w*\s*(?:,\s*\w+\s*)?\)\s*=>\s*(?:const\s+)?([A-Z]\w*)\(")
D_GOROUTE = re.compile(r"\bGoRoute\(\s*(?:name:\s*['\"][^'\"]*['\"]\s*,\s*)?path:\s*['\"]([^'\"]+)['\"]")
D_ROUTE_CLASS = re.compile(r"=>\s*(?:const\s+)?([A-Z]\w*)\(|return\s+(?:const\s+)?([A-Z]\w*)\(")
D_FROG = re.compile(r"^\s*(?:Future<Response>|Response|FutureOr<Response>)\s+onRequest\s*\(")
D_SERVERPOD = re.compile(r"^\s*class\s+(\w+)Endpoint\s+extends\s+Endpoint\b")
D_SP_METHOD = re.compile(r"^\s*(?:Future<[^>]*>|void|String|int|bool)\s+(\w+)\s*\(\s*Session\s+\w+")
D_CHANNEL = re.compile(r"\bMethodChannel\(\s*['\"]([\w./:-]+)['\"]")
D_DEEPLINK = re.compile(r"\b(?:uni_links|app_links|getInitialLink|uriLinkStream|onGenerateRoute)\b")


def _dart_entries(rel, lines):
    out = []
    m0 = re.search(r"(?:^|/)routes/(.*?)(?:/index)?\.dart$", rel)
    if m0 and any(D_FROG.match(x) for x in lines):  # Dart Frog: file-system routes
        path = "/" + re.sub(r"\[(\w+)\]", r":\1", m0.group(1)).strip("/")
        path = "/" if path == "/index" else path.replace("/index", "")
        ln_ = next(i for i, x in enumerate(lines, 1) if D_FROG.match(x))
        out.append(_entry("endpoint", ln_, f"ANY {path}", method="ANY", path=path, handler="onRequest"))
    sp_class = None
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400 or ln.lstrip().startswith(("//", "*", "/*")):
            continue
        if D_MAIN.match(ln):
            out.append(_entry("cli_command", i, "main", handler="main", proto="cli"))
            continue
        if D_RUNAPP.search(ln):
            out.append(_entry("cli_command", i, "runApp (Flutter app)", near=False, proto="ui"))
        m = D_SHELF.search(ln)
        if m:
            h = m.group(3).strip()
            hm = re.match(r"^&?([A-Za-z_][\w.]*)\s*\)", h)
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=("ANY" if m.group(1) == "all" else m.group(1).upper()), path=m.group(2),
                              handler=hm.group(1) if hm else None, defer=bool(hm), inline=not hm, near=False))
            continue
        m = D_SHELF_ANNOT.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"{m.group(1).upper()} {m.group(2)}", method=("ANY" if m.group(1) == "all" else m.group(1).upper()), path=m.group(2)))
            continue
        for m in D_NAMED_ROUTE.finditer(ln):
            out.append(_entry("endpoint", i, f"GET {m.group(1)}", method="GET", path=m.group(1), handler=m.group(2), defer=True, near=False, proto="ui"))
        m = D_GOROUTE.search(ln)
        if m:
            tail = " ".join(lines[i - 1:i + 4])
            cm = D_ROUTE_CLASS.search(tail)
            h = (cm.group(1) or cm.group(2)) if cm else None
            out.append(_entry("endpoint", i, f"GET {m.group(1)}", method="GET", path=m.group(1), handler=h, defer=bool(h), near=False, proto="ui"))
            continue
        m = D_SERVERPOD.match(ln)
        if m:
            sp_class = m.group(1).lower()
            continue
        if sp_class:
            mm = D_SP_METHOD.match(ln)
            if mm:
                out.append(_entry("endpoint", i, f"RPC /{sp_class}/{mm.group(1)}", method="RPC", path=f"/{sp_class}/{mm.group(1)}", proto="rpc", handler=mm.group(1)))
        if D_DEEPLINK.search(ln):
            out.append(_entry("endpoint", i, "deep link", method="ANY", path="/deeplink", near=False, enclosing=True, proto="ui"))
    return out


# ------------------------------------------------------------------ Perl

P_SHEBANG = re.compile(r"^#!.*\bperl\b")
P_LITE = re.compile(r"^\s*(get|post|put|patch|delete|any)\s+(?:\[[^\]]*\]\s*=>\s*)?['\"]([^'\"]+)['\"]\s*(?:=>\s*\[[^\]]*\]\s*)?=>\s*(sub\b|\\&?([\w:]+))?")
P_MOJO_TO = re.compile(r"\b(?:\$\w+->)?(get|post|put|patch|delete|any|route)\(\s*['\"]?([^'\")]*)['\"]?\s*\)\s*(?:->\w+\([^)]*\)\s*)*->to\(\s*(?:['\"]([\w:-]+)#(\w+)['\"]|(?:controller\s*=>\s*['\"]([\w:]+)['\"]\s*,\s*)?action\s*=>\s*['\"](\w+)['\"])")
P_CATALYST = re.compile(r"^\s*sub\s+(\w+)\s*:\s*(?:Local|Path(?:\(\s*['\"]?([^'\")]*)['\"]?\s*\))?|Global|Chained\([^)]*\)|Private|Args\(\d*\)|\w+)")
P_CATALYST_PATH = re.compile(r":\s*Path\(\s*['\"]?([^'\")]*)['\"]?\s*\)")
P_PSGI = re.compile(r"^\s*my\s+\$app\s*=\s*sub\s*\{|^\s*builder\s*\{|^\s*\$app->to_psgi")
P_CGI = re.compile(r"\bCGI->new\b|\buse\s+CGI\b|\bCGI::Fast\b")
P_CRON = re.compile(r"\bMojo::IOLoop->recurring\(|\bAnyEvent->timer\(|\bPOE::Kernel\b")


def _perl_entries(rel, lines):
    out = []
    if lines and P_SHEBANG.match(lines[0]):
        out.append(_entry("cli_command", 1, f"script {rel.rsplit('/', 1)[-1]}", near=False, proto="cli"))
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400 or ln.lstrip().startswith("#"):
            continue
        m = P_MOJO_TO.search(ln)
        if m:
            meth = "ANY" if m.group(1) in ("any", "route") else m.group(1).upper()
            path = m.group(2) if m.group(2).startswith("/") else "/" + m.group(2)
            ctrl, act = m.group(3), m.group(4) or m.group(6)
            out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=act, defer=True, near=False, controller=(ctrl or m.group(5) or "").lower()))
            continue
        m = P_LITE.match(ln)
        if m and (m.group(1) not in ("get", "any") or m.group(3)):
            meth = "ANY" if m.group(1) == "any" else m.group(1).upper()
            if m.group(4):
                out.append(_entry("endpoint", i, f"{meth} {m.group(2)}", method=meth, path=m.group(2), handler=m.group(4).split("::")[-1], defer=True, near=False))
            else:
                out.append(_entry("endpoint", i, f"{meth} {m.group(2)}", method=meth, path=m.group(2), inline=True))
            continue
        m = P_CATALYST.match(ln)
        if m and re.search(r":\s*(Local|Path|Global|Chained)\b", ln):
            pm = P_CATALYST_PATH.search(ln)
            path = "/" + (pm.group(1).strip("/") if pm and pm.group(1) else m.group(1))
            meth = "ANY"
            out.append(_entry("endpoint", i, f"{meth} {path}", method=meth, path=path, handler=m.group(1), near=True))
            continue
        if P_PSGI.match(ln):
            out.append(_entry("endpoint", i, "ANY /", method="ANY", path="/", near=False, enclosing=True, proto="psgi"))
            continue
        if P_CRON.search(ln):
            out.append(_entry("cron_job", i, "scheduled callback", near=False))
    if any(P_CGI.search(x) for x in lines) and not any(e["kind"] == "endpoint" for e in out):
        out.append(_entry("endpoint", 1, f"ANY /cgi-bin/{rel.rsplit('/', 1)[-1]}", method="ANY", path=f"/cgi-bin/{rel.rsplit('/', 1)[-1]}", near=False, proto="cgi"))
    return out


# ------------------------------------------------------------------ ABAP (lower-cased names: ABAP is case-insensitive)

A_RESTATTACH = re.compile(r"->\s*attach\(\s*iv_template\s*=\s*'([^']+)'\s*iv_handler_class\s*=\s*'(\w+)'", re.I)
A_SUBMIT_TX = re.compile(r"^\s*(?:CALL\s+TRANSACTION|SET\s+PARAMETER)\b", re.I)
A_REPORT = re.compile(r"^\s*(REPORT|PROGRAM)\s+(\w+)", re.I)
A_EVENT = re.compile(r"^\s*(START-OF-SELECTION|INITIALIZATION)\s*\.", re.I)
A_ICF = re.compile(r"^\s*METHOD\s+if_http_extension~handle_request\s*\.", re.I)
A_RFC = re.compile(r"^\s*FUNCTION\s+(\w+)\s*\.", re.I)
A_RFC_FLAG = re.compile(r"\bREMOTE-ENABLED\b|\bRFC\s+ENABLED\b", re.I)
A_ODATA = re.compile(r"^\s*METHOD\s+(\w+_(?:create|update|delete|get)_entity(?:set)?)\s*\.", re.I)
A_IDOC = re.compile(r"^\s*FUNCTION\s+(idoc_input\w*|idoc_output\w*)\s*\.", re.I)
A_JOB = re.compile(r"\bJOB_OPEN\b|\bJOB_SUBMIT\b", re.I)
A_PARAM = re.compile(r"^\s*(PARAMETERS|SELECT-OPTIONS)\b", re.I)


def _abap_entries(rel, lines):
    out = []
    rest_class = any(re.search(r"\bIF_REST_RESOURCE\b|\bCL_REST_RESOURCE\b", x, re.I) for x in lines)
    for i, ln in enumerate(lines, 1):
        if len(ln) > 400 or ln.lstrip().startswith("*"):
            continue
        m = A_RESTATTACH.search(ln)
        if m:
            out.append(_entry("endpoint", i, f"ANY {m.group(1)}", method="ANY", path=m.group(1), handler=m.group(2).lower(), defer=True, near=False))
            continue
        if A_ICF.match(ln):
            cls = re.search(r"zcl_\w+|\b[yz]\w+", rel.rsplit("/", 1)[-1]) or None
            path = "/sap/bc/" + (rel.rsplit("/", 1)[-1].split(".")[0].lower())
            out.append(_entry("endpoint", i, f"ANY {path}", method="ANY", path=path, near=True, proto="icf"))
            continue
        m = A_RFC.match(ln)
        if m:
            tail = " ".join(lines[max(0, i - 4):i + 1])
            if A_RFC_FLAG.search(tail) or ".fugr." in rel or re.search(r"\bIDOC_INPUT\b", m.group(1), re.I):  # remote-enabled is metadata in the abapGit XML: modules of a function group are listed as RFC candidates
                out.append(_entry("endpoint", i, f"RFC /{m.group(1).lower()}", method="RFC", path=f"/rfc/{m.group(1).lower()}", handler=m.group(1).lower(), proto="rfc", near=True))
            continue
        m = A_ODATA.match(ln)
        if m:
            out.append(_entry("endpoint", i, f"ODATA /{m.group(1).lower()}", method="ODATA", path=f"/odata/{m.group(1).lower()}", handler=m.group(1).lower(), proto="odata", near=True))
            continue
        m = A_EVENT.match(ln)
        if m:
            out.append(_entry("cli_command", i, f"report {m.group(1).lower()}", near=True, proto="report"))
            continue
        if A_JOB.search(ln):
            out.append(_entry("cron_job", i, "background job", near=False))
    if rest_class and not any(e["kind"] == "endpoint" for e in out):
        pass  # a REST resource class has no route of its own: the router that attaches it (zcl_*_router) declares the path
    return out


def native_entries(lang: str, rel: str, lines: list[str]) -> list[dict] | None:
    if lang in ("c", "cpp"):
        return _c_entries(lang, lines)
    if lang == "dart":
        return _dart_entries(rel, lines)
    if lang == "perl":
        return _perl_entries(rel, lines)
    if lang == "abap":
        return _abap_entries(rel, lines)
    return None


# ------------------------------------------------------------------ taint sources

_C_SRC = [
    ("http_param", re.compile(r"\bmg_get_request_info\(|->query_string\b|\bmg_(?:read|get_var|get_cookie|get_header)\(|\bevhttp_(?:request_get_uri|parse_query|find_header|request_get_input_buffer)\(|"
                              r"\bMHD_lookup_connection_value\(|\bupload_data\b|\bhm->(?:body|query|uri)\b|\bmg_http_get_var\(|\bFCGX_GetParam\(|"
                              r"\bgetenv\(\s*\"(?:QUERY_STRING|CONTENT_LENGTH|HTTP_\w+|PATH_INFO|REQUEST_METHOD|COOKIE\w*)\"")),
    ("cli_arg", re.compile(r"\bargv\s*\[|\bgetopt(?:_long)?\(|\boptarg\b|\bargp_parse\(")),
    ("stdin", re.compile(r"\bscanf\(|\bgets\(|\bfgets\([^)]*stdin|\bgetline\([^)]*(?:stdin|std::cin)|\bstd::cin\s*>>|\bgetchar\(\)|\bread\(\s*0\s*,")),
    ("network", re.compile(r"\brecv(?:from|msg)?\(|\bSSL_read\(|\bBIO_read\(|\bbufferevent_read\(|\bevbuffer_(?:remove|pullup)\(")),
    ("file_read", re.compile(r"\bfread\(|\bfgetc\(|\bfopen\([^)]*\"r")),
    ("env", re.compile(r"\bgetenv\(")),
]
_CPP_SRC = [
    ("http_param", re.compile(r"\breq(?:uest)?(?:\.|->)(?:body|get_param_value|has_param|get_header_value|params|query\(\)|param\(|headers\(\)|url_params|path_params|get_file_value)\b|"
                              r"\breq(?:uest)?\.(?:body\(\)|query\(\))|\bBODY_(?:DTO|STRING)\(|\bQUERY\(|\bPATH\(|\bHEADER\(|\bcrow::request\b|->getParameter\(|->getJsonObject\(|->getBody\(")),
] + _C_SRC
_DART_SRC = [
    ("http_param", re.compile(r"\brequest\.(?:readAsString|read\(\)|headers\b|url\b|requestedUri\b|context\b)|\bcontext\.request\b|\bparams\[|\.queryParameters\b|\.pathSegments\b|\bgetHeader\(")),
    ("ui_input", re.compile(r"\b\w*[cC]ontroller\.text\b|\bonChanged\s*:|\bTextEditingController\b|\bonSubmitted\s*:")),
    ("deeplink", re.compile(r"\bgetInitialLink\(|\buriLinkStream\b|\bUri\.base\b|\bModalRoute\.of\([^)]*\)\??\.settings\.arguments\b")),
    ("local_storage", re.compile(r"\bSharedPreferences\b|\bgetString\(|\bFlutterSecureStorage\b")),
    ("cli_arg", re.compile(r"\bmain\([^)]*List<String>\s+\w+")),
    ("stdin", re.compile(r"\bstdin\.(?:readLineSync|readLine|listen)\b")),
    ("file_read", re.compile(r"\bFile\([^)]*\)\.(?:readAsString|readAsBytes|openRead|readAsLines)")),
    ("message_body", re.compile(r"\bjsonDecode\(\s*\w+\.body\b|\bsetMethodCallHandler\(|\bcall\.arguments\b")),
]
_PERL_SRC = [
    ("http_param", re.compile(r"(?:->|\b)param\(|\b(?:body_parameters|query_parameters|route_parameters|route_params|query_params|body_params)\b|\b(?:req|request)->(?:param|parameters|json|body|content|cookies?|headers?|uploads?)\b|"
                              r"\$c->req\b|\$env\s*->?\s*\{\s*['\"]?(?:QUERY_STRING|PATH_INFO|HTTP_\w+|psgi\.input)|\$ENV\{\s*['\"]?(?:QUERY_STRING|HTTP_\w+|PATH_INFO|CONTENT_LENGTH)|\bCGI->new\b|->Vars\b|->multi_param\(")),
    ("cli_arg", re.compile(r"@ARGV\b|\$ARGV\[|\bshift\s*(?:@ARGV)?\s*;?\s*(?://|\|\|)|\bGetOptions\(|\bGetopt::\w+")),
    ("stdin", re.compile(r"<STDIN>|\bSTDIN\b|<>")),
    ("file_read", re.compile(r"\bopen\s*\(?\s*(?:my\s+)?\$?\w+\s*,\s*['\"]?<|\bFile::Slurp\b|\bread_file\(|\bpath\([^)]*\)->slurp")),
    ("env", re.compile(r"\$ENV\{")),
]
_ABAP_SRC = [
    ("http_param", re.compile(r"(?i)\b(?:get_form_field|get_uri_query_parameter|get_uri_attribute|get_header_field|get_cdata|get_data|get_form_fields|get_uri_query_parameters|get_entity|get_binary|request->get_\w+|io_request->get_\w+|io_data_provider->read_entry_data)\b")),
    ("rfc_param", re.compile(r"(?i)^\s*(?:\"\*\"|\*\")?\s*IMPORTING\s+(?:VALUE\(\s*)?\w+|\bFUNCTION\s+\w+")),
    ("ui_input", re.compile(r"(?i)^\s*(?:PARAMETERS|SELECT-OPTIONS)\b|\bGET\s+PARAMETER\s+ID\b|\bCALL\s+SELECTION-SCREEN\b")),
    ("file_read", re.compile(r"(?i)\bOPEN\s+DATASET\b.*\bFOR\s+INPUT\b|\bREAD\s+DATASET\b|\bcl_gui_frontend_services=>gui_upload\b")),
    ("message_body", re.compile(r"(?i)\bidoc_data\b|\bedidd\b|\bio_idoc\b")),
]
NATIVE_SOURCES = {"c": _C_SRC, "cpp": _CPP_SRC, "dart": _DART_SRC, "perl": _PERL_SRC, "abap": _ABAP_SRC}

# ------------------------------------------------------------------ sinks (same tuple shape as graph_patterns.SINK_RULES)

L = lambda *x: set(x)  # noqa: E731
CC = L("c", "cpp")
NATIVE_SINK_RULES = [
    # --- C / C++
    (CC, re.compile(r"\b(?:sqlite3_(?:exec|prepare(?:_v2|_v3)?)\(\s*[^,]+,\s*(?P<arg>[^,)]*)|mysql_(?:real_)?query\(\s*[^,]+,\s*(?P<arg2>[^,)]*)|PQexec\(\s*[^,]+,\s*(?P<arg3>[^,)]*)|"
                    r"(?:stmt|statement|stmt_|query|q)(?:->|\.)(?:execute|exec|executeQuery|prepare)\(\s*(?P<arg4>[^;]*)|\bQSqlQuery\b[^;]*\bexec\(\s*(?P<arg5>[^)]*))"), "sql", "sql", "SQL call"),
    (CC, re.compile(r"(?<![\w.>])(?:std::)?(?:system|popen|_popen|execl|execlp|execle|execv|execvp|execvpe|posix_spawn(?:p)?|WinExec|ShellExecuteA?)\(\s*(?P<arg>[^;]*)|\bQProcess(?:::\w+)?\b[^;]*(?:start\w*|execute)\(\s*(?P<arg2>[^;)]*)"), "command", "dyn", "process execution"),
    (CC, re.compile(r"(?<![\w.>])(?:strcpy|strcat|sprintf|vsprintf|gets|stpcpy|wcscpy|wcscat)\s*\("), "memory", "unsafe", "unbounded copy or format (buffer overflow)"),
    (CC, re.compile(r"(?<![\w.>:])(?:memcpy|memmove|strncpy|strncat|read|recv|fread)\(\s*[^,]+,\s*[^,]+,\s*(?P<arg>(?!\s*(?:\d|sizeof\b))[^)]*)\)"), "memory", "dyn", "copy with a length that may be attacker-controlled"),
    (CC, re.compile(r"(?<![\w.>:])printf\(\s*(?P<arg>[a-z_]\w*)\s*[,)]|(?<![\w.>:])(?:fprintf|dprintf)\(\s*[^,()]+,\s*(?P<arg2>[a-z_]\w*)\s*[,)]|(?<![\w.>:])syslog\(\s*[^,()]+,\s*(?P<arg3>[a-z_]\w*)\s*[,)]|"
                    r"(?<![\w.>:])snprintf\(\s*[^,()]+,\s*[^,()]+,\s*(?P<arg4>[a-z_]\w*)\s*[,)]|(?<![\w.>:])sprintf\(\s*[^,()]+,\s*(?P<arg5>[a-z_]\w*)\s*[,)]"), "format", "dyn", "format string taken from a variable"),
    (CC, re.compile(r"(?<![\w.>:])(?:fopen|open|freopen|unlink|remove|rename|mkdir|opendir|chdir|stat|access)\(\s*(?P<arg>[^,;)]*)|\bstd::(?:i|o)?fstream\b[^;]*\(\s*(?P<arg2>[A-Za-z_][^,;)]*)|\bQFile\(\s*(?P<arg3>[^,;)]*)"), "path", "dyn", "file access"),
    (CC, re.compile(r"\bcurl_easy_setopt\(\s*[^,]+,\s*CURLOPT_URL\s*,\s*(?P<arg>[^)]*)|\b(?:cli|client|http|session|c)\.(?:Get|Post|Put|Delete|Head|Patch)\(\s*(?P<arg2>[^,)]*)|\bhttplib::Client\s+\w+\(\s*(?P<arg3>[^)]*)|\bgetaddrinfo\(\s*(?P<arg4>[^,]*)|\bgethostbyname\(\s*(?P<arg5>[^)]*)"), "ssrf", "dynlit", "outbound request"),
    (CC, re.compile(r"\bdlopen\(\s*(?P<arg>[^,)]*)|\bLoadLibrary[AW]?\(\s*(?P<arg2>[^)]*)|\bQLibrary\(\s*(?P<arg3>[^)]*)"), "code", "dyn", "dynamic library load"),
    (CC, re.compile(r"\bSSL_(?:CTX_)?set_verify\([^)]*SSL_VERIFY_NONE|\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*0L?|\benable_server_certificate_verification\(\s*false"), "tls", "unsafe", "certificate verification disabled"),
    (CC, re.compile(r"\bunserialize\(|\bboost::archive::\w+_iarchive\b|\bcereal::\w+InputArchive\b|\bYAML::Load\(\s*(?P<arg>[^)]*)"), "deserialization", "unsafe", "deserialization of untrusted data"),
    (CC, re.compile(r"\bxmlReadMemory\([^)]*XML_PARSE_NOENT|\bxmlParseFile\(|\bxmlCtxtReadFile\([^)]*XML_PARSE_NOENT|\bXML_PARSE_NOENT\b"), "xxe", "unsafe", "XML external entities enabled"),
    (CC, re.compile(r"\bmg_send_http_redirect\(\s*[^,]+,\s*[^,]+,\s*(?P<arg>[^,)]*)|\bevhttp_add_header\([^,]*,\s*\"Location\"\s*,\s*(?P<arg2>[^)]*)"), "redirect", "dyn", "redirect"),
    # --- Dart / Flutter
    (L("dart"), re.compile(r"\.(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute|customSelect|customStatement|customUpdate|query)\(\s*(?P<arg>[^;]*)"), "sql", "sql", "SQL call"),
    (L("dart"), re.compile(r"\bProcess\.(?:run|runSync|start)\(\s*(?P<arg>[^,;)]*)|\bShell\(\)\.run\(\s*(?P<arg2>[^;]*)"), "command", "dyn", "process execution"),
    (L("dart"), re.compile(r"\bhttp\.(?:get|post|put|delete|patch|head|read)\(\s*(?:Uri\.parse\(\s*)?(?P<arg>[^,;)]*)|\bUri\.parse\(\s*(?P<arg2>[^)]*)\)|\bdio\.(?:get|post|put|delete|fetch)\(\s*(?P<arg3>[^,;)]*)|\bHttpClient\(\)\.\w+Url\(\s*(?P<arg4>[^)]*)"), "ssrf", "dynlit", "outbound request"),
    (L("dart"), re.compile(r"\bFile\(\s*(?P<arg>[^)]*)\)|\bDirectory\(\s*(?P<arg2>[^)]*)\)|\bFile\.fromUri\(\s*(?P<arg3>[^)]*)"), "path", "dyn", "file access"),
    (L("dart"), re.compile(r"\bloadHtmlString\(\s*(?P<arg>[^,)]*)|\bloadData\(\s*data:\s*(?P<arg2>[^,)]*)|\brunJavaScript(?:ReturningResult)?\(\s*(?P<arg3>[^)]*)|\bevaluateJavascript\(\s*(?:source:\s*)?(?P<arg4>[^)]*)|\bHtml\(\s*data:\s*(?P<arg5>[^,)]*)|\bjavaScriptMode\s*:\s*JavaScriptMode\.unrestricted"), "xss", "dyn", "HTML/JS loaded into a web view"),
    (L("dart"), re.compile(r"\bbadCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true|\bonBadCertificate\s*[:=]\s*\([^)]*\)\s*=>\s*true"), "tls", "unsafe", "certificate verification disabled"),
    (L("dart"), re.compile(r"\bDynamicLibrary\.(?:open|process|executable)\(\s*(?P<arg>[^)]*)|\bIsolate\.spawnUri\(\s*(?P<arg2>[^,)]*)"), "code", "dyn", "native library / isolate code load"),
    (L("dart"), re.compile(r"\blaunchUrl(?:String)?\(\s*(?P<arg>[^,)]*)|\bNavigator\.(?:pushNamed|pushReplacementNamed)\(\s*[^,]+,\s*(?P<arg2>[^,)]*)"), "redirect", "dyn", "navigation target"),
    (L("dart"), re.compile(r"\bjson(?:Decode)?\b[^;]*\bfromJson\b(?=.*\bdynamic\b)|\bSerializable\b[^;]*\bdynamic\b"), "deserialization", "unsafe", "untyped deserialization"),
    # --- Perl
    (L("perl"), re.compile(r"(?:->|\bDBI->)\s*(?:do|prepare|prepare_cached|selectrow_array|selectrow_arrayref|selectrow_hashref|selectall_arrayref|selectall_hashref|selectcol_arrayref)\(\s*(?P<arg>[^;]*)|\bdo\s*\(\s*(?P<arg2>\"[^;]*)"), "sql", "sql", "DBI call"),
    (L("perl"), re.compile(r"(?<![\w$>:])(?:system|exec)(?![\w])\s*\(?\s*(?P<arg>[^;]*)|\bqx\s*[({\[/]\s*(?P<arg2>[^)}\]/]*)|`(?P<arg3>[^`]*)`|\bopen\s*\(?\s*(?:my\s+)?\$?\w+\s*,\s*(?P<arg4>[\"'][^\"']*\|[\"']|[\"']\|[^\"']*[\"']|\"[^\"]*\$[^\"]*\|\")|\bIPC::Open[23]::open[23]\(\s*(?P<arg5>[^;]*)"), "command", "dyn", "process execution"),
    (L("perl"), re.compile(r"(?<![\w$>:])eval\s*(?!\{)(?P<arg>[\$\"'(][^;]*)|(?<![\w$>:])(?:do|require)\s+(?P<arg2>\$[^;]*)|\bs/[^/]*/[^/]*/[a-z]*e[a-z]*\b|->\s*eval\(\s*(?P<arg3>[^)]*)"), "code", "dyn", "string eval / dynamic require"),
    (L("perl"), re.compile(r"\bStorable::(?:thaw|retrieve|fd_retrieve)\(|(?<![\w$>:])(?:thaw|retrieve|fd_retrieve)\(|\bYAML(?:::XS|::Syck)?::(?:Load|LoadFile)\(|\bLoad(?:File)?\(\s*\$|\bData::Dumper\b.*\beval\b|\bunserialize\("), "deserialization", "unsafe", "unsafe deserialization"),
    (L("perl"), re.compile(r"\$(?:ua|agent|http|lwp|browser|mech|client)\w*->(?:get|post|head|put|delete|patch|request|mirror)\(\s*(?P<arg>[^;]*)|(?<![\w$>:])(?:get|getstore|getprint|head)\(\s*(?P<arg2>\$[^;]*)|\bHTTP::Tiny->new\b[^;]*->(?:get|post)\(\s*(?P<arg3>[^;]*)|\$\w+->(?:get_p|post_p)\(\s*(?P<arg4>[^;]*)"), "ssrf", "dynlit", "outbound request"),
    (L("perl"), re.compile(r"\bopen(?:dir)?\s*\(?\s*(?:my\s+)?[\$\w]+\s*,\s*(?:[\"'][^\"']*[\"']\s*,\s*)?(?P<arg>[^;)]*)|(?<![\w$>:])(?:unlink|rmdir|mkdir|chdir|rename|opendir|chmod|chown|utime|truncate)(?![\w])\s*\(?\s*(?P<arg2>[^;)]*)|(?<![\w$>:])(?:copy|move)\(\s*(?P<arg3>[^;)]*)|->(?:send_file|static|reply->file)\(\s*(?P<arg4>[^;)]*)"), "path", "dyn", "file access"),
    (L("perl"), re.compile(r"\bprint\s+[^;]*\b(?:param\(|\$q->param|\$cgi->param|->param\()|->render\(\s*(?:text|data)\s*=>\s*[^;]*->param\("), "xss", "unsafe", "unescaped request data in output"),
    (L("perl"), re.compile(r"->redirect(?:_to)?\(\s*(?P<arg>[^)]*)|\bprint\s+\$\w+->redirect\(\s*(?P<arg2>[^)]*)|\bredirect\s+(?P<arg3>[^;]*)"), "redirect", "dyn", "redirect"),
    (L("perl"), re.compile(r"->render\(\s*inline\s*=>\s*(?P<arg>[^;]*)|\bTemplate->new\b[^;]*->process\(\s*\\(?P<arg2>[^,)]*)|\bText::Template->new\(\s*TYPE\s*=>\s*['\"]STRING"), "template", "dyn", "template built from a string"),
    (L("perl"), re.compile(r"\bSSL_verify_mode\s*=>\s*(?:0|SSL_VERIFY_NONE|0x0)|\bverify_hostname\s*=>\s*0|\bPERL_LWP_SSL_VERIFY_HOSTNAME\b[^;]*=\s*0|\$ENV\{\s*['\"]?PERL_LWP_SSL_VERIFY_HOSTNAME['\"]?\s*\}\s*=\s*0"), "tls", "unsafe", "certificate verification disabled"),
    (L("perl"), re.compile(r"\bXML::LibXML\b[^;]*(?:load_ext_dtd\s*=>\s*1|expand_entities\s*=>\s*1)|\bXML::Twig->new\b|\bXML::Simple\b[^;]*\bXMLin\("), "xxe", "unsafe", "XML parser with entity expansion"),
    # --- ABAP (lines are case-insensitive)
    (L("abap"), re.compile(r"(?i)\bEXEC\s+SQL\b|\bSELECT\b[^.]*\bWHERE\s*\(\s*(?P<arg>[\w-]+)\s*\)|\bFROM\s*\(\s*(?P<arg2>[\w-]+)\s*\)|\bSELECT\s*\(\s*(?P<arg3>[\w-]+)\s*\)|->\s*execute_(?:query|update|ddl)\(\s*(?:iv_\w+\s*=\s*)?(?P<arg4>[^)]*)\)|\b(?:UPDATE|DELETE\s+FROM|INSERT)\s*\(\s*(?P<arg5>[\w-]+)\s*\)"), "sql", "dyn", "dynamic Open SQL / native SQL"),
    (L("abap"), re.compile(r"(?i)\bCALL\s+FUNCTION\s+'(?:SXPG_(?:COMMAND|CALL_SYSTEM)_\w*|SYSTEM|RFC_REMOTE_PIPE|RFC_REMOTE_EXEC)'|\bCALL\s+'SYSTEM'|\bOPEN\s+DATASET\b[^.]*\bFILTER\b\s+(?P<arg>[^.]*)|\bcl_sxpg\w*=>\w+|\bsxpg_command_execute\b"), "command", "dyn", "operating-system command"),
    (L("abap"), re.compile(r"(?i)\bGENERATE\s+SUBROUTINE\s+POOL\b|\bINSERT\s+REPORT\s+(?P<arg>[\w-]+)|\bEDITOR-CALL\s+FOR\s+REPORT\b|\bCALL\s+TRANSFORMATION\b[^.]*\bSOURCE\s+XML\b|\bPERFORM\s+\(\s*(?P<arg2>[\w-]+)\s*\)|\bPERFORM\s+\w+\s+IN\s+PROGRAM\s+\(\s*(?P<arg3>[\w-]+)\s*\)|\bCALL\s+METHOD\s+\(\s*(?P<arg4>[\w-]+)\s*\)|\bCALL\s+METHOD\s+[\w-]+=>\(\s*(?P<arg5>[\w-]+)\s*\)|\bASSIGN\s+\(\s*(?P<arg6>[\w-]+)\s*\)\s*TO\b|\bCREATE\s+OBJECT\s+[\w-]+\s+TYPE\s+\(\s*(?P<arg7>[\w-]+)\s*\)"), "code", "dyn", "dynamic code generation or dispatch"),
    (L("abap"), re.compile(r"(?i)\bSUBMIT\s+\(\s*(?P<arg>[\w-]+)\s*\)|\bCALL\s+TRANSACTION\s+(?P<arg2>[\w-]+)(?!\s+AUTHORITY-CHECK)(?![^.]*\bWITH\s+AUTHORITY-CHECK)|\bCALL\s+FUNCTION\s+(?P<arg3>[\w-]+)\b(?!\s*')|\bLEAVE\s+TO\s+TRANSACTION\s+(?P<arg4>[\w-]+)"), "code", "dyn", "dynamic SUBMIT / CALL TRANSACTION / CALL FUNCTION"),
    (L("abap"), re.compile(r"(?i)\bOPEN\s+DATASET\s+(?P<arg>[\w-]+)\b|\bDELETE\s+DATASET\s+(?P<arg2>[\w-]+)\b|\bTRANSFER\b[^.]*\bTO\s+(?P<arg3>[\w-]+)\b|\bFILE_GET_NAME\b|\bcl_gui_frontend_services=>(?:gui_download|gui_upload)\b"), "path", "dyn", "file access on the application server"),
    (L("abap"), re.compile(r"(?i)\bcl_http_client=>create_by_url\(\s*(?:EXPORTING\s+)?url\s*=\s*(?P<arg>[^)]*?)(?:\s+IMPORTING|\s*\))|\bcall\s+function\s+'HTTP_GET'|\bcl_http_client=>create\(\s*(?:EXPORTING\s+)?host\s*=\s*(?P<arg2>[^)]*)"), "ssrf", "dynlit", "outbound HTTP request"),
    (L("abap"), re.compile(r"(?i)\bcl_abap_(?:xml|message)_?\w*\b[^.]*\bCALL\s+TRANSFORMATION\b|\bIMPORT\b[^.]*\bFROM\s+DATA\s+BUFFER\b|\bIMPORT\b[^.]*\bFROM\s+SHARED\s+BUFFER\b|\bCALL\s+TRANSFORMATION\b[^.]*\bsource\s+xml\b"), "deserialization", "unsafe", "import of untrusted serialized data"),
    (L("abap"), re.compile(r"(?i)\bssl_id\s*=\s*'ANONYM'|\bssl_verify\w*\s*=\s*abap_false|\bset_ssl_?verify\w*\(\s*abap_false|\bCALL\s+FUNCTION\s+'SSFC_\w+'[^.]*\bABAP_FALSE\b|\bssl_id\s*=\s*space"), "tls", "unsafe", "TLS certificate verification disabled (anonymous SSL client)"),
    (L("abap"), re.compile(r"(?i)\bcl_http_utility=>(?:unescape_url|escape_url)\b|\bcl_http_server=>(?:redirect|response_redirect)\b|->\s*redirect\(\s*(?:iv_\w+\s*=\s*)?(?P<arg>[^)]*)\)|->\s*set_header_field\(\s*name\s*=\s*'location'\s+value\s*=\s*(?P<arg2>[^)]*)"), "redirect", "dyn", "redirect"),
]
