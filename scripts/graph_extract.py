#!/usr/bin/env python3
"""Extract per-file graph fragments from one registered repo. Reads files only; never executes them.

Usage:
  graph_extract.py --out OUT_DIR --key REPO_KEY [--root ROOT] [--files rel1 rel2 ...] [--backend auto|ast|regex|tree-sitter]

Backends (provenance recorded on every node/edge):
  ast          Python files via the stdlib `ast` module (always available)
  tree-sitter  other languages, only if `tree_sitter_language_pack` or `tree_sitter_languages` is already
               installed (ckb never installs it); falls back to regex on any error
  regex        every other language, driven by the per-language specs in lang_specs.py: declarations and class spans, typed receivers,
               calls, imports, inheritance, routes, sources, sinks, env, SQL, queues (tree-sitter is only used for languages without a spec)

Writes <out>/graph/fragments/<key>/<sha256-of-path>.json, one per source file, containing nodes, edges
(intra-file, resolved) and refs (cross-file references the linker resolves in graph_build.py).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import is_binary, is_secret_file, read_text, repo_excludes, repo_roots_for_output, walk_files  # noqa: E402
from graph_common import atomic_write, cite, make_edge, make_node, node_id, safe_str, sig_hash  # noqa: E402
from graph_patterns import arg_kind, find_entries, line_sinks, line_sources  # noqa: E402
from lang_specs import KEYWORDS_BY_LANG, LIBC_FUNCS, SPEC, block_end, mask, norm_call, parse_bases, pkg_of  # noqa: E402
from roles import FIXTURE_PATH, GENERATED_NAME, TEST_PATH  # noqa: E402

LANG = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby",
        ".php": "php", ".rs": "rust", ".cs": "csharp", ".scala": "scala", ".swift": "swift",
        ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp", ".dart": "dart",
        ".pl": "perl", ".pm": "perl", ".t": "perl", ".psgi": "perl", ".cgi": "perl", ".abap": "abap"}
CPP_HINT = re.compile(r"^[ \t]*(?:class\s+\w+|namespace\s+\w+|template\s*<|using\s+namespace|#\s*include\s*<(?:iostream|string|vector|memory|map|functional)>)|\bstd::", re.M)
PY_SOURCE = re.compile(r"^(?:flask\.)?request\.(args|form|json|values|files|headers|cookies|data|GET|POST|query_params|path_params|body|FILES|META|get_json)\b")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "all", "route", "api_route", "websocket"}
SQL_WRITE = re.compile(r"(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|REPLACE\s+INTO)\s+[`\"]?([A-Za-z_][\w.]*)")
SQL_READ = re.compile(r"(?i)\b(?:FROM|JOIN)\s+[`\"]?([A-Za-z_][\w.]*)")
SQL_KW = re.compile(r"(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|WITH|MERGE|REPLACE)\b")


def ts_available() -> str | None:
    for mod in ("tree_sitter_language_pack", "tree_sitter_languages"):
        if importlib.util.find_spec(mod):
            return mod
    return None


def norm_path(p: str) -> str:
    """Normalize an HTTP route/path template for cross-repo matching."""
    p = re.sub(r"\$\{[^}]*\}|\{[^}]*\}|<[^>]*>|:[A-Za-z_]\w*", "{p}", p.strip())
    p = re.sub(r"^https?://[^/]+", "", p)
    p = "/" + p.lstrip("/")
    return re.sub(r"/+", "/", p.rstrip("/")) or "/"


class Frag:
    def __init__(self, key, rel, extractor):
        self.key, self.rel, self.extractor = key, rel, extractor
        self.nodes, self.edges, self.refs, self.constants = {}, [], [], {}
        self.file_id = node_id("file", key, rel, "")
        self.sink_counts = {}

    def node(self, n):
        self.nodes.setdefault(n["id"], n)
        return n["id"]

    def edge(self, src, kind, dst, line, conf="high", label="observed", **kw):
        self.edges.append(make_edge(src, kind, dst, cite(self.key, self.rel, line), extractor=kw.pop("extractor", self.extractor),
                                    confidence=conf, label=label, **kw))

    def ref(self, **kw):
        kw.setdefault("path", self.rel)
        self.refs.append(kw)

    def shared(self, kind, name, line, conf="high", **attrs):
        """Node shared across repos (table/topic/external): repo '_system', cited at first sighting."""
        n = make_node(kind, "_system", "", safe_str(name, 200), name, line, extractor=self.extractor, confidence=conf,
                      citation=cite(self.key, self.rel, line), attrs=attrs or None)
        n["path"] = ""
        return self.node(n)

    def env(self, name, line):
        n = make_node("env_var", self.key, "", name, name, line, extractor=self.extractor,
                      citation=cite(self.key, self.rel, line))
        return self.node(n)

    def sink(self, owner, qual, stype, safe, reason, line, conf="medium"):
        c = self.sink_counts[(owner, stype)] = self.sink_counts.get((owner, stype), 0) + 1
        n = make_node("sink", self.key, self.rel, f"{qual}.{stype}.{c}", f"{stype} sink in {qual}", line,
                      extractor=self.extractor, confidence=conf, attrs={"sink_type": stype, "safe": safe, "reason": reason})
        sid = self.node(n)
        self.edge(owner, "reaches_sink", sid, line, conf=conf)
        return sid

    def entry(self, kind, name, line, handler_id=None, conf="medium", label="observed", **attrs):
        """Entry point node (endpoint, consumer, cron_job, cli_command) with a routes_to edge to its handler."""
        q = name if kind == "endpoint" else f"{name} ({self.rel}:{line})"
        n = make_node(kind, self.key, "", q, name, line, extractor=self.extractor, confidence=conf, label=label,
                      citation=cite(self.key, self.rel, line), attrs={k: v for k, v in attrs.items() if v is not None})
        eid = self.node(n)
        if handler_id and handler_id != self.file_id:
            self.edge(eid, "routes_to", handler_id, line, conf=conf, label=label)
        return eid

    def consumer_for(self, owner, topic, line, conf="medium"):
        if owner != self.file_id:
            self.entry("consumer", f"consume {topic}", line, handler_id=owner, conf=conf, queue=topic)

    def source(self, owner, qual, stype, detail, line, conf="medium"):
        """One taint_source node per (function, source type); later hits only bump its count."""
        if owner == self.file_id:
            return None
        sid = node_id("taint_source", self.key, self.rel, f"{qual}.{stype}")
        if sid in self.nodes:
            self.nodes[sid]["attrs"]["count"] = self.nodes[sid]["attrs"].get("count", 1) + 1
            return sid
        n = make_node("taint_source", self.key, self.rel, f"{qual}.{stype}", f"{stype} input in {qual}", line, extractor=self.extractor,
                      confidence=conf, attrs={"source_type": stype, "detail": safe_str(detail, 60), "count": 1})
        self.node(n)
        self.edge(sid, "flows_to", owner, line, conf=conf)
        return sid

    def sql(self, owner, text, line, safe, conf="high"):
        if not SQL_KW.search(text or ""):
            return
        for m in SQL_WRITE.finditer(text):
            self.edge(owner, "writes", self.shared("table", m.group(2).split(".")[-1].lower(), line), line, conf=conf)
        if re.search(r"(?i)\bSELECT\b", text):
            for m in SQL_READ.finditer(text):
                self.edge(owner, "reads", self.shared("table", m.group(1).split(".")[-1].lower(), line), line, conf=conf)
        self.sink(owner, self.nodes[owner].get("qualname", "module") if owner in self.nodes else "module", "sql", safe,
                  "parameterized" if safe else "string-built query", line, conf="high" if not safe else "medium")

    def dump(self):
        return {"repo": self.key, "path": self.rel, "extractor": self.extractor, "nodes": list(self.nodes.values()),
                "edges": self.edges, "refs": self.refs, "constants": self.constants}


# ---------------------------------------------------------------- Python (ast)

def dotted(n) -> str:
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        base = dotted(n.value)
        return f"{base}.{n.attr}" if base else f"<expr>.{n.attr}"  # receiver is an arbitrary expression: never matched by the bare method name
    if isinstance(n, ast.Call):
        return dotted(n.func)
    return ""


NOT_TYPES = {"Any", "List", "Dict", "Set", "Tuple", "Optional", "Union", "Callable", "Type", "Iterable", "Iterator", "Sequence", "Mapping", "Literal",
             "None", "Self", "Awaitable", "Generator", "AsyncIterator", "TypeVar", "ClassVar", "Final", "Annotated", "NoReturn"}


def type_name(ann):
    """Class name from a type annotation (Foo, pkg.Foo, 'Foo', Optional[Foo], list[Foo], Foo | None) or None."""
    if ann is None:
        return None
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        s_ = re.split(r"[\[|, ]", ann.value.strip())[0]
    elif isinstance(ann, (ast.Name, ast.Attribute)):
        s_ = dotted(ann)
    elif isinstance(ann, ast.Subscript):
        sl = ann.slice
        first = sl.elts[0] if isinstance(sl, ast.Tuple) and sl.elts else sl
        return type_name(first)
    elif isinstance(ann, ast.BinOp):
        return type_name(ann.left) or type_name(ann.right)
    else:
        return None
    last = s_.rsplit(".", 1)[-1]
    return s_ if last[:1].isupper() and last not in NOT_TYPES and "<expr>" not in s_ else None


def ctor_type(v):
    """Class name when v is a constructor call: Foo(...), pkg.Foo(...), await Foo(...)."""
    if isinstance(v, ast.Await):
        v = v.value
    if isinstance(v, ast.Call):
        d = dotted(v.func)
        last = d.rsplit(".", 1)[-1]
        if last[:1].isupper() and "<expr>" not in d and last not in NOT_TYPES:
            return d
    return None


def collect_attr_types(cn):
    """self.x types of a class: class-level annotations, self.x = Foo(), self.x: Foo, self.x = <annotated __init__ param>."""
    out = {}
    for st in cn.body:
        if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
            t = type_name(st.annotation)
            if t:
                out[st.target.id] = t
    for fn in cn.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        ptypes = {a.arg: type_name(a.annotation) for a in fn.args.args + fn.args.kwonlyargs if a.annotation is not None}
        for sub_ in ast.walk(fn):
            tgt = val = None
            if isinstance(sub_, ast.Assign) and len(sub_.targets) == 1:
                tgt, val = sub_.targets[0], sub_.value
            elif isinstance(sub_, ast.AnnAssign):
                tgt, val = sub_.target, sub_.value
            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id in ("self", "cls"):
                t = type_name(sub_.annotation) if isinstance(sub_, ast.AnnAssign) else None
                if not t and val is not None:
                    t = ctor_type(val) or (ptypes.get(val.id) if isinstance(val, ast.Name) else None)
                if t:
                    out.setdefault(tgt.attr, t)
    return out


def local_types(fn):
    """Variable types inside a function: annotated params and locals, x = Foo(), with Foo() as x."""
    out = {a.arg: type_name(a.annotation) for a in fn.args.args + fn.args.kwonlyargs if a.annotation is not None}
    for sub_ in ast.walk(fn):
        if isinstance(sub_, ast.Assign) and len(sub_.targets) == 1 and isinstance(sub_.targets[0], ast.Name):
            t = ctor_type(sub_.value)
            if t:
                out[sub_.targets[0].id] = t
        elif isinstance(sub_, ast.AnnAssign) and isinstance(sub_.target, ast.Name):
            t = type_name(sub_.annotation) or (ctor_type(sub_.value) if sub_.value is not None else None)
            if t:
                out[sub_.target.id] = t
        elif isinstance(sub_, ast.With):
            for it in sub_.items:
                if isinstance(it.optional_vars, ast.Name) and ctor_type(it.context_expr):
                    out[it.optional_vars.id] = ctor_type(it.context_expr)
    return {k: v for k, v in out.items() if v}


def literal(n, consts) -> str | None:
    if isinstance(n, ast.Constant) and isinstance(n.value, str):
        return n.value
    if isinstance(n, ast.Name) and n.id in consts:
        return consts[n.id]
    if isinstance(n, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{p}" for v in n.values)
    return None


def env_read(call: ast.Call):
    """os.environ.get('X', d) / os.getenv('X') -> (name, default)"""
    d = dotted(call.func)
    if d in ("os.environ.get", "os.getenv", "environ.get", "getenv") and call.args and isinstance(call.args[0], ast.Constant):
        default = call.args[1].value if len(call.args) > 1 and isinstance(call.args[1], ast.Constant) else None
        return str(call.args[0].value), default
    return None


def first_para(text: str, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", (text or "").split("\n\n")[0]).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def leading_comment(lines: list[str], line: int) -> str:
    """Comment block directly above a 1-based declaration line (//, ///, #, /** */, * lines)."""
    i, buf = line - 2, []
    while i >= 0 and i > line - 14:
        s = lines[i].strip()
        if not s and buf:
            break
        if s.startswith(("//", "#", "*", "/*", "*/", "---")) or s.endswith("*/"):
            buf.append(re.sub(r"^(/\*+|\*+/|\*|///?|#+|--+)\s?", "", s).rstrip("*/ ").strip())
            i -= 1
            continue
        break
    txt = " ".join(x for x in reversed(buf) if x and not x.startswith(("@", "eslint", "nolint", "noqa", "pylint", "type:")))
    return first_para(txt)


def _walk_own(node):
    """Yield node and descendants without descending into nested functions/classes (they are their own owners)."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        for ch in ast.iter_child_nodes(cur):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and ch is not node:
                continue
            stack.append(ch)


def extract_python(key, rel, text) -> Frag:
    f = Frag(key, rel, "ast")
    tree = ast.parse(text)
    lines = text.splitlines()
    sec = not (TEST_PATH.search(rel) or GENERATED_NAME.search(rel))  # entry points/sources/sinks are not extracted from tests or generated code
    defused = "defusedxml" in text
    f.node(make_node("file", key, rel, "", rel, 1, max(1, len(lines)), extractor="ast", attrs={"language": "python"}))
    # module constants (incl. env defaults)
    for st in tree.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            v = st.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                f.constants[st.targets[0].id] = v.value
            elif isinstance(v, ast.Call) and env_read(v):
                name, default = env_read(v)
                if isinstance(default, str):
                    f.constants[st.targets[0].id] = default
                f.constants.setdefault("__env__" + st.targets[0].id, name)

    cattrs = {}
    mtypes = {}
    rprefix = {}  # router = APIRouter(prefix="/orders") / Blueprint("x", __name__, url_prefix="/x")
    for st in tree.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and isinstance(st.value, ast.Call):
            cn_ = dotted(st.value.func).rsplit(".", 1)[-1]
            if cn_ in ("APIRouter", "Blueprint", "Router", "Namespace"):
                for kw in st.value.keywords:
                    if kw.arg in ("prefix", "url_prefix", "path") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        rprefix[st.targets[0].id] = kw.value.value
    for st in tree.body:  # module-level variables with a known class: service = OrderService(...)
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and ctor_type(st.value):
            mtypes[st.targets[0].id] = ctor_type(st.value)
        elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and (type_name(st.annotation) or (st.value is not None and ctor_type(st.value))):
            mtypes[st.target.id] = type_name(st.annotation) or ctor_type(st.value)

    def visit_def(node, parent_id, prefix, in_class):
        qual = f"{prefix}{node.name}"
        kind = "class" if isinstance(node, ast.ClassDef) else ("method" if in_class else "function")
        sig = lines[node.lineno - 1].strip() if node.lineno - 1 < len(lines) else node.name
        doc = first_para(ast.get_docstring(node) or "")
        nid = f.node(make_node(kind, key, rel, qual, node.name, node.lineno, getattr(node, "end_lineno", node.lineno),
                               extractor="ast", signature=sig[:200], sig_hash=sig_hash(sig),
                               tags=["test"] if TEST_PATH.search(rel) else None,
                               summary=doc or None, summary_source="docstring" if doc else None))
        f.edge(parent_id, "contains", nid, node.lineno)
        if isinstance(node, ast.ClassDef):
            for b in node.bases:
                bn = dotted(b)
                if bn and "<expr>" not in bn:
                    f.ref(type="inherit", src=nid, name=bn, line=node.lineno)
            cattrs[qual] = collect_attr_types(node)
            if sec and any(dotted(b).endswith("Servicer") for b in node.bases):  # gRPC service implementation: every public method is an RPC
                svc = node.name[:-len("Servicer")] if node.name.endswith("Servicer") else node.name
                for ch in node.body:
                    if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) and not ch.name.startswith("_"):
                        f.entry("endpoint", f"GRPC /{svc}/{ch.name}", ch.lineno, method="GRPC", path=f"/{svc}/{ch.name}", norm=norm_path(f"/{svc}/{ch.name}"),
                                protocol="grpc", handler_id=node_id("method", key, rel, f"{qual}.{ch.name}"))
            for dec in node.decorator_list:
                dn = dotted(dec.func if isinstance(dec, ast.Call) else dec)
                if dn and dn not in ("dataclass", "dataclasses.dataclass", "total_ordering"):
                    f.ref(type="arg_ref", src=nid, name=dn, line=dec.lineno)
            for ch in node.body:
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visit_def(ch, nid, qual + ".", True)
                else:  # calls in the class body (attribute defaults, registrations)
                    for sub_ in ast.walk(ch):
                        if isinstance(sub_, ast.Call):
                            handle_call(sub_, nid, qual)
            return
        ltypes = {**mtypes, **local_types(node)}
        cattr = cattrs.get(prefix[:-1], {}) if in_class else {}
        for a in node.args.args + node.args.kwonlyargs:
            tn = type_name(a.annotation) if a.annotation is not None else None
            if tn:
                f.ref(type="uses_type", src=nid, name=tn, line=node.lineno)
        rn = type_name(node.returns) if node.returns is not None else None
        if rn:
            f.ref(type="uses_type", src=nid, name=rn, line=node.lineno)
        for dec in node.decorator_list:
            dn_ = dotted(dec.func if isinstance(dec, ast.Call) else dec)
            if dn_ and dn_ not in ("staticmethod", "classmethod", "property", "abstractmethod", "override") and "<expr>" not in dn_:
                f.ref(type="arg_ref", src=nid, name=dn_, line=dec.lineno)
        is_entry = None
        for dec in (node.decorator_list if sec else []):
            dn = dotted(dec.func if isinstance(dec, ast.Call) else dec)
            dlast = dn.rsplit(".", 1)[-1]
            if dlast in ("task", "shared_task"):
                f.entry("consumer", f"consume task {qual}", dec.lineno, handler_id=nid, queue=qual, protocol="celery")
                is_entry = "message_body"
            elif dlast in ("periodic_task", "scheduled_job", "cron", "crontab"):
                f.entry("cron_job", f"schedule {qual}", dec.lineno, handler_id=nid)
            elif dn in ("click.command", "click.group", "app.command", "typer.command") or dlast == "command" and dn.split(".")[0] in ("cli", "app", "typer", "click"):
                f.entry("cli_command", f"command {qual}", dec.lineno, handler_id=nid)
                is_entry = "cli_arg"
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in HTTP_METHODS and dec.args:
                path = literal(dec.args[0], f.constants)
                if path is not None and isinstance(dec.func.value, ast.Name) and dec.func.value.id in rprefix:
                    path = "/" + "/".join(x for x in (rprefix[dec.func.value.id].strip("/") + "/" + path.strip("/")).split("/") if x)
                if path is not None:
                    methods = [dec.func.attr.upper()]
                    for kw in dec.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            methods = [str(e.value).upper() for e in kw.value.elts if isinstance(e, ast.Constant)]
                    for m in methods:
                        m = "GET" if m in ("ROUTE", "API_ROUTE") else m
                        ep = make_node("endpoint", key, "", f"{m} {path}", f"{m} {path}", dec.lineno, extractor="ast",
                                       citation=cite(key, rel, dec.lineno), attrs={"method": m, "path": path, "norm": norm_path(path)})
                        eid = f.node(ep)
                        f.edge(eid, "routes_to", nid, dec.lineno)
                        is_entry = "http_param"
        if sec and not in_class and node.name in ("lambda_handler", "handler", "main_handler") and [a.arg for a in node.args.args][:2] == ["event", "context"]:
            f.entry("endpoint", f"ANY lambda/{node.name}", node.lineno, handler_id=nid, method="ANY", path=f"/lambda/{node.name}", norm=norm_path(f"/lambda/{node.name}"), protocol="lambda")
            is_entry = is_entry or "http_param"
        if is_entry and sec and not isinstance(node, ast.ClassDef):
            params = [a.arg for a in node.args.args + node.args.kwonlyargs if a.arg not in ("self", "cls", "request", "response", "req", "res", "db", "session", "background_tasks", "background")]
            if params:
                f.source(nid, qual, is_entry, "handler parameters: " + ", ".join(params[:6]), node.lineno, conf="medium")
        for sub in _walk_own(node):
            if sec and isinstance(sub, ast.Attribute):
                d = dotted(sub)
                m_ = PY_SOURCE.match(d)
                if m_:
                    f.source(nid, qual, "http_param", m_.group(0), sub.lineno)
                elif d in ("sys.argv", "sys.stdin"):
                    f.source(nid, qual, "cli_arg" if d == "sys.argv" else "stdin", d, sub.lineno)
            if isinstance(sub, ast.Call):
                handle_call(sub, nid, qual, ltypes, cattr)
            elif isinstance(sub, ast.Subscript) and dotted(sub.value) in ("os.environ", "environ") and isinstance(sub.slice, ast.Constant):
                f.edge(nid, "reads_env", f.env(str(sub.slice.value), sub.lineno), sub.lineno)
            elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and "__env__" + sub.id in f.constants:
                f.edge(nid, "reads_env", f.env(f.constants["__env__" + sub.id], sub.lineno), sub.lineno, conf="medium")
        for ch in node.body:
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit_def(ch, nid, qual + ".", False)

    def handle_call(c: ast.Call, owner, qual, ltypes=None, cattr=None):
        name = dotted(c.func)
        ln = c.lineno
        if not name:
            return
        er = env_read(c)
        if er:
            f.edge(owner, "reads_env", f.env(er[0], ln), ln)
            return
        parts_ = name.split(".")
        rt = None
        if len(parts_) == 2 and ltypes and parts_[0] in ltypes:
            rt = ltypes[parts_[0]]
        elif len(parts_) == 3 and parts_[0] in ("self", "cls") and cattr and parts_[1] in cattr:
            rt = cattr[parts_[1]]
        ref_ = {"type": "call", "src": owner, "name": name, "line": ln}
        if rt:
            ref_.update(recv_type=rt, recv_conf="medium")
        f.ref(**ref_)
        if parts_[-1][:1].isupper() and "<expr>" not in name:  # constructor call: the code depends on that class
            f.ref(type="uses_type", src=owner, name=name, line=ln)
        for arg_ in list(c.args) + [kw.value for kw in c.keywords]:  # functions passed as callbacks
            if isinstance(arg_, (ast.Name, ast.Attribute)):
                an = dotted(arg_)
                if an and "<expr>" not in an and an not in ("self", "cls", "None", "True", "False"):
                    f.ref(type="arg_ref", src=owner, name=an, line=ln)
        last = name.rsplit(".", 1)[-1]
        a0 = c.args[0] if c.args else None
        if sec and last in ("add_get", "add_post", "add_put", "add_delete", "add_patch", "get", "post", "put", "delete", "patch") and name.split(".")[0] in ("web", "app", "router") \
                and len(c.args) >= 2 and isinstance(c.args[0], ast.Constant) and isinstance(c.args[0].value, str) and str(c.args[0].value).startswith("/") and dotted(c.args[1]):
            pth = c.args[0].value  # aiohttp web.get('/x', handler) / router.add_get('/x', handler)
            m_ = last.replace("add_", "").upper()
            ep = f.entry("endpoint", f"{m_} {pth}", ln, method=m_, path=pth, norm=norm_path(pth), protocol="http")
            f.ref(type="route_handler", src=ep, name=dotted(c.args[1]).split(".")[-1], line=ln)
        elif sec and last == "Route" and len(c.args) >= 2 and isinstance(c.args[0], ast.Constant) and dotted(c.args[1]):
            pth = str(c.args[0].value)  # Starlette Route('/x', endpoint)
            ep = f.entry("endpoint", f"ANY {pth}", ln, method="ANY", path=pth, norm=norm_path(pth), protocol="http")
            f.ref(type="route_handler", src=ep, name=dotted(c.args[1]).split(".")[-1], line=ln)
        elif sec and last == "Application" and c.args and isinstance(c.args[0], (ast.List, ast.Tuple)):
            for el in c.args[0].elts:  # Tornado Application([(r"/x", Handler), ...])
                if isinstance(el, ast.Tuple) and len(el.elts) >= 2 and isinstance(el.elts[0], ast.Constant) and dotted(el.elts[1]):
                    pth = "/" + str(el.elts[0].value).lstrip("^/").rstrip("$")
                    ep = f.entry("endpoint", f"ANY {pth}", ln, method="ANY", path=pth, norm=norm_path(pth), protocol="http")
                    f.ref(type="route_handler", src=ep, name=dotted(el.elts[1]).split(".")[-1], line=ln)
        if sec and last in ("path", "re_path", "url") and len(c.args) >= 2 and Path(rel).name in ("urls.py", "routes.py"):
            pth = literal(a0, f.constants)
            view = c.args[1]
            vname = dotted(view.func.value) if isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) and view.func.attr == "as_view" else dotted(view)
            if pth is not None and vname and not vname.endswith("include"):
                pth = "/" + pth.lstrip("^/").rstrip("$")
                ep = f.entry("endpoint", f"ANY {pth}", ln, method="ANY", path=pth, norm=norm_path(pth), protocol="http")
                f.ref(type="route_handler", src=ep, name=vname.split(".")[-1], line=ln)
        elif sec and last == "add_url_rule" and a0 is not None:
            pth = literal(a0, f.constants)
            vf = next((kw.value for kw in c.keywords if kw.arg == "view_func"), None)
            ms = next(([str(e.value).upper() for e in kw.value.elts if isinstance(e, ast.Constant)] for kw in c.keywords if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple))), ["GET"])
            if pth is not None:
                for m_ in ms:
                    ep = f.entry("endpoint", f"{m_} {pth}", ln, method=m_, path=pth, norm=norm_path(pth), protocol="http")
                    if vf is not None and dotted(vf):
                        f.ref(type="route_handler", src=ep, name=dotted(vf).split(".")[-1], line=ln)
        elif sec and last == "register" and name.endswith(("router.register", "routes.register")) and len(c.args) >= 2 and literal(a0, f.constants) is not None:
            pth = "/" + literal(a0, f.constants).strip("^/$")
            ep = f.entry("endpoint", f"ANY {pth}", ln, method="ANY", path=pth, norm=norm_path(pth), protocol="http")
            f.ref(type="route_handler", src=ep, name=dotted(c.args[1]).split(".")[-1], line=ln)
        elif sec and name in ("argparse.ArgumentParser", "ArgumentParser", "optparse.OptionParser"):
            f.entry("cli_command", f"command {Path(rel).stem}", ln, handler_id=owner, conf="low")
            f.source(owner, qual, "cli_arg", name, ln, conf="low")
        if last in ("execute", "executemany", "raw", "exec_driver_sql", "query", "text") and a0 is not None:
            lit = literal(a0, f.constants)
            unsafe = isinstance(a0, (ast.JoinedStr, ast.BinOp)) or (isinstance(a0, ast.Call) and dotted(a0.func).endswith("format"))
            if lit or unsafe:
                f.sql(owner, lit or "SELECT ?", ln, safe=not unsafe)
            elif sec and last in ("execute", "executemany", "exec_driver_sql") and isinstance(a0, (ast.Name, ast.Attribute)):
                f.sink(owner, qual, "sql", safe=False, reason="non-literal query (variable): check how it is built", line=ln, conf="low")
        elif name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
                      "subprocess.check_call", "os.system", "os.popen"):
            shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in c.keywords)
            target = None
            if isinstance(a0, (ast.List, ast.Tuple)) and a0.elts:
                target = literal(a0.elts[0], f.constants) or (a0.elts[0].id if isinstance(a0.elts[0], ast.Name) else None)
            elif a0 is not None:
                target = literal(a0, f.constants)
            f.sink(owner, qual, "command", safe=not shell and name.startswith("subprocess"),
                   reason="shell=True" if shell else ("os.system" if name.startswith("os.") else "argument list"), line=ln)
            if target:
                ext = f.shared("external", Path(str(target)).name or str(target), ln, conf="medium", raw=str(target)[:120])
                f.edge(owner, "spawns", ext, ln, conf="medium")
        # Detection only: these call names in the *target's* source mark deserialization/code sinks.
        # ckb never loads pickle/marshal data itself.
        elif name in ("eval", "exec", "compile", "pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "jsonpickle.decode", "dill.load",
                      "dill.loads", "torch.load", "shelve.open", "cPickle.loads", "pickle.Unpickler"):
            safe_loader = name == "yaml.load" and any(kw.arg == "Loader" and "Safe" in dotted(kw.value) for kw in c.keywords)
            f.sink(owner, qual, "code" if name in ("eval", "exec", "compile") else "deserialization", safe=safe_loader, reason=name + (" with SafeLoader" if safe_loader else ""), line=ln)
        elif re.match(r"^(requests|httpx|urllib\.request|aiohttp)\.", name) or last in ("urlopen",):
            url = literal(a0, f.constants) if a0 is not None else None
            if url and not url.startswith("{p}") and "://" not in url[:12] and not url.startswith("/"):
                url = None
            if url is not None:
                f.ref(type="http", src=owner, method=(last.upper() if last in HTTP_METHODS else "GET"), url=url, line=ln)
            f.sink(owner, qual, "ssrf", safe=url is not None and "{p}" not in (url or "")[:12], reason="dynamic URL" if url is None else "templated URL", line=ln, conf="low")
        elif sec and (last in ("render_template_string", "from_string") or name in ("Template", "jinja2.Template", "mako.template.Template")) and a0 is not None \
                and not (isinstance(a0, ast.Constant) and isinstance(a0.value, str)):
            f.sink(owner, qual, "template", safe=False, reason=f"{name} with a non-constant template string", line=ln, conf="medium")
        elif sec and last in ("mark_safe", "Markup", "SafeString") and a0 is not None and not isinstance(a0, ast.Constant):
            f.sink(owner, qual, "xss", safe=False, reason=f"{name} marks dynamic text as safe HTML", line=ln, conf="medium")
        elif sec and last in ("redirect", "HttpResponseRedirect", "RedirectResponse") and a0 is not None and not isinstance(a0, ast.Constant):
            f.sink(owner, qual, "redirect", safe=False, reason="redirect to a non-constant URL", line=ln, conf="low")
        elif sec and last in ("send_file", "send_from_directory", "FileResponse") and a0 is not None and not isinstance(a0, ast.Constant):
            f.sink(owner, qual, "path", safe=False, reason=f"{name} with a non-constant path", line=ln, conf="low")
        elif sec and name == "open" and isinstance(a0, (ast.JoinedStr, ast.BinOp)):
            f.sink(owner, qual, "path", safe=False, reason="open() on a path built from strings", line=ln, conf="low")
        elif sec and (re.search(r"(^|\.)(etree|ET|minidom|sax|xmlrpc)\.(parse|fromstring|XML|parseString|XMLParser)$", name) or name in ("parseString", "parse_xml")):
            hard = defused or any(kw.arg in ("resolve_entities", "no_network") and isinstance(kw.value, ast.Constant) and kw.value.value in (False, True) and kw.arg == "resolve_entities" and kw.value.value is False for kw in c.keywords)
            f.sink(owner, qual, "xxe", safe=bool(hard), reason="XML parser" + (" (defusedxml or resolve_entities=False)" if hard else " without visible hardening"), line=ln, conf="low")
        elif sec and last in ("search_s", "search", "search_st") and "ldap" in name.lower() and isinstance(a0, (ast.JoinedStr, ast.BinOp)):
            f.sink(owner, qual, "ldap", safe=False, reason="LDAP filter built from strings", line=ln, conf="medium")
        elif last in ("basic_publish", "publish", "produce", "send_message", "put_record"):
            kws = {kw.arg: kw.value for kw in c.keywords}
            key_ = literal(kws.get("routing_key") or kws.get("topic") or (c.args[1] if len(c.args) > 1 else a0), f.constants) if (kws or c.args) else None
            exch = literal(kws.get("exchange"), f.constants) if kws.get("exchange") is not None else None
            if key_:
                f.edge(owner, "publishes", f.shared("topic", key_, ln, exchange=exch), ln)
        elif last in ("basic_consume", "subscribe", "consume") and c.keywords:
            q = next((literal(kw.value, f.constants) for kw in c.keywords if kw.arg in ("queue", "topic", "topics")), None)
            if q:
                f.edge(owner, "consumes", f.shared("topic", q, ln), ln, conf="medium")
                if sec:
                    f.consumer_for(owner, q, ln)

    for st in tree.body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            visit_def(st, f.file_id, "", False)
        elif isinstance(st, (ast.Import, ast.ImportFrom)):
            mod = st.module if isinstance(st, ast.ImportFrom) else None
            level = getattr(st, "level", 0)
            for a in st.names:
                f.ref(type="import", src=f.file_id, module=mod if isinstance(st, ast.ImportFrom) else a.name,
                      name=a.name if isinstance(st, ast.ImportFrom) else None, alias=a.asname or a.name.split(".")[0],
                      level=level, line=st.lineno)
        else:
            for sub in ast.walk(st):
                if isinstance(sub, ast.Call):
                    handle_call(sub, f.file_id, "module", mtypes)
    return f


# ---------------------------------------------------------------- regex (JS/TS/Go/others)

RX = {
    "javascript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"),
        re.compile(r"^\s+(?:(?:public|private|protected|static|async|readonly)\s+)*(?!if\b|for\b|while\b|switch\b|catch\b|return\b)([A-Za-z_$][\w$]*)\s*\([^{;]*\)\s*(?::\s*[^{;]+)?\{\s*$"),
    ],
    "go": [re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")],
    "java": [re.compile(r"^\s*(?:public|private|protected|static|final|\s)+[\w<>\[\],\s]+\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:throws [\w., ]+)?\{")],
    "ruby": [re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?]?)")],
    "php": [re.compile(r"^\s*(?:public|private|protected|static|\s)*function\s+([A-Za-z_]\w*)\s*\(")],
    "rust": [re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)")],
}
RX["typescript"] = RX["javascript"]
RX["kotlin"] = [re.compile(r"^\s*(?:\w+\s+)*fun\s+(?:<[^>]+>\s*)?([A-Za-z_]\w*)\s*\(")]
RX["csharp"] = [re.compile(r"^\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract|extern|unsafe|new|partial)\s+)+[\w<>\[\],.?\s]+?\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(")]
CLASS_RX = re.compile(r"^\s*(?:export\s+)?(?:public\s+|abstract\s+|final\s+)*(?:class|interface|struct)\s+([A-Za-z_]\w*)(?:\s+extends\s+([\w.]+))?")
GO_TYPE_RX = re.compile(r"^type\s+([A-Za-z_]\w*)\s+(struct|interface)\b")
CALL_RX = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
DECL_SKIP = {"if", "for", "while", "switch", "catch", "return", "else", "case", "throw", "function", "typeof", "delete", "void", "yield", "sizeof",
             "foreach", "using", "lock", "synchronized", "elif", "when", "do", "try", "finally", "await", "new"}
KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "typeof", "new", "await", "async", "func",
            "make", "len", "append", "cap", "panic", "recover", "defer", "go", "select", "range", "super", "this",
            "require", "import", "case", "else", "throw", "delete", "void", "yield", "sizeof", "print", "println"}
JS_IMPORT = re.compile(r"""(?:require\(\s*['"]([^'"]+)['"]\s*\)|^\s*import\s+(?:[\w*{}\s,$]+\s+from\s+)?['"]([^'"]+)['"])""")
GO_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:[A-Za-z_.]\w*\s+)?"([\w./-]+)"\s*$')
ENV_RX = re.compile(r"process\.env\.([A-Z0-9_]+)|process\.env\[['\"]([A-Z0-9_]+)|os\.Getenv\(\"([A-Z0-9_]+)\"\)|System\.getenv\(\"([A-Z0-9_]+)\"\)|ENV\[['\"]([A-Z0-9_]+)|env::var\(\"([A-Z0-9_]+)\"\)")
HTTP_JS = re.compile(r"\b(axios|fetch|got|http|https|request)(?:\.(get|post|put|patch|delete|request))?(?:<[^()]*>)?\(\s*([`'\"])(.*?)\3")
HTTP_GO = re.compile(r"http\.(?:NewRequest|NewRequestWithContext)\(\s*(?:ctx\s*,\s*)?\"(GET|POST|PUT|PATCH|DELETE)\"\s*,\s*([^,]+),")
HTTP_GO2 = re.compile(r"http\.(Get|Post)\(\s*([^,)]+)")
SQL_STR = re.compile(r"""(?:Exec|Query|QueryRow|QueryContext|ExecContext|query|execute|raw|run)\(\s*(?:ctx\s*,\s*)?([`'"])((?:SELECT|INSERT|UPDATE|DELETE|WITH)\b.*?)\1""", re.I)
SQL_DYN = re.compile(r"""(?:Exec|Query|QueryRow|query|execute|raw)\(\s*(?:fmt\.Sprintf|`[^`]*\$\{|['"][^'"]*['"]\s*\+)""")
AMQP_BIND = re.compile(r"QueueBind\(\s*[^,]+,\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"")
PUBLISH_RX = re.compile(r"\.(?:Publish|PublishWithContext|publish|send|produce)\(\s*[^)]*?['\"`]([a-z][\w.-]+\.[\w.-]+)['\"`]")
SUBSCRIBE_RX = re.compile(r"\.(?:subscribe|consume)\(\s*\{?\s*(?:topic|queue)?\s*:?\s*['\"`]([\w.-]+)['\"`]")
CMD_RX = re.compile(r"exec\.Command\(\s*\"?([^\",)]+)|child_process\.(exec|execSync|spawn)\(|\b(execSync|spawnSync)\(")
GO_SHELL = re.compile(r"exec\.Command(?:Context)?\(\s*(?:ctx\s*,\s*)?\"(?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)\"\s*,\s*\"(?:-c|/c|-Command)\"\s*,\s*(?P<arg>[^)]*)")
EVAL_RX = re.compile(r"(?<![\w.])(eval|new Function)\s*\(")
SSRF_JS = re.compile(r"\b(axios|fetch|got)(?:\.\w+)?\(\s*([^,)]+)")


def extract_regex(key, rel, text, lang, aux: str = "") -> Frag:
    f = Frag(key, rel, "regex")
    lines = text.splitlines()
    if len(text) > 800_000 or len(lines) > 20000:  # bound the work a single hostile or generated file can cause
        SKIPS.append({"path": rel, "reason": "very large file: only the first 20000 lines / 800 KB were analysed"})
        lines = lines[:20000]
        text = "\n".join(lines)[:800_000]
        lines = text.splitlines()
    f.node(make_node("file", key, rel, "", rel, 1, max(1, len(lines)), extractor="regex", attrs={"language": lang}))
    sec = not (TEST_PATH.search(rel) or GENERATED_NAME.search(rel))  # no entry points/sources/sinks from tests or generated code
    entries = find_entries(lang, rel, lines) if sec else []
    inline_at = {}
    for e in entries:
        if e["inline"] and e["kind"] == "endpoint":
            inline_at.setdefault(e["line"], []).append(e)
    spec = SPEC.get(lang)
    mlines = mask(text, lang).splitlines() if spec else lines
    mlines += [""] * (len(lines) - len(mlines))
    decls = []  # (line, name, kind, extra)
    cinfo, fowner, fend, ctype = {}, {}, {}, {}
    cspans = []  # (start, end, class name) for owner assignment; includes impl/extension owners that are not nodes
    if spec:
        for i, ml in enumerate(mlines, 1):
            if len(ml) > 600 or not ml.strip():
                continue
            if len(decls) > 4000:
                SKIPS.append({"path": rel, "reason": "more than 4000 declarations: the rest of the file was not parsed"})
                break
            for crx in spec["cls"]:
                m = crx.match(ml)
                if m and m.group("name") not in DECL_SKIP:
                    kind_ = (m.groupdict().get("kind") or "class")
                    head = " ".join((lines if lang == "perl" else mlines)[i - 1:i + 3])  # Perl base classes are strings: read the unmasked text
                    head = head.split("{")[0] if "{" in head else head
                    ext_, imp_ = parse_bases(lang, "interface" if kind_ in ("interface", "protocol", "trait") else "class", head if m.group("name") else ml)
                    end_ = block_end(mlines, i - 1, lang)
                    if lang == "abap" and kind_ != "interface":  # INTERFACES statements sit inside the class definition body
                        for ml2 in mlines[i:end_]:
                            im_ = re.match(r"\s*interfaces\s*:?\s*([\w, ]+?)\s*\.\s*$", ml2)
                            if im_:
                                imp_ = imp_ + [x.strip() for x in im_.group(1).split(",") if x.strip()]
                    if lang == "go" and kind_ == "struct":  # embedded structs act as base types
                        for ml2 in mlines[i:end_ - 1]:
                            em = re.match(r"^\s+\*?(?:\w+\.)?([A-Z]\w*)\s*$", ml2)
                            if em:
                                ext_.append(em.group(1))
                    decls.append((i, m.group("name"), "class", None))
                    cinfo[i] = {"ext": ext_, "imp": imp_, "kind": kind_}
                    fend[i] = end_
                    cspans.append((i, end_, m.group("name")))
                    break
            else:
                om = spec.get("owner") and spec["owner"].match(ml)
                if om:  # Rust impl blocks / Swift extensions: methods belong to the named type
                    cspans.append((i, block_end(mlines, i - 1, lang), om.group("name").split("::")[-1]))
                    tr = om.groupdict().get("trait")
                    if tr:
                        cinfo.setdefault(("impl", om.group("name").split("::")[-1]), []).append((tr.split("::")[-1], i))
    if lang in ("cpp", "perl"):  # namespaces / package prefixes of this repo are never external libraries
        for ml in mlines:
            nm_ = re.match(r"\s*namespace\s+([A-Za-z_]\w*)", ml) if lang == "cpp" else re.match(r"\s*package\s+([\w:]+)", ml)
            if nm_:
                segs_ = nm_.group(1).split("::")
                for k_ in range(len(segs_)):
                    f.ref(type="ns", name=segs_[k_] if lang == "cpp" else "::".join(segs_[:k_ + 1]).replace("::", "."), line=1)
                f.ref(type="ns", name=segs_[0], line=1)
    pats = spec["func"] if spec else RX.get(lang, [])
    class_lines = {d[0] for d in decls if d[2] == "class"}
    for i, ml in enumerate(mlines, 1):
        if len(ml) > 600 or not ml.strip():
            continue
        if len(decls) > 8000:
            break
        if i not in class_lines:
            for p_ in pats:
                m = p_.match(ml)
                if not m:
                    continue
                name = m.groupdict().get("name") or m.groupdict().get("init")
                if not name or name in DECL_SKIP:
                    continue
                ret = m.groupdict().get("ret")
                if ret is not None and (ret in spec.get("ret_skip", ()) or (ret in DECL_SKIP and ret != "void")):
                    continue
                if lang == "java" and re.match(r"^\s*(return|new|throw|else|if|for|while|switch|catch|try|do)\b", ml):
                    continue
                own_ = m.groupdict().get("owner")
                if own_ == "self":
                    own_ = None
                if own_ is None and lang != "go":
                    inner = [(e_ - s_, c_) for s_, e_, c_ in cspans if s_ < i <= e_]
                    own_ = min(inner)[1] if inner else None
                    if lang in ("csharp", "java") and own_ and name == own_:
                        pass  # constructor
                decls.append((i, name, "function", None))
                fowner[i] = own_
                fend[i] = block_end(mlines, i - 1, lang) if spec else None
                break
        if i in inline_at:
            first = inline_at[i][0]
            decls.append((i, first["name"], "route", first["path"]))
    decls.sort(key=lambda d: d[0])
    owners = []
    route_nids = set()
    class_ids = {}
    for idx, (line, name, kind, extra) in enumerate(decls):
        nxt = (decls[idx + 1][0] - 1) if idx + 1 < len(decls) else len(lines)
        end = max(line, min(fend.get(line) or nxt, len(lines))) if spec else nxt
        if kind == "class":
            nid = f.node(make_node("class", key, rel, name, name, line, end, extractor="regex", confidence="medium",
                                   signature=lines[line - 1].strip()[:200], sig_hash=sig_hash(lines[line - 1])))
            f.edge(f.file_id, "contains", nid, line, conf="medium")
            class_ids[name] = nid
            ci = cinfo.get(line, {})
            for b_ in ci.get("ext", []):
                f.ref(type="inherit", src=nid, name=b_, line=line)
            for b_ in ci.get("imp", []):
                f.ref(type="implements", src=nid, name=b_, line=line)
            if extra:
                f.ref(type="inherit", src=nid, name=extra, line=line)
            continue
        if kind == "route":
            qual = f"route {name}"
            nid = f.node(make_node("function", key, rel, qual, qual, line, end, extractor="regex", confidence="medium",
                                   signature=lines[line - 1].strip()[:200], sig_hash=sig_hash(lines[line - 1]), attrs={"inline_handler": True}))
            for e in inline_at[line]:
                f.entry("endpoint", e["name"], line, handler_id=nid, conf="high", method=e["method"], path=e["path"], norm=norm_path(e["path"]), protocol="http")
            route_nids.add(nid)
            qual_for = qual
        else:
            sig = lines[line - 1].strip()
            doc = leading_comment(lines, line)
            own_ = fowner.get(line)
            qual_for = f"{own_}.{name}" if own_ else name
            nid = f.node(make_node("method" if own_ else "function", key, rel, qual_for, name, line, end, extractor="regex", confidence="medium",
                                   signature=sig[:200], sig_hash=sig_hash(sig), tags=["test"] if TEST_PATH.search(rel) else None,
                                   summary=doc or None, summary_source="comment" if doc else None))
            if own_ and own_ in class_ids:
                f.edge(class_ids[own_], "contains", nid, line, conf="medium")
        f.edge(f.file_id, "contains", nid, line, conf="medium") if not (fowner.get(line) and fowner.get(line) in class_ids) else None
        owners.append((line, end, nid, qual_for, name))
    for (kk, vv) in [(k_, v_) for k_, v_ in cinfo.items() if isinstance(k_, tuple)]:  # impl Trait for Type
        tname = kk[1]
        for tr, ln_ in vv:
            if tname in class_ids:
                f.ref(type="implements", src=class_ids[tname], name=tr, line=ln_)

    def owner_at(i):
        best = None
        for s_, e_, nid, qual_, name in owners:
            if s_ <= i <= e_ and (best is None or e_ - s_ < best[1]):
                best = (nid, e_ - s_, qual_)
        if best:
            return best[0], best[2]
        inner = [(e_ - s_, n_) for s_, e_, n_ in cspans if s_ <= i <= e_ and n_ in class_ids]
        if inner:
            cn_ = min(inner)[1]
            return class_ids[cn_], cn_
        return f.file_id, "module"

    # variable types visible in this file (typed declarations, constructor assignments), conflicting names dropped
    vtypes = {}
    if spec:
        for ml in mlines + (mask(aux, lang).splitlines() if aux else []):  # aux: the same-stem header of a C++ source file (member declarations live there)
            if len(ml) > 600:
                continue
            for trx in spec["types"]:
                for m in trx.finditer(ml):
                    v_, t_ = m.group("var").lstrip("@$"), m.group("type")
                    if t_ in DECL_SKIP or v_ in DECL_SKIP:
                        continue
                    t_ = t_.replace("::", ".")
                    if lang == "perl":
                        t_ = t_.split(".")[-1]
                    if v_ in vtypes and vtypes[v_] not in (None, t_):
                        vtypes[v_] = None
                    elif v_ not in vtypes:
                        vtypes[v_] = t_
    uses = set()
    this_names = {"this", "self", "super", "cls", "Self", "$this", "base", "parent", "me"}
    call_lines = {d[0] for d in decls if d[2] in ("function", "class")}

    # entry points that are not inline route callbacks: bind each to the handler declared right after the annotation/route line,
    # or by name (resolved across files by the linker)
    funcs = [(s_, nid, name) for s_, e_, nid, qual_, name in owners if nid not in route_nids]
    for e in entries:
        if e["inline"] and e["kind"] == "endpoint":
            continue
        hid, dist = None, None
        if e.get("enclosing"):  # Ktor/Akka/tRPC style: the route's body is a lambda inside the enclosing function
            o_, _q = owner_at(e["line"])
            hid = o_ if o_ != f.file_id else None
        if hid is None and e["handler"] and not e["defer"]:
            hid = next((nid for s_, nid, name in funcs if name == e["handler"]), None)
        if hid is None and not e["defer"] and e.get("near", True) and not e.get("enclosing"):
            cand = [(s_ - e["line"], nid) for s_, nid, name in funcs if 0 <= s_ - e["line"] <= 8]
            if cand:
                dist, hid = min(cand)
        label = "observed" if (hid is not None and (dist is None or dist <= 3)) or e["handler"] else "inferred"
        attrs = {"protocol": e["proto"]}
        if e["kind"] == "endpoint":
            attrs.update(method=e["method"] or "ANY", path=e["path"], norm=norm_path(e["path"]))
        if e["queue"]:
            attrs["queue"] = e["queue"]
        eid = f.entry(e["kind"], e["name"], e["line"], handler_id=hid, conf="medium", label=label, **attrs)
        if e["handler"] and e["handler"] != "func" and (e["defer"] or hid is None):
            f.ref(type="route_handler", src=eid, name=e["handler"], line=e["line"], hint=(e.get("controller") or "").split("/")[-1].lower() or None, meth=e.get("method"))
        if e["kind"] == "consumer" and e["queue"]:
            f.edge(eid, "consumes", f.shared("topic", e["queue"], e["line"]), e["line"], conf="medium")

    for i, ln in enumerate(lines, 1):
        if len(ln) > 500:
            continue
        own, qual = owner_at(i)
        if spec:
            for im in spec["imports"](ln, lines, i):
                f.ref(type="import", src=f.file_id, module=im["module"], name=im["name"], alias=im["alias"], line=i, lang=lang)
        for m in ENV_RX.finditer(ln):
            name = next(g for g in m.groups() if g)
            f.edge(own, "reads_env", f.env(name, i), i)
        if lang in ("javascript", "typescript") and own != f.file_id:
            for m in re.finditer(r"<([A-Z][\w.]*)\b", mlines[i - 1] if spec else ln):
                f.ref(type="arg_ref", src=own, name=m.group(1), line=i)  # React/JSX component use
        if sec and not ln.lstrip().startswith(("//", "#", "*", "/*", "<!--", "--") + (('"',) if lang == "abap" else ())):
            for stype, label in line_sources(lang, ln):
                f.source(own, qual, stype, label, i)
            old_sql = bool(SQL_DYN.search(ln) or SQL_STR.search(ln))
            for stype, safe, reason, conf in line_sinks(lang, ln, text):
                if stype == "sql" and old_sql:
                    continue  # already reported by the SQL handlers below
                f.sink(own, qual, stype, safe, reason, i, conf=conf)
        for m in HTTP_JS.finditer(ln):
            url = m.group(4)
            method = (m.group(2) or "get").upper()
            if url.startswith(("/", "${", "http")):
                f.ref(type="http", src=own, method="GET" if method == "REQUEST" else method, url=url, line=i)
        for m in list(HTTP_GO.finditer(ln)) + list(HTTP_GO2.finditer(ln)):
            meth, url = m.group(1).upper(), m.group(2)
            url = re.sub(r'^[^"]*"|"[^"]*$', "", url) if '"' in url else url
            f.ref(type="http", src=own, method=meth, url=re.sub(r'"\s*\+\s*|\s*\+\s*"', "", url), line=i)
        for m in SSRF_JS.finditer(ln):
            arg = m.group(2).strip()
            if re.search(r"req\.(query|body|params|headers)|request\.", arg):
                host_controlled = bool(re.match(r"^[`'\"]?\$?\{?\s*(req|request)\.", arg) or re.match(r"^(req|request)\.", arg))
                f.sink(own, qual, "ssrf", safe=not host_controlled, line=i, conf="high" if host_controlled else "medium",
                       reason="request input controls the URL/host" if host_controlled else "request input only in the URL path (check downstream handling)")
        if SQL_DYN.search(ln):
            f.sql(own, "SELECT {p}", i, safe=False, conf="medium")
        else:
            for m in SQL_STR.finditer(ln):
                body = m.group(2)
                safe = bool(re.search(r"\$\d|\?|:\w+|%s", body)) and "${" not in body
                f.sql(own, body, i, safe=safe)
        for m in AMQP_BIND.finditer(ln):
            f.edge(own, "consumes", f.shared("topic", m.group(1), i, exchange=m.group(2)), i)
            if sec:
                f.consumer_for(own, m.group(1), i)
        for m in PUBLISH_RX.finditer(ln):
            f.edge(own, "publishes", f.shared("topic", m.group(1), i), i, conf="medium")
        for m in SUBSCRIBE_RX.finditer(ln):
            f.edge(own, "consumes", f.shared("topic", m.group(1), i), i, conf="medium")
            if sec:
                f.consumer_for(own, m.group(1), i)
        for m in CMD_RX.finditer(ln):
            shell = GO_SHELL.search(ln)
            if shell:
                dyn = arg_kind(shell.group("arg"), "go") != "literal"
                f.sink(own, qual, "command", safe=not dyn, line=i, conf="high" if dyn and re.search(r"\b(r|req)\.|Query\(|FormValue|cmd\b", shell.group("arg")) else "medium",
                       reason="shell -c with a non-literal command string" if dyn else "shell -c with a constant command")
            else:
                f.sink(own, qual, "command", safe=bool(m.group(1)), reason="exec.Command" if m.group(1) else "child_process", line=i)
            if m.group(1) and not m.group(1).startswith(("os.", "cfg")):
                f.edge(own, "spawns", f.shared("external", Path(m.group(1).strip()).name, i, conf="low"), i, conf="low")
        if EVAL_RX.search(ln) and lang in ("javascript", "typescript"):
            f.sink(own, qual, "code", safe=False, reason="eval/new Function", line=i)
        if spec and spec.get("extra_refs"):
            for r_ in spec["extra_refs"](mlines[i - 1]):
                f.ref(src=own, line=i, **r_)
        if own != f.file_id and spec and spec.get("extra_calls") and not ln.lstrip().startswith(("*", '"', "#", "=")):
            code_ = re.sub(r'\s"[^\n]*$' if lang == "abap" else r"\s#[^\n]*$", "", ln)  # trailing comment
            for r_ in spec["extra_calls"](code_):
                f.ref(src=own, line=i, **r_)
        if lang in ("dart", "kotlin", "java", "swift"):  # Flutter platform channels: the Dart side and the native handler meet on the channel name
            for m in re.finditer(r"""MethodChannel\(\s*(?:[\w.]+\s*,\s*)?(?:name:\s*)?["']([\w./:-]+)["']""", ln):
                tail = " ".join(lines[i - 1:i + 3])
                kind_ = "consumes" if "setMethodCallHandler" in tail else "publishes"
                f.edge(own, kind_, f.shared("topic", "channel:" + m.group(1), i), i, conf="medium")
        decl_like = re.match(r"^\s*(?:(?:public|private|protected|static|abstract|virtual|override|internal|async|final|open|fun|def|func|extern|const|inline|explicit)\s+)*[\w<>\[\],.?*&:]+\s+\w+\s*\(", mlines[i - 1]) if own in class_ids.values() else None
        if own != f.file_id and spec and i not in call_lines and not decl_like:
            ml = mlines[i - 1]
            for m in spec["call"].finditer(ml):
                raw = m.group("name")
                name = norm_call(lang, raw)
                parts = name.split(".")
                if not name or name in KEYWORDS_BY_LANG or ((parts[0] in KEYWORDS_BY_LANG or parts[0] in DECL_SKIP) and parts[0] not in this_names and len(parts) == 1):
                    continue
                if name in spec.get("skip", ()) or (len(parts) == 1 and parts[0] in spec.get("skip", ())):
                    continue
                if spec.get("not_after") and spec["not_after"].search(ml[:m.start()]):
                    continue
                if lang in ("c", "cpp") and re.match(r"^\s*(?:(?:const|static|struct|unsigned|signed|volatile|enum|auto|register)\s+)*[\w:]+(?:<[^;()]*>)?(?:\s*[*&]+\s*|\s+)$", ml[:m.start()]) \
                        and not re.match(r"^\s*(?:return|else|case|new|delete|throw|co_return|co_await|co_yield|sizeof|do|goto|and|or|not)\s+$", ml[:m.start()]):
                    continue  # `Type name(args);` declares a variable, it does not call `name`
                libc_ = lang in ("c", "cpp") and len(parts) == 1 and bool(LIBC_FUNCS.match(name))
                if parts[0] in DECL_SKIP and parts[0] not in this_names:
                    continue
                if lang in ("rust",) and parts[0] == "Self":
                    parts[0] = next((c_ for s_, e_, c_ in cspans if s_ <= i <= e_), "Self")
                    name = ".".join(parts)
                ref = {"type": "call", "src": own, "name": name, "line": i}
                if libc_:
                    ref["pkg"] = "libc"
                if len(parts) == 2 and vtypes.get(parts[0]):
                    ref.update(recv_type=vtypes[parts[0]], recv_conf="medium")
                elif len(parts) == 3 and vtypes.get(parts[1]):
                    ref.update(recv_type=vtypes[parts[1]], recv_conf="medium")
                if ("::" in raw and lang in ("rust", "cpp", "php", "ruby", "perl")) or ("=>" in raw and lang == "abap"):
                    ref["path_call"] = True
                f.ref(**ref)
                if parts[-1][:1].isupper() and (len(parts) == 1 or lang in ("java", "kotlin", "csharp", "scala", "swift", "php", "javascript", "typescript")) \
                        and re.search(r"\bnew\s+" + re.escape(raw.split("(")[0]) + r"\b|^[A-Z]", raw):
                    uses.add((own, name))
                # callbacks: bare identifiers passed as arguments
                args = ml[m.end():]
                depth, buf = 1, ""
                for ch in args:
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    buf += ch
                for tok in re.split(r",(?![^(]*\))", buf)[:6]:
                    tok = tok.strip().lstrip("&").replace("::", ".")
                    if re.match(r"^[A-Za-z_$][\w$.]*$", tok) and tok not in KEYWORDS_BY_LANG and tok not in ("true", "false", "null", "nil", "None", "undefined"):
                        f.ref(type="arg_ref", src=own, name=norm_call(lang, tok), line=i)
    for own_id, tname in sorted(uses):
        f.ref(type="uses_type", src=own_id, name=tname, line=next((o[0] for o in owners if o[2] == own_id), 1))
    if spec:  # classes depend on the types in their constructor/primary-constructor parameters and fields
        for s_, e_, cname in cspans:
            if cname not in class_ids:
                continue
            for ml in mlines[s_ - 1:min(e_, s_ + (120 if lang in ("c", "cpp", "dart", "perl", "abap") else 2))]:
                for trx in spec["types"]:
                    for m in trx.finditer(ml):
                        t_ = m.group("type")
                        if t_ and t_ != cname and t_ not in DECL_SKIP:
                            f.ref(type="uses_type", src=class_ids[cname], name=t_, line=s_)
    # parameter/field types of each function (typed declarations inside its span)
    if spec:
        for s_, e_, nid, qual_, name in owners:
            tset = set()
            for ml in mlines[s_ - 1:min(e_, s_ + 6)]:
                for trx in spec["types"]:
                    for m in trx.finditer(ml):
                        if m.group("type") and m.group("type") not in DECL_SKIP:
                            tset.add(m.group("type"))
            own_cls = qual_.rsplit(".", 1)[0] if "." in qual_ else None
            for t_ in sorted(tset)[:8]:
                if t_ != own_cls:
                    f.ref(type="uses_type", src=nid, name=t_, line=s_)
    return f


# ---------------------------------------------------------------- tree-sitter (optional)

TS_FUNC = {"function_declaration", "method_declaration", "function_definition", "method_definition",
           "function_item", "arrow_function", "func_literal", "method", "function"}
TS_CALL = {"call_expression", "call", "method_invocation", "invocation_expression"}
TS_LANG = {"javascript": "javascript", "typescript": "typescript", "go": "go", "java": "java", "ruby": "ruby",
           "php": "php", "rust": "rust", "csharp": "c_sharp", "kotlin": "kotlin", "scala": "scala", "swift": "swift"}


def extract_ts(key, rel, text, lang, mod) -> Frag:
    """Tree-sitter structure (functions, calls); behavioural edges still come from the regex pass."""
    tsmod = __import__(mod)
    parser = tsmod.get_parser(TS_LANG[lang])
    tree = parser.parse(text.encode())
    base = extract_regex(key, rel, text, lang)  # routes/env/sql/http/queues
    f = Frag(key, rel, "tree-sitter")
    f.constants = base.constants
    lines = text.splitlines()
    f.node(make_node("file", key, rel, "", rel, 1, max(1, len(lines)), extractor="tree-sitter", attrs={"language": lang}))
    src = text.encode()

    def name_of(n):
        c = n.child_by_field_name("name")
        return src[c.start_byte:c.end_byte].decode(errors="replace") if c else None

    stack = [(tree.root_node, f.file_id)]
    while stack:
        n, owner = stack.pop()
        cur = owner
        if n.type in TS_FUNC and name_of(n):
            nm = name_of(n)
            s, e = n.start_point[0] + 1, n.end_point[0] + 1
            sig = lines[s - 1].strip() if s - 1 < len(lines) else nm
            cur = f.node(make_node("function", key, rel, nm, nm, s, e, extractor="tree-sitter", signature=sig[:200], sig_hash=sig_hash(sig)))
            f.edge(owner if owner == f.file_id else owner, "contains", cur, s)
        elif n.type in TS_CALL:
            fn = n.child_by_field_name("function") or n.child_by_field_name("name") or (n.children[0] if n.children else None)
            if fn is not None and cur != f.file_id:
                f.ref(type="call", src=cur, name=src[fn.start_byte:fn.end_byte].decode(errors="replace")[:120], line=n.start_point[0] + 1)
        stack.extend((ch, cur) for ch in reversed(n.children))
    # keep regex behavioural facts (endpoints, sinks, tables, topics, env) and their edges
    for nid, node in base.nodes.items():
        if node["kind"] not in ("file", "function", "class"):
            f.nodes.setdefault(nid, node)
        elif node.get("attrs", {}).get("inline_handler"):
            f.nodes.setdefault(nid, node)
    keep = set(f.nodes)
    for e in base.edges:
        if e["kind"] != "contains" and e["src"] in keep | set(base.nodes) and e["dst"] in keep:
            if e["src"] not in f.nodes and e["src"] in base.nodes:
                f.nodes.setdefault(e["src"], base.nodes[e["src"]])
            f.edges.append(e)
    f.refs += [r for r in base.refs if r["type"] in ("import", "http", "route_handler", "inherit")]
    return f


# ---------------------------------------------------------------- driver

SKIPS: list[dict] = []  # files that were not extracted or were downgraded, written to evidence/extract-skips-<key>.json


def extract_file(key, root: Path, rel: str, backend: str, tsmod: str | None) -> dict | None:
    lang = LANG.get(Path(rel).suffix.lower())
    if not lang:
        return None
    p = root / rel
    aux = ""
    if is_secret_file(rel) or is_binary(p):
        SKIPS.append({"path": rel, "reason": "secret-bearing or binary file (not read)"})
        return None
    text = read_text(p, max_bytes=1_500_000)
    if text is None:
        SKIPS.append({"path": rel, "reason": "unreadable or larger than 1.5 MB: no functions, routes or sinks were extracted"})
        return None
    if not text.strip():
        return None  # empty files (e.g. bare __init__.py) have no citable lines
    if rel.lower().endswith(".h") and CPP_HINT.search(text[:200_000]):
        lang = "cpp"  # a header that declares classes/namespaces or uses the C++ standard library
    if lang == "cpp" and Path(rel).suffix.lower() in (".cpp", ".cc", ".cxx"):
        for ext_ in (".h", ".hpp", ".hh", ".hxx"):
            hp = p.with_suffix(ext_)
            if hp.is_file() and not hp.is_symlink():
                aux = read_text(hp, max_bytes=300_000) or ""
                break
    try:
        if lang == "python" and backend in ("auto", "ast"):
            try:
                return extract_python(key, rel, text).dump()
            except (SyntaxError, RecursionError, ValueError):
                SKIPS.append({"path": rel, "reason": "Python syntax error: downgraded to the regex parser"})
                return extract_regex(key, rel, text, lang).dump() if (lang in RX or lang in SPEC) else None
        if tsmod and backend in ("auto", "tree-sitter") and lang in TS_LANG and lang not in SPEC:  # spec-driven regex parsing is the primary path for every supported language
            try:
                return extract_ts(key, rel, text, lang, tsmod).dump()
            except Exception:  # noqa: BLE001 - any tree-sitter API/version problem falls back to regex
                pass
        if lang in RX or lang in SPEC or lang == "python":
            return extract_regex(key, rel, text, lang if (lang in RX or lang in SPEC) else "javascript", aux).dump()
    except RecursionError:
        return None
    return None


def frag_path(out: Path, key: str, rel: str) -> Path:
    return out / "graph" / "fragments" / key / (hashlib.sha256(rel.encode()).hexdigest()[:24] + ".json")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--root")
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--backend", default="auto", choices=["auto", "ast", "regex", "tree-sitter"])
    ap.add_argument("--exclude", action="append", default=[])
    a = ap.parse_args()
    out = Path(a.out).resolve()
    root = Path(a.root).resolve() if a.root else repo_roots_for_output(out).get(a.key)
    if not root:
        print(f"repo key {a.key} not registered in {out}/evidence/targets.json", file=sys.stderr)
        return 2
    tsmod = ts_available() if a.backend in ("auto", "tree-sitter") else None
    excludes = a.exclude + repo_excludes(out).get(a.key, [])
    files = a.files if a.files is not None else [rel for _, rel in walk_files(root, excludes)]
    counts = {"files": 0, "nodes": 0, "edges": 0, "by_extractor": {}}
    for rel in files:
        fp = frag_path(out, a.key, rel)
        frag = extract_file(a.key, root, rel, a.backend, tsmod)
        if frag is None:
            if fp.exists():
                fp.unlink()
            continue
        frag["sha256"] = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        atomic_write(fp, json.dumps(frag))
        counts["files"] += 1
        counts["nodes"] += len(frag["nodes"])
        counts["edges"] += len(frag["edges"])
        counts["by_extractor"][frag["extractor"]] = counts["by_extractor"].get(frag["extractor"], 0) + 1
    if a.files is None:
        atomic_write(out / "evidence" / f"extract-skips-{a.key}.json", json.dumps({"repo": a.key, "skipped": SKIPS[:500], "count": len(SKIPS)}, indent=1))
    counts["skipped"] = len(SKIPS)
    counts["tree_sitter"] = tsmod or "not installed (regex fallback for non-Python)"
    print(json.dumps({"repo": a.key, **counts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
