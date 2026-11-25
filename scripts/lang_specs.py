"""Per-language parsing specs for the regex extractor: declarations, class spans, calls, imports, variable types, inheritance.

Pure text functions (no file access, nothing executed). graph_extract.extract_regex drives these for every non-Python language;
Python uses the stdlib `ast`. Each spec is one realistic rule set per language, so adding a language is adding a spec:

  mask(text, lang)              comments and string contents blanked (same length, newlines kept) so they never produce calls
  SPEC[lang]                    func / cls regexes, call regex, variable-type regexes, import parser, package-name rule
  block_end(mlines, idx, lang)  1-based last line of the declaration starting at 0-based line idx (braces, or indentation + `end`)
  parse_bases(lang, text)       (extends, implements) names from a class declaration
  norm_call(lang, raw)          `a?.b`, `a->b`, `A::b`, `$a->b`, `a\\b` -> dotted `a.b`
  pkg_of(lang, module)          the package an external import belongs to (the `package` node name)

Everything here is heuristic and line-based; results carry medium/low confidence and unresolved cases are counted, never hidden.
"""
from __future__ import annotations

import re

# ------------------------------------------------------------------ masking

_STR_DQ = r'"(?:\\.|[^"\\\n])*"'
_STR_SQ = r"'(?:\\.|[^'\\\n])*'"
_CHAR = r"'(?:\\.|[^'\\\n])'"
_STR_BT = r"`(?:\\.|[^`\\])*`"
_TRIPLE = r'"""[\s\S]*?"""'
_LC_C = r"//[^\n]*"
_BC_C = r"/\*[\s\S]*?\*/"
_LC_HASH = r"#[^\n]*"

MASK_RX = {}


def _mk(*parts):
    return re.compile("|".join(parts))


for _l in ("javascript", "typescript"):
    MASK_RX[_l] = _mk(_BC_C, _LC_C, _STR_BT, _STR_DQ, _STR_SQ)
MASK_RX["go"] = _mk(_BC_C, _LC_C, _STR_BT, _STR_DQ, _CHAR)
MASK_RX["java"] = _mk(_TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["kotlin"] = _mk(_TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["scala"] = _mk(_TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["csharp"] = _mk(r'@"(?:""|[^"])*"', _TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["swift"] = _mk(_TRIPLE, _BC_C, _LC_C, _STR_DQ)
MASK_RX["rust"] = _mk(r'r#*"[\s\S]*?"#*', _BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["php"] = _mk(_BC_C, _LC_C, r"#(?!\[)[^\n]*", _STR_DQ, _STR_SQ)
MASK_RX["ruby"] = _mk(r"(?m)^=begin[\s\S]*?^=end", _LC_HASH, _STR_DQ, _STR_SQ)
MASK_RX["c"] = _mk(_BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["cpp"] = MASK_RX["c"]
MASK_RX["dart"] = _mk(r"'''[\s\S]*?'''", _TRIPLE, _BC_C, _LC_C, _STR_DQ, _STR_SQ)
MASK_RX["perl"] = _mk(r"(?m)^=\w+[\s\S]*?^=cut", r"(?<![\$@%&\w])#[^\n]*", _STR_DQ, _STR_SQ)
MASK_RX["abap"] = _mk(r"(?m)^\*[^\n]*", r'"[^\n]*', r"'(?:''|[^'\n])*'", r"\|(?:\\.|[^|\n])*\|")


def mask(text: str, lang: str) -> str:
    rx = MASK_RX.get(lang)
    if not rx:
        return text

    def blank(m):
        t = m.group(0)
        if t[0] in "\"'`|" and len(t) >= 2 and "\n" not in t[:1]:
            q = t[0]
            inner = re.sub(r"[^\n]", " ", t[1:-1])
            return q + inner + (t[-1] if t[-1] == q else " ")
        return re.sub(r"[^\n]", " ", t)
    return rx.sub(blank, text)


# ------------------------------------------------------------------ block extents

def block_end(mlines: list[str], idx: int, lang: str) -> int:
    """1-based last line of the declaration that starts at 0-based line idx."""
    n = len(mlines)
    if lang == "ruby":
        base = len(mlines[idx]) - len(mlines[idx].lstrip())
        if re.search(r"\bend\s*$", mlines[idx]) or re.search(r"def\s+[\w.?!=]+\s*(\([^)]*\))?\s*=\s*\S", mlines[idx]):
            return idx + 1
        for j in range(idx + 1, min(n, idx + 5000)):
            s = mlines[j]
            if s.strip() and len(s) - len(s.lstrip()) <= base and re.match(r"\s*(end|\}|else|elsif|rescue|ensure)\b", s):
                return j + 1 if s.strip().startswith("end") else j
            if s.strip() and len(s) - len(s.lstrip()) < base:
                return j
        return idx + 1
    if lang == "abap":
        kw = re.match(r"\s*(CLASS|METHOD|FORM|FUNCTION|MODULE|START-OF-SELECTION|INTERFACE)\b", mlines[idx], re.I)
        end = {"class": r"ENDCLASS", "method": r"ENDMETHOD", "form": r"ENDFORM", "function": r"ENDFUNCTION", "module": r"ENDMODULE", "interface": r"ENDINTERFACE"}
        if kw and kw.group(1).lower() in end:
            for j in range(idx + 1, min(n, idx + 8000)):
                if re.match(rf"\s*{end[kw.group(1).lower()]}\b", mlines[j], re.I):
                    return j + 1
        return idx + 1
    if lang == "perl":
        base = len(mlines[idx]) - len(mlines[idx].lstrip())
        depth, started = 0, False
        for j in range(idx, min(n, idx + 3000)):
            for ch in mlines[j]:
                if ch == "{":
                    depth, started = depth + 1, True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                return j + 1
            if not started and j > idx + 2:
                break
        return idx + 1
    depth, started = 0, False
    for j in range(idx, min(n, idx + 6000)):
        for ch in mlines[j]:
            if ch == "{":
                depth, started = depth + 1, True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return j + 1
        if not started and (j >= idx + 3 or mlines[j].rstrip().endswith(";")):
            return idx + 1
    return idx + 1


# ------------------------------------------------------------------ call-name normalisation

def norm_call(lang: str, raw: str) -> str:
    s = raw.replace("?.", ".").replace("!!.", ".").replace("!.", ".").replace("&.", ".").replace("->", ".").replace("::", ".")
    s = s.replace("\\", ".")
    if lang in ("php", "perl"):
        s = s.replace("$", "")
    return s.lstrip("@.").replace("..", ".")


# ------------------------------------------------------------------ import parsing -> list of dicts(module, name, alias)

def _imp(module, name=None, alias=None):
    return {"module": module, "name": name, "alias": alias}


def js_imports(line: str, _lines=None, _i=0):
    out = []
    for m in re.finditer(r"""^\s*import\s+(?:type\s+)?(?P<clause>[^'"]*?)\s*from\s*['"](?P<mod>[^'"]+)['"]""", line):
        clause, mod = m.group("clause").strip(), m.group("mod")
        named = re.search(r"\{([^}]*)\}", clause)
        default = re.match(r"^([A-Za-z_$][\w$]*)\s*(?:,|$)", clause)
        ns = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
        if default:
            out.append(_imp(mod, "default", default.group(1)))
        if ns:
            out.append(_imp(mod, None, ns.group(1)))
        if named:
            for part in named.group(1).split(","):
                part = re.sub(r"^\s*type\s+", "", part.strip())
                if not part:
                    continue
                a = re.match(r"^([\w$]+)(?:\s+as\s+([\w$]+))?$", part)
                if a:
                    out.append(_imp(mod, a.group(1), a.group(2) or a.group(1)))
    if not out:
        m = re.match(r"""^\s*import\s*['"]([^'"]+)['"]""", line)
        if m:
            out.append(_imp(m.group(1)))
    for m in re.finditer(r"""(?:(?:const|let|var)\s+(?P<lhs>\{[^}]*\}|[\w$]+)\s*=\s*)?(?:await\s+)?require\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""", line):
        lhs, mod = m.group("lhs"), m.group("mod")
        if lhs and lhs.startswith("{"):
            for part in lhs.strip("{} ").split(","):
                a = re.match(r"^\s*([\w$]+)(?:\s*:\s*([\w$]+))?\s*$", part)
                if a:
                    out.append(_imp(mod, a.group(1), a.group(2) or a.group(1)))
        elif lhs:
            out.append(_imp(mod, None, lhs))
        else:
            out.append(_imp(mod))
    for m in re.finditer(r"""^\s*export\s+(?:\*|\{[^}]*\})\s*(?:as\s+\w+\s*)?from\s*['"]([^'"]+)['"]""", line):
        out.append(_imp(m.group(1)))
    return out


def go_imports(line: str, lines=None, i=0):
    m = re.match(r'^\s*(?:import\s+)?(?:(?P<alias>[A-Za-z_.]\w*)\s+)?"(?P<mod>[\w./~-]+)"\s*$', line)
    if not m or not lines:
        return []
    if "import" not in line and not any("import (" in x for x in lines[max(0, i - 40):i]):
        return []
    mod = m.group("mod")
    return [_imp(mod, None, m.group("alias") or mod.rstrip("/").split("/")[-1].replace("-", "_"))]


def java_imports(line: str, *_):
    m = re.match(r"^\s*import\s+(?:static\s+)?([\w.]+?)(?:\.\*)?\s*;?\s*$", line)
    if not m:
        return []
    mod = m.group(1)
    last = mod.rsplit(".", 1)[-1]
    return [_imp(mod, last, last)] if not line.rstrip().rstrip(";").endswith("*") else [_imp(mod)]


def kotlin_imports(line: str, *_):
    m = re.match(r"^\s*import\s+([\w.]+?)(?:\.\*)?(?:\s+as\s+(\w+))?\s*$", line)
    if not m:
        return []
    mod = m.group(1)
    last = mod.rsplit(".", 1)[-1]
    return [_imp(mod, last, m.group(2) or last)] if not line.strip().endswith("*") else [_imp(mod)]


def scala_imports(line: str, *_):
    m = re.match(r"^\s*import\s+([\w.]+?)\.(?:\{([^}]*)\}|(\w+|_))\s*$", line)
    if not m:
        return []
    base = m.group(1)
    if m.group(2):
        out = []
        for part in m.group(2).split(","):
            a = re.match(r"^\s*(\w+)(?:\s*=>\s*(\w+))?\s*$", part)
            if a:
                out.append(_imp(f"{base}.{a.group(1)}", a.group(1), a.group(2) or a.group(1)))
        return out
    n = m.group(3)
    return [_imp(f"{base}.{n}", n, n)] if n != "_" else [_imp(base)]


def csharp_imports(line: str, *_):
    m = re.match(r"^\s*(?:global\s+)?using\s+(?:static\s+)?(?:(\w+)\s*=\s*)?([\w.]+)\s*;", line)
    if not m:
        return []
    return [_imp(m.group(2), m.group(2).rsplit(".", 1)[-1] if m.group(1) else None, m.group(1))]


def php_imports(line: str, *_):
    out = []
    m = re.match(r"^\s*use\s+(?:function\s+|const\s+)?([\w\\]+)(?:\s+as\s+(\w+))?\s*;", line)
    if m:
        mod = m.group(1).lstrip("\\")
        last = mod.rsplit("\\", 1)[-1]
        out.append(_imp(mod, last, m.group(2) or last))
    m = re.match(r"^\s*use\s+([\w\\]+)\\\{([^}]*)\}\s*;", line)
    if m:
        for part in m.group(2).split(","):
            a = re.match(r"^\s*(\w+)(?:\s+as\s+(\w+))?\s*$", part)
            if a:
                out.append(_imp(f"{m.group(1).lstrip(chr(92))}\\{a.group(1)}", a.group(1), a.group(2) or a.group(1)))
    for m in re.finditer(r"""\b(?:require|include)(?:_once)?\s*\(?\s*(?:__DIR__\s*\.\s*)?['"]([^'"]+\.php)['"]""", line):
        out.append(_imp("./" + m.group(1).lstrip("/")))
    return out


def ruby_imports(line: str, *_):
    out = []
    m = re.match(r"""^\s*require_relative\s*\(?\s*['"]([^'"]+)['"]""", line)
    if m:
        rel_ = m.group(1)
        out.append(_imp(rel_ if rel_.startswith(".") else "./" + rel_, None, None))
    m = re.match(r"""^\s*(?:require|load|autoload\s+:\w+,)\s*\(?\s*['"]([^'"]+)['"]""", line)
    if m:
        out.append(_imp(m.group(1)))
    return out


def rust_imports(line: str, *_):
    out = []
    m = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([\w:]+)::\{([^}]*)\}\s*;", line)
    if m:
        for part in m.group(2).split(","):
            a = re.match(r"^\s*(\w+|self)(?:\s+as\s+(\w+))?\s*$", part)
            if a:
                out.append(_imp(m.group(1) if a.group(1) == "self" else f"{m.group(1)}::{a.group(1)}", a.group(1), a.group(2) or a.group(1)))
        return out
    m = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([\w:]+?)(?:\s+as\s+(\w+))?\s*;", line)
    if m:
        last = m.group(1).rsplit("::", 1)[-1]
        out.append(_imp(m.group(1), last, m.group(2) or last))
    m = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", line)
    if m:
        out.append(_imp(f"self::{m.group(1)}", m.group(1), m.group(1)))
    return out


def swift_imports(line: str, *_):
    m = re.match(r"^\s*(?:@\w+\s+)?import\s+(?:class\s+|struct\s+|enum\s+|protocol\s+|func\s+)?([\w.]+)", line)
    return [_imp(m.group(1))] if m else []


def c_imports(line: str, *_):
    m = re.match(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', line)
    return [_imp(("" if m.group(1) == '"' else "<") + m.group(2))] if m else []


def dart_imports(line: str, *_):
    m = re.match(r"""^\s*(?:import|export|part)\s+['"]([^'"]+)['"](?:\s+(?:as\s+(\w+)|show\s+([\w,\s]+)|hide\s+[\w,\s]+))*""", line)
    if not m:
        return []
    alias = re.search(r"\bas\s+(\w+)", line)
    return [_imp(m.group(1), None, alias.group(1) if alias else None)]


def perl_imports(line: str, *_):
    out = []
    m = re.match(r"^\s*(?:use|require)\s+(?:parent|base)\s+(?:-norequire\s*,\s*)?(?:qw\(([^)]*)\)|['\"]([\w:]+)['\"])", line)
    if m:
        for mod in (m.group(1) or m.group(2) or "").split():
            out.append(_imp(mod.strip("'\","), None, mod.split("::")[-1]))
        return out
    m = re.match(r"^\s*(?:use|require)\s+([A-Z][\w:]*)\b", line)
    if m:
        out.append(_imp(m.group(1), None, m.group(1).split("::")[-1]))
    m = re.match(r"""^\s*require\s+['"]([^'"]+\.p[lm])['"]""", line)
    if m:
        out.append(_imp("./" + m.group(1)))
    return out


def abap_imports(line: str, *_):
    m = re.match(r"^\s*INCLUDE\s+(\w+)\s*\.", line, re.I)
    return [_imp(m.group(1))] if m else []


# ------------------------------------------------------------------ the specs

def _c(p, flags=0):
    return re.compile(p, flags)


_JS_CALL = _c(r"(?<![\w$.])(?P<name>(?:this\.|super\.)?[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)\s*[(<]")
_JVM_CALL = _c(r"(?<![\w$.])(?P<name>(?:this\.|super\.)?[A-Za-z_$][\w$]*(?:(?:\?\.|!!\.|!\.|\.)[A-Za-z_$][\w$]*)*)\s*(?:<[^()<>]*>)?\s*[(\{]?(?=\s*(?:\(|\{|$))")

SPEC: dict[str, dict] = {}

SPEC["javascript"] = {
    "func": [
        _c(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)\s*[(<]"),
        _c(r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)"),
        _c(r"^\s+(?:(?:public|private|protected|static|async|readonly|override|get|set)\s+)*(?!if\b|for\b|while\b|switch\b|catch\b|return\b|function\b)(?P<name>[A-Za-z_$#][\w$]*)\s*(?:<[^>]*>)?\s*\([^{;]*\)\s*(?::\s*[^{;]+)?\{(?:.*\})?\s*$"),
        _c(r"^\s+(?:(?:public|private|protected|static|readonly)\s+)*(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*(?::[^=]+)?=>"),
    ],
    "cls": [_c(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?(?P<kind>class|interface)\s+(?P<name>[A-Za-z_$][\w$]*)(?:<[^>{]*>)?(?P<bases>[^{]*)")],
    "call": _JS_CALL, "imports": js_imports,
    "types": [_c(r"(?P<var>[A-Za-z_$][\w$]*)\s*\??\s*:\s*(?P<type>[A-Z][\w.$]*)(?:<[^()]*?>)?(?:\[\])?\s*(?=[,)=;\s{]|$)"),
              _c(r"(?:this\.)?(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?new\s+(?P<type>[A-Z][\w.$]*)")],
    "exts": [".js", ".mjs", ".cjs", ".jsx"],
}
SPEC["typescript"] = {**SPEC["javascript"], "exts": [".ts", ".tsx", ".mts", ".cts"]}

SPEC["go"] = {
    "func": [_c(r"^func\s+(?:\((?:\w+\s+)?\*?(?P<owner>[A-Za-z_]\w*)(?:\[[^\]]*\])?\)\s*)?(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\(")],
    "cls": [_c(r"^type\s+(?P<name>[A-Za-z_]\w*)\s+(?P<kind>struct|interface)\b(?P<bases>)")],
    "call": _c(r"(?<![\w.])(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*[(\[]"), "imports": go_imports,
    "types": [_c(r"(?P<var>\w+)\s*:?=\s*&?(?P<type>[A-Z]\w*)\{"), _c(r"(?P<var>\w+)\s*:?=\s*(?:\w+\.)?New(?P<type>[A-Z]\w*)\("),
              _c(r"(?P<var>[a-z_]\w*)\s+\*?(?:\w+\.)?(?P<type>[A-Z]\w*)\b(?=\s*[,)\n=]|\s*$|\s*`)"),
              _c(r"\((?P<var>\w+)\s+\*?(?P<type>[A-Z]\w*)\)")],
    "exts": [".go"],
}

_JAVA_MODS = r"(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|strictfp|transient)\s+)*"
SPEC["java"] = {
    "func": [
        _c(rf"^\s*(?:@\w+(?:\([^)]*\))?\s+)*{_JAVA_MODS}(?:<[^>]+>\s*)?(?P<ret>[A-Za-z_][\w.$<>\[\],?&]*(?:\s*<[^>]*>)?(?:\[\])*)\s+(?P<name>[A-Za-z_]\w*)\s*\((?!.*\)\s*;\s*$)"),
        _c(rf"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:public|private|protected)\s+(?P<name>[A-Z]\w*)\s*\((?!.*\)\s*;\s*$)"),
    ],
    "cls": [_c(rf"^\s*(?:@\w+(?:\([^)]*\))?\s+)*{_JAVA_MODS}(?:sealed\s+|non-sealed\s+)?(?P<kind>class|interface|enum|record|@interface)\s+(?P<name>[A-Za-z_]\w*)(?:<[^>{{]*>)?(?P<bases>[^{{]*)")],
    "call": _JVM_CALL, "imports": java_imports, "ret_skip": {"return", "new", "throw", "else", "case", "assert", "yield", "package", "import", "goto"},
    "types": [_c(r"(?P<type>[A-Z][\w.]*)(?:<[^()]*?>)?(?:\[\])?\s+(?P<var>[a-z_]\w*)\s*(?=[=;,)]|$)"),
              _c(r"(?P<var>[a-z_]\w*)\s*=\s*new\s+(?P<type>[A-Z][\w.]*)")],
    "exts": [".java"],
}

SPEC["kotlin"] = {
    "func": [_c(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|internal|override|open|abstract|suspend|inline|operator|tailrec|final|infix|external)\s+)*fun\s+(?:<[^>]+>\s*)?(?:(?P<owner>[A-Za-z_][\w.<>?]*)\.)?(?P<name>[A-Za-z_]\w*)\s*\(")],
    "cls": [_c(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|internal|open|abstract|sealed|data|enum|inner|annotation|value|fun)\s+)*(?P<kind>class|interface|object)\s+(?P<name>\w+)(?:<[^>]*>)?(?P<bases>[^{=]*)")],
    "call": _JVM_CALL, "imports": kotlin_imports,
    "types": [_c(r"(?P<var>\w+)\s*:\s*(?P<type>[A-Z][\w.]*)(?:<[^()]*?>)?\??"), _c(r"(?P<var>\w+)\s*=\s*(?P<type>[A-Z]\w*)\(")],
    "exts": [".kt", ".kts"],
}

SPEC["scala"] = {
    "func": [_c(r"^\s*(?:(?:private|protected|override|final|implicit|lazy|inline|abstract)\s+)*def\s+(?P<name>\w+)")],
    "cls": [_c(r"^\s*(?:(?:case|abstract|sealed|final|private|protected|implicit)\s+)*(?P<kind>class|trait|object)\s+(?P<name>\w+)(?:\[[^\]]*\])?(?:\([^)]*\))?(?P<bases>[^{=]*)")],
    "call": _JVM_CALL, "imports": scala_imports,
    "types": [_c(r"(?P<var>\w+)\s*:\s*(?P<type>[A-Z][\w.]*)(?:\[[^\]]*\])?"), _c(r"(?:val|var)\s+(?P<var>\w+)\s*=\s*(?:new\s+)?(?P<type>[A-Z]\w*)[(\[]")],
    "exts": [".scala", ".sc"],
}

_CS_MODS = r"(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract|extern|unsafe|new|partial|readonly)\s+)"
SPEC["csharp"] = {
    "func": [
        _c(rf"^\s*(?:\[[^\]]+\]\s*)*{_CS_MODS}+(?:[\w<>\[\],.?]+\s+)+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\("),
        _c(rf"^\s*(?:\[[^\]]+\]\s*)*{_CS_MODS}+(?P<name>[A-Z]\w*)\s*\("),
    ],
    "cls": [_c(rf"^\s*(?:\[[^\]]+\]\s*)*{_CS_MODS}*(?P<kind>class|interface|struct|record|enum)\s+(?P<name>\w+)(?:<[^>]*>)?(?P<bases>[^{{]*)")],
    "call": _JVM_CALL, "imports": csharp_imports,
    "types": [_c(r"(?P<type>[A-Z][\w.]*)(?:<[^()]*?>)?(?:\[\])?\??\s+(?P<var>[a-zA-Z_]\w*)\s*(?=[=;,)]|$)"),
              _c(r"(?P<var>\w+)\s*=\s*new\s+(?P<type>[A-Z][\w.]*)")],
    "exts": [".cs"],
}

SPEC["ruby"] = {
    "func": [_c(r"^\s*def\s+(?:(?P<owner>self)\.)?(?P<name>[A-Za-z_]\w*[!?=]?)")],
    "cls": [_c(r"^\s*(?P<kind>class|module)\s+(?P<name>[A-Z][\w:]*)(?:\s*<\s*(?P<bases>[A-Z][\w:]*))?")],
    "call": _c(r"(?<![\w@$:.])(?P<name>@?[A-Za-z_]\w*(?:(?:\.|::|&\.)[A-Za-z_]\w*[!?]?)*)(?:\s*\(|(?<=\.new)(?=\s|$))"), "imports": ruby_imports,
    "types": [_c(r"(?P<var>@?\w+)\s*=\s*(?P<type>[A-Z][\w:]*)\.new\b")],
    "exts": [".rb", ".rake"],
}

SPEC["php"] = {
    "func": [_c(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(?P<name>[A-Za-z_]\w*)\s*\(")],
    "cls": [_c(r"^\s*(?:(?:abstract|final|readonly)\s+)*(?P<kind>class|interface|trait|enum)\s+(?P<name>\w+)(?P<bases>[^{]*)")],
    "call": _c(r"(?<![\w$>])(?P<name>\$?[A-Za-z_\\][\w\\]*(?:(?:->|\?->|::)\$?[A-Za-z_]\w*)*)\s*\("), "imports": php_imports,
    "types": [_c(r"\??(?P<type>[A-Z][\w\\]*)\s+\$(?P<var>\w+)"), _c(r"\$(?:this->)?(?P<var>\w+)\s*=\s*new\s+(?P<type>[A-Z][\w\\]*)")],
    "exts": [".php", ".phtml", ".inc"],
}

SPEC["rust"] = {
    "func": [_c(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_]\w*)")],
    "cls": [_c(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?P<kind>struct|enum|trait|union)\s+(?P<name>\w+)(?:<[^>{]*>)?(?P<bases>\s*:\s*[^{;]*)?")],
    "owner": _c(r"^\s*(?:unsafe\s+)?impl(?:<[^>]*>)?\s+(?:(?P<trait>[\w:]+)(?:<[^>]*>)?\s+for\s+)?(?P<name>[A-Za-z_][\w:]*)"),
    "call": _c(r"(?<![\w:.])(?P<name>[A-Za-z_]\w*(?:(?:::|\.)[A-Za-z_]\w*)*)\s*(?:::<[^>]*>)?\("), "imports": rust_imports,
    "types": [_c(r"(?P<var>\w+)\s*:\s*&?(?:mut\s+)?(?:Box<|Arc<|Rc<|Option<)?(?P<type>[A-Z]\w*)"),
              _c(r"let(?:\s+mut)?\s+(?P<var>\w+)\s*=\s*(?P<type>[A-Z]\w*)::(?:new|default|from|build|create|connect|open)\b")],
    "exts": [".rs"],
}

SPEC["swift"] = {
    "func": [_c(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|fileprivate|internal|open|static|class|final|override|mutating|nonmutating|convenience|required|async)\s+)*(?:func\s+(?P<name>[A-Za-z_]\w*)|(?P<init>init)\s*[?!]?\()")],
    "cls": [_c(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|fileprivate|internal|open|final)\s+)*(?P<kind>class|struct|protocol|enum|actor|extension)\s+(?P<name>\w+)(?:<[^>]*>)?(?P<bases>\s*:\s*[^{]*)?")],
    "call": _JVM_CALL, "imports": swift_imports,
    "types": [_c(r"(?P<var>\w+)\s*:\s*(?P<type>[A-Z][\w.]*)(?:<[^()]*?>)?\??"), _c(r"(?:let|var)\s+(?P<var>\w+)\s*=\s*(?P<type>[A-Z]\w*)\(")],
    "exts": [".swift"],
}

# ------------------------------------------------------------------ bases / package names / keywords

def _names(s: str) -> list[str]:
    return [re.split(r"[<(\[]", x.strip())[0].strip() for x in re.split(r",", s) if x.strip()]


def parse_bases(lang: str, kind: str, decl: str) -> tuple[list[str], list[str]]:
    """(extends, implements) type names from a class declaration (text up to the opening brace)."""
    d = re.sub(r"\s+", " ", decl)
    ext, imp = [], []
    if lang in ("javascript", "typescript", "java", "php"):
        m = re.search(r"\bextends\s+([\w$.\\<>, ]+?)(?=\s+implements\b|\s*\{|$)", d)
        if m:
            names = _names(m.group(1))
            (imp if kind == "interface" else ext).extend(names)
        m = re.search(r"\bimplements\s+([\w$.\\<>, ]+?)(?=\s*\{|$)", d)
        if m:
            imp.extend(_names(m.group(1)))
    elif lang == "scala":
        m = re.search(r"\bextends\s+([\w.\[\], ]+?)(?:\s+with\s+([\w.\[\], with]+))?(?=\s*\{|\s*$)", d)
        if m:
            ext.append(_names(m.group(1))[0])
            if m.group(2):
                imp.extend(_names(m.group(2).replace(" with ", ",")))
    elif lang in ("kotlin", "csharp", "swift"):
        m = re.match(r"^[^:]*?(?:\([^)]*\))?\s*:\s*(.+)$", d) if ":" in d else None
        if m:
            items = [x.strip() for x in re.split(r",", re.sub(r"\bwhere\b.*", "", m.group(1))) if x.strip()]
            for i, it in enumerate(items):
                nm = re.split(r"[<(\[ ]", it)[0]
                if not nm or not nm[0].isupper():
                    continue
                is_ctor = "(" in it
                is_iface = bool(re.match(r"^I[A-Z]", nm)) if lang == "csharp" else False
                if lang == "kotlin":
                    (ext if is_ctor else imp).append(nm)
                elif lang == "csharp":
                    (ext if (i == 0 and kind == "class" and not is_iface) else imp).append(nm)
                else:
                    (ext if (i == 0 and kind == "class") else imp).append(nm)
    elif lang == "ruby":
        m = re.search(r"<\s*([A-Z][\w:]*)", d)
        if m:
            ext.append(m.group(1))
    elif lang == "rust":
        m = re.search(r":\s*([\w:+ <>]+)", d)
        if m and kind == "trait":
            imp.extend(x.strip() for x in m.group(1).split("+") if x.strip())
    elif lang == "dart":
        m = re.search(r"\bextends\s+([\w.<>?]+)", d)
        if m:
            ext.append(re.split(r"[<]", m.group(1))[0])
        for key in ("implements", "with"):
            m = re.search(rf"\b{key}\s+([\w.<>?, ]+?)(?=\s+(?:implements|with|extends)\b|\s*\{{|$)", d)
            if m:
                imp.extend(_names(m.group(1)))
    elif lang == "cpp":
        m = re.search(r":\s*((?:(?:public|protected|private|virtual)\s+)*[\w:<>]+(?:\s*,\s*(?:(?:public|protected|private|virtual)\s+)*[\w:<>]+)*)", d)
        if m:
            for it in m.group(1).split(","):
                nm = re.sub(r"^(?:(?:public|protected|private|virtual)\s+)*", "", it.strip())
                if nm:
                    (ext if not ext else imp).append(nm.split("<")[0])
    elif lang == "perl":
        pass
    elif lang == "abap":
        m = re.search(r"INHERITING\s+FROM\s+(\w+)", d, re.I)
        if m:
            ext.append(m.group(1))
    return ext, imp


KEYWORDS_BY_LANG = {"if", "for", "while", "switch", "catch", "return", "function", "typeof", "new", "await", "async", "func", "make", "len", "append", "cap",
                    "panic", "recover", "defer", "go", "select", "range", "super", "this", "require", "import", "case", "else", "throw", "delete", "void",
                    "yield", "sizeof", "print", "println", "elif", "when", "do", "try", "finally", "using", "lock", "synchronized", "foreach", "match",
                    "unless", "until", "begin", "rescue", "ensure", "puts", "p", "fn", "let", "mut", "impl", "self", "Self", "init", "guard", "defer",
                    "echo", "isset", "empty", "unset", "array", "list", "die", "exit", "include", "require_once", "include_once", "assert", "instanceof",
                    "nameof", "typeof", "default", "operator", "in", "is", "as", "with", "where", "throws", "class", "struct", "enum", "interface", "package"}


def pkg_of(lang: str, module: str) -> str | None:
    m = (module or "").strip()
    if not m or m.startswith((".", "/")):
        return None
    if lang in ("javascript", "typescript"):
        parts = m.split("/")
        return "/".join(parts[:2]) if m.startswith("@") and len(parts) > 1 else parts[0]
    if lang == "go":
        parts = m.split("/")
        return "/".join(parts[:3]) if "." in parts[0] and len(parts) >= 3 else m
    if lang in ("java", "kotlin", "scala"):
        parts = m.split(".")
        return ".".join(parts[:2]) if len(parts) > 1 else parts[0]
    if lang in ("csharp", "swift"):
        return m.split(".")[0]
    if lang == "php":
        return m.split("\\")[0]
    if lang == "rust":
        return m.split("::")[0]
    if lang in ("c", "cpp"):
        return m.lstrip("<").split("/")[0].split(".")[0]
    if lang == "dart":
        return m.split(":", 1)[1].split("/")[0] if m.startswith("package:") else (m.split(":")[0] if m.startswith("dart:") else None)
    if lang == "perl":
        return m.split("::")[0]
    return m.split("/")[0].split(".")[0]


def ext_lang_map() -> dict[str, str]:
    out = {}
    for lang, sp in SPEC.items():
        for e in sp.get("exts", []):
            out[e] = lang
    return out
