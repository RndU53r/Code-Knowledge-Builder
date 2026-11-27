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


MASK_NB = {}  # same rules without the lazy multi-line block alternatives (used when a block opener is never closed)


def _reg(lang, *parts):
    MASK_RX[lang] = _mk(*parts)
    MASK_NB[lang] = _mk(*[x for x in parts if "[\\s\\S]*?" not in x])


for _l in ("javascript", "typescript"):
    _reg(_l, _BC_C, _LC_C, _STR_BT, _STR_DQ, _STR_SQ)
_reg("go", _BC_C, _LC_C, _STR_BT, _STR_DQ, _CHAR)
_reg("java", _TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
_reg("kotlin", _TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
_reg("scala", _TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
_reg("csharp", r'@"(?:""|[^"])*"', _TRIPLE, _BC_C, _LC_C, _STR_DQ, _CHAR)
_reg("swift", _TRIPLE, _BC_C, _LC_C, _STR_DQ)
_reg("rust", r'r#*"[\s\S]*?"#*', _BC_C, _LC_C, _STR_DQ, _CHAR)
_reg("php", _BC_C, _LC_C, r"#(?!\[)[^\n]*", _STR_DQ, _STR_SQ)
_reg("ruby", r"(?m)^=begin[\s\S]*?^=end", _LC_HASH, _STR_DQ, _STR_SQ)
_reg("c", _BC_C, _LC_C, _STR_DQ, _CHAR)
MASK_RX["cpp"], MASK_NB["cpp"] = MASK_RX["c"], MASK_NB["c"]
_reg("dart", r"'''[\s\S]*?'''", _TRIPLE, _BC_C, _LC_C, _STR_DQ, _STR_SQ)
_reg("perl", r"(?m)^=\w+[\s\S]*?^=cut", r"(?<![\$@%&\w])#[^\n]*", _STR_DQ, _STR_SQ)
_reg("abap", r"(?m)^\*[^\n]*", r'"[^\n]*', r"'(?:''|[^'\n])*'", r"`(?:``|[^`\n])*`", r"\|(?:\\.|[^|\n])*\|")


TQ = "'" * 3
_KEEP_BREAKS = r"[^\n\r\f\v\x1c-\x1e\x85\u2028\u2029]"  # line separators survive masking so line numbers stay aligned with str.splitlines()


def _unterminated(text: str, lang: str) -> bool:
    """A block opener without its closer makes every lazy scan run to the end of the file (quadratic): detect that and skip block masking."""
    if "/*" in text and text.count("/*") > text.count("*/") + 3:
        return True
    if '"""' in text and text.count('"""') % 2 == 1:
        return True
    if lang == "ruby" and text.count("=begin") > text.count("=end") + 1:
        return True
    if lang == "perl" and re.search(r"(?m)^=\w+", text):
        blocks = len(re.findall(r"(?m)^=(?:pod|head\d|over|item|begin|for|encoding)\b", text))
        if text.count("\n=cut") + text.startswith("=cut") == 0 and blocks:  # a pod block with no =cut anywhere swallows the rest of the file
            return True
    if lang == "dart" and (TQ in text and text.count(TQ) % 2 == 1):
        return True
    return False


def mask(text: str, lang: str) -> str:
    rx = MASK_RX.get(lang)
    if not rx:
        return text
    if _unterminated(text, lang):
        rx = MASK_NB.get(lang, rx)

    def blank(m):
        t = m.group(0)
        if t[0] in "\"'`|" and len(t) >= 2:
            q = t[0]
            inner = re.sub(_KEEP_BREAKS, " ", t[1:-1])
            return q + inner + (t[-1] if t[-1] == q else " ")
        return re.sub(_KEEP_BREAKS, " ", t)
    out = rx.sub(blank, text)
    return out.lower() if lang == "abap" else out


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
        if re.match(r"\s*(START-OF-SELECTION|END-OF-SELECTION|INITIALIZATION)\b", mlines[idx], re.I):
            for j in range(idx + 1, min(n, idx + 8000)):
                if re.match(r"\s*(START-OF-SELECTION|END-OF-SELECTION|INITIALIZATION|FORM|CLASS|FUNCTION|MODULE|AT\s|TOP-OF-PAGE|LOAD-OF-PROGRAM|METHOD)\b", mlines[j], re.I):
                    return j
            return n
        kw = re.match(r"\s*(CLASS|METHOD|FORM|FUNCTION|MODULE|INTERFACE)\b", mlines[idx], re.I)
        end = {"class": r"ENDCLASS", "method": r"ENDMETHOD", "form": r"ENDFORM", "function": r"ENDFUNCTION", "module": r"ENDMODULE", "interface": r"ENDINTERFACE"}
        if kw and kw.group(1).lower() in end:
            for j in range(idx + 1, min(n, idx + 8000)):
                if re.match(rf"\s*{end[kw.group(1).lower()]}\b", mlines[j], re.I):
                    return j + 1
        return idx + 1
    if lang == "perl":
        if re.match(r"\s*package\s+[\w:]+\s*(?:[\d._]+\s*)?;", mlines[idx]):  # `package X;` runs to the next package statement or the end of the file
            for j in range(idx + 1, n):
                if re.match(r"\s*package\s+[\w:]+", mlines[j]) or re.match(r"__(?:END|DATA)__", mlines[j]):
                    return j
            return n
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
    for j in range(idx, min(n, idx + 2500)):
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
    if lang == "perl":
        raw = re.sub(r"->\{(\w+)\}", r".\1", raw)
    if lang == "abap":
        raw = raw.lower().replace("=>", ".").replace("->", ".")
        return ("self." + raw[3:]) if raw.startswith("me.") else raw
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
    if not m:
        return []
    stem = m.group(2).rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return [_imp(("" if m.group(1) == '"' else "<") + m.group(2), None, stem)]


def dart_imports(line: str, *_):
    m = re.match(r"""^\s*(?:import|export|part)\s+['"]([^'"]+)['"](?:\s+(?:as\s+(\w+)|show\s+([\w,\s]+)|hide\s+[\w,\s]+))*""", line)
    if not m:
        return []
    alias = re.search(r"\bas\s+(\w+)", line)
    return [_imp(m.group(1), None, alias.group(1) if alias else None)]


def perl_imports(line: str, *_):
    out = []
    m = re.match(r"^\s*(?:use|require)\s+(?:parent|base)\s+(?:-norequire\s*,?\s*)?(?:qw\(([^)]*)\)|['\"]([\w:]+)['\"])", line)
    if m:
        for mod in [x for x in (m.group(1) or m.group(2) or "").split() if not x.startswith("-")]:
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



# ------------------------------------------------------------------ per-language extras (calls the generic call regex cannot see)

_ABAP_STD = re.compile(r"^[a-xA-X]")  # customer namespace is Z*/Y*/ns; everything else is SAP standard


def abap_extra_calls(line: str) -> list[dict]:
    """PERFORM / CALL FUNCTION / CALL METHOD / SUBMIT / CREATE OBJECT / NEW: statements whose target is in a string or keyword form."""
    out = []
    low = line
    for m in re.finditer(r"(?i)\bPERFORM\s+([A-Za-z_][\w-]*)", low):
        if m.group(1).lower() not in ("on", "using", "changing", "tables", "in"):
            out.append({"type": "call", "name": m.group(1).lower()})
    for m in re.finditer(r"(?i)\bCALL\s+FUNCTION\s+'([^']+)'(.*)", low):
        nm = m.group(1).lower()
        rfc = bool(re.search(r"(?i)\bDESTINATION\b", m.group(2)))
        d = {"type": "call", "name": nm}
        if rfc:
            d["pkg"] = "rfc"
        elif _ABAP_STD.match(nm):
            d["pkg"] = nm.split("_")[0] if nm.split("_")[0] in ("bapi", "rfc", "sxpg", "ssfc", "popup", "reuse", "gui", "ws") else "sap-standard"
        out.append(d)
    for m in re.finditer(r"(?i)\bCALL\s+METHOD\s+([A-Za-z_][\w-]*(?:(?:->|=>)[A-Za-z_~][\w~]*)+)", low):
        d = {"type": "call", "name": m.group(1).lower().replace("=>", ".").replace("->", "."), "path_call": "=>" in m.group(1)}
        out.append(d)
    for m in re.finditer(r"(?i)\bSUBMIT\s+([A-Za-z_][\w/]*)", low):
        nm = m.group(1).lower()
        out.append({"type": "call", "name": nm, **({"pkg": "sap-standard"} if _ABAP_STD.match(nm) else {})})
    for m in re.finditer(r"(?i)\b(?:CREATE\s+OBJECT\s+[\w-]+\s+TYPE\s+([A-Za-z_][\w/]*)|\bNEW\s+([A-Za-z_][\w/]*)\s*\()", low):
        nm = (m.group(1) or m.group(2)).lower()
        if nm not in ("#", "string", "i", "f", "c", "n", "d", "t", "x", "p"):
            out.append({"type": "call", "name": nm + ".new", **({"pkg": nm} if _ABAP_STD.match(nm) else {})})
    return out


def perl_extra_calls(line: str) -> list[dict]:
    out = []
    for m in re.finditer(r"&([A-Za-z_][\w:]*)\s*\(", line):
        out.append({"type": "call", "name": m.group(1).replace("::", ".")})
    for m in re.finditer(r"\\&([A-Za-z_][\w:]*)", line):
        out.append({"type": "arg_ref", "name": m.group(1).replace("::", ".")})
    for m in re.finditer(r"->can\(\s*['\"](\w+)['\"]\s*\)", line):
        out.append({"type": "arg_ref", "name": m.group(1)})
    return out


def c_extra_refs(line: str) -> list[dict]:
    """Function-pointer tables: `.save = pg_save,` / `{ &handler, ... }` become references (the registered function)."""
    out = []
    for m in re.finditer(r"\.\s*([A-Za-z_]\w*)\s*=\s*&?([A-Za-z_]\w*)\s*[,}]", line):
        out.append({"type": "arg_ref", "name": m.group(2)})
    return out


def dart_extra_refs(line: str) -> list[dict]:
    out = []
    for m in re.finditer(r"\b(?:onPressed|onTap|onChanged|onSubmitted|onGenerateRoute|builder|handler|listen|then|map)\s*[:(]\s*(?:_?[a-z]\w*\.)?(_?[a-z]\w*)\s*[,)]", line):
        out.append({"type": "arg_ref", "name": m.group(1)})
    return out


LIBC_FUNCS = re.compile(r"^(?:strlen|strnlen|strcmp|strncmp|strcasecmp|strncasecmp|strcpy|strncpy|strcat|strncat|strchr|strrchr|strstr|strdup|strndup|strtok|strtok_r|strspn|strcspn|strpbrk|strerror|strtol|strtoul|strtoll|strtoull|strtod|strtof|"
                       r"memcpy|memmove|memset|memcmp|memchr|printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|dprintf|scanf|fscanf|sscanf|fopen|fclose|fread|fwrite|fgets|fputs|fseek|ftell|fflush|fgetc|fputc|getc|putc|puts|putchar|getchar|feof|ferror|"
                       r"malloc|calloc|realloc|free|exit|abort|atexit|atoi|atol|atoll|atof|getenv|setenv|putenv|system|popen|pclose|open|close|read|write|lseek|socket|bind|listen|accept|connect|send|recv|sendto|recvfrom|setsockopt|getsockopt|shutdown|select|poll|"
                       r"signal|sigaction|sigemptyset|sigaddset|sigprocmask|kill|fork|execl|execlp|execle|execv|execvp|execvpe|wait|waitpid|pipe|dup|dup2|time|clock|gettimeofday|sleep|usleep|nanosleep|qsort|bsearch|abs|labs|rand|srand|perror|assert|"
                       r"gethostbyname|getaddrinfo|freeaddrinfo|inet_pton|inet_ntop|inet_addr|htons|htonl|ntohs|ntohl|opendir|readdir|closedir|stat|fstat|lstat|access|unlink|remove|rename|mkdir|rmdir|chdir|getcwd|realpath|basename|dirname|"
                       r"setjmp|longjmp|syslog|openlog|closelog|getopt|getopt_long|getpid|getuid|setuid|chmod|chown|umask|mmap|munmap|dlopen|dlsym|dlclose|isalpha|isdigit|isalnum|isspace|isupper|islower|toupper|tolower|pthread_\w+|sem_\w+)$")


# ------------------------------------------------------------------ the specs

def _c(p, flags=0):
    return re.compile(p, flags)


_JS_CALL = _c(r"(?<![\w$.])(?P<name>(?:this\.|super\.)?[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)\s*(?:\(|<[^<>()=;]*>\s*\()")
_JVM_CALL = _c(r"(?<![\w$.])(?P<name>(?:this\.|super\.)?[A-Za-z_$][\w$]*(?:(?:\?\.|!!\.|!\.|\.)[A-Za-z_$][\w$]*)*)\s*(?:<[^()<>]*>)?\s*(?=\(|\{)")

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
    "call": _c(r"(?<![\w.])(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?:\(|\[[^\[\]()]*\]\()"), "imports": go_imports,
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


_C_RET_SKIP = {"return", "else", "case", "goto", "sizeof", "typedef", "do", "new", "delete", "throw", "co_return", "co_await", "co_yield", "using", "namespace", "typeof"}
_C_MODS = r"(?:(?:static|inline|extern|const|volatile|unsigned|signed|struct|enum|union|register|constexpr|virtual|explicit|friend|typename|class|noexcept|__inline__|__attribute__\(\([^)]*\)\))\s+)*"

SPEC["c"] = {
    "func": [_c(r"^[ \t]*" + _C_MODS + r"(?P<ret>[A-Za-z_]\w*)(?:[\s*]+)(?P<name>[A-Za-z_]\w*)\s*\((?:[^;]*|[^;{]*\)[^;{]*\{.*)$")],
    "cls": [_c(r"^[ \t]*(?:typedef\s+)?(?P<kind>struct|union|enum)\s+(?P<name>[A-Za-z_]\w*)\s*\{?\s*$")],
    "call": _c(r"(?<![\w.>])(?![A-Z][A-Z0-9_]*\s*\()(?P<name>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*\("),
    "imports": c_imports,
    "types": [_c(r"\b(?:struct\s+)?(?P<type>[A-Za-z_]\w*)\s*\*+\s*(?P<var>[A-Za-z_]\w*)\s*[=,);\[]")],
    "ret_skip": _C_RET_SKIP,
    "skip": {"defined", "static_assert", "_Static_assert", "alignof", "offsetof", "__attribute__", "__typeof__", "va_start", "va_end", "va_arg", "__builtin_expect"},
    "extra_refs": c_extra_refs,
    "exts": [".c", ".h"],
}

SPEC["cpp"] = {
    "func": [
        _c(r"^[ \t]*(?:template\s*<[^>]*>\s*)?" + _C_MODS + r"(?P<ret>[A-Za-z_][\w:<>,]*?)(?:[\s*&]+)(?:(?P<owner>[A-Za-z_]\w*)(?:<[^>]*>)?::)?(?P<name>~?[A-Za-z_]\w*|operator\s*\S+?)\s*\((?:[^;]*|[^;{]*\)[^;{]*\{.*)$"),
        _c(r"^[ \t]*(?:template\s*<[^>]*>\s*)?(?P<owner>[A-Za-z_]\w*)(?:<[^>]*>)?::(?P<name>~?[A-Za-z_]\w*)\s*\((?:[^;]*|[^;{]*\)[^;{]*\{.*)$"),
        _c(r"^[ \t]*(?:explicit\s+)?(?P<name>~?[A-Z][a-z]\w*)\s*\([^;]*\)\s*(?:noexcept\s*)?(?::[^;{]*)?(?:\{.*)?$"),
    ],
    "cls": [_c(r"^[ \t]*(?:template\s*<[^>]*>\s*)?(?P<kind>class|struct|union)\s+(?:\[\[[^\]]*\]\]\s*)?(?:[A-Z_]+_API\s+)?(?P<name>[A-Za-z_]\w*)(?:\s+final)?(?P<bases>\s*:[^{;]*)?[ \t]*\{?[ \t]*$")],
    "call": _c(r"(?<![\w.>:])(?![A-Z][A-Z0-9_]*\s*\()(?P<name>(?:this->)?[A-Za-z_]\w*(?:(?:->|\.|::)~?[A-Za-z_]\w*)*)\s*(?:<[^()<>;]*>)?\s*\("),
    "imports": c_imports,
    "types": [_c(r"\b(?P<type>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*(?:<[^;>()]*>)?\s*[*&]+\s*(?P<var>[A-Za-z_]\w*)\s*[;=,){(\[]"),
              _c(r"\b(?:std::)?(?:unique_ptr|shared_ptr|weak_ptr|optional)\s*<\s*(?P<type>(?:\w+::)*\w+)\s*>\s+(?P<var>[A-Za-z_]\w*)"),
              _c(r"(?P<var>[A-Za-z_]\w*)\s*=\s*(?:std::)?make_(?:unique|shared)\s*<\s*(?P<type>(?:\w+::)*\w+)\s*>"),
              _c(r"(?P<var>[A-Za-z_]\w*)\s*=\s*new\s+(?P<type>(?:\w+::)*\w+)"),
              _c(r"^[ \t]*(?:const\s+)?(?P<type>(?:[A-Za-z_]\w*::)*[A-Z]\w*|std::\w+)(?:<[^;>()]*>)?\s+(?P<var>[a-z_]\w*)\s*[;{(=]"),
              _c(r"[(,]\s*(?:const\s+)?(?P<type>(?:[A-Za-z_]\w*::)*[A-Z]\w*|std::\w+)(?:<[^;>()]*>)?\s+(?P<var>[a-z_]\w*)\s*[,)=]")],
    "ret_skip": _C_RET_SKIP | {"else", "static_cast", "dynamic_cast"},
    "skip": {"static_cast", "dynamic_cast", "reinterpret_cast", "const_cast", "decltype", "noexcept", "alignas", "alignof", "typeid", "sizeof", "static_assert", "assert", "defined", "catch", "throw"},
    "extra_refs": c_extra_refs,
    "exts": [".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"],
}

SPEC["dart"] = {
    "func": [
        _c(r"^[ \t]*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:static|external|abstract|override|final|const|late|factory|async)\s+)*(?P<ret>[A-Za-z_][\w<>,.?]*(?:<[^>()]*>)?\??)\s+(?:get\s+|set\s+)?(?P<name>[A-Za-z_]\w*)\s*(?:<[^>(]*>)?\s*\((?![\s]*['\"])[^;]*?\)\s*(?:async\*?\s*|sync\*\s*)?(?:\{|=>)"),
        _c(r"^[ \t]*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:static|external|abstract|override|final|const|late|factory|async)\s+)*(?P<ret>[A-Za-z_][\w<>,.?]*(?:<[^>()]*>)?\??)\s+(?:get\s+|set\s+)?(?P<name>[A-Za-z_]\w*)\s*(?:<[^>(]*>)?\s*\(\s*$"),
        _c(r"^[ \t]*(?:const\s+|factory\s+)?(?P<name>[A-Z]\w*)(?:\.\w+)?\s*\((?![\s]*['\"])[^;]*\)\s*(?::\s*[^;{]*)?\{"),
    ],
    "cls": [_c(r"^[ \t]*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:abstract|base|final|sealed|interface|mixin)\s+)*(?P<kind>class|mixin|enum)\s+(?P<name>[A-Za-z_]\w*)(?:<[^{]*?>)?(?P<bases>[^{;]*)\{?")],
    "owner": _c(r"^[ \t]*extension\s+(?:(?P<ext>\w+)\s+)?on\s+(?P<name>[A-Za-z_]\w*)"),
    "call": _c(r"(?<![\w$.])(?P<name>(?:this\.|super\.)?[A-Za-z_$][\w$]*(?:(?:\?\.|!\.|\.)[A-Za-z_$][\w$]*)*)\s*(?:<[^()<>;]*>)?\s*\("),
    "imports": dart_imports,
    "types": [_c(r"(?:final|var|late)\s+(?P<type>[A-Z]\w*)(?:<[^>]*>)?\??\s+(?P<var>_?\w+)"),
              _c(r"\b(?P<type>[A-Z]\w*)(?:<[^>]*>)?\??\s+(?P<var>_?[a-z]\w*)\s*[;=,)]"),
              _c(r"(?:final|var)\s+(?P<var>_?\w+)\s*=\s*(?:await\s+)?(?:const\s+|new\s+)?(?P<type>[A-Z]\w*)(?:<[^>]*>)?\("),
              _c(r"\b(?P<var>_?\w+)\s*=\s*(?:await\s+)?(?:const\s+|new\s+)?(?P<type>[A-Z]\w*)\(")],
    "ret_skip": {"return", "await", "else", "throw", "new", "const", "yield", "case", "assert", "in", "is", "as"},
    "skip": {"print", "debugPrint", "assert", "identical", "super"},
    "extra_refs": dart_extra_refs,
    "exts": [".dart"],
}

_PERL_BUILTINS = {"print", "printf", "push", "pop", "shift", "unshift", "splice", "keys", "values", "each", "defined", "exists", "delete", "scalar", "join", "split", "map", "grep", "sort",
                  "reverse", "ref", "die", "warn", "eval", "bless", "sprintf", "lc", "uc", "lcfirst", "ucfirst", "length", "substr", "index", "rindex", "open", "close", "chomp", "chop",
                  "chdir", "mkdir", "rmdir", "opendir", "readdir", "closedir", "unlink", "rename", "require", "return", "sub", "if", "elsif", "unless", "while", "until", "foreach", "for",
                  "my", "our", "local", "use", "no", "package", "last", "next", "redo", "goto", "wantarray", "abs", "int", "sqrt", "sin", "cos", "atan2", "exp", "log", "hex", "oct",
                  "rand", "srand", "time", "localtime", "gmtime", "sleep", "exit", "system", "exec", "fork", "wait", "waitpid", "kill", "read", "seek", "tell", "eof", "binmode", "select",
                  "pos", "quotemeta", "pack", "unpack", "lock", "tie", "untie", "tied", "chr", "ord", "caller", "do", "qw", "q", "qq", "qr", "tr", "y", "m", "s", "undef", "exists", "local",
                  "sprintf", "readline", "chmod", "chown", "utime", "truncate", "glob", "stat", "lstat", "wait", "alarm", "sysopen", "sysread", "syswrite"}

SPEC["perl"] = {
    "func": [_c(r"^\s*sub\s+(?P<name>[A-Za-z_]\w*)\b")],
    "cls": [_c(r"^\s*package\s+(?:\w+::)*(?P<name>\w+)\s*(?:[\d._]+\s*)?(?:;|\{)")],
    "call": _c(r"(?<![\w$@%&>])(?P<name>\$?[A-Za-z_]\w*(?:->\{\w+\}|->\w+|::\w+)*)(?:\s*\(|(?<=->new)(?=\s*[;,)]|\s*$))"),
    "imports": perl_imports,
    "types": [_c(r"(?:my\s+)?\$(?P<var>\w+)\s*=\s*(?P<type>(?:\w+::)*[A-Z]\w*)->(?:new|connect|instance|create|open)\b"),
              _c(r"\$self->\{(?P<var>\w+)\}\s*(?://|\|\|)?=\s*(?P<type>(?:\w+::)*[A-Z]\w*)->new\b"),
              _c(r"\b(?P<var>\w+)\s*=>\s*(?P<type>(?:\w+::)*[A-Z]\w*)->new\b"),
              _c(r"\bhas\s+['\"]?(?P<var>\w+)['\"]?\s*=>\s*\([^)]*\bisa\s*=>\s*['\"](?P<type>(?:\w+::)*\w+)['\"]")],
    "skip": _PERL_BUILTINS,
    "extra_calls": perl_extra_calls,
    "exts": [".pl", ".pm", ".t", ".psgi", ".cgi"],
}

_ABAP_BUILTINS = {"strlen", "lines", "line_exists", "line_index", "condense", "to_upper", "to_lower", "to_mixed", "from_mixed", "concat_lines_of", "boolc", "boolx", "xsdbool", "abs", "ceil",
                  "floor", "sign", "frac", "trunc", "round", "ipow", "sqrt", "exp", "log", "log10", "sin", "cos", "tan", "nmax", "nmin", "matches", "match", "contains", "contains_any_of",
                  "contains_any_not_of", "count", "count_any_of", "find", "find_any_of", "find_any_not_of", "insert", "repeat", "replace", "reverse", "segment", "shift_left", "shift_right",
                  "substring", "substring_after", "substring_before", "substring_from", "substring_to", "translate", "escape", "cmax", "cmin", "char_off", "numofchar", "distance", "charlen",
                  "dbmaxlen", "if", "elseif", "case", "when", "while", "xstrlen", "rescale", "present", "bit-set"}

SPEC["abap"] = {
    "func": [_c(r"^\s*METHOD\s+(?P<name>[\w~]+)\s*\.", re.I),
             _c(r"^\s*FORM\s+(?P<name>[\w-]+)", re.I),
             _c(r"^\s*FUNCTION\s+(?P<name>\w+)\s*\.", re.I),
             _c(r"^\s*MODULE\s+(?P<name>\w+)\s+(?:OUTPUT|INPUT)\b", re.I),
             _c(r"^\s*(?P<name>START-OF-SELECTION|INITIALIZATION|END-OF-SELECTION)\s*\.", re.I)],
    "cls": [_c(r"^\s*CLASS\s+(?P<name>\w+)\s+DEFINITION\b(?!\s+(?:DEFERRED|LOAD))", re.I),
            _c(r"^\s*(?P<kind>INTERFACE)\s+(?P<name>\w+)\s*(?:PUBLIC\b)?[^.]*\.?\s*$", re.I)],
    "owner": _c(r"^\s*CLASS\s+(?P<name>\w+)\s+IMPLEMENTATION\b", re.I),
    "call": _c(r"(?<![\w>~=-])(?P<name>[A-Za-z_][\w-]*(?:(?:->|=>)[A-Za-z_~][\w~]*)*)\(\s", re.I),
    "imports": abap_imports,
    "types": [_c(r"(?:DATA|CLASS-DATA|STATICS|FINAL)\s*\(?\s*(?P<var>[\w-]+)\s*\)?\s+TYPE\s+REF\s+TO\s+(?P<type>\w+)", re.I),
              _c(r"\b(?P<var>\w+)\s+TYPE\s+REF\s+TO\s+(?P<type>\w+)", re.I),
              _c(r"(?:DATA|FINAL)\(\s*(?P<var>\w+)\s*\)\s*=\s*NEW\s+(?P<type>\w+)\s*\(", re.I),
              _c(r"CREATE\s+OBJECT\s+(?P<var>[\w-]+)\s+TYPE\s+(?P<type>\w+)", re.I)],
    "skip": _ABAP_BUILTINS,
    "not_after": re.compile(r"\b(?:new|cast|type|ref|to|conv|exact|value|cond|switch|reduce|filter|corresponding)\s*$", re.I),
    "extra_calls": abap_extra_calls,
    "exts": [".abap"],
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
        if m and _names(m.group(1)):
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
        m = re.search(r":\s*([^{;]+)", d)
        if m:
            depth_, cur_, parts_ = 0, "", []
            for ch_ in m.group(1):
                depth_ += (ch_ == "<") - (ch_ == ">")
                if ch_ == "," and depth_ <= 0:
                    parts_.append(cur_)
                    cur_ = ""
                else:
                    cur_ += ch_
            parts_.append(cur_)
            for it in parts_:
                nm = re.sub(r"^(?:(?:public|protected|private|virtual)\s+)*", "", it.strip())
                if nm:
                    (ext if not ext else imp).append(nm.split("<")[0])
    elif lang == "perl":
        m = re.search(r"\b(?:use\s+(?:parent|base)\b|use\s+Mojo::Base\b|@ISA\s*=|push\s+@ISA\s*,)\s*(?:-norequire\s*,\s*)?(?:qw\s*[(/]([^)/]*)|([^;]*))", d)
        if m:
            names = re.findall(r"[A-Za-z_][\w:]*", (m.group(1) or m.group(2) or "").replace("-norequire", ""))
            names = [x for x in names if x[:1].isupper() and x not in ("Mojo::Base", "Moose", "Moo", "Role")]
            if names:
                ext.append(names[0])
                imp.extend(names[1:])
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


STD_CPP_HEADERS = {"string", "vector", "memory", "map", "set", "unordered_map", "unordered_set", "algorithm", "functional", "iostream", "fstream", "sstream", "thread", "mutex", "chrono", "optional", "variant",
                   "utility", "array", "deque", "list", "queue", "stack", "tuple", "numeric", "iterator", "regex", "random", "atomic", "condition_variable", "future", "filesystem", "exception", "stdexcept",
                   "typeinfo", "type_traits", "limits", "cassert", "span", "ranges", "format", "string_view", "bitset", "complex", "ostream", "istream", "iomanip", "initializer_list", "new", "numbers"}
LIBC_DIRS = {"sys", "arpa", "netinet", "net", "linux", "asm", "bits"}
LIBC_HEADERS = {"assert", "complex", "ctype", "errno", "fenv", "float", "inttypes", "iso646", "limits", "locale", "math", "setjmp", "signal", "stdalign", "stdarg", "stdatomic", "stdbool",
                "stddef", "stdint", "stdio", "stdlib", "stdnoreturn", "string", "strings", "tgmath", "threads", "time", "uchar", "wchar", "wctype", "unistd", "fcntl", "pthread", "dirent",
                "netdb", "poll", "semaphore", "sched", "regex", "glob", "dlfcn", "syslog", "termios", "getopt", "libgen", "utime", "grp", "pwd", "ifaddrs", "ftw", "fnmatch", "wordexp"}


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
        h = m.lstrip("<")
        last = h.rsplit("/", 1)[-1]
        top = h.split("/")[0]
        if "." not in last:  # extensionless: a C++ standard header (<string>, <vector>) or a framework header such as Qt's <QProcess>
            return "std" if (last in STD_CPP_HEADERS or re.match(r"^c(?:std\w+|math|time|type|string|errno|limits|assert|signal|locale|wchar)$", last)) else last
        if top in LIBC_DIRS or h.rsplit(".", 1)[0] in LIBC_HEADERS:
            return "libc"
        return top.split(".")[0] if "/" in h else last.split(".")[0]
    if lang == "dart":
        return m.split(":", 1)[1].split("/")[0] if m.startswith("package:") else (m if m.startswith("dart:") else None)
    if lang == "perl":
        return m.split("::")[0]
    if lang == "abap":
        return None
    return m.split("/")[0].split(".")[0]


def ext_lang_map() -> dict[str, str]:
    out = {}
    for lang, sp in SPEC.items():
        for e in sp.get("exts", []):
            out[e] = lang
    return out
