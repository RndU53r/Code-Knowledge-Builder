#!/usr/bin/env python3
"""Build the ckb knowledge graph from fragments: link cross-file references, attach security findings,
merge verified agent proposals, carry over summaries, and write graph.json + graph.sqlite.

Usage:
  graph_build.py --out OUT_DIR [--extract] [--incremental] [--structural-only] [--enrich]

  --extract          run graph_extract.py for every registered code repo first (ctx-* keys are skipped)
  --incremental      with --extract: re-extract only files changed since the last hash snapshot
  --structural-only  skip proposals (used by the git-commit auto-update hook)
  --enrich           also run repo_context.py, doc_claims.py, pipeline_facts.py and threat_seed.py (draft threat model), rebuild, then
                     write the per-repo context-facts tables (context_facts.py)

Outputs: <out>/graph/graph.json, <out>/graph/graph.sqlite, <out>/system/graph.md
"""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ckb_common import load_json, now_iso, repo_roots_for_output  # noqa: E402
from lang_specs import pkg_of  # noqa: E402
from graph_common import (EXTRACTOR_VERSION, SCHEMA_VERSION, atomic_write, cite, graph_dir, make_edge,  # noqa: E402
                          make_node, md_safe, node_id, validate)

CODE_KINDS = {"function", "method", "class"}


def path_py(path: str) -> bool:
    return path.endswith(".py")


def lang_of(path: str, r: dict) -> str:
    return r.get("lang") or ("python" if path.endswith(".py") else "")


def load_fragments(out: Path, repos: dict) -> list[dict]:
    frags = []
    for key in repos:
        d = graph_dir(out) / "fragments" / key
        for p in sorted(d.glob("*.json")):
            try:
                frags.append(json.loads(p.read_text()))
            except ValueError:
                continue
    return frags


class Linker:
    def __init__(self, frags, repos, out: Path):
        self.nodes, self.edges, self.out = {}, {}, out
        self.repos = repos
        self.frags = frags
        self.by_file = {}          # (repo, path) -> frag
        self.defs_by_name = defaultdict(list)   # (repo, name) -> [node ids]
        self.file_defs = defaultdict(dict)       # (repo, path) -> {name: id}
        self.go_module = {}
        self._jsons = {}
        self._dircache = {}
        for f in frags:
            self.by_file[(f["repo"], f["path"])] = f
            for n in f["nodes"]:
                self.add_node(n)
                if n["kind"] in CODE_KINDS:
                    short = n.get("qualname", n["name"]).split(".")[-1]
                    self.defs_by_name[(f["repo"], short)].append(n["id"])
                    self.file_defs[(f["repo"], f["path"])][n.get("qualname", n["name"])] = n["id"]
            for e in f["edges"]:
                self.edges[e["id"]] = e
        for key, root in repos.items():
            gm = Path(root) / "go.mod"
            if gm.is_file():
                m = re.search(r"(?m)^module\s+(\S+)", gm.read_text(errors="replace"))
                if m:
                    self.go_module[key] = m.group(1)

    def add_node(self, n):
        cur = self.nodes.get(n["id"])
        if cur is None:
            self.nodes[n["id"]] = n
        elif n["kind"] in ("table", "topic", "external", "env_var", "endpoint"):
            seen = cur.setdefault("attrs", {}).setdefault("also_cited", [])
            if n["citation"] != cur["citation"] and n["citation"] not in seen and len(seen) < 20:
                seen.append(n["citation"])
            for k, v in (n.get("attrs") or {}).items():
                if v and not cur["attrs"].get(k):
                    cur["attrs"][k] = v

    def add_edge(self, e):
        self.edges.setdefault(e["id"], e)

    # ------------------------------------------------------------ structure
    def structure(self):
        for key, root in self.repos.items():
            meta = load_json(self.out / "evidence" / "targets.json", {}).get("repos", {}).get(key, {})
            rn = make_node("repo", key, "", key, key, 1, extractor="regex", citation="",
                           attrs={"revision": meta.get("revision"), "kind": meta.get("kind")})
            rn["citation"] = ""
            self.add_node(rn)
        for (repo, path), f in self.by_file.items():
            fid = node_id("file", repo, path, "")
            parts = path.split("/")[:-1]
            parent = node_id("repo", repo, "", repo)
            for i in range(len(parts)):
                d = "/".join(parts[: i + 1])
                did = node_id("dir", repo, d, "")
                if did not in self.nodes:
                    dn = make_node("dir", repo, d, "", d, 1, extractor="regex")
                    dn["citation"] = ""
                    self.add_node(dn)
                    self.add_edge(make_edge(parent, "contains", did, cite(repo, path, 1)))
                parent = did
            self.add_edge(make_edge(parent, "contains", fid, cite(repo, path, 1)))

    # ------------------------------------------------------------ imports
    def _suffix_files(self, repo, suffixes):
        out = []
        for (rp, p) in self.by_file:
            if rp == repo and any(p == sfx or p.endswith("/" + sfx) for sfx in suffixes):
                out.append(p)
        return out

    def _repo_json(self, repo, name):
        key = (repo, name)
        if key not in self._jsons:
            val = {}
            root = self.repos.get(repo)
            fp = Path(root) / name if root else None
            if fp and fp.is_file():
                try:
                    val = json.loads(re.sub(r"(?m)^\s*//.*$|/\*.*?\*/", "", fp.read_text(errors="replace"), flags=re.S))
                except ValueError:
                    val = {}
            self._jsons[key] = val
        return self._jsons[key]

    def resolve_import(self, f, r) -> str | None:
        repo, path = f["repo"], f["path"]
        mod = r.get("module") or ""
        lang = r.get("lang") or ("python" if path.endswith(".py") else "")
        cands = []
        here = Path(path).parent
        if path.endswith(".py"):
            base = here
            level = r.get("level") or 0
            if level:
                for _ in range(level - 1):
                    base = base.parent
                pieces = [p for p in (mod or "").split(".") if p]
                stem = base.joinpath(*pieces) if pieces else base
                if r.get("name"):
                    cands += [str(stem / r["name"]) + ".py", str(stem / r["name"] / "__init__.py")]
                cands += [str(stem) + ".py", str(stem / "__init__.py")]
            else:
                stem = Path(*mod.split(".")) if mod else None
                if stem:
                    cands += [str(stem) + ".py", str(stem / "__init__.py"), str(here / stem) + ".py"]
        elif lang in ("javascript", "typescript"):
            bases = []
            if mod.startswith("."):
                bases.append(str(here / mod))
            else:  # tsconfig baseUrl / paths aliases
                ts = self._repo_json(repo, "tsconfig.json").get("compilerOptions", {}) or {}
                base_url = ts.get("baseUrl", ".")
                for pat, targets in (ts.get("paths") or {}).items():
                    star = pat.endswith("*")
                    if (star and mod.startswith(pat[:-1])) or mod == pat:
                        rest = mod[len(pat) - 1:] if star else ""
                        for t in targets:
                            bases.append(str(Path(base_url) / (t[:-1] + rest if t.endswith("*") else t)))
                if ts.get("baseUrl"):
                    bases.append(str(Path(base_url) / mod))
            for b0 in bases:
                parts = []
                for p in Path(b0).as_posix().split("/"):
                    if p == ".." and parts:
                        parts.pop()
                    elif p not in ("..", ".", ""):
                        parts.append(p)
                s_ = "/".join(parts)
                cands += [s_] + [s_ + e for e in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".d.ts")] + [s_ + "/index" + e for e in (".ts", ".tsx", ".js", ".jsx")]
        elif lang == "go" and self.go_module.get(repo) and mod.startswith(self.go_module[repo] + "/"):
            d = mod[len(self.go_module[repo]) + 1:]
            cands += sorted((p for (rp, p) in self.by_file if rp == repo and str(Path(p).parent) == d), key=lambda p: (p.endswith("_test.go"), p))
        elif lang in ("java", "kotlin", "scala") and mod:
            rel = mod.replace(".", "/")
            exts = {"java": (".java", ".kt", ".scala"), "kotlin": (".kt", ".java"), "scala": (".scala", ".java")}[lang]
            cands += self._suffix_files(repo, [rel + e for e in exts])
        elif lang == "php" and mod:
            if mod.startswith("."):
                cands.append(str(here / mod))
            else:
                comp = self._repo_json(repo, "composer.json")
                for sect in ("autoload", "autoload-dev"):
                    for prefix, dirs in ((comp.get(sect) or {}).get("psr-4") or {}).items():
                        pre = prefix.rstrip("\\")
                        if mod == pre or mod.startswith(pre + "\\"):
                            for d_ in ([dirs] if isinstance(dirs, str) else dirs):
                                cands.append(str(Path(d_) / (mod[len(pre):].lstrip("\\").replace("\\", "/") + ".php")))
                cands += self._suffix_files(repo, [mod.replace("\\", "/") + ".php"])
        elif lang == "ruby" and mod:
            if mod.startswith("."):
                s_ = str((here / mod))
                cands += [s_, s_ + ".rb"]
            else:
                cands += self._suffix_files(repo, [mod + ".rb", "lib/" + mod + ".rb", "app/" + mod + ".rb"])
        elif lang == "rust" and mod:
            segs = [x for x in mod.split("::") if x]
            root = next((str(x) for x in [here, *here.parents] if (repo, str(x / "lib.rs")) in self.by_file or (repo, str(x / "main.rs")) in self.by_file), "src")
            if segs and segs[0] in ("crate",):
                base = Path(root)
                segs = segs[1:]
            elif segs and segs[0] == "self":
                base, segs = here, segs[1:]
            elif segs and segs[0] == "super":
                base = here.parent
                segs = segs[1:]
                while segs and segs[0] == "super":
                    base, segs = base.parent, segs[1:]
            else:
                base = Path(root)
            for n_ in range(len(segs), 0, -1):
                sub_ = base.joinpath(*segs[:n_])
                cands += [str(sub_) + ".rs", str(sub_ / "mod.rs")]
        elif lang in ("c", "cpp") and mod and not mod.startswith("<"):
            cands += [str(here / mod), mod, "include/" + mod]
            cands += self._suffix_files(repo, [mod])
        elif lang == "dart" and mod:
            if mod.startswith("package:"):
                pkgname, rest = mod[8:].split("/", 1) if "/" in mod[8:] else (mod[8:], "")
                if pkgname == (self._pubspec_name(repo) or pkgname):
                    cands += [f"lib/{rest}", rest]
                    cands += self._suffix_files(repo, [rest])
            elif not mod.startswith("dart:"):
                cands.append(str(here / mod))
        elif lang == "perl" and mod:
            if mod.startswith("."):
                cands.append(str(here / mod))
            else:
                cands += self._suffix_files(repo, [mod.replace("::", "/") + ".pm", "lib/" + mod.replace("::", "/") + ".pm"])
        for c in cands:
            c = posixpath.normpath(Path(c).as_posix())
            c = c[2:] if c.startswith("./") else c
            if (repo, c) in self.by_file:
                return c
        return None

    CS_EXTERNAL = {"System", "Microsoft", "Newtonsoft", "Azure", "Amazon", "AWSSDK", "Google", "NUnit", "Xunit", "Moq", "Serilog", "AutoMapper", "Dapper", "MediatR",
                   "FluentValidation", "Npgsql", "MySql", "Oracle", "StackExchange", "Grpc", "RestSharp", "Polly", "Swashbuckle", "Hangfire", "Humanizer", "Bogus"}

    def internal_import(self, f, r) -> bool:
        """An unresolved import that points into this repo (same package/namespace/crate) must not become an external `package` node."""
        lang, repo = lang_of(f["path"], r), f["repo"]
        mod = r.get("module") or ""
        name = r.get("name") or re.split(r"[.:\\]+", mod)[-1]
        if name and any(self.nodes[c]["kind"] == "class" for c in self.defs_by_name.get((repo, name), [])):
            return True
        if lang in ("java", "kotlin", "scala"):
            d = "/".join(mod.split(".")[:-1] if r.get("name") else mod.split("."))
            key = (repo, d)
            if key not in self._dircache:
                self._dircache[key] = bool(d) and any(rp == repo and ("/" + d + "/") in ("/" + p) for (rp, p) in self.by_file)
            return self._dircache[key]
        if lang == "csharp":
            return mod.split(".")[0] not in self.CS_EXTERNAL
        if lang == "rust":
            return mod.split("::")[0] in ("crate", "self", "super")
        if lang == "php":
            comp = self._repo_json(repo, "composer.json")
            pres = [pre.rstrip("\\") for sect in ("autoload", "autoload-dev") for pre in ((comp.get(sect) or {}).get("psr-4") or {})]
            return any(mod == p or mod.startswith(p + "\\") for p in pres if p)
        if lang == "go":
            return bool(self.go_module.get(repo)) and mod.startswith(self.go_module[repo])
        if lang == "dart":
            own = self._pubspec_name(repo)
            return bool(own) and mod.startswith(f"package:{own}/")
        return False

    def _pubspec_name(self, repo):
        root = self.repos.get(repo)
        fp = Path(root) / "pubspec.yaml" if root else None
        if fp and fp.is_file():
            m = re.search(r"(?m)^name:\s*(\S+)", fp.read_text(errors="replace"))
            return m.group(1) if m else None
        return None

    def imports(self):
        self.aliases = defaultdict(dict)  # (repo,path) -> alias -> (target_path or None, name)
        for f in self.frags:
            for r in f["refs"]:
                if r["type"] != "import":
                    continue
                tgt = self.resolve_import(f, r)
                src = f"file:{f['repo']}:{f['path']}:"
                c = cite(f["repo"], f["path"], r["line"])
                if tgt:
                    self.add_edge(make_edge(src, "imports", node_id("file", f["repo"], tgt, ""), c,
                                            extractor=f["extractor"] if f["extractor"] != "tree-sitter" else "tree-sitter"))
                    alias = r.get("alias") or Path(tgt).stem
                    self.aliases[(f["repo"], f["path"])][alias] = (tgt, r.get("name"))
                else:
                    pkg = pkg_of(lang_of(f["path"], r), r.get("module") or r.get("name") or "") if not (r.get("module") or "").startswith(".") else None
                    if pkg and not path_py(f["path"]) and self.internal_import(f, r):
                        pkg = None
                    if pkg:
                        pid = node_id("package", f["repo"], "", pkg)
                        if pid not in self.nodes:
                            pn = make_node("package", f["repo"], "", pkg, pkg, r["line"], extractor=f["extractor"] if f["extractor"] != "tree-sitter" else "regex",
                                           confidence="medium", citation=c)
                            self.add_node(pn)
                        self.add_edge(make_edge(src, "imports", pid, c, extractor=f["extractor"], confidence="medium"))
                        if r.get("alias"):
                            self.aliases[(f["repo"], f["path"])][r["alias"]] = (None, pkg)

    # ------------------------------------------------------------ calls / inherits / handlers
    def resolve_name(self, f, name, src) -> tuple[str | None, str]:
        repo, path = f["repo"], f["path"]
        parts = name.split(".")
        local = self.file_defs[(repo, path)]
        al = self.aliases[(repo, path)]
        if len(parts) == 1:
            if name in local:
                return local[name], "high"
            if name in al and al[name][0]:
                tgt, imported = al[name]
                defs_ = self.file_defs[(repo, tgt)]
                t = defs_.get(imported if imported not in (None, "default") else name)
                if not t and imported == "default":  # default export: the file's only top-level definition, or one named like the file
                    top = [v for k_, v in defs_.items() if "." not in k_]
                    t = top[0] if len(top) == 1 else defs_.get(Path(tgt).stem)
                if t:
                    return t, "high"
        else:
            head, last = parts[0], parts[-1]
            if head in al and al[head][0]:
                t = self.file_defs[(repo, al[head][0])].get(last)
                if t:
                    return t, "high"
            if head in ("self", "this", "cls"):
                owner_q = self.nodes.get(src, {}).get("qualname", "")
                cls = owner_q.rsplit(".", 1)[0] if "." in owner_q else ""
                t = local.get(f"{cls}.{last}") if cls else None
                if t:
                    return t, "medium"
            if head in al and not al[head][0]:
                return None, ""  # external package method
        short = parts[-1]
        cands = [c for c in self.defs_by_name.get((repo, short), []) if c != src]
        if len(cands) == 1 and (len(parts) == 1 or parts[0][0].islower()):
            return cands[0], "medium" if len(parts) == 1 else "low"
        return None, ""

    # ------------------------------------------------------------ classes, objects, libraries
    def resolve_class(self, f, name):
        """Class node for a (possibly dotted/generic) type name seen in file f: local, imported, or the only class of that name in the repo."""
        repo, path = f["repo"], f["path"]
        name = re.split(r"[<\[(|?]", (name or "").strip())[0].strip().strip("&*\\")
        if not name:
            return None
        parts = re.split(r"[.\\:]+", name.replace("::", "."))
        parts = [x for x in parts if x]
        if not parts:
            return None
        local = self.file_defs[(repo, path)]
        if len(parts) == 1 and parts[0] in local and self.nodes[local[parts[0]]]["kind"] == "class":
            return local[parts[0]]
        al = self.aliases[(repo, path)]
        if parts[0] in al and al[parts[0]][0]:
            tgt, imported = al[parts[0]]
            defs = self.file_defs[(repo, tgt)]
            for key in (imported if len(parts) == 1 else None, parts[-1], parts[0]):
                t = defs.get(key) if key else None
                if t and self.nodes[t]["kind"] == "class":
                    return t
        cands = [c for c in self.defs_by_name.get((repo, parts[-1]), []) if self.nodes[c]["kind"] == "class"]
        if len(cands) > 1 and len(parts) > 1:  # a qualified name: prefer the file whose path matches it
            hint = "/".join(parts[:-1]).lower()
            narrowed = [c for c in cands if hint in self.nodes[c].get("path", "").lower()]
            cands = narrowed or cands
        return cands[0] if len(cands) == 1 else None

    def mro(self, cid):
        out, seen, q = [], {cid}, list(self.bases.get(cid, []))
        while q:
            b = q.pop(0)
            if b in seen:
                continue
            seen.add(b)
            out.append(b)
            q += self.bases.get(b, [])
        return out

    def find_method(self, cid, name):
        for c in [cid] + self.mro(cid):
            n = self.nodes[c]
            t = self.file_defs[(n["repo"], n["path"])].get(f"{n.get('qualname', n['name'])}.{name}")
            if t:
                return t, c == cid
        seen, q = {cid}, list(self.subs.get(cid, []))  # polymorphic call through an interface/base type: first implementation that has the method
        while q:
            c = q.pop(0)
            if c in seen:
                continue
            seen.add(c)
            n = self.nodes[c]
            t = self.file_defs[(n["repo"], n["path"])].get(f"{n.get('qualname', n['name'])}.{name}")
            if t:
                return t, False
            q += self.subs.get(c, [])
        return None

    def resolve_call(self, f, r):
        """-> (target id or None, confidence, status) with status resolved | external | ambiguous | unresolved | dynamic."""
        name, src = r["name"], r["src"]
        parts = name.split(".")
        short = parts[-1]
        if r.get("recv_type"):
            cid = self.resolve_class(f, r["recv_type"])
            if cid:
                m = self.find_method(cid, short)
                if m:
                    return m[0], r.get("recv_conf", "medium"), "resolved"
        if r.get("recv_type"):  # typed receiver whose class comes from an external package: a library call
            h_ = re.split(r"[.\\:]+", r["recv_type"])[0]
            al_ = self.aliases[(f["repo"], f["path"])]
            if h_ in al_ and not al_[h_][0]:
                return None, "", "external"
        if ((parts[0] in ("super", "base", "parent") and len(parts) == 2) or name == "super") and self.nodes.get(src, {}).get("qualname", "").count("."):
            sn = self.nodes[src]
            if name == "super":
                short = sn["qualname"].rsplit(".", 1)[-1]
            cid = node_id("class", sn["repo"], sn["path"], sn["qualname"].rsplit(".", 1)[0])
            for b in self.mro(cid):
                bn = self.nodes[b]
                t = self.file_defs[(bn["repo"], bn["path"])].get(f"{bn.get('qualname', bn['name'])}.{short}")
                if t:
                    return t, "medium", "resolved"
            return None, "", "unresolved"
        if parts[0] == "<expr>":  # receiver is an arbitrary expression: never guess from the bare method name
            cands = [c for c in self.defs_by_name.get((f["repo"], short), []) if c != src and self.nodes[c]["kind"] in ("function", "method")]
            return (cands[0], "low", "resolved") if len(cands) == 1 else (None, "", "dynamic")
        if len(parts) >= 2 and short == "new":  # Ruby/Rust-style constructor: Foo.new / Foo::new
            cid = self.resolve_class(f, ".".join(parts[:-1]))
            if cid:
                return cid, "high", "resolved"
        if len(parts) >= 2:  # Class.static() / Class::static() / mod.Class.method()
            cid = self.resolve_class(f, ".".join(parts[:-1]))
            if cid:
                m = self.find_method(cid, short)
                if m:
                    return m[0], "high" if m[1] else "medium", "resolved"
            if len(parts) == 2 and parts[0] in self.aliases[(f["repo"], f["path"])] and not self.aliases[(f["repo"], f["path"])][parts[0]][0]:
                return None, "", "external"
        if len(parts) == 1 and parts[0] in self.aliases[(f["repo"], f["path"])] and not self.aliases[(f["repo"], f["path"])][parts[0]][0] \
                and parts[0] not in self.file_defs[(f["repo"], f["path"])]:
            return None, "", "external"
        tgt, conf = self.resolve_name(f, name, src)
        if tgt:
            return tgt, conf, "resolved"
        al = self.aliases[(f["repo"], f["path"])]
        if parts[0] in al and not al[parts[0]][0]:
            return None, "", "external"
        repo = f["repo"]
        in_repo = lambda n_: bool(self.defs_by_name.get((repo, n_)))  # noqa: E731
        if len(parts) >= 2 and parts[0][:1].isupper() and not in_repo(parts[0]):  # static call on a type that is not ours: Net::HTTP.get, URLSession.shared
            r["_pkg"] = parts[0]
            return None, "", "external"
        if len(parts) >= 2 and r.get("path_call") and parts[0][:1].islower() and parts[0] not in ("crate", "self", "super") and not in_repo(parts[0]):
            r["_pkg"] = parts[0]  # crate/module path call: reqwest::get
            return None, "", "external"
        if r.get("recv_type") and r["recv_type"][:1].isupper() and not in_repo(re.split(r"[.\\:]+", r["recv_type"])[-1]):
            ext = [m_ for m_ in self.aliases[(repo, f["path"])].values() if not m_[0] and m_[1]]
            r["_pkg"] = ext[0][1] if ext else r["recv_type"].split(".")[0]  # typed receiver of an unknown (library) class
            return None, "", "external"
        cands = [c for c in self.defs_by_name.get((f["repo"], short), []) if c != src]
        return (None, "", "ambiguous") if len(cands) > 1 else (None, "", "unresolved")

    def calls(self):
        self.bases = defaultdict(list)
        self.subs = defaultdict(list)
        self.call_stats = defaultdict(Counter)
        self.unresolved = defaultdict(Counter)
        self.unres_cite = {}
        lib = {}
        # pass 1: inheritance and interface implementation, then overrides
        for f in self.frags:
            for r in f["refs"]:
                if r["type"] not in ("inherit", "implements"):
                    continue
                c, ex = cite(f["repo"], f["path"], r["line"]), f["extractor"]
                tgt = self.resolve_class(f, r["name"])
                conf = "medium"
                if not tgt:
                    tgt, conf = self.resolve_name(f, r["name"], r["src"])
                if tgt and tgt != r["src"]:
                    self.bases[r["src"]].append(tgt)
                    self.subs[tgt].append(r["src"])
                    self.add_edge(make_edge(r["src"], "inherits" if r["type"] == "inherit" else "implements", tgt, c, extractor=ex, confidence=conf or "medium"))
        for cid in list(self.bases):
            cn = self.nodes[cid]
            q = cn.get("qualname", cn["name"])
            own = self.file_defs[(cn["repo"], cn["path"])]
            for key, mid in own.items():
                if not key.startswith(q + ".") or "." in key[len(q) + 1:] or key.endswith((".__init__", ".constructor", ".__new__")):
                    continue
                mname = key[len(q) + 1:]
                for b in self.mro(cid):
                    bn = self.nodes[b]
                    t = self.file_defs[(bn["repo"], bn["path"])].get(f"{bn.get('qualname', bn['name'])}.{mname}")
                    if t:
                        self.add_edge(make_edge(mid, "overrides", t, self.nodes[mid]["citation"], extractor="rule", confidence="medium"))
                        break
        # pass 2: calls, types, callbacks, route handlers
        for f in self.frags:
            lang = Path(f["path"]).suffix.lower().lstrip(".") or "?"
            for r in f["refs"]:
                c = cite(f["repo"], f["path"], r["line"])
                ex = f["extractor"]
                t = r["type"]
                if t == "call":
                    tgt, conf, status = self.resolve_call(f, r)
                    if tgt and tgt != r["src"]:
                        if ex != "ast" and conf == "high" and not r.get("recv_type"):
                            conf = "medium"
                        self.add_edge(make_edge(r["src"], "calls", tgt, c, extractor=ex, confidence=conf,
                                                label="observed" if conf != "low" else "inferred"))
                        if "test" in (self.nodes.get(r["src"], {}).get("tags") or []):
                            self.add_edge(make_edge(tgt, "tested_by", r["src"], c, extractor=ex if ex != "tree-sitter" else "regex", confidence=conf))
                    elif tgt:
                        status = "resolved"  # self-recursion: resolved, no edge
                    if status == "external":
                        al = self.aliases[(f["repo"], f["path"])]
                        head = (r.get("recv_type") or r["name"]).split(".")[0]
                        pkg = al.get(head, (None, None))[1] or r.get("_pkg")
                        pid = node_id("package", f["repo"], "", pkg) if pkg else None
                        if pid and pid not in self.nodes and pkg:
                            pn = make_node("package", f["repo"], "", pkg, pkg, r["line"], extractor=ex if ex != "tree-sitter" else "regex", confidence="low", citation=c)
                            self.add_node(pn)
                        if pid and pid in self.nodes:
                            e = lib.setdefault((r["src"], pid), {"apis": set(), "n": 0, "cite": c, "ex": ex})
                            e["apis"].add(".".join(r["name"].split(".")[1:]) or r["name"])
                            e["n"] += 1
                    self.call_stats[(f["repo"], lang)][status] += 1
                    if status in ("unresolved", "ambiguous", "dynamic"):
                        self.unresolved[f["repo"]][r["name"]] += 1
                        self.unres_cite.setdefault((f["repo"], r["name"]), c)
                elif t == "uses_type":
                    cid = self.resolve_class(f, r["name"])
                    if cid and cid != r["src"]:
                        self.add_edge(make_edge(r["src"], "uses_type", cid, c, extractor=ex, confidence="medium"))
                elif t == "arg_ref":
                    tgt, conf = self.resolve_name(f, r["name"], r["src"])
                    if tgt and tgt != r["src"] and self.nodes.get(tgt, {}).get("kind") in ("function", "method"):
                        self.add_edge(make_edge(r["src"], "references", tgt, c, extractor=ex, confidence="low" if conf != "high" else "medium", label="inferred"))
                elif t == "route_handler":
                    tgt, conf = self.resolve_name(f, r["name"], r["src"])
                    if r.get("hint"):  # Rails controller#action / Laravel Controller@method: prefer the file that matches the controller name
                        short = r["name"].split(".")[-1]
                        hc = [c_ for c_ in self.defs_by_name.get((f["repo"], short), []) if r["hint"].replace("controller", "") in self.nodes[c_].get("path", "").lower()]
                        if len(hc) == 1:
                            tgt, conf = hc[0], "medium"
                    if tgt:
                        self.add_edge(make_edge(r["src"], "routes_to", tgt, c, extractor=ex, confidence=conf or "medium"))
        for (src, pid), e in lib.items():
            self.add_edge(make_edge(src, "calls_lib", pid, e["cite"], extractor=e["ex"], confidence="medium",
                                    attrs={"apis": sorted(e["apis"])[:8], "count": e["n"]}))

    # ------------------------------------------------------------ cross-repo HTTP
    def http(self):
        from graph_extract import norm_path
        eps = [n for n in self.nodes.values() if n["kind"] == "endpoint"]
        for f in self.frags:
            for r in f["refs"]:
                if r["type"] != "http":
                    continue
                url = r["url"]
                path = norm_path(re.sub(r"^\$\{[^}]*\}|^\{p\}", "", url))
                method = r.get("method", "GET").upper()
                c = cite(f["repo"], f["path"], r["line"])
                matches = [e for e in eps if e["attrs"].get("norm") == path and e["repo"] != f["repo"]
                           and e["attrs"].get("method") in (method, "ANY")]
                if not matches:
                    matches = [e for e in eps if e["attrs"].get("norm") == path and e["repo"] != f["repo"]]
                for e in matches[:3]:
                    conf = "medium" if len(matches) == 1 else "low"
                    self.add_edge(make_edge(r["src"], "http_calls", e["id"], c, extractor="regex" if f["extractor"] != "ast" else "ast",
                                            confidence=conf, label="inferred" if conf == "low" else "observed",
                                            dst_citation=e["citation"], attrs={"method": method, "url": url[:120]}))
                if not matches:
                    xid = node_id("external", "_system", "", re.sub(r"^\$\{([^}]*)\}.*", r"\1", url)[:80] or "http")
                    if xid not in self.nodes:
                        xn = make_node("external", "_system", "", xid.split("::", 1)[1], xid.split("::", 1)[1], r["line"], extractor="regex",
                                       confidence="low", citation=c)
                        xn["path"] = ""
                        self.add_node(xn)
                    self.add_edge(make_edge(r["src"], "http_calls", xid, c, extractor="regex" if f["extractor"] != "ast" else "ast",
                                            confidence="low", label="inferred", attrs={"method": method, "url": url[:120]}))

    # ------------------------------------------------------------ subprocess -> built binary
    def spawns(self):
        for e in list(self.edges.values()):
            if e["kind"] != "spawns":
                continue
            ext = self.nodes.get(e["dst"])
            if not ext or ext["kind"] != "external":
                continue
            binname = ext["name"]
            for (repo, path), f in self.by_file.items():
                if re.search(rf"(^|/)cmd/{re.escape(binname)}/main\.go$", path) or re.search(rf"(^|/){re.escape(binname)}/__main__\.py$", path):
                    main = self.file_defs[(repo, path)].get("main") or node_id("file", repo, path, "")
                    self.add_edge(make_edge(e["src"], "spawns", main, e["citation"], extractor=e["provenance"]["extractor"],
                                            confidence="medium", label="inferred", dst_citation=cite(repo, path, 1),
                                            attrs={"via": binname}))

    def build(self):
        self.structure()
        self.imports()
        self.calls()
        self.http()
        self.spawns()
        return self


# ---------------------------------------------------------------- security, proposals, carry-over

def call_resolution(link: Linker, out: Path) -> dict:
    """Per repo and language: how many call references resolved, were external library calls, ambiguous, dynamic or unresolved.
    Writes evidence/call-resolution-<repo>.json (top unresolved names with a citation) so gaps are visible, never silent."""
    summary = {}
    for repo in link.repos:
        langs = {lang: dict(c) for (r, lang), c in link.call_stats.items() if r == repo}
        total = {k: sum(v.get(k, 0) for v in langs.values()) for k in ("resolved", "external", "ambiguous", "dynamic", "unresolved")}
        attempted = sum(total.values())
        summary[repo] = {"calls": attempted, **total, "resolved_pct": round(100 * (total["resolved"] + total["external"]) / attempted, 1) if attempted else None}
        top = [{"name": n, "count": k, "citation": link.unres_cite.get((repo, n))} for n, k in link.unresolved[repo].most_common(40)]
        atomic_write(out / "evidence" / f"call-resolution-{repo}.json", json.dumps(
            {"repo": repo, "summary": summary[repo], "by_language": langs, "top_unresolved": top,
             "note": "resolved = an in-repo target was found; external = a library call (see calls_lib edges); ambiguous = several candidates; "
                     "dynamic = receiver is an arbitrary expression; unresolved = no candidate. None of these are silently dropped."}, indent=1))
    return summary


def attach_security(link: Linker, out: Path):
    try:
        import graph_security
    except ImportError:
        return {}
    return graph_security.attach(link, out)


def merge_proposals(link: Linker, out: Path):
    try:
        import graph_merge
    except ImportError:
        return {}
    return graph_merge.merge_into(link, out)


def prune_superseded_drafts(link: Linker, out: Path) -> int:
    """Once a reviewer/agent has refined system/threat-model.md (no draft marker) and contributed its own threat
    nodes, the rule-based draft threats are superseded: drop them so the graph matches the model."""
    md = out / "system" / "threat-model.md"
    if not md.is_file() or "<!-- ckb:threat-seed -->" in md.read_text():
        return 0
    if not any(n["kind"] == "threat" and n["provenance"]["extractor"] == "llm" for n in link.nodes.values()):
        return 0  # refined by hand without graph proposals: keep the drafts so the graph is not left without threats
    drop = [nid for nid, n in link.nodes.items() if n["kind"] == "threat" and n["provenance"]["extractor"] == "rule"]
    for nid in drop:
        del link.nodes[nid]
    return len(drop)


def carry_over(link: Linker, out: Path):
    """Keep agent-written summaries across rebuilds (idea from Bevel's description merge; own code)."""
    ann_p = graph_dir(out) / "annotations.json"
    ann = load_json(ann_p, {"nodes": {}})
    by_sig = defaultdict(list)
    for nid, n in link.nodes.items():
        if n.get("sig_hash"):
            by_sig[(n["repo"], n["sig_hash"])].append(nid)
    stats = {"kept": 0, "outdated": 0, "moved": 0, "dropped": 0}
    new_ann = {}
    for old_id, a in ann.get("nodes", {}).items():
        n = link.nodes.get(old_id)
        target, status = None, None
        if n is not None:
            target = old_id
            status = "fresh" if n.get("sig_hash") == a.get("sig_hash") else "OUTDATED"
        else:
            cands = by_sig.get((a.get("repo"), a.get("sig_hash")), [])
            if len(cands) == 1:
                target, status = cands[0], "fresh"
                link.nodes[target].setdefault("attrs", {})["moved_from"] = old_id
                stats["moved"] += 1
            else:
                same = [nid for nid, x in link.nodes.items() if x.get("path") == a.get("path") and x.get("name") == a.get("name")
                        and x["kind"] == a.get("kind")]
                if len(same) == 1:
                    target, status = same[0], "OUTDATED"
        if target is None:
            stats["dropped"] += 1
            continue
        node = link.nodes[target]
        if node.get("summary_status") == "OUTDATED":
            status = "OUTDATED"
        for k in ("summary", "tags", "layer", "summary_source"):
            if a.get(k):
                node[k] = a[k]
        node["summary_status"] = status
        stats["kept" if status == "fresh" else "outdated"] += 1
        new_ann[target] = {**a, "sig_hash": node.get("sig_hash") if status == "fresh" else a.get("sig_hash")}
    if ann.get("nodes"):
        atomic_write(ann_p, json.dumps({"nodes": new_ann}, indent=1))
    return stats


# ---------------------------------------------------------------- outputs

def write_sqlite(graph: dict, path: Path):
    tmp = path.with_suffix(".sqlite.tmp")
    if tmp.exists():
        tmp.unlink()
    db = sqlite3.connect(tmp)
    db.executescript("""
      CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
      CREATE TABLE nodes(id TEXT PRIMARY KEY, kind TEXT, repo TEXT, path TEXT, start INT, "end" INT, name TEXT,
                         qualname TEXT, confidence TEXT, extractor TEXT, label TEXT, citation TEXT, json TEXT);
      CREATE TABLE edges(id TEXT PRIMARY KEY, src TEXT, dst TEXT, kind TEXT, confidence TEXT, extractor TEXT,
                         label TEXT, citation TEXT, json TEXT);
      CREATE INDEX e_src ON edges(src, kind); CREATE INDEX e_dst ON edges(dst, kind); CREATE INDEX n_kind ON nodes(kind);
    """)
    try:
        db.execute("CREATE VIRTUAL TABLE nodes_fts USING fts5(id UNINDEXED, name, qualname, path, summary)")
        fts = True
    except sqlite3.OperationalError:
        fts = False
    db.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
        (n["id"], n["kind"], n["repo"], n.get("path", ""), n.get("range", {}).get("start"), n.get("range", {}).get("end"),
         n["name"], n.get("qualname", ""), n["confidence"], n["provenance"]["extractor"], n["label"], n.get("citation", ""),
         json.dumps(n)) for n in graph["nodes"]])
    db.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?)", [
        (e["id"], e["src"], e["dst"], e["kind"], e["confidence"], e["provenance"]["extractor"], e["label"], e["citation"],
         json.dumps(e)) for e in graph["edges"]])
    if fts:
        db.executemany("INSERT INTO nodes_fts VALUES (?,?,?,?,?)",
                       [(n["id"], n["name"], n.get("qualname", ""), n.get("path", ""), n.get("summary", "")) for n in graph["nodes"]])
    db.executemany("INSERT INTO meta VALUES (?,?)", [("schema_version", graph["schema_version"]), ("generated", graph["generated"]),
                                                     ("fts", "1" if fts else "0"), ("stats", json.dumps(graph["stats"]))])
    db.commit()
    db.close()
    tmp.replace(path)


def report(graph: dict, out: Path, sec: dict, props: dict, carry: dict) -> str:
    st = graph["stats"]
    repos = ", ".join(f"`{k}` @ `{(v.get('revision') or 'local')[:12]}`" for k, v in graph["repos"].items())
    lines = ["# System knowledge graph", "",
             "> **ckb provenance**", f"> - Sources: {repos}", f"> - Generated: {graph['generated']} by ckb graph {EXTRACTOR_VERSION}, stage `graph`",
             "> - Scope: registered code repos · Excluded: vendored, generated, binaries, symlinks, secret files",
             "> - Method: static extraction (ast / tree-sitter if installed / regex); agent proposals merged only after citation verification",
             "> - Verification: see evidence/graph-verification.md", "",
             "## Size", "", "| Item | Count |", "| --- | --- |"]
    lines += [f"| nodes: {k} | {v} |" for k, v in sorted(st["nodes_by_kind"].items())]
    lines += [f"| edges: {k} | {v} |" for k, v in sorted(st["edges_by_kind"].items())]
    lines += ["", "## Extractors", "", "| Extractor | Nodes | Edges |", "| --- | --- | --- |"]
    for ex in sorted(set(st["nodes_by_extractor"]) | set(st["edges_by_extractor"])):
        lines.append(f"| {ex} | {st['nodes_by_extractor'].get(ex, 0)} | {st['edges_by_extractor'].get(ex, 0)} |")
    rk = [n for n in graph["nodes"] if n["kind"] == "repo" and (n.get("attrs") or {}).get("repo_kind")]
    if rk:
        lines += ["", "## Repo kinds [inferred]", "", "| Repo | Kind | Signals |", "| --- | --- | --- |"]
        lines += [f"| {md_safe(n['name'])} | {md_safe(n['attrs']['repo_kind'])}{md_safe(' (' + n['attrs'].get('primary_kind', '') + ' + ' + ', '.join(n['attrs'].get('secondary_kinds', [])) + ')' if n['attrs']['repo_kind'] == 'mixed' else '')} | {md_safe('; '.join(n['attrs'].get('repo_kind_signals', [])))} |" for n in rk]
    eps = [n for n in graph["nodes"] if n["kind"] == "endpoint"][:40]
    lines += ["", "## Entry points (endpoints)", "", "| Endpoint | Repo | Source |", "| --- | --- | --- |"]
    lines += [f"| {md_safe(n['name'])} | {md_safe(n['repo'])} | `{n['citation']}` |" for n in eps] or ["| [unknown] none found | | |"]
    unsafe = [n for n in graph["nodes"] if n["kind"] == "sink" and not (n.get("attrs") or {}).get("safe")][:40]
    lines += ["", "## Unsafe sink candidates", "", "| Sink | Type | Reason | Source |", "| --- | --- | --- | --- |"]
    lines += [f"| {md_safe(n['name'])} | {md_safe(n['attrs'].get('sink_type'))} | {md_safe(n['attrs'].get('reason'))} | `{n['citation']}` |" for n in unsafe] \
        or ["| [n/a] none detected | | | |"]
    xr = [e for e in graph["edges"] if e.get("dst_citation")][:40]
    lines += ["", "## Cross-repo edges", "", "| From | Kind | To | Confidence | Source |", "| --- | --- | --- | --- | --- |"]
    lines += [f"| {md_safe(e['src'].split(':', 2)[-1].strip(':'))} | {e['kind']} | {md_safe(e['dst'].split(':', 2)[-1].strip(':'))} | {e['confidence']} | `{e['citation']}` |"
              for e in xr] or ["| [unknown] none matched statically | | | | |"]
    lines += ["", "## Merge and carry-over", "",
              f"- Security nodes attached: {json.dumps(sec)} [inferred]",
              f"- Agent proposals: {json.dumps(props)} [inferred]",
              f"- Summary carry-over: {json.dumps(carry)} [inferred]",
              "", "Query it with `/ckb:ask`, `/ckb:impact`, the viewer (`graph/index.html`), or the `ckb-graph` MCP server."]
    return "\n".join(lines) + "\n"


def build(out: Path, structural_only=False) -> dict:
    roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
    frags = load_fragments(out, roots)
    link = Linker(frags, roots, out).build()
    try:
        import roles
        role_stats = roles.apply(link, roots, out)
    except Exception as e:  # noqa: BLE001 - roles are derived labels; never fail the graph build
        role_stats = {"error": f"{type(e).__name__}: {e}"}
    cres = call_resolution(link, out)
    sec = attach_security(link, out)
    props = {} if structural_only else merge_proposals(link, out)
    pruned = prune_superseded_drafts(link, out)
    if pruned:
        props = {**props, "superseded_draft_threats_dropped": pruned}
    carry = carry_over(link, out)
    # drop edges whose ends vanished (e.g. removed files)
    link.edges = {k: e for k, e in link.edges.items() if e["src"] in link.nodes and e["dst"] in link.nodes}
    targets = load_json(out / "evidence" / "targets.json", {}).get("repos", {})
    nodes, edges = list(link.nodes.values()), list(link.edges.values())

    def count(items, f):
        d = defaultdict(int)
        for x in items:
            d[f(x)] += 1
        return dict(d)
    tours = load_json(graph_dir(out) / "tours.json", {"tours": []}).get("tours", [])
    layers = load_json(graph_dir(out) / "layers.json", {"layers": []}).get("layers", [])
    graph = {"schema_version": SCHEMA_VERSION, "generator": f"ckb-graph/{EXTRACTOR_VERSION}", "generated": now_iso(),
             "repos": {k: {"revision": targets.get(k, {}).get("revision"), "dirty": targets.get(k, {}).get("dirty")} for k in roots},
             "nodes": nodes, "edges": edges, "layers": layers, "tours": tours,
             "stats": {"nodes": len(nodes), "edges": len(edges), "nodes_by_kind": count(nodes, lambda n: n["kind"]),
                       "edges_by_kind": count(edges, lambda e: e["kind"]),
                       "call_resolution": cres,
                       "nodes_by_extractor": count(nodes, lambda n: n["provenance"]["extractor"]),
                       "edges_by_extractor": count(edges, lambda e: e["provenance"]["extractor"])}}
    probs = validate(graph)
    gd = graph_dir(out)
    atomic_write(gd / "graph.json", json.dumps(graph, indent=1))
    write_sqlite(graph, gd / "graph.sqlite")
    atomic_write(out / "system" / "graph.md", report(graph, out, sec, props, carry))
    cg_stats = None
    try:
        import callgraph
        cg_stats = callgraph.run(out)["stats"]
    except Exception as e:  # noqa: BLE001 - call graphs are derived; never fail the graph build
        cg_stats = {"error": f"{type(e).__name__}: {e}"}
    return {"callgraph": cg_stats, "roles": role_stats, **{"nodes": len(nodes), "edges": len(edges), "schema_problems": probs[:20], "security": sec, "proposals": props, "carry_over": carry}}


def enrich(out: Path, structural_only=False) -> dict:
    """Deterministic enrichment in dependency order: build, repo context + doc claims, rebuild (merges their
    seed proposals incl. drift nodes), draft threat model, final rebuild. Each step is skipped if it has no input."""
    steps = {}
    build(out, structural_only)
    import doc_claims
    import repo_context
    import pipeline_facts
    import threat_seed
    steps["repo_context"] = repo_context.run(out)
    import coverage_report
    steps["coverage"] = coverage_report.run(out)
    steps["pipeline_facts"] = pipeline_facts.run(out)
    import agent_graph
    steps["agent_graph"] = agent_graph.run(out)
    import deploy_facts
    steps["deploy_facts"] = deploy_facts.run(out)
    steps["doc_claims"] = doc_claims.run(out)
    build(out, structural_only)
    steps["threat_seed"] = threat_seed.run(out)
    res = build(out, structural_only)
    try:
        import context_facts
        steps["context_facts"] = context_facts.run(out)
    except Exception as e:  # noqa: BLE001 - derived tables; never fail the build
        steps["context_facts"] = {"error": f"{type(e).__name__}: {e}"}
    res["enrich"] = steps
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--enrich", action="store_true", help="also run repo_context, doc_claims and threat_seed (draft threat model) and merge their results")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--incremental", action="store_true")
    ap.add_argument("--structural-only", action="store_true")
    ap.add_argument("--backend", default="auto")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    if a.extract:
        roots = {k: v for k, v in repo_roots_for_output(out).items() if not k.startswith("ctx")}
        changed = None
        if a.incremental and (out / "evidence" / "hashes.json").is_file():
            r = subprocess.run([sys.executable, str(HERE / "hash_index.py"), "diff", "--out", str(out)], capture_output=True, text=True)
            try:
                changed = json.loads(r.stdout)
            except ValueError:
                changed = None
        for key in roots:
            cmd = [sys.executable, str(HERE / "graph_extract.py"), "--out", str(out), "--key", key, "--backend", a.backend]
            if changed and key in changed and changed[key].get("status") == "unchanged":
                continue
            if changed and key in changed and changed[key].get("status") == "changed":
                files = changed[key].get("added", []) + changed[key].get("changed", []) + changed[key].get("removed", [])
                cmd += ["--files", *files]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL)
    res = enrich(out, a.structural_only) if a.enrich else build(out, a.structural_only)
    print(json.dumps(res, indent=2))
    return 1 if res["schema_problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
