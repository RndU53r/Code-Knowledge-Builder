#!/usr/bin/env python3
"""Agent, skill, command, hook and tool graph for every registered repo. Reads files only; never runs an agent or a tool.

Usage:
  agent_graph.py --out OUT_DIR [--repo KEY]

Two kinds of repo are understood:

  Claude Code plugins / agent definitions   agents/*.md, skills/*/SKILL.md, commands/*.md (and the .claude/ equivalents),
      hooks/hooks.json, .mcp.json, plugin.json. Nodes: agent, skill, command, hook, mcp_tool. Edges: `dispatches`
      (command/skill/agent -> agent/skill/command: `ns:name` tokens, "follow the X skill", `/ns:name`, Agent/Skill in the
      tool list), `invokes` (-> a script file via ${CLAUDE_PLUGIN_ROOT}/scripts/x.py, a hook -> its script). References
      are resolved against the name index of the repo, so a token that is not an agent/skill/command (for example an HTML
      comment marker) never becomes an edge; HTML comments are ignored.
  Agent frameworks in code                  LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Claude Agent SDK, MCP servers
      (FastMCP, server.tool), tool/function registrations. Nodes: agent, mcp_tool. Edges: `dispatches` agent -> agent
      (graph edges, handoffs, group chats, sub-agents), `invokes` agent -> the tool function it registers.

Writes
  <out>/graph/proposals/seed-agents.jsonl   nodes and edges (extractor "rule"), verified by graph_merge.py like any proposal
  <out>/evidence/agent-graph-<repo>.json    nodes, edges, tools per agent, orphans, dangling references
  <out>/system/agents.md                    agents/skills/commands/tools, who calls whom, risk flags, orphans and dangling names
Static text matching: edges are `observed` where the text is explicit and medium confidence where the name is resolved from prose.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import now_iso, read_text, repo_roots_for_output, walk_files  # noqa: E402
from graph_common import atomic_write, graph_dir, md_safe, safe_quote  # noqa: E402

RISKY_TOOLS = {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch"}
READ_TOOLS = {"Read", "Grep", "Glob", "WebFetch", "WebSearch"}
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)


def frontmatter(text: str) -> tuple[dict, int]:
    """(fields, body start line) from a leading --- YAML block (simple key: value, folded/literal scalars and inline arrays)."""
    if not text.startswith("---"):
        return {}, 0
    lines = text.splitlines()
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, 0
    fm, key = {}, None
    for ln in lines[1:end]:
        m = re.match(r"^([A-Za-z_-]+)\s*:\s*(.*)$", ln)
        if m and not ln.startswith(" "):
            key = m.group(1)
            fm[key] = m.group(2).strip().strip(">|-").strip()
        elif key and ln.strip():
            fm[key] = (fm[key] + " " + ln.strip()).strip()
    return fm, end + 2


def tool_list(v: str) -> list[str]:
    return [t.strip().strip("\"'") .split("(")[0] for t in re.split(r"[,\[\]]", v or "") if t.strip().strip("\"'")]


def plugin_files(root: Path):
    out = {"agent": [], "skill": [], "command": [], "hooks": None, "mcp": None, "manifest": None}
    for p, rel in walk_files(root, []):
        if re.match(r"^(\.claude/)?agents/[^/]+\.md$", rel):
            out["agent"].append((p, rel))
        elif re.match(r"^(\.claude/)?skills/[^/]+/SKILL\.md$", rel):
            out["skill"].append((p, rel))
        elif re.match(r"^(\.claude/)?commands/[^/]+\.md$", rel):
            out["command"].append((p, rel))
        elif rel in ("hooks/hooks.json", ".claude/hooks.json"):
            out["hooks"] = (p, rel)
        elif rel == ".mcp.json":
            out["mcp"] = (p, rel)
        elif rel == ".claude-plugin/plugin.json":
            out["manifest"] = (p, rel)
    return out


class Graph:
    def __init__(self, repo):
        self.repo = repo
        self.nodes = {}   # id -> dict
        self.edges = []   # dicts
        self.by_name = defaultdict(dict)  # kind -> name -> id

    def node(self, kind, name, rel, line, quote, **attrs):
        nid = f"{kind}:{self.repo}::{name}"
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "kind": kind, "name": name, "repo": self.repo, "citation": f"{self.repo}/{rel}:{line}", "quote": safe_quote(quote)[:120] or name,
                               "attrs": {k: v for k, v in attrs.items() if v not in (None, "", [])}}
            self.by_name[kind][name] = nid
        return nid

    def edge(self, src, kind, dst, rel, line, quote, conf="medium", **attrs):
        if src == dst or not src or not dst:
            return
        key = (src, kind, dst)
        if any((e["src"], e["kind"], e["dst"]) == key for e in self.edges):
            return
        self.edges.append({"src": src, "kind": kind, "dst": dst, "citation": f"{self.repo}/{rel}:{line}", "quote": safe_quote(quote)[:120], "confidence": conf,
                           "label": "observed" if conf == "high" else "inferred", "attrs": attrs})


def scan_plugin(root: Path, repo: str, known_files: set[str]) -> tuple[Graph, dict]:
    g = Graph(repo)
    pf = plugin_files(root)
    ns = repo
    if pf["manifest"]:
        try:
            ns = json.loads(pf["manifest"][0].read_text()).get("name") or repo
        except ValueError:
            pass
    docs = {}
    for kind in ("agent", "skill", "command"):
        for p, rel in pf[kind]:
            text = read_text(p, max_bytes=400_000) or ""
            fm, body_line = frontmatter(text)
            name = fm.get("name") or (Path(rel).parent.name if kind == "skill" else Path(rel).stem)
            tools = tool_list(fm.get("tools") or fm.get("allowed-tools") or "")
            nline = next((i for i, ln in enumerate(text.splitlines(), 1) if re.match(r"^name\s*:", ln)), 1)
            g.node(kind, name, rel, nline, text.splitlines()[nline - 1] if text.splitlines() else name, tools=tools[:20], user_invocable=("disable-model-invocation" in fm and "true" in fm["disable-model-invocation"].lower()) or kind == "command",
                   description=(fm.get("description") or "")[:160])
            docs[(kind, name)] = (rel, text, body_line, tools)
    names = {k: set(v) for k, v in g.by_name.items()}
    all_names = {n for s in names.values() for n in s}
    called = defaultdict(set)
    dangling = []
    for (kind, name), (rel, text, body_line, tools) in docs.items():
        src = g.by_name[kind][name]
        can_dispatch = bool(set(tools) & {"Agent", "Task", "Skill", "SendMessage"}) or kind in ("command", "skill")
        clean = HTML_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
        for i, ln in enumerate(clean.splitlines(), 1):
            if i < body_line:
                continue
            # `ns:name` tokens and /ns:name commands
            for m in re.finditer(rf"`{re.escape(ns)}:([\w-]+)`|(?<![\w/])/{re.escape(ns)}:([\w-]+)", ln):
                tgt = m.group(1) or m.group(2)
                hit = next(((k, g.by_name[k][tgt]) for k in ("agent", "command", "skill") if tgt in names.get(k, ())), None)
                if not hit:
                    if tgt not in all_names and not re.search(r"seed|marker", tgt):
                        dangling.append({"from": f"{kind}:{name}", "ref": f"{ns}:{tgt}", "citation": f"{repo}/{rel}:{i}"})
                    continue
                dispatch = bool(re.search(r"(?i)dispatch|agent call|one\s+`?\w+:?[\w-]*`?\s+agent|spawn|delegate|run\s+(?:the\s+)?`", ln)) or hit[0] == "agent"
                g.edge(src, "dispatches", hit[1], rel, i, m.group(0), "high" if (dispatch and can_dispatch) else "medium", via=hit[0])
                called[hit[1]].add(src)
            # skills: "follow the `x` skill", "Using the x skill", "the x skill"
            for m in re.finditer(r"(?i)\b(?:follow(?:ing)?|using|use|see|read|apply)\s+the\s+`?([\w-]+)`?\s+skill\b|\bthe\s+`([\w-]+)`\s+skill\b", ln):
                tgt = m.group(1) or m.group(2)
                if tgt in names.get("skill", ()) and g.by_name["skill"][tgt] != src:
                    g.edge(src, "dispatches", g.by_name["skill"][tgt], rel, i, m.group(0), "medium", via="skill")
                    called[g.by_name["skill"][tgt]].add(src)
            # scripts the document tells the model to run
            for m in re.finditer(r"(?:\$\{CLAUDE_PLUGIN_ROOT\}/|(?<![\w/.-]))scripts/([\w.-]+\.py)", ln):
                fid = f"file:{repo}:scripts/{m.group(1)}:"
                if f"scripts/{m.group(1)}" in known_files:
                    g.edge(src, "invokes", fid, rel, i, m.group(0), "medium", via="script")
    # hooks
    if pf["hooks"]:
        p, rel = pf["hooks"]
        text = read_text(p, max_bytes=200_000) or ""
        try:
            hj = json.loads(text)
        except ValueError:
            hj = {}
        hooks = hj.get("hooks", hj)
        for event, entries in (hooks.items() if isinstance(hooks, dict) else []):
            for ent in entries if isinstance(entries, list) else []:
                matcher = ent.get("matcher", "*")
                for h in ent.get("hooks", []):
                    cmd = h.get("command", "")
                    m = re.search(r"scripts/([\w.-]+\.py)", cmd)
                    needle = f"scripts/{m.group(1)}" if m else cmd.split()[0] if cmd else ""
                    line = next((i for i, ln in enumerate(text.splitlines(), 1) if needle and needle in ln), 1)
                    nid = g.node("hook", f"{event}:{matcher}:{(m.group(1) if m else 'cmd')}{(':' + cmd.split()[-1]) if m and len(cmd.split()) > 2 else ''}", rel, line, needle, event=event, matcher=matcher)
                    if m and f"scripts/{m.group(1)}" in known_files:
                        g.edge(nid, "invokes", f"file:{repo}:scripts/{m.group(1)}:", rel, line, needle, "high", via="hook")
    # MCP tools declared as a literal table in a script (name + op/description keys)
    if pf["mcp"]:
        p, rel = pf["mcp"]
        try:
            servers = json.loads(read_text(p, max_bytes=100_000) or "{}").get("mcpServers", {})
        except ValueError:
            servers = {}
        for sname, sv in servers.items():
            blob = " ".join([str(sv.get("command", "")), *map(str, sv.get("args", []))])
            m = re.search(r"scripts/([\w.-]+\.py)", blob)
            if m:
                sp = root / "scripts" / m.group(1)
                stext = read_text(sp, max_bytes=300_000) or ""
                for i, ln in enumerate(stext.splitlines(), 1):
                    tm = re.search(r"\"name\"\s*:\s*\"([\w-]+)\".*\"op\"", ln) or re.search(r"\"name\"\s*:\s*\"(ckb_[\w]+|[a-z]+_[a-z_]+)\"", ln) if "op" in ln or "description" in ln else None
                    if tm:
                        g.node("mcp_tool", tm.group(1), f"scripts/{m.group(1)}", i, ln.strip()[:110], server=sname)
    unparsed = [f"{rel}: over the size cap or unreadable" for kind in ("agent", "skill", "command") for p, rel in pf[kind] if not read_text(p, max_bytes=400_000)]
    for key_, label_ in (("hooks", "hooks"), ("mcp", "MCP config"), ("manifest", "plugin manifest")):
        if pf[key_]:
            try:
                json.loads(read_text(pf[key_][0], max_bytes=400_000) or "")
            except ValueError:
                unparsed.append(f"{pf[key_][1]}: not valid JSON ({label_} ignored)")
    orphans = [n["name"] for n in g.nodes.values() if n["kind"] in ("agent", "skill") and not any(e["dst"] == n["id"] for e in g.edges) and not n["attrs"].get("user_invocable")]
    return g, {"dangling": dangling, "orphans": orphans, "unparsed": unparsed}


# ---------------------------------------------------------------- agent frameworks in code

FW_FILES = {".py", ".ts", ".tsx", ".js", ".mjs"}
FW_SIG = re.compile(r"langgraph|StateGraph|crewai|autogen|AssistantAgent|agents import|openai_agents|AgentDefinition|claude_agent_sdk|claude-agent-sdk|FastMCP|mcp\.server|@modelcontextprotocol|"
                    r"semantic_kernel|google\.adk|pydantic_ai|smolagents|mastra|strands")


def scan_frameworks(root: Path, repo: str, graph_nodes: dict) -> Graph:
    g = Graph(repo)
    funcs = defaultdict(dict)  # path -> name -> node id
    for n in graph_nodes.values():
        if n.get("repo") == repo and n["kind"] in ("function", "method"):
            funcs[n["path"]][n["name"]] = n["id"]
    for p, rel in walk_files(root, []):
        if p.suffix.lower() not in FW_FILES or re.search(r"(^|/)(tests?|node_modules)/|\.test\.|\.spec\.", rel):
            continue
        text = read_text(p, max_bytes=400_000)
        if not text or not FW_SIG.search(text):
            continue
        lines = text.splitlines()
        var_agent = {}

        def agent(name, i, fw, var=None):
            nid = g.node("agent", name, rel, i, lines[i - 1].strip(), framework=fw)
            if var:
                var_agent[var] = nid
            return nid

        def nearest_owner(i):  # the agent variable assigned closest above line i (multi-line Agent(...) calls)
            for j in range(i - 1, max(-1, i - 12), -1):
                mm = re.match(r"^\s*(\w+)\s*=\s*(?:\w+\.)*Agent\(", lines[j - 1] if j >= 1 else "")
                if mm and mm.group(1) in var_agent:
                    return var_agent[mm.group(1)]
            return None

        def tool(name, i, fw, fn=None, owner=None):
            nid = g.node("mcp_tool", name, rel, i, lines[i - 1].strip(), framework=fw)
            tgt = funcs.get(rel, {}).get(fn or name)
            if tgt:
                g.edge(nid, "invokes", tgt, rel, i, lines[i - 1].strip(), "medium", via="tool-function")
            if owner:
                g.edge(owner, "invokes", nid, rel, i, lines[i - 1].strip(), "medium", via="registers-tool")
            return nid
        for i, ln in enumerate(lines, 1):
            # LangGraph
            m = re.search(r"\.add_node\(\s*[\"']([\w-]+)[\"']\s*(?:,\s*([\w.]+))?", ln)
            if m:
                nid = agent(m.group(1), i, "langgraph")
                if m.group(2) and funcs.get(rel, {}).get(m.group(2).split(".")[-1]):
                    g.edge(nid, "invokes", funcs[rel][m.group(2).split(".")[-1]], rel, i, ln.strip(), "medium", via="node-function")
            m = re.search(r"\.add_edge\(\s*[\"']([\w-]+)[\"']\s*,\s*[\"']([\w-]+)[\"']", ln)
            if m and m.group(1) not in ("START", "__start__") and m.group(2) not in ("END", "__end__"):
                g.edge(agent(m.group(1), i, "langgraph"), "dispatches", agent(m.group(2), i, "langgraph"), rel, i, ln.strip(), "high", via="langgraph-edge")
            m = re.search(r"\.add_conditional_edges\(\s*[\"']([\w-]+)[\"']", ln)
            if m:
                agent(m.group(1), i, "langgraph")
            m = re.search(r"Command\(\s*goto\s*=\s*[\"']([\w-]+)[\"']", ln)
            if m:
                g.edge(next(iter(var_agent.values()), agent(Path(rel).stem, i, "langgraph")), "dispatches", agent(m.group(1), i, "langgraph"), rel, i, ln.strip(), "medium", via="command-goto")
            m = re.search(r"(\w+)\s*=\s*create_react_agent\(", ln)
            if m:
                agent(m.group(1), i, "langgraph", m.group(1))
            # CrewAI
            m = re.search(r"(\w+)\s*=\s*Agent\(\s*(?:role\s*=\s*)?[\"']([^\"']+)[\"']", ln)
            if m and "crewai" in text:
                agent(m.group(2), i, "crewai", m.group(1))
            m = re.search(r"Crew\(\s*agents\s*=\s*\[([^\]]*)\]", ln)
            if m:
                members = [var_agent[v.strip()] for v in m.group(1).split(",") if v.strip() in var_agent]
                for a, b in zip(members, members[1:]):
                    g.edge(a, "dispatches", b, rel, i, ln.strip(), "medium", via="crew-sequence")
            # AutoGen
            m = re.search(r"(\w+)\s*=\s*(?:autogen\.)?(?:AssistantAgent|UserProxyAgent|ConversableAgent)\(\s*(?:name\s*=\s*)?[\"']([\w-]+)[\"']", ln)
            if m:
                agent(m.group(2), i, "autogen", m.group(1))
            m = re.search(r"(\w+)\.initiate_chat\(\s*(\w+)", ln)
            if m and m.group(1) in var_agent and m.group(2) in var_agent:
                g.edge(var_agent[m.group(1)], "dispatches", var_agent[m.group(2)], rel, i, ln.strip(), "high", via="initiate_chat")
            m = re.search(r"GroupChat\(\s*agents\s*=\s*\[([^\]]*)\]", ln)
            if m:
                members = [var_agent[v.strip()] for v in m.group(1).split(",") if v.strip() in var_agent]
                for a in members:
                    for b in members:
                        g.edge(a, "dispatches", b, rel, i, ln.strip(), "medium", via="group-chat")
            # OpenAI Agents SDK / Claude Agent SDK / ADK / pydantic-ai
            m = re.search(r"(\w+)\s*=\s*Agent\(\s*(?:\n\s*)?name\s*=\s*[\"']([^\"']+)[\"']", ln + " " + (lines[i] if i < len(lines) else ""))
            if m and "crewai" not in text:
                agent(m.group(2), i, "openai-agents", m.group(1))
            m = re.search(r"handoffs\s*=\s*\[([^\]]*)\]", ln)
            if m:
                owner = nearest_owner(i)
                for v in re.findall(r"[\w]+", m.group(1)):
                    if v in var_agent and owner and var_agent[v] != owner:
                        g.edge(owner, "dispatches", var_agent[v], rel, i, ln.strip(), "high", via="handoff")
            m = re.search(r"sub_agents\s*=\s*\[([^\]]*)\]", ln)
            if m:
                owner = nearest_owner(i)
                for v in re.findall(r"[\w]+", m.group(1)):
                    if v in var_agent and owner and var_agent[v] != owner:
                        g.edge(owner, "dispatches", var_agent[v], rel, i, ln.strip(), "high", via="sub_agents")
            m = re.search(r"[\"']([\w-]+)[\"']\s*:\s*AgentDefinition\(", ln)
            if m:
                agent(m.group(1), i, "claude-agent-sdk")
            m = re.search(r"AgentDefinition\(", ln)
            if m and not re.search(r"[\"'][\w-]+[\"']\s*:\s*AgentDefinition", ln):
                nm = re.search(r"(\w+)\s*=\s*AgentDefinition", ln)
                if nm:
                    agent(nm.group(1), i, "claude-agent-sdk", nm.group(1))
            # tools
            m = re.search(r"@function_tool|@tool\b(?:\(\s*[\"']([\w-]+)[\"'])?|@mcp\.tool\(|@server\.tool\(|@agent\.tool|@kernel_function", ln)
            if m:
                nm = next((re.match(r"^\s*(?:async\s+)?def\s+(\w+)", lines[j]) for j in range(i, min(len(lines), i + 4)) if re.match(r"^\s*(?:async\s+)?def\s+\w+", lines[j])), None)
                if nm:
                    owner = next(iter(var_agent.values()), None) if len(var_agent) == 1 else None
                    tool(m.group(1) or nm.group(1), i, "mcp" if "mcp" in ln else "agent-tool", nm.group(1), owner)
            m = re.search(r"\b(?:server\.tool|server\.registerTool|mcp\.tool|tool)\(\s*[\"']([\w-]+)[\"']", ln)
            if m and re.search(r"modelcontextprotocol|claude-agent-sdk|mastra|ai\b", text):
                tool(m.group(1), i, "mcp")
            m = re.search(r"FastMCP\(\s*[\"']([^\"']+)[\"']", ln)
            if m:
                agent(m.group(1), i, "mcp-server")
    return g


# ---------------------------------------------------------------- output

def run(out: Path, only: str | None = None) -> dict:
    gp = graph_dir(out) / "graph.json"
    nodes = {}
    if gp.is_file():
        nodes = {n["id"]: n for n in json.loads(gp.read_text()).get("nodes", [])}
    known = defaultdict(set)
    for n in nodes.values():
        if n["kind"] == "file" and n.get("path"):
            known[n["repo"]].add(n["path"])
    stats, all_nodes, all_edges, reports = {}, {}, [], {}
    produced = set()
    for repo, root in repo_roots_for_output(out).items():
        if repo.startswith("ctx") or (only and repo != only):
            continue
        g1, meta = scan_plugin(Path(root), repo, known[repo])
        g2 = scan_frameworks(Path(root), repo, nodes)
        all_n = {**g1.nodes, **g2.nodes}
        all_e = g1.edges + g2.edges
        if not all_n:
            continue
        flags = []
        for n in all_n.values():
            tools = set(n["attrs"].get("tools", []))
            if n["kind"] in ("agent", "skill", "command") and tools & RISKY_TOOLS:
                flags.append({"node": n["name"], "kind": n["kind"], "risky_tools": sorted(tools & RISKY_TOOLS), "reads_untrusted": bool(tools & READ_TOOLS), "citation": n["citation"]})
        produced.add(repo)
        reports[repo] = {"repo": repo, "nodes": list(all_n.values()), "edges": all_e, "orphans": meta["orphans"], "dangling": meta["dangling"], "risk_flags": flags, "unparsed": meta.get("unparsed", [])}
        atomic_write(out / "evidence" / f"agent-graph-{repo}.json", json.dumps(reports[repo], indent=1))
        all_nodes.update(all_n)
        all_edges += all_e
        stats[repo] = {"agents": sum(1 for n in all_n.values() if n["kind"] == "agent"), "skills": sum(1 for n in all_n.values() if n["kind"] == "skill"),
                       "commands": sum(1 for n in all_n.values() if n["kind"] == "command"), "hooks": sum(1 for n in all_n.values() if n["kind"] == "hook"),
                       "tools": sum(1 for n in all_n.values() if n["kind"] == "mcp_tool"), "edges": len(all_e), "orphans": len(meta["orphans"]), "dangling": len(meta["dangling"])}
    if not only:  # evidence of repos that no longer yield agent facts (or are no longer registered) must not feed the threat model
        for p in (out / "evidence").glob("agent-graph-*.json"):
            if p.name[len("agent-graph-"):-len(".json")] not in produced:
                p.unlink()
    lines = []
    for n in all_nodes.values():
        lines.append({"op": "node", "kind": n["kind"], "repo": n["repo"], "qualname": n["name"], "name": n["name"], "citation": n["citation"], "quote": n["quote"],
                      "confidence": "high", "label": "observed", "extractor": "rule", "attrs": n["attrs"]})
    for e in all_edges:
        lines.append({"op": "edge", "src": e["src"], "kind": e["kind"], "dst": e["dst"], "citation": e["citation"], "quote": e["quote"], "confidence": e["confidence"],
                      "label": e["label"], "extractor": "rule", "attrs": e["attrs"]})
    pp = graph_dir(out) / "proposals" / "seed-agents.jsonl"
    if lines:
        pp.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(pp, "\n".join(json.dumps(x) for x in lines) + "\n")
    elif pp.exists():
        pp.unlink()
    if reports:
        atomic_write(out / "system" / "agents.md", render(reports))
    return stats


def render(reports: dict) -> str:
    L = ["# Agents, skills, commands and tools", "", "> **ckb provenance**", f"> - Sources: {', '.join(f'`{md_safe(r)}`' for r in reports)}",
         f"> - Generated: {now_iso()} by ckb agent_graph, stage `agents`", "> - Method: frontmatter, hook/MCP config and prose references resolved against a name index; framework signatures in code. Static text matching, [inferred] unless the text is explicit.",
         "> - Verification: edges are mirrored as graph proposals (graph/proposals/seed-agents.jsonl) and verified by graph_merge", ""]
    for repo, r in reports.items():
        nodes = {n["id"]: n for n in r["nodes"]}
        L += [f"## {md_safe(repo)}", "", "| Kind | Name | Tools | Called by | Calls | Source |", "| --- | --- | --- | --- | --- | --- |"]
        for n in sorted(nodes.values(), key=lambda n: (n["kind"], n["name"])):
            if n["kind"] == "mcp_tool" and len([x for x in nodes.values() if x["kind"] == "mcp_tool"]) > 30:
                continue
            callers = sorted({nodes[e["src"]]["name"] for e in r["edges"] if e["dst"] == n["id"] and e["src"] in nodes and e["kind"] == "dispatches"})
            callees = sorted({nodes[e["dst"]]["name"] if e["dst"] in nodes else e["dst"].split(":")[2] for e in r["edges"] if e["src"] == n["id"]})
            L.append(f"| {n['kind']} | {md_safe(n['name'])} | {md_safe(', '.join(n['attrs'].get('tools', [])) or '-', 60)} | {md_safe(', '.join(callers) or '-', 60)} | {md_safe(', '.join(callees[:6]) or '-', 80)} | `{n['citation']}` |")
        if r["risk_flags"]:
            L += ["", "**Risk flags** (tools that can change files, run commands or fetch remote content):", ""]
            L += [f"- {f['kind']} `{md_safe(f['node'])}`: {', '.join(f['risky_tools'])}" + (" and reads untrusted content" if f["reads_untrusted"] else "") + f" (`{f['citation']}`)" for f in r["risk_flags"]]
        if r.get("unparsed"):
            L += ["", "**Not parsed** (the graph for this repo is incomplete): " + "; ".join(md_safe(x, 90) for x in r["unparsed"])]
        L += ["", f"**Orphans** (never called by another agent or skill and not user-invocable): {', '.join(md_safe(x) for x in r['orphans']) or 'none'}", "",
              "**Dangling references** (a `ns:name` token that matches no agent, skill or command): " + (", ".join(f"`{md_safe(d['ref'])}` (`{d['citation']}`)" for d in r["dangling"]) or "none"), ""]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo")
    a = ap.parse_args()
    print(json.dumps(run(Path(a.out).resolve(), a.repo), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
