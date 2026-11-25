#!/usr/bin/env python3
"""Tests for the agent / skill / tool graph (scripts/agent_graph.py). Run: python3 tests/test_agents.py
Fixtures under tests/fixtures/agents are copied to a temp dir and only read."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "scripts"
FX = ROOT / "tests" / "fixtures" / "agents"
sys.path.insert(0, str(S))
tmp = Path(tempfile.mkdtemp(prefix="ckb-agents-test-"))
os.environ["CKB_HOME"] = str(tmp / "home")
fails = 0


def check(name, ok, extra=""):
    global fails
    fails += not ok
    print("PASS" if ok else "FAIL", name, "" if ok else str(extra)[:400])


def run(script, *args):
    return subprocess.run([sys.executable, str(S / script), *map(str, args)], capture_output=True, text=True, env=os.environ)


work = tmp / "agents"
shutil.copytree(FX, work)
out = tmp / ".ckb"
for d in sorted(p for p in work.iterdir() if p.is_dir()):
    assert run("fetch_source.py", "--out", out, "--key", d.name, d).returncode == 0
r = run("graph_build.py", "--out", out, "--extract", "--enrich")
res = json.loads(r.stdout)
check("builds with no schema problems", r.returncode == 0 and not res["schema_problems"], r.stderr[-300:] + str(res.get("schema_problems")))
check("agent proposals are accepted by the merge verifier (none rejected)", res["proposals"].get("rejected", 0) == 0 and res["proposals"].get("accepted", 0) > 20, res["proposals"])
g = json.loads((out / "graph" / "graph.json").read_text())
N = {n["id"]: n for n in g["nodes"]}


def nodes(repo, kind):
    return {n["name"]: n for n in g["nodes"] if n["repo"] == repo and n["kind"] == kind}


def edges(repo, kind):
    return {(N[e["src"]]["name"], N[e["dst"]]["name"]) for e in g["edges"] if e["kind"] == kind and N.get(e["src"], {}).get("repo") == repo and e["dst"] in N}


# plugin repo
check("plugin: agents, skills, hook and MCP tools become nodes", {"reviewer", "fixer", "orphan"} <= set(nodes("plugin-demo", "agent")) and {"audit", "style"} <= set(nodes("plugin-demo", "skill"))
      and nodes("plugin-demo", "hook") and {"demo_search", "demo_status"} <= set(nodes("plugin-demo", "mcp_tool")))
d = edges("plugin-demo", "dispatches")
check("plugin: `demo:x` tokens and 'follow the x skill' become dispatch edges", {("audit", "reviewer"), ("audit", "fixer"), ("audit", "style"), ("reviewer", "style")} <= d, sorted(d))
check("plugin: scripts and hooks become invokes edges", ("audit", "scripts/run.py") in edges("plugin-demo", "invokes") and ("fixer", "scripts/run.py") in edges("plugin-demo", "invokes")
      and any(b == "scripts/guard.py" for a, b in edges("plugin-demo", "invokes")), sorted(edges("plugin-demo", "invokes")))
check("plugin: the HTML comment marker is not an agent and creates no edge", "marker" not in {x for a in d for x in a})
rep = json.loads((out / "evidence" / "agent-graph-plugin-demo.json").read_text())
check("plugin: orphan and dangling reference are reported", rep["orphans"] == ["orphan"] and [x["ref"] for x in rep["dangling"]] == ["demo:ghost"], (rep["orphans"], rep["dangling"]))
check("plugin: risk flag for the agent with Bash/Write/WebFetch that also reads files", any(f["node"] == "fixer" and "Bash" in f["risky_tools"] and f["reads_untrusted"] for f in rep["risk_flags"]))
# frameworks
lg = edges("langgraph-app", "dispatches")
check("langgraph: add_node/add_edge become agents and dispatch edges", {("plan", "research"), ("research", "write")} <= lg and "plan" in nodes("langgraph-app", "agent"), sorted(lg))
check("langgraph: a node's function is linked (invokes)", ("research", "research_fn") in edges("langgraph-app", "invokes"), sorted(edges("langgraph-app", "invokes")))
check("crewai: Crew(agents=[...]) orders the agents", ("Researcher", "Writer") in edges("crewai-app", "dispatches"), sorted(edges("crewai-app", "dispatches")))
oa = edges("openai-agents", "dispatches")
check("openai agents: handoffs=[...] become dispatch edges", {("Triage", "Billing"), ("Triage", "Support")} <= oa, sorted(oa))
check("openai agents: @function_tool becomes a tool linked to its function", "refund" in nodes("openai-agents", "mcp_tool") and ("refund", "refund") in edges("openai-agents", "invokes"), sorted(edges("openai-agents", "invokes")))
check("claude agent sdk: agents={'x': AgentDefinition(...)} and @tool", "reviewer" in nodes("claude-sdk", "agent") and "lookup" in nodes("claude-sdk", "mcp_tool"))
check("autogen: initiate_chat links the agents", ("user_proxy", "assistant") in edges("autogen-app", "dispatches"), sorted(edges("autogen-app", "dispatches")))
check("mcp server: FastMCP and @mcp.tool", "records" in nodes("mcp-py", "agent") and "lookup" in nodes("mcp-py", "mcp_tool"))
tm = (out / "system" / "threat-model.md").read_text()
check("threat model: agent threats (excessive agency, unguarded tool, broken reference) from the agent graph", all(x in tm for x in ("can read untrusted content and also use", "are not covered by any hook", "Reference to a missing agent, skill or command: demo:ghost")))
check("threat model: LLM-directed path (agent -> tool function -> sink) is an attack path", "langgraph" in tm.lower() and "OWASP LLM Top 10: LLM05" in tm, tm[tm.index("## Attack paths"):tm.index("## Analysis coverage")][-600:])
md = (out / "system" / "agents.md").read_text()
check("system/agents.md lists nodes, risk flags, orphans and dangling names", "Risk flags" in md and "demo:ghost" in md and "orphan" in md)
q = json.loads(run("graph_query.py", "--out", out, "agents", "--repo", "plugin-demo").stdout)
check("agents op returns the graph with call relations", any(a["name"] == "audit" and "reviewer" in a["calls"] for a in q["agents"]), str(q)[:300])
import graph_mcp  # noqa: E402
check("MCP exposes ckb_agents", "ckb_agents" in {t["name"] for t in graph_mcp.TOOLS})

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
