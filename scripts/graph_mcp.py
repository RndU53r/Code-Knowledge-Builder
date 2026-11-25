#!/usr/bin/env python3
"""ckb-graph MCP server (stdio, JSON-RPC 2.0). Read-only tools over the ckb knowledge graph.

Registered by the plugin's .mcp.json. The graph location is resolved from the CKB_OUT env var, then
`output_dir` in .claude/code-knowledge-builder.local.md, then ./.ckb (relative to the session's cwd);
every tool also accepts an explicit `out`. When no graph exists, tools say how to build one.
Never writes, never executes target code, no network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from graph_common import resolve_out  # noqa: E402

PROTOCOL = "2025-06-18"
OUT_PROP = {"out": {"type": "string", "description": "ckb output dir (default: CKB_OUT, settings output_dir, or ./.ckb)"}}
TOOLS = [
    {"name": "ckb_status", "op": "status", "description": "Graph size, repos, generation time and available tours.",
     "inputSchema": {"type": "object", "properties": {**OUT_PROP}}},
    {"name": "ckb_search", "op": "search", "description": "Find nodes (functions, endpoints, tables, topics, files, findings...) by name or path.",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}, "kinds": {"type": "array", "items": {"type": "string"}},
                                                      "repo": {"type": "string"}, "limit": {"type": "integer"}, **OUT_PROP}, "required": ["q"]}},
    {"name": "ckb_explain", "op": "explain", "description": "A node with its cited source location, incoming/outgoing edges, and attached threats/findings. Target may be a node id, repo/path, or symbol name.",
     "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, **OUT_PROP}, "required": ["target"]}},
    {"name": "ckb_neighbors", "op": "neighbors", "description": "Neighbourhood of a node (depth 1-3), optionally filtered by edge kinds and direction.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "dir": {"type": "string", "enum": ["in", "out", "both"]},
                                                      "kinds": {"type": "array", "items": {"type": "string"}}, "depth": {"type": "integer"}, **OUT_PROP}, "required": ["id"]}},
    {"name": "ckb_path", "op": "path", "description": "Up to k paths from src to dst following calls, HTTP, queues, tables and subprocess edges.",
     "inputSchema": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}, "kinds": {"type": "array", "items": {"type": "string"}},
                                                      "max_depth": {"type": "integer"}, "k": {"type": "integer"}, **OUT_PROP}, "required": ["src", "dst"]}},
    {"name": "ckb_impact", "op": "impact", "description": "Multi-hop blast radius of changing files/symbols (or a git diff rev): affected callers, endpoints, consumers, readers, plus sinks, threats and findings in scope, each with its hop chain and citations.",
     "inputSchema": {"type": "object", "properties": {"targets": {"type": "array", "items": {"type": "string"}}, "diff": {"type": "string"},
                                                      "depth": {"type": "integer"}, **OUT_PROP}}},
    {"name": "ckb_taint", "op": "taint", "description": "Candidate source-to-sink paths (endpoints/consumers to unsafe SQL/command/SSRF/code sinks). Candidates only: confirm each hop in code.",
     "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}, "sink": {"type": "string"}, "max_depth": {"type": "integer"}, **OUT_PROP}}},
    {"name": "ckb_callgraph", "op": "callgraph", "description": "Call graph rolled up at function, file or repo level (HTTP/gRPC, topics, shared tables, subprocess, imports), optionally for one repo or around a focus node. Every edge carries citations and confidence.",
     "inputSchema": {"type": "object", "properties": {"level": {"type": "string", "enum": ["function", "file", "repo"]}, "repo": {"type": "string"},
                                                      "focus": {"type": "string"}, "depth": {"type": "integer"}, "limit": {"type": "integer"}, **OUT_PROP}}},
    {"name": "ckb_roles", "op": "roles", "description": "Repo kinds (application, service, library, iac, cicd-pipeline, gitops-config, mixed) and file roles (core, utility, test, fixture, iac, pipeline, generated, ...). core/utility are inferred; each row lists its signals.",
     "inputSchema": {"type": "object", "properties": {"repo": {"type": "string"}, "role": {"type": "string"}, "limit": {"type": "integer"}, **OUT_PROP}}},
    {"name": "ckb_entrypoints", "op": "entrypoints", "description": "Entry points (HTTP/gRPC endpoints, queue consumers, cron jobs, CLI commands) with handler, taint sources read and unsafe sinks reachable from each. Reachability is a candidate path, not proven dataflow.",
     "inputSchema": {"type": "object", "properties": {"repo": {"type": "string"}, "kinds": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "integer"}, **OUT_PROP}}},
    {"name": "ckb_tour", "op": "tour", "description": "List guided tours, or return one tour's steps (node, note, citation).",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, **OUT_PROP}}},
]
BY_NAME = {t["name"]: t for t in TOOLS}
_stores = {}


def store_for(out_arg):
    from graph_query import GraphStore
    out = resolve_out(out_arg)
    st = _stores.get(str(out))
    if st is None:
        st = GraphStore(out)
        _stores[str(out)] = st
    else:
        st.refresh()
    return st


def call_tool(name, args):
    t = BY_NAME.get(name)
    if not t:
        return {"isError": True, "content": [{"type": "text", "text": f"unknown tool {name}"}]}
    args = dict(args or {})
    out = args.pop("out", None)
    try:
        st = store_for(out)
    except FileNotFoundError as e:
        return {"isError": True, "content": [{"type": "text", "text": f"{e}. Build it with /ckb:graph build (or /ckb:full)."}]}
    res = st.dispatch(t["op"], args)
    text = json.dumps(res, indent=1, default=str)
    if len(text) > 200_000:
        text = text[:200_000] + "\n…(truncated)"
    return {"content": [{"type": "text", "text": text}], "isError": "error" in res if isinstance(res, dict) else False}


def handle(msg):
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": params.get("protocolVersion", PROTOCOL),
                                                          "capabilities": {"tools": {"listChanged": False}},
                                                          "serverInfo": {"name": "ckb-graph", "version": "0.3.0"},
                                                          "instructions": "Read-only queries over the ckb code knowledge graph. Results carry repo/path:line citations; open the cited lines before stating facts."}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [{k: v for k, v in t.items() if k != "op"} for t in TOOLS]}}
    if method == "tools/call":
        return {"jsonrpc": "2.0", "id": mid, "result": call_tool(params.get("name"), params.get("arguments"))}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if mid is None:  # notification (e.g. notifications/initialized)
        return None
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        try:
            resp = handle(msg)
        except Exception as e:  # noqa: BLE001 - never crash the server on one bad call
            resp = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, default=str) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
