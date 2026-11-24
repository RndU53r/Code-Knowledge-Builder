---
name: knowledge-graph
description: >-
  Builds and queries a cited code knowledge graph across one or more repositories. Nodes are files,
  functions, classes, endpoints, topics, tables, env vars, cloud resources, sinks, threats, and
  supply-chain or CSPM findings. Edges are calls, imports, routes, HTTP calls, publish and consume,
  reads and writes, subprocess, reaches_sink, threatens, and similar. Every node and edge carries a
  repo/path:line citation, an extractor, and a confidence. Use whenever someone asks cross-file or
  cross-service questions such as "who calls X", "where is Y used", "how many functions in Z", "what
  breaks if I change this", "which endpoints reach this SQL query", "show me the path from the gateway
  to the consumer", or wants a graph view, impact analysis, taint paths, a Neo4j or Cypher export, or
  an MCP-queryable graph of a codebase. Part of ckb (/ckb:graph, /ckb:ask, /ckb:impact, /ckb:tour).
---

# Knowledge graph

ckb's graph is the structural backbone the other stages navigate with. A deterministic extractor builds it from code (stdlib `ast` for Python, tree-sitter for other languages when it's installed, regex otherwise). Agents then add semantic edges, but only through proposals that pass citation verification. Unlike graphs that come purely from model output, every fact can be checked.

Follow `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`.

## When invoked outside a /ckb command

- For a quick question, query the existing graph (`<out>/graph/graph.sqlite`) and answer with citations. If no graph exists yet, build one first (below); that needs registration and the authorization question from `shared/pipeline.md` P0–P2.
- `<out>` is the ckb output dir (default `<target>/.ckb`).

## Build

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_build.py" --out <out> --extract            # full
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_build.py" --out <out> --extract --enrich   # + repo context, doc claims/drift, draft threat model
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_build.py" --out <out> --extract --incremental
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_check.py" --out <out> --report              # must be 0 errors
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_viewer.py" --out <out>                      # graph/index.html
```

Every build also writes the call graphs (`system/call-graphs.md`, `graph/callgraph.json`, `diagrams/callgraph-*.mmd`). Function and class summaries come from docstrings and leading comments at extraction time (`summary_source: docstring|comment`); agent annotations override them.

The build merges supply-chain findings (`evidence/sc-*.json`), CSPM rows from `ctx-*` context, IaC cloud resources, and agent proposals. It writes `graph/graph.json` (the citable source of truth), `graph/graph.sqlite` (for queries), and `system/graph.md`.

## Query

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_query.py" --out <out> <op> ...
```

| Op | Use for |
| --- | --- |
| `search <text>` | find nodes by name or path |
| `explain <id\|repo/path\|name>` | node + cited edges + threats and findings on it |
| `neighbors <id> --depth 2 --kinds calls` | local structure |
| `path <src> <dst>` | how A reaches B (follows calls, HTTP, queues, tables, subprocess) |
| `impact <target...>` or `impact --diff HEAD~1` | multi-hop blast radius, plus endpoints, sinks, threats, and findings in scope |
| `callgraph function\|file\|repo [--repo R] [--focus X] [--depth N]` | function→function, file→file or repo→repo call graph (HTTP/gRPC resolved to handlers, topics, shared tables, subprocess, imports), each edge with citations and the weakest confidence |
| `taint [--source X] [--sink Y]` | candidate source→unsafe-sink paths (candidates: confirm each hop) |
| `sql "SELECT ..."` | ad-hoc read-only SQL over `nodes` and `edges` |
| `cypher "MATCH ..."` | only when Neo4j is configured (`graph_neo4j.py`) |

`references/query-recipes.md` maps common questions to ops and SQL. `references/cypher-recipes.md` has the Neo4j equivalents.

**Results are pointers, not proof.** Before stating a fact, open the cited lines. Edges labelled `inferred` or `low` are leads to check, not facts.

## Adding semantic edges (agents)

Agents never edit `graph.json`. They append JSON lines to `<out>/graph/proposals/<stage>-<repo>.jsonl` (format in `references/proposal-format.md`). Every line needs a citation plus an exact quote from those lines. The PostToolUse hook and `graph_merge.py` verify each line; rejected lines go to `graph/rejected.jsonl` with the reason. Rebuild after proposing.

## Schema

The node kinds, edge kinds, required fields, and which extractor may produce which edge are listed in `references/schema.md`. IDs are stable (`kind:repo:path:qualname`); line numbers live in citations, never in IDs, so a node keeps its ID when code moves.
