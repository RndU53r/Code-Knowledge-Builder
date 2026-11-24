---
name: graph
description: Build, view, serve, check or export the ckb code knowledge graph (JSON + SQLite; interactive HTML viewer; live local server; Understand-Anything JSON, Neo4j Cypher/CSV, GraphML; push to an existing Neo4j after confirmation).
argument-hint: "[build|view|serve|check|export ua|cypher|csv|graphml|neo4j] [--incremental]"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*), Bash(git diff:*)
---

# /ckb:graph

Action: $ARGUMENTS (default `build`). Follow the `knowledge-graph` skill and `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md`.

1. Locate `<out>` (pipeline P0). If no repos are registered there, run pipeline P1–P2 first (authorization question, `fetch_source.py`).
2. Then do the requested action:

| Action | Do |
| --- | --- |
| `build` | `graph_build.py --out <out> --extract` (add `--incremental` if requested or if `evidence/hashes.json` exists), then `graph_check.py --out <out> --report` and `graph_viewer.py --out <out>` |
| `view` | `graph_viewer.py --out <out>`, then tell the user the path `<out>/graph/index.html` (opens offline in any browser) |
| `serve` | Run `graph_serve.py --out <out>` in the background and give the user the printed localhost URL. It's read-only, token-protected, and reloads live when the graph is rebuilt. |
| `check` | `graph_check.py --out <out> --report` |
| `export <fmt>` | `graph_export.py --out <out> <ua\|cypher\|csv\|graphml>` |
| `neo4j` | `graph_neo4j.py --out <out> check`. Then **ask the user to confirm before writing to their database** and run `graph_neo4j.py --out <out> push --yes` only on an explicit yes. |

3. Report the node and edge counts by kind, the extractor mix (tree-sitter used or not), `graph_check` errors (must be 0), and the output paths.
