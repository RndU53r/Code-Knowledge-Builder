---
name: tour
description: Create or run guided onboarding tours through the ckb knowledge graph (ordered steps over real nodes with notes and citations), shown in the interactive viewer and via MCP.
argument-hint: "[create [audience]|list|<tour-name>]"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*), Bash(git diff:*)
---

# /ckb:tour

Arguments: $ARGUMENTS

| Argument | Do |
| --- | --- |
| `list` or none | `graph_query.py --out <out> tour` |
| `<name>` | Walk the user through the tour in chat, step by step. Read each step's cited lines and explain them briefly. Mention that the same tour is in `graph/index.html` under Tours. |
| `create [audience]` | Dispatch `ckb:graph-curator` with `<out>`, the audience (default "new engineer"), and the tour count from `evidence/auto-plan.json` if present (otherwise 1–3 by repo size). It writes `op:"tour"` (and `op:"annotate"`) proposals. Then run `graph_build.py --out <out>`, `graph_check.py` and `graph_viewer.py`. Report the tours created and any rejected proposal lines. |
