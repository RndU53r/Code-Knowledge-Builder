---
name: ask
description: Answer a natural-language question about the analyzed codebase using the ckb knowledge graph (graph queries or Cypher when Neo4j is configured), confirming every fact against the cited source lines.
argument-hint: "<question>  e.g. \"which endpoints can reach a SQL query built from user input?\""
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*), Bash(git diff:*)
---

# /ckb:ask

Question: $ARGUMENTS

Follow the `knowledge-graph` skill (`references/query-recipes.md`) and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`.

1. Make sure `<out>/graph/graph.sqlite` exists. If it doesn't, run `/ckb:graph build` first (including authorization if nothing is registered).
2. Translate the question into one or more graph operations (`search`, `explain`, `neighbors`, `path`, `impact`, `taint`, read-only `sql`), or into Cypher via `graph_query.py cypher` when Neo4j is configured and the question suits it. Chain queries when one answer feeds the next. Never write to the graph.
3. **Confirm.** Open every cited line that your answer relies on with Read. Drop or relabel anything the code doesn't support. Inferred or low-confidence edges stay `[inferred]`.
4. Answer in chat: a direct answer first, then the evidence as `repo/path:line` citations, then the queries you ran. If the user wants it saved, or the answer is long, write `<out>/answers/<slug>.md` from `${CLAUDE_PLUGIN_ROOT}/shared/templates/answer.md`. The PostToolUse hook verifies it.
5. If the graph can't answer the question (dynamic dispatch, a missing repo), say so and say what evidence would resolve it.
