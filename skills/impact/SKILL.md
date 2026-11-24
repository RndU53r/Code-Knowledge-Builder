---
name: impact
description: Security-aware multi-hop impact analysis of changing a file, symbol, or git diff using the ckb knowledge graph (affected callers, endpoints, consumers, readers across repos, plus sinks, threats, CSPM and supply-chain findings in scope).
argument-hint: "<file|symbol|node-id ...> | --diff <rev>"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*), Bash(git diff:*)
---

# /ckb:impact

Targets: $ARGUMENTS

1. Ensure the graph exists and is current. If `evidence/hashes.json` shows changes, run `graph_build.py --out <out> --extract --incremental` first.
2. Run `graph_query.py --out <out> impact <targets...>`, or `impact --diff <rev>` (read-only `git diff --name-only` with hooks disabled). The default depth is 6. Use a smaller depth for huge graphs.
3. Read the hop chain for the top affected items (endpoints, cross-repo consumers, data readers) and confirm the important hops in code.
4. Write `<out>/system/impact-<slug>.md` from `${CLAUDE_PLUGIN_ROOT}/shared/templates/impact.md`:
   - **Change set:** what changed.
   - **Blast radius by kind:** with hop counts and the citation chain.
   - **Externally reachable entry points affected.**
   - **Security in scope:** unsafe sinks, threats, findings, trust boundaries, each cited.
   - **Suggested tests:** `tested_by` edges, plus gaps where no tests exist.
5. Summarize in chat: number affected, top risks, and where the report is.
