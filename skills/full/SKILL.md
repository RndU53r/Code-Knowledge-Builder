---
name: full
description: Run the whole ckb pipeline on one or more repos (authorization, safe acquisition, inventory, per-repo and system architecture, cross-repo flows, outputs and conditions, threat model, context.md, supply-chain audit, citation verification, and index). Static analysis only.
argument-hint: "<source...> [--context <docs|diagrams|iac|cspm...>]"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*)
---

# /ckb:full

Run everything for: $ARGUMENTS

Read `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`.

1. **P0–P2b** once for all sources and context (one authorization question; ingest any `--context` paths).
2. **Parallel per-repo wave:** in a single message, dispatch one `ckb:repo-analyzer` and one `ckb:supply-chain-auditor` per repo. They're independent.
3. Verify each repo's files (`ckb:citation-verifier`) and fix failures.
4. Write `system/supply-chain-report.md` (cross-repo ranking, `shared/templates/supply-chain-report.md`) → verify.
5. **System wave, in order:** `ckb:flow-tracer` → verify → `ckb:threat-modeler` (give it the supply-chain reports too) → verify.
6. **Context:** as in `/ckb:context`: one agent per repo for `repos/<repo>/context.md`, then `system/context.md`, using the `security-context` skill → verify.
7. **P4** finish, and report the top risks across the threat model and supply chain, verification status, and where everything lives.

In CI, follow the P1 CI rule in `shared/pipeline.md`. The CI templates in `ci/` pre-approve the plugin's `python3` scripts with `--allowedTools`.
