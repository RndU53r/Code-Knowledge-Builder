---
name: threat-model
description: Build a STRIDE threat model (assets, actors, entry points, trust boundaries, DFDs, CWE/OWASP mapping, prioritized risks) for repos already analyzed by ckb, running the analysis first if needed.
argument-hint: "[source...] [--context <docs|diagrams|iac|cspm...>]"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*)
---

# /ckb:threat-model

Read `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`.

1. Find the output dir (P0). If $ARGUMENTS names sources that aren't registered there yet, or `repos/*/flows.md` or `system/data-flows.md` are missing, run the `/ckb:analyze` steps for them first, including authorization. If no sources are registered and none are given, run P1: propose the current directory and ask for authorization.
2. If `repos/*/supply-chain.md` exists, pass it along: build-path threats belong in the model. If `--context` paths are given, ingest them (P2b). Pass the `ctx-*` keys so CSPM findings, cloud IaC, and documented controls (and their drift) feed the model.
3. Make sure the graph exists (P2c). The threat modeler navigates it and writes threat proposals.
4. Dispatch `ckb:threat-modeler` to write `system/threat-model.md` using the `threat-modeling` skill.
5. Run `graph_build.py` and `graph_check.py` (P3g).
6. Verify with `ckb:citation-verifier` and fix failures (at most two rounds).
7. Run P4 (verify, check outputs, snapshot hashes, refresh the "Top findings" in `index.md`), then report the top five risks with their citations.
