---
name: update
description: Incrementally refresh an existing ckb knowledge base. Re-fetches remote sources, diffs content hashes, and re-runs only the stale stages for changed repos, then re-verifies.
argument-hint: "[output_dir]  (default: ./.ckb or the configured output_dir)"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*)
---

# /ckb:update

Read `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`.

1. Locate `<out>` (argument, settings, or `./.ckb`) and read `<out>/evidence/targets.json`. Authorization carries over for the sources already recorded in `evidence/authorization.md`. New sources need P1.
2. **Remote sources:** re-run `fetch_source.py` with the same `--key`, `source`, and `ref` recorded in `targets.json` (it makes a fresh safe clone and updates the registry). **Local sources:** use them in place.
3. Re-ingest context: re-run `ingest_context.py` with the same `--key` and the source paths recorded for each `ctx-*` key in `targets.json`.
4. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/hash_index.py" diff --out <out>`: per repo, the changed files and `stale_stages`. If no repo changed, report "up to date" and stop.
5. Re-run only what's stale. Per-repo stages go to `ckb:repo-analyzer` or `ckb:supply-chain-auditor`, told which files changed so they update the affected sections instead of rewriting everything. If any per-repo stage re-ran, or contracts or infra changed, re-run the system stages that already have outputs, in order: flow-tracer; the system supply-chain report (if any audit re-ran); threat-modeler; context (via the `security-context` skill).
6. Because line numbers shift when files change, re-verify **every** output (not only the rewritten ones) with `ckb:citation-verifier`, and fix any citations that broke.
7. P4: snapshot hashes, refresh `index.md`, and report what changed, which stages re-ran, and the verification status.
