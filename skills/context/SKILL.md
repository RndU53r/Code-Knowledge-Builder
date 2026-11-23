---
name: context
description: Generate scanner-ready context.md files (per repo and system-level, nine fixed sections with YAML front matter) from the ckb analysis and threat model, running missing stages first.
argument-hint: "[source...] [--context <docs|diagrams|iac|cspm...>]"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*)
---

# /ckb:context

Read `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`.

1. Locate the output dir. Ingest any `--context` paths (P2b). Run whatever is missing first: the analysis (`/ckb:analyze` steps, including authorization for new sources), then `system/threat-model.md` (`/ckb:threat-model` steps). Section 9 of context.md depends on the threat model.
2. Using the `security-context` skill, write `repos/<repo>/context.md` for each repo (parallel Agent calls are fine: one general agent per repo, given `<out>`, the repo key and root, and told to follow the security-context skill and the safety contract) and then `system/context.md`.
3. Verify all context files with `ckb:citation-verifier`, and check that each has the nine numbered headings in order and valid front matter.
4. Run P4 (verify, check outputs, snapshot hashes, refresh `index.md`), then report the paths and each repo's `focus_areas`.
