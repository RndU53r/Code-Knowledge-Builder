---
name: analyze
description: Analyze one or more repositories (local paths, GitHub, GitLab, or git URLs) into a cited knowledge base covering inventory, per-repo HLD/LLD and flows, cross-repo data flows, and outputs and conditions, written to .ckb/. Static analysis only.
argument-hint: "<source...>  e.g. ./svc-a ./svc-b github:acme/orders gitlab:team/payments"
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, AskUserQuestion, Skill, Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(git blame:*)
---

# /ckb:analyze

Build the knowledge base for: $ARGUMENTS

Read `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md` first, then:

1. **P0–P2** from the pipeline: settings, sources and authorization (ask the user to confirm each source), acquire and register.
2. **Per repo, in parallel:** one `ckb:repo-analyzer` agent per repo. Each writes `repos/<repo>/overview.md`, `flows.md`, `hld.md`, `lld.md`, and `outputs-and-conditions.md` using the `repo-inventory`, `code-analysis`, `architecture-docs`, and `outputs-and-conditions` skills.
3. **Verify** each repo's files with `ckb:citation-verifier`, and send failures back for fixing.
4. **System:** one `ckb:flow-tracer` agent writes `system/data-flows.md`, `system/hld.md`, and `system/outputs-and-conditions.md` (cross-repo index). Verify.
5. **P4** steps 1–5: verify all, check outputs, snapshot hashes, write `index.md` and `evidence/citations.md`, report.

With a single repo, still write the `system/` files, scoped to that repo plus its external dependencies.
