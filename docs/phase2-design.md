# Phase 2: Design for `code-knowledge-builder`

## Inputs from Phase 2 questions

| Topic | Answer | Design consequence |
| --- | --- | --- |
| Targets | Fixtures + your real repos | Build against two fixtures first. Your repos get listed and authorized before any scan (list still to come). |
| Source acquisition | Local folder, git (GitHub), GitLab, CI pipeline | `fetch-source` supports all four (§4). The plugin also runs headless inside GitHub Actions / GitLab CI. |
| Infra context | Not narrowed | Parse whatever exists: K8s/Helm/Kustomize, Terraform, Dockerfile/compose, gateway/ingress, CI configs. |
| Scanner format | Generic markdown | `context.md` = the 9 required sections plus a small YAML front-matter block for machine parsing (§6). |
| Scope | User-scoped | Install once and use on any repo. Output defaults to `<target>/.ckb/`, or the directory you choose. |
| Diagrams | Mermaid (default) | Inline in markdown, with `.mmd` copies in `diagrams/`. |

## 1. Component plan

| Type | Count | Purpose |
| --- | --- | --- |
| Knowledge skills (auto-trigger) | 8 | One per analysis capability; hold the method and the references |
| Command skills (user-invoked) | 6 | `analyze`, `threat-model`, `context`, `supply-chain`, `full`, `update` |
| Agents | 5 | Per-repo analyzer, flow tracer, threat modeler, supply-chain auditor, citation verifier |
| Hooks | 3 | PreToolUse exec/install guard, PreToolUse write guard, PostToolUse citation and redaction check |
| Scripts (Python 3 stdlib only, no installs) | 7 | Deterministic helpers (§5) |
| MCP servers | 0 | Not needed: git, Read, and Grep cover acquisition and analysis |
| Settings | 1 | `.claude/code-knowledge-builder.local.md` (§7) |

Commands are written as `skills/<name>/SKILL.md` with `disable-model-invocation: true`, which plugin-dev recommends over the legacy `commands/` directory. They appear as slash commands all the same.

## 2. Skills

### Knowledge skills (auto-trigger on matching requests)

| Skill | Produces | Key references (`references/`) |
| --- | --- | --- |
| `repo-inventory` | Languages, frameworks, build systems, entry points (main, HTTP, CLI, cron, queue consumers, lambdas), deps → `overview.md` | entry-point patterns per language; manifest catalogue |
| `code-analysis` | Per-repo call/data flow, modules, data models, error handling → `lld.md`, `flows.md` | tracing method (adapted from othman, MIT); polyglot edge catalogue (FFI, subprocess, generated clients) |
| `cross-repo-flow-mapping` | System edges: REST/gRPC/GraphQL/SDK, Kafka/SQS/RabbitMQ/pub-sub/webhooks, shared DB/cache/bucket, shared contracts → `system/data-flows.md` | contract matching rules (OpenAPI path ↔ client call, topic name ↔ consumer, proto service ↔ stub) |
| `architecture-docs` | System HLD, per-repo HLD/LLD, sequence diagrams → `hld.md`, `lld.md` | HLD/LLD templates; Mermaid safety rules |
| `outputs-and-conditions` | What / how / when / who for each output, with a `condition \| effect \| default \| source` table | output-type catalogue; condition sources (flags, env, config, roles, retries) |
| `threat-modeling` | Scope, assets, actors, trust boundaries, DFD, STRIDE per component and flow, CWE/OWASP and LLM Top 10 → `threat-model.md` | STRIDE prompts; sink catalogue (SQL, cmd, template, deser, SSRF, path traversal); likelihood/impact rubric |
| `security-context` | `context.md` per repo and for the system | context.md schema (§6) |
| `supply-chain-audit` | Ranked findings: manifests, install-time exec, CI/CD, containers/IaC, source indicators, agent injection, dependency list → `supply-chain*.md` | check catalogue with IDs (SC-001…); severity rubric; "confirmed suspicious" vs "risky practice" definitions |

### Command skills

| Command | What it does |
| --- | --- |
| `/ckb:analyze <sources...>` | Authorize → fetch → inventory → parallel per-repo analysis → cross-repo flows → HLD/LLD → outputs-and-conditions → verify |
| `/ckb:threat-model` | Needs an existing analysis; runs the threat modeler → verify |
| `/ckb:context` | Builds `context.md` files from the analysis + threat model (runs whichever is missing first) |
| `/ckb:supply-chain [sources...]` | Standalone audit; doesn't need a prior analysis |
| `/ckb:full <sources...>` | Everything, in order, then `index.md` and the evidence index |
| `/ckb:update` | Re-hashes the targets, re-runs only the affected repos and stages, re-verifies |

Every command starts the same way: list the sources, ask you to confirm authorization for each one, and record the confirmation in `evidence/authorization.md`.

### Shared material (plugin root, used by every skill)

```
shared/
  safety-contract.md     # untrusted input, read-only, no symlinks, redaction (adapted from othman, MIT)
  evidence-model.md      # observed/inferred/unknown labels, [inferred]/[unknown], confidence, citation format
  templates/             # one template per output file (overview, hld, lld, flows, outputs, threat-model, context, supply-chain, index)
```

## 3. Agents

| Agent | Runs | Tools | Output |
| --- | --- | --- | --- |
| `repo-analyzer` | One per repo, in parallel | Read, Grep, Glob, Bash (plugin scripts only), Write (output dir only) | `repos/<repo>/*` except supply-chain |
| `flow-tracer` | Once, after all analyzers | Read, Grep, Glob, Write | `system/data-flows.md`, `system/hld.md` |
| `threat-modeler` | Once | Read, Grep, Glob, Write | `system/threat-model.md` |
| `supply-chain-auditor` | One per repo, in parallel | Read, Grep, Glob, Bash (scanner script only), Write | `repos/<repo>/supply-chain.md`, `system/supply-chain-report.md` |
| `citation-verifier` | After every stage | Read, Grep, Bash (verifier script only) | `evidence/verification.md`; failures go back to the stage that produced them |

## 4. Source acquisition (`scripts/fetch_source.py`)

| Source | How |
| --- | --- |
| Local folder | Use in place, read-only. Record the canonical path, git revision if any, and the dirty status. |
| GitHub / any git URL | `git -c core.hooksPath=/dev/null -c protocol.file.allow=never clone --depth 1 --no-recurse-submodules` with `GIT_LFS_SKIP_SMUDGE=1`, into a new empty scratch directory. |
| GitLab (gitlab.com or self-hosted) | Same as git, plus a self-hosted base URL. |
| Private repos | Token read from an env var you name (`GITHUB_TOKEN`, `GITLAB_TOKEN`), passed through a one-shot git credential helper. Never put in the URL, a log, or an output file. |
| CI pipeline | Example GitHub Actions and `.gitlab-ci.yml` jobs that run `claude -p "/ckb:full ."` headless on the checked-out repo and upload `.ckb/` as an artifact. In CI, authorization comes from the repo owner adding the job. |

Only `https://` and `ssh://` / `git@` are allowed. `file://`, `ext::`, and other git transports are refused.

## 5. Scripts (deterministic, static-only)

| Script | Purpose |
| --- | --- |
| `fetch_source.py` | Safe acquisition (§4) and provenance record |
| `inventory.py` | File and language census, manifest discovery, entry-point candidates by regex. Skips vendored, generated, binary, and symlinked paths. |
| `scan_supply_chain.py` | Pattern checks: lifecycle scripts, unpinned and floating versions, missing lockfiles, git/URL deps, unpinned actions, `pull_request_target`, `${{ github.event.* }}` in `run:`, `permissions: write-all`, `curl\|sh`, `FROM :latest`, `ADD http`, root user, hidden or bidi Unicode, long base64/hex blobs, `eval` of fetched content, agent-directed phrases, committed binaries and git hooks. Output is JSON with `path:line`. |
| `verify_citations.py` | Every `path:line` exists. A quoted snippet next to a citation must match that line (idea from arden, written from scratch). Sections without citations are flagged. |
| `check_outputs.py` | Mermaid syntax sanity, broken internal links, secret-pattern scan of outputs |
| `hash_index.py` | Per-file content hashes and a stage dependency map for `/ckb:update` |
| `guard.py` | Hook logic (§8) |

The scripts read target files. They never execute, import, or build anything in the target.

## 6. `context.md` shape

```markdown
---
ckb_context: 1
repo: payments-api
revision: <sha>
generated: <iso8601>
languages: [python, go]
entry_points: 12
focus_areas: [authz-bypass, ssrf, deserialization]
---
# Security context: payments-api
1. Purpose and tech stack
2. Entry points and trust boundaries
3. Authn/authz model
4. Sensitive data and where it flows
5. Dangerous sinks and sanitizers already in place
6. Known-safe patterns and known-risky areas
7. Inter-service contracts
8. Config and env conditions that change behavior
9. Threat-model summary and prioritized scanner focus
```

Each section is mostly bullets and tables, and every line carries a citation.

## 7. Settings (`.claude/code-knowledge-builder.local.md`, optional)

| Field | Default | Meaning |
| --- | --- | --- |
| `output_dir` | `<target>/.ckb` | Where outputs go |
| `scratch_dir` | system temp + `ckb-<id>` | Where remote clones land |
| `exclude_paths` | built-in list | Extra globs to skip |
| `token_env` | `GITHUB_TOKEN`, `GITLAB_TOKEN` | Env vars to read tokens from |
| `gitlab_base_url` | `https://gitlab.com` | Self-hosted GitLab |
| `advisory_lookup` | `off` | When `on`, sends package names and versions to OSV.dev to check for known CVEs |

## 8. Hooks

| Event | Matcher | Behavior |
| --- | --- | --- |
| PreToolUse | `Bash` | Blocks (exit 2) commands that install, build, run, or test while the working directory or any path argument is inside a registered target. Covers npm/yarn/pnpm/pip/poetry/uv/go run/build/test, cargo, mvn/gradle, make, docker build/run, `sh`/`bash` on target files, `python <target file>`, `node <target file>`, `git` commands that run hooks, and `curl\|sh`. Read-only git (`log`, `show`, `blame`, `ls-files`) is allowed. |
| PreToolUse | `Write\|Edit\|MultiEdit` | Blocks writes inside a target except under its output directory |
| PostToolUse | `Write\|Edit` on `**/.ckb/**/*.md` | Runs `verify_citations.py` and the secret scan on the written file. If citations are missing or broken, or a secret-looking value appears, the problem is sent back to Claude (exit 2) to fix. |

Registered targets live in `<output_dir>/evidence/targets.json`, plus a per-user registry, so the guard knows what to protect.

## 9. Output layout

As specified: `.ckb/index.md`, `system/*`, `repos/<repo>/*`, `diagrams/*.mmd`, `evidence/` (citation index, scan logs, authorization record, verification report, hashes).

## 10. Plugin layout

```
code-knowledge-builder/            (this repo's root)
  .claude-plugin/plugin.json
  .claude-plugin/marketplace.json  # so you can /plugin marketplace add RndU53r/Code-Knowledge-Builder
  skills/<8 knowledge + 6 command skills>/SKILL.md (+ references/)
  agents/*.md
  hooks/hooks.json
  scripts/*.py
  shared/{safety-contract.md, evidence-model.md, templates/}
  ci/{github-actions.yml, gitlab-ci.yml}
  tests/fixtures/{polyglot/, poisoned/}
  evals/<skill>/evals.json
  NOTICE                            # MIT notice for othman-derived text; credit to arden (ideas only)
  README.md
```

## 11. Fixtures

- **polyglot/**: `gateway` (Node/Express) calls `orders` (Python/FastAPI) over REST. `orders` publishes `order.created` to a queue that `fulfillment` (Go) consumes. All three share a Postgres DB and an OpenAPI spec, and `orders` calls a Go binary via subprocess. Includes Dockerfiles, a compose file, a K8s manifest, and a GitHub Actions workflow.
- **poisoned/**: a malicious-looking `postinstall` (`curl … | sh` to a `.invalid` host, so it's inert), an unpinned third-party action, `pull_request_target` with `${{ github.event.pull_request.title }}` in `run:`, a prompt-injection comment aimed at AI tools, a bidi-Unicode trick, a base64 blob passed to `eval`, and a fake credential (a test value that looks like a real AWS key).

## 12. Open decisions

1. **Slash-command namespace.** Claude Code namespaces commands by plugin name. A plugin named `code-knowledge-builder` gives `/code-knowledge-builder:analyze`, not `/ckb:analyze`. **Recommend:** name the plugin `ckb` (display name "Code Knowledge Builder") so the commands are `/ckb:*` as specified.
2. **Advisory lookups.** Checking for known CVEs means sending package names and versions to OSV.dev. **Recommend:** off by default, with a setting to turn it on. When off, reports say "not checked".
3. **Your real repos.** Not needed until Phase 5 validation. Send the list (paths or URLs, languages, deployment) whenever you're ready, and I'll ask you to confirm authorization for each.

## Addendum (v0.2.0)

- **Advisories:** `advisory_lookup: off | osv | snyk | osv,snyk`. Snyk uses the REST API (`SNYK_TOKEN`, `SNYK_ORG_ID`). Every registry dependency gets a `security.snyk.io` page link with no network call.
- **Context inputs (`--context`, `context_paths`):** architecture docs (docx, pptx, pdf, md, html), diagrams (draw.io, vsdx, svg, images), cloud IaC (Terraform AWS/Azure/GCP, CloudFormation/SAM/CDK, ARM/Bicep, Deployment Manager, k8s/Helm), and CSPM or scanner results (ASFF, Prowler, ScoutSuite, Defender, GCP SCC, Checkov, SARIF, CSV). They're converted by `scripts/ingest_context.py` into `ctx-*` citable sources. The new `context-ingest` skill and the `[documented]` label separate intent from observation, and a "Documented vs observed" drift table feeds the HLD and threat model.
- **IaC checks** SC-D07 (public storage), SC-D08 (wildcard IAM), SC-D09 (encryption/TLS off), and multi-cloud SC-D05; the inventory lists `cloud_resources`.
