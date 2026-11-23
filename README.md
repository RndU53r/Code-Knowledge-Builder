# Code Knowledge Builder (`ckb`)

A Claude Code plugin that turns one or more repositories (polyglot, monorepo, or microservices) into:

- a **navigable knowledge base**: inventory, per-repo HLD/LLD and flows, cross-repo data flows, outputs and conditions;
- a **STRIDE threat model** with trust boundaries, DFDs, and CWE/OWASP mapping (plus the OWASP LLM Top 10 when the system calls LLMs);
- **`context.md` files** a security scanner can consume (per repo and system-wide);
- a **supply-chain and prompt-injection audit**, with optional advisory lookups (OSV.dev and/or Snyk) and a `security.snyk.io` link for every dependency;
- **context-aware results:** existing architecture documents, diagrams, cloud IaC, and CSPM findings are ingested as evidence, and the docs are checked against the code ("documented vs observed" drift).

Every claim cites `repo/path:line`. Anything not proven by the code is marked `[inferred]` or `[unknown]`. Target code is never executed.

## Install

Claude Code with Python 3.9+ available as `python3` on `PATH` (on Windows, use WSL or add a `python3` alias, since the hooks call `python3`) and `git`. No other dependencies: all scripts use only the Python standard library.

```text
/plugin marketplace add RndU53r/Code-Knowledge-Builder
/plugin install ckb@code-knowledge-builder
```

Or try it from a local checkout without installing:

```bash
claude --plugin-dir /path/to/Code-Knowledge-Builder
```

The plugin is user-scoped: install it once and use it on any repo.

## Usage

| Command | What it does |
| --- | --- |
| `/ckb:analyze <sources...>` | Inventory, per-repo flows, HLD/LLD, outputs and conditions, cross-repo data flows |
| `/ckb:threat-model [sources...]` | STRIDE threat model (runs the analysis first if needed) |
| `/ckb:context [sources...]` | Scanner-ready `context.md` per repo and for the system (type the full `/ckb:context`: plain `/context` is Claude Code's built-in context-usage command) |
| `/ckb:supply-chain <sources...>` | Standalone supply-chain and prompt-injection audit |
| `/ckb:full <sources...>` | Everything above, verified, with an `index.md` |
| `/ckb:update [output_dir]` | Incremental refresh: re-fetches, diffs hashes, re-runs stale stages, re-verifies |

Add supporting context to any command with `--context`:

```text
/ckb:full ./svc-a ./svc-b --context ./docs/architecture ./infra ./security/prowler.ocsf.json
```

| Context type | Formats |
| --- | --- |
| Architecture documents | Word `.docx`, PowerPoint `.pptx`, PDF (text via `pdftotext` if installed, otherwise Claude reads it), Markdown, HTML, text |
| Diagrams | draw.io / diagrams.net (`.drawio`, compressed pages included), Visio `.vsdx`, SVG, PNG/JPG whiteboards (Claude reads the image) |
| Cloud IaC | Terraform (AWS `aws_*`, Azure `azurerm_*`, GCP `google_*`), AWS CloudFormation / SAM / CDK, Azure ARM and Bicep, GCP Deployment Manager, Kubernetes, Helm, Pulumi |
| CSPM and IaC-scan results | AWS Security Hub (ASFF), Prowler (JSON/OCSF/CSV), ScoutSuite, Microsoft Defender for Cloud, GCP Security Command Center, Checkov JSON, SARIF (Checkov, tfsec, KICS, Trivy, Snyk IaC), CSV exports with severity, resource, and title columns (Wiz, Prisma Cloud, Orca) |

Context is converted into citable files under `.ckb/evidence/context/ctx-*` (`scripts/ingest_context.py`). Precedence: code and IaC (what is built) > CSPM results (what was deployed at scan time) > documents and diagrams (`[documented]` intent). Disagreements are reported as drift, for example a design doc that says "all traffic uses mTLS" while the code calls `http://orders:8000`.

Sources can be:

```text
/ckb:full ./services/gateway ./services/orders          # local folders
/ckb:full github:acme/orders gitlab:platform/payments   # shorthands
/ckb:full https://github.com/acme/orders.git git@gitlab.example.com:team/billing.git
```

- **Private repos:** set `token_env` (for example `GITHUB_TOKEN`) in the settings file. The token is read from the environment, passed through a one-shot git credential helper, and never written to a URL, log, or output.
- **Self-hosted GitLab:** set `gitlab_base_url`.
- **CI pipelines:** see [`ci/github-actions.yml`](ci/github-actions.yml) and [`ci/gitlab-ci.yml`](ci/gitlab-ci.yml). They run `/ckb:full .` headless and upload `.ckb/` as an artifact.

The eight knowledge skills (`repo-inventory`, `code-analysis`, `cross-repo-flow-mapping`, `architecture-docs`, `outputs-and-conditions`, `threat-modeling`, `security-context`, `supply-chain-audit`) also trigger on their own from ordinary requests such as "how do these services talk to each other?" or "is this repo safe to npm install?".

### Settings (optional)

Copy [`examples/code-knowledge-builder.local.md`](examples/code-knowledge-builder.local.md) to `<project>/.claude/code-knowledge-builder.local.md`. It sets `output_dir`, `scratch_dir`, `exclude_paths`, `token_env`, `gitlab_base_url`, `context_paths`, and `advisory_lookup`.

**Advisory lookups** are off by default, and reports then say "not checked". Set `advisory_lookup` to `osv`, `snyk`, or `osv,snyk` to look up exactly pinned dependencies. This sends package names and versions off-machine: to api.osv.dev, and/or to the Snyk REST API (needs `SNYK_TOKEN` and `SNYK_ORG_ID`, read from the environment and never printed). Whatever the setting, each registry dependency in the report links to its `https://security.snyk.io/package/...` page so a reviewer can check it by hand.

### Output

A complete example run over the code fixtures (version 0.1.0, before context ingestion) is in [`examples/sample-output/`](examples/sample-output/index.md): 45 files, 1,053 citations, 0 verification errors.


```
.ckb/
  index.md                    # entry point and navigation
  system/
    hld.md  data-flows.md  outputs-and-conditions.md
    threat-model.md  context.md  supply-chain-report.md
  repos/<repo>/
    overview.md  hld.md  lld.md  flows.md
    outputs-and-conditions.md  context.md  supply-chain.md
  diagrams/                   # .mmd sources for every Mermaid diagram
  evidence/                   # targets.json, authorization.md, verification.md,
                              # citations.md, inventory/scan JSON, hashes.json
```

## Safety model

ckb assumes the repos it analyzes may be hostile.

| Layer | What it does |
| --- | --- |
| **Authorization** | Every command lists the sources and asks you to confirm you own each one or are authorized to audit it. The answer is recorded in `evidence/authorization.md`. Unlisted repos, submodules, and dependency URLs are never followed. |
| **Safe acquisition** | `scripts/fetch_source.py` clones with `core.hooksPath=/dev/null`, `--depth 1`, no submodules, no LFS smudge, `file://`/`ext::` transports refused, and credentials-in-URL refused, into a new empty scratch directory. |
| **PreToolUse guard (hook)** | Blocks Bash commands that would install, build, run, or test code inside a registered target (npm/yarn/pnpm, pip/poetry/uv, go, cargo, mvn/gradle, make, docker, interpreters on target files, `source`, `./script`, git commands that run hooks, nested `bash -c`), blocks shell writes into a target (`rm`, `mv`, `cp` into, `sed -i`, `tee`, `chmod`, `>`/`>>` redirection), and blocks Write/Edit into a target outside its `.ckb/`. Commands outside registered targets aren't affected. |
| **Untrusted-input rule** | Repo content is data. Text aimed at AI agents (in READMEs, comments, `CLAUDE.md`/`AGENTS.md`/`.cursorrules`, hidden HTML comments) is reported as a `prompt-injection` finding and never followed. |
| **Evidence or it didn't happen** | Citations are `repo/path:line` with optional «quotes». `scripts/verify_citations.py` checks the repo key, file, line range, and quoted text. The **PostToolUse hook** runs it on every output file written and pushes failures back to Claude. The `citation-verifier` agent also samples citations to check that they support the claims. |
| **Secret redaction** | Secret files aren't opened. Secret-looking values appear only as type, location, and `AKIA…[REDACTED]`. The PostToolUse hook rejects outputs that contain unredacted values. |
| **Network** | None during analysis, except cloning the sources you list. Advisory lookups (OSV.dev, Snyk API) are opt-in. URLs inside documents are never fetched. |
| **Context files** | Office files are read in memory as XML (macros and embedded objects are never run), with size and compression-ratio limits. XML with DOCTYPE or ENTITY declarations is refused. Secret-looking values are redacted in converted text. Supplied IaC folders are registered so the guard blocks `terraform apply` and similar commands against them. |

## Components

| Type | Items |
| --- | --- |
| Skills (knowledge) | repo-inventory, code-analysis, cross-repo-flow-mapping, architecture-docs, outputs-and-conditions, threat-modeling, security-context, supply-chain-audit, context-ingest |
| Skills (commands) | analyze, threat-model, context, supply-chain, full, update |
| Agents | repo-analyzer (parallel, one per repo), supply-chain-auditor (parallel, one per repo), flow-tracer, threat-modeler, citation-verifier |
| Hooks | PreToolUse Bash guard, PreToolUse write guard, PostToolUse citation, Mermaid, link, and redaction check |
| Scripts | `fetch_source.py`, `ingest_context.py`, `inventory.py` (incl. cloud resources), `scan_supply_chain.py` (36 checks incl. multi-cloud IaC; OSV/Snyk), `verify_citations.py`, `check_outputs.py`, `hash_index.py`, `guard.py` |
| Shared | `shared/safety-contract.md`, `shared/evidence-model.md`, `shared/pipeline.md`, `shared/templates/*.md` |

## Development and tests

The command skills don't pre-approve `python3`. Claude Code asks the first time a ckb script runs. To skip the prompts, allow just the plugin's scripts in your settings, for example `"Bash(python3 /path/to/ckb/scripts/*)"`.

```bash
python3 tests/test_guard.py                 # guard hook: deny and allow cases, write guard, post check
python3 tests/test_ingest.py                # context ingest (docx/vsdx/drawio/CSPM), refusals, redaction, IaC checks
python3 tests/make_context_fixtures.py      # regenerate tests/fixtures/context
python3 tests/make_evals.py                 # regenerate the skill eval cases (skills/*/evals/)
python3 scripts/scan_supply_chain.py --root tests/fixtures/poisoned --key poisoned --md-out /tmp/sc.md
```

- **Fixtures:** `tests/fixtures/polyglot` (Node gateway → Python orders → Go fulfillment over REST and RabbitMQ, shared Postgres, a Python→Go subprocess edge) and `tests/fixtures/poisoned` (malicious-looking postinstall, pwn-request workflow, script injection, unpinned action, prompt-injection text, Trojan Source characters, typosquat, a documentation example AWS key). Ground truth is in `tests/fixtures/EXPECTED.md`. Fixture URLs use the reserved `.invalid` TLD. Never install or run the fixtures.
- **Running the evals with the CLI** (real, billed model runs): `claude plugin eval skills/<skill> --scaffold --allow-tools Write,Edit,Bash`.

## Known limitations

- **Static analysis only.** Runtime-only behavior (reflection, dynamic routing, config loaded from remote stores, generated code that isn't committed) is marked `[inferred]` or `[unknown]`, not resolved.
- **Heuristic scripts.** Inventory and the supply-chain scanner are regex-based, high-recall helpers. The agents confirm or dismiss each candidate by reading the code, so quality depends on that triage.
- **Cross-repo matching** relies on literal identifiers (paths, topics, tables). Identifiers built at runtime or kept in remote config produce low-confidence or unmatched edges.
- **Vulnerability data** is "not checked" unless you turn on `advisory_lookup`, and then only for exactly pinned versions OSV.dev or Snyk knows about. The Snyk lookup uses the REST "list issues for a package" endpoint and needs a token and org ID. It was built to the documented API but hasn't been exercised against a live Snyk account.
- **Context formats:** legacy binary Office files (`.doc`, `.vsd`, `.ppt`, `.xls`) must be exported first. PDF text needs `pdftotext` (poppler); otherwise Claude reads the PDF page by page. Diagram arrows in images and SVGs come from Claude reading them, so they're labeled `[documented]` like any doc claim. CSPM format detection is structural; unrecognized JSON is kept as pretty-printed text.
- **IaC checks** are pattern-based (public storage, wildcard IAM, open ingress, disabled encryption/TLS, literal passwords). They complement, not replace, a dedicated IaC scanner; feed Checkov/tfsec/KICS SARIF in as context to combine both.
- **Shallow clones** limit history-based checks (for example suspicious recent commits).
- **The guard hook** recognizes common toolchains and patterns. It's a strong safety net, not a sandbox: run ckb on untrusted code inside a container or VM for defense in depth. If the hook script itself errors, it fails open (allows) and reports the error, so it never wedges your session.
- **Large monorepos:** per-repo agents work within their context budget. Untraced flows are listed as `[unknown]` rather than silently dropped. Register large services separately with `--key`.
- **Mermaid checks** are structural (types, balance, no interactivity), not a full renderer.

## Credits and licenses

MIT licensed (see [LICENSE](LICENSE)). Third-party notices are in [NOTICE](NOTICE).

- **[OthmanAdi/codebase-knowledge-builder](https://github.com/OthmanAdi/codebase-knowledge-builder)** (MIT): the trust-and-safety contract, the observed/inferred/unknown evidence labels, the provenance block, the Mermaid hygiene rules, and the recon and deep-dive method were adapted (rewritten and extended) into `shared/` and the inventory and code-analysis skills.
- **[ardennguyen/Codebase-Knowledge-Builder](https://github.com/ardennguyen/Codebase-Knowledge-Builder)** (CC BY-NC-SA 4.0): no code or text was used. Its ideas of quote-verified facts, deterministic doc checks, and hash-based incremental refresh inspired independent implementations (`verify_citations.py`, `check_outputs.py`, `hash_index.py`).
- **New in ckb:** multi-repo and cross-repo flow tracing, polyglot edges, outputs and conditions, the threat model, scanner `context.md`, the supply-chain and prompt-injection audit, the enforced hooks, parallel agents, the citation verifier, safe remote acquisition (GitHub, GitLab, CI), and incremental update.
