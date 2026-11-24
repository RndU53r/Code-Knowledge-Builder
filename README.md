# Code Knowledge Builder (`ckb`)

A Claude Code plugin that turns one or more repositories (polyglot, monorepo, or microservices) into:

- a **navigable knowledge base**: inventory, per-repo HLD/LLD and flows, cross-repo data flows, outputs and conditions;
- a **STRIDE threat model** with trust boundaries, DFDs, and CWE/OWASP mapping (plus the OWASP LLM Top 10 when the system calls LLMs);
- **`context.md` files** a security scanner can consume (per repo and system-wide);
- a **supply-chain and prompt-injection audit**, with optional advisory lookups (OSV.dev and/or Snyk) and a `security.snyk.io` link for every dependency;
- a **cited code knowledge graph** (functions, endpoints, topics, tables, cloud resources, sinks, threats, findings) with an interactive viewer, a live local server, an MCP server, multi-hop impact and taint queries, and Neo4j/Understand-Anything/GraphML exports;
- **auto mode:** `/ckb:auto` looks at the environment (tools, logins, token names, CI) and the code, then picks sources (a local folder by default, a workspace of git repos, a monorepo, or whole **Azure DevOps projects**, GitHub orgs and GitLab groups, on **main else master**), parsers, context, and stages itself, and always produces a threat model and **function, file and repo call graphs**;
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
| `/ckb:auto [path\|ado:ORG/PROJECT\|github-org:NAME\|gitlab-group:PATH ...] [--ref BRANCH]` | Auto mode: probes the environment and the code, chooses sources, branches, context, parsers and stages, then runs everything (one authorization question) |
| `/ckb:graph [build\|view\|serve\|check\|export ...\|neo4j]` | Build, view, serve live, check, or export the knowledge graph |
| `/ckb:ask <question>` | Answer a question from the graph (or Cypher with Neo4j), confirmed against cited lines |
| `/ckb:impact <file\|symbol\|--diff rev>` | Security-aware multi-hop blast radius |
| `/ckb:tour [create\|<name>]` | Create or walk guided onboarding and security tours |

Add supporting context to any command with `--context`:

```text
/ckb:full ./svc-a ./svc-b --context ./docs/architecture ./infra ./security/prowler.ocsf.json
```

| Context type | Formats |
| --- | --- |
| Architecture documents and notes | Word `.docx`, PowerPoint `.pptx`, PDF (text via `pdftotext` if installed, otherwise Claude reads it), Markdown, HTML, text, RTF, email `.eml` (addresses omitted) |
| Diagrams | draw.io / diagrams.net (`.drawio`, compressed pages included), Visio `.vsdx`, Excalidraw, Mermaid `.mmd`, PlantUML `.puml`, Gliffy, SVG, PNG/JPG whiteboards and scanned PDFs (read by the `context-reader` agent) |
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

### Auto mode

`/ckb:auto` with no arguments analyzes the **current folder** (the local default). It then decides everything it can:

| Decision | How |
| --- | --- |
| **Capabilities from the environment** | `env_probe.py` checks git, tree-sitter, pdftotext, `az` login, which token variables exist (names only, values are never read into output), CI, CPUs, disk. Tree-sitter is used only if already installed; PDFs go through `pdftotext` or Claude's reader; parallel agents are sized to the CPUs |
| **Sources** | a workspace folder holding several git repos becomes one source per repo; a monorepo becomes one source per service plus a `platform` source for IaC, contracts and CI; `ado:ORG/PROJECT`, `github-org:NAME`, `gitlab-group:PATH` are expanded through their APIs (archived/disabled repos and forks skipped, capped by `auto_max_repos`) |
| **Branches** | **main, else master, else the repo default**, unless you pass `--ref`. A local repo whose checkout is on another branch is read as a **read-only snapshot** of main/master (`git archive`; your checkout is never switched, uncommitted work is not included; `--working-tree` overrides) |
| **Polyglot** | the parser is chosen per language (Python `ast`, tree-sitter if installed, regex otherwise) and cross-language edges (subprocess, FFI, HTTP, queues) are linked |
| **Stages** | only what the code supports: cloud layer if IaC exists, OWASP LLM Top 10 if an LLM SDK is imported, cross-repo flows if there are several services or broker/HTTP clients. Threat model, call graphs, and repo context are always on |
| **Azure DevOps auth** | an `az login` session if present, else a PAT from `AZURE_DEVOPS_EXT_PAT` / `ADO_PAT` / `SYSTEM_ACCESSTOKEN`, else anonymous (public projects). Tokens reach git only through environment variables, never argv, URLs or output |
| **Consent** | anything that leaves the machine (cloning remote repos, OSV, Snyk when `SNYK_TOKEN`/`SNYK_ORG_ID` are set, a Neo4j push when `NEO4J_*` are set) is detected and listed in the **one** authorization question; the default for each is no |

Never automated: authorization, off-machine lookups without a yes, Neo4j writes, running target code. The plan (`evidence/auto-plan.json`, finalized as `auto-plan-final.json` after fetching) shows every choice with the files that triggered it.

### Threat model

Every run gets a threat model. `threat_seed.py` writes a deterministic, cited **draft** (`system/threat-model.md`, marked draft) from the graph: injection paths to unsafe sinks, endpoints with no authentication evidence, security switches an env var can turn off, plaintext or identity-header trust between services, unauthenticated message channels, requeue-forever consumers, tables written by several services, cloud misconfigurations (IaC + CSPM), confirmed-suspicious supply-chain findings, documentation drift, and LLM use. Each threat has STRIDE, CWE/OWASP, likelihood, impact, cited mitigations, gaps and controls, and is mirrored into the graph as a `threat` node. The `threat-modeler` agent then confirms, re-rates or removes each one and adds what rules cannot see. Without agents (CI) the draft stays, labelled. A refined model is never overwritten.

### Call graphs

`system/call-graphs.md`, `graph/callgraph.json` and `diagrams/callgraph-*.mmd` hold three levels, each edge cited with the weakest confidence along the way: **function → function** (resolved calls, HTTP calls mapped to the handler behind the endpoint, subprocess/FFI spawns, publish → consume over a topic), **file → file** (the same rolled up, plus imports) and **repo → repo** (HTTP/gRPC, topics, shared tables, subprocess, internal package dependencies, external systems). Query them with `graph_query.py callgraph repo|file|function [--repo R] [--focus X]`, the `ckb_callgraph` MCP tool, or the viewer's Level selector.

### Documentation, diagrams, images and notes

Supplied context (`--context`, doc folders auto mode finds, or `context_paths`) is converted into citable files; images and scanned PDFs are read by the `context-reader` agent. `doc_claims.py` then extracts what the documents *claim* (components, connections, mTLS/TLS, encryption at rest, authentication, internal-only exposure), matches each claim to repos, endpoints and cloud resources, and writes `system/documented-vs-observed.md` with a verdict per claim (`consistent`, `drift`, `not verifiable statically`) citing both the document line and the code or IaC. Drift becomes graph nodes and draft threats. Documents never overrule code.

### Context from the repos themselves

Docstrings and leading comments become function and class summaries at extraction time. `repo_context.py` adds README summaries, ADRs, CODEOWNERS owners (as tags), OpenAPI/AsyncAPI operation summaries on endpoints and topics, and docker-compose service metadata. All of it is untrusted text: lines that address AI agents are never used in a summary, and secrets are redacted.

### Knowledge graph

`graph_build.py` extracts a graph from code. Python uses the stdlib `ast`. Other languages use tree-sitter if `tree-sitter-language-pack` (or `tree_sitter_languages`) is already installed, and fall back to regex otherwise; ckb never installs it. The build then links imports, calls, cross-repo HTTP calls, queues, shared tables, and subprocess→binary edges. Supply-chain findings, CSPM findings, IaC cloud resources, and agent-proposed threats and drift are attached. Agent proposals are merged only after their citation and exact quote verify.

| Output | Purpose |
| --- | --- |
| `graph/graph.json` | citable source of truth (stable IDs `kind:repo:path:qualname`; each node and edge has a citation, extractor, confidence, and label) |
| `graph/graph.sqlite` | fast queries: recursive SQL, FTS search |
| `graph/index.html` | self-contained interactive viewer: search, filters, expand, path finder, impact, taint overlay, threat and finding overlays, tours. No network; strict CSP |
| `graph_serve.py` | live viewer at `http://127.0.0.1:<random>/?token=…`. Read-only, reloads when the graph is rebuilt |
| `ckb-graph` MCP server | tools `ckb_search`, `ckb_explain`, `ckb_neighbors`, `ckb_path`, `ckb_impact`, `ckb_taint`, `ckb_tour`, `ckb_status`, available to Claude Code, Cursor, or any MCP client |
| Exports | `ua` (Understand-Anything-compatible JSON), `cypher`/`csv` (Neo4j), `graphml` |
| Neo4j (optional) | if you already run Neo4j, `graph_neo4j.py push --yes` loads it after you confirm, and `/ckb:ask` can use read-only Cypher |

Example queries:
```text
graph_query.py --out .ckb impact orders/app/db.py
graph_query.py --out .ckb taint
graph_query.py --out .ckb path gateway/src/server.js fulfillment/internal/queue/consumer.go
```

### Settings (optional)

Copy [`examples/code-knowledge-builder.local.md`](examples/code-knowledge-builder.local.md) to `<project>/.claude/code-knowledge-builder.local.md`. It sets `output_dir`, `scratch_dir`, `exclude_paths`, `token_env`, `gitlab_base_url`, `context_paths`, `advisory_lookup`, `graph_autoupdate`, `ado_token_env`, `auto_max_repos`, `include_forks`, and the Neo4j env-var names.

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
  graph/                      # graph.json, graph.sqlite, index.html, exports, proposals/, rejected.jsonl
  answers/                    # /ckb:ask answers
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
| **Graph servers** | The MCP server (stdio) and the viewer server (127.0.0.1, random port, random token, GET only, Host check, CSP) are read-only. The viewer HTML renders target strings with `textContent` only. Neo4j writes need your explicit confirmation, and Neo4j queries refuse write clauses. |
| **Network** | None during analysis, except cloning the sources you list. Advisory lookups (OSV.dev, Snyk API) are opt-in. URLs inside documents are never fetched. |
| **Context files** | Office files are read in memory as XML (macros and embedded objects are never run), with size and compression-ratio limits. XML with DOCTYPE or ENTITY declarations is refused. Secret-looking values are redacted in converted text. Supplied IaC folders are registered so the guard blocks `terraform apply` and similar commands against them. |

## Components

| Type | Items |
| --- | --- |
| Skills (knowledge) | repo-inventory, code-analysis, cross-repo-flow-mapping, architecture-docs, outputs-and-conditions, threat-modeling, security-context, supply-chain-audit, context-ingest, knowledge-graph |
| Skills (commands) | analyze, threat-model, context, supply-chain, full, update, auto, graph, ask, impact, tour |
| Agents | repo-analyzer (parallel, one per repo), supply-chain-auditor (parallel, one per repo), flow-tracer, threat-modeler (refines the draft), citation-verifier, graph-curator, context-reader (images, scanned PDFs) |
| Hooks | PreToolUse Bash guard, PostToolUse graph-proposal check, opt-in graph auto-update after `git commit`, PreToolUse write guard, PostToolUse citation, Mermaid, link, and redaction check |
| Scripts | `auto_plan.py`, `env_probe.py`, `enumerate_sources.py`, `threat_seed.py`, `callgraph.py`, `doc_claims.py`, `repo_context.py`, `graph_extract.py`, `graph_build.py`, `graph_query.py`, `graph_merge.py`, `graph_security.py`, `graph_check.py`, `graph_viewer.py`, `graph_serve.py`, `graph_mcp.py`, `graph_export.py`, `graph_neo4j.py`, `fetch_source.py`, `ingest_context.py`, `inventory.py` (incl. cloud resources), `scan_supply_chain.py` (36 checks incl. multi-cloud IaC; OSV/Snyk), `verify_citations.py`, `check_outputs.py`, `hash_index.py`, `guard.py` |
| Shared | `shared/safety-contract.md`, `shared/evidence-model.md`, `shared/pipeline.md`, `shared/templates/*.md` |

## Development and tests

The command skills don't pre-approve `python3`. Claude Code asks the first time a ckb script runs. To skip the prompts, allow just the plugin's scripts in your settings, for example `"Bash(python3 /path/to/ckb/scripts/*)"`.

```bash
python3 tests/test_guard.py                 # guard hook: deny and allow cases, write guard, post check
python3 tests/test_auto.py                  # auto mode: env probe, main/master snapshots, ADO/GitHub/GitLab enumeration, workspace plans, threat draft, call graphs, doc drift, repo context
python3 tests/test_graph.py                 # graph: extraction, linking, IDs, merge, impact/taint/path, SQL guard, viewer, server, MCP, auto mode
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
- **Threat draft and doc checks are rule-based.** Exposure is inferred (an endpoint nobody else calls is a "public candidate"), authentication is looked for on the route and handler chain only (global middleware and gateway auth are invisible), and documentation claims are recognized by patterns, so unusual wording is missed. The threat-modeler agent exists to review and extend the draft.
- **Azure DevOps, GitHub and GitLab enumeration** is tested against a mock server and the clone/auth paths against local repos; it has not been run against live ADO/GitHub/GitLab accounts. `az` and PAT auth need your own login or token. Org-wide runs are capped (`auto_max_repos`) and shallow.
- **Snapshots** read main/master as committed: uncommitted work, submodules and LFS objects are not included (use `--working-tree` to analyze the folder as it is).
- **Knowledge graph precision:** regex-extracted edges (non-Python without tree-sitter) are medium or low confidence. Dynamic dispatch, reflection, and URLs or topics built at runtime may be missed or marked `[inferred]`. Taint paths are *candidates* over call edges, not full data-flow analysis. The viewer starts from an overview and caps at about 5k visible nodes.
- **Mermaid checks** are structural (types, balance, no interactivity), not a full renderer.

## Credits and licenses

MIT licensed (see [LICENSE](LICENSE)). Third-party notices are in [NOTICE](NOTICE).

- **[OthmanAdi/codebase-knowledge-builder](https://github.com/OthmanAdi/codebase-knowledge-builder)** (MIT): the trust-and-safety contract, the observed/inferred/unknown evidence labels, the provenance block, the Mermaid hygiene rules, and the recon and deep-dive method were adapted (rewritten and extended) into `shared/` and the inventory and code-analysis skills.
- **[ardennguyen/Codebase-Knowledge-Builder](https://github.com/ardennguyen/Codebase-Knowledge-Builder)** (CC BY-NC-SA 4.0): no code or text was used. Its ideas of quote-verified facts, deterministic doc checks, and hash-based incremental refresh inspired independent implementations (`verify_citations.py`, `check_outputs.py`, `hash_index.py`).
- **New in ckb:** multi-repo and cross-repo flow tracing, polyglot edges, outputs and conditions, the threat model, scanner `context.md`, the supply-chain and prompt-injection audit, the enforced hooks, parallel agents, the citation verifier, safe remote acquisition (GitHub, GitLab, CI), and incremental update.
