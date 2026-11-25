# Changelog

Versions follow `plugin.json`. Newest first.

## 0.5.0

### Added
- **File roles** (`roles.py`): every file is labelled `core`, `utility`, `test`, `fixture`, `config`, `build`, `iac`, `pipeline`, `migration`, `docs`, `generated` or `tooling`. Path and content rules decide most roles; `core` vs `utility` comes from graph signals (entry point, reached from one, owns I/O, helper-style name, fan-in) and is always `[inferred]` with its signals listed. Written to `evidence/file-roles-<repo>.json`, `repos/<repo>/code-map.md` and as `role` attributes and `role:*` tags on graph file nodes.
- **Repo kinds**: every repo is classified as `application`, `service`, `library`, `iac`, `cicd-pipeline`, `gitops-config`, `docs`, `tooling`, `config` or `mixed` (primary plus secondary kinds), shown in the plan, the graph report, the code map and `context.md`. Pipelines and Terraform/Bicep/GitOps repos no longer produce empty application output.
- **Entry points for Java/Kotlin, C#, Ruby and PHP** (Spring, JAX-RS, ASP.NET controllers, minimal APIs and Azure Functions, Rails routes and Sinatra, Laravel and Symfony), plus deeper Python (Django `path()`, Flask `add_url_rule`, DRF routers, Celery, click/typer/argparse), JS/TS (any router receiver, `app.route()` chains, Nest, Next.js file routing, Hapi, cron, commander) and Go (chi/gin/echo/fiber, gorilla `.Methods`, Go 1.22 patterns, gRPC services, cobra, cron). New node kinds in use: `consumer`, `cron_job`, `cli_command`.
- **Taint sources** (`taint_source` nodes: `http_param`, `cli_arg`, `stdin`, `file_read`, `message_body`) in all supported languages, linked to their handlers with `flows_to`.
- **Many more sink classes**: `template`, `xss`, `path`, `redirect`, `nosql`, `ldap`, `xpath`, `xxe`, and the existing sql/command/ssrf/code/deserialization sinks for Java, C#, Ruby, PHP and Go. Python `execute(variable)` is now reported (low confidence, unknown verdict). Tests and generated files are not scanned for entry points or sinks.
- **CI/CD pipeline facts** (`pipeline_facts.py`) for GitHub Actions, Azure Pipelines, GitLab CI, Jenkins and CircleCI: triggers, fork reachability, runners, secrets and service connections (names only), third-party code and pinning, deploy steps and gates; findings PF01 to PF05 for what the supply-chain scanner does not cover.
- **Pipeline and IaC threats** in the draft threat model (`rule_pipeline`), a wider sink-to-CWE map, and class-level authentication evidence for Spring, ASP.NET, Rails, Laravel, Nest and Django.
- **`deploys` links** between pipeline, IaC or GitOps repos and the application repos they name, in the repo call graph.
- **Context facts** (`context_facts.py`): deterministic tables per repo (code map, entry points with auth evidence and exposure, sources, sinks with CWE and reachable entry points, known-safe patterns; or resources and pipelines for IaC and CI/CD repos) embedded verbatim in `context.md`; `check_outputs.py` check F1 proves the embedded block matches the generated one.
- `graph_query.py` ops `roles` and `entrypoints`, MCP tools `ckb_roles` and `ckb_entrypoints`, viewer file-role filter, `kind_hint` in the auto plan, and `tests/test_entrypoints.py` with fixtures for eight languages and four repo kinds.

### Changed
- The `taint` op starts from endpoints, consumers, cron jobs, CLI commands and sources and removes duplicate paths; results remain candidate paths, not proven dataflow.
- The supply-chain scanner recognizes HCL-style wildcard IAM actions (`Action = "*"`).

### Security
- Snapshots of local repos are stored in a per-user, owner-only cache and are never reused unless they are real directories owned by the current user with no group/world access (previously a predictable directory name in the shared temp dir).

### Documentation
- New documentation set under `docs/`: user guide, command reference, auto mode, output reference, architecture, script reference (generated from the scripts' usage text by `tests/make_script_docs.py`), security model, developer guide, troubleshooting. README slimmed to an overview with links. Sample output regenerated from a v0.4 end-to-end run.

## 0.4.0

### Added
- **Environment-aware auto mode**: `env_probe.py` (tools, logins, token variable names, CI, CPUs, disk) feeds a capabilities block and consent items in `auto_plan.py`; second pass `--from-registered`.
- **Sources**: local folder default; workspace of git repos; monorepo (services + `platform`); `ado:`, `github-org:`, `gitlab-group:` expansion via `enumerate_sources.py`. Branch rule main → master → default; local repos on another branch are read as a read-only `git archive` snapshot; Azure DevOps auth via `az` or PAT environment variable.
- **Always-on draft threat model** (`threat_seed.py`, extractor `rule`) refined by the threat-modeler agent; refined models are never overwritten; superseded draft threats are dropped from the graph.
- **Call graphs** at function, file and repo level (`callgraph.py`, `system/call-graphs.md`, `graph/callgraph.json`, `ckb_callgraph`, viewer Level selector).
- **Context both ways**: Excalidraw, Mermaid, PlantUML, Gliffy, email and RTF ingestion; `context-reader` agent for images and scanned PDFs; `doc_claims.py` (documented vs observed drift); `repo_context.py` (README, ADR, CODEOWNERS, OpenAPI/AsyncAPI, compose); docstring and comment summaries at extraction.
- `tests/test_auto.py` (100 checks), extra context fixtures, new eval cases.

### Security
- Azure DevOps detection decided on the parsed hostname (a crafted URL could previously have received an `az` token/PAT); https URLs with query/fragment refused.
- Proposal quotes never contain secret values; hostile identifiers neutralized in all generated markdown; hostile README paragraphs never used as summaries.

## 0.3.0

### Added
- **Cited code knowledge graph** (`graph.json` + `graph.sqlite`): stable IDs, extractor and confidence on every node and edge; Python `ast`, optional tree-sitter, regex fallback; linker for imports, calls, cross-repo HTTP, queues, tables and subprocess edges.
- Security layer (sinks, supply-chain and CSPM findings, IaC cloud resources, threats and drift via verified proposals).
- Queries: search, explain, neighbors, path, multi-hop impact, taint candidates, read-only SQL, optional Cypher. Interactive offline viewer and live local server; `ckb-graph` MCP server; exports (Understand-Anything JSON, Neo4j Cypher/CSV, GraphML); optional Neo4j push after confirmation.
- Commands `/ckb:auto`, `/ckb:graph`, `/ckb:ask`, `/ckb:impact`, `/ckb:tour`; `knowledge-graph` skill; `graph-curator` agent; incremental updates with summary carry-over (`[OUTDATED]`).

### Security
- `impact --diff` revisions validated and git run with `--end-of-options`.

## 0.2.0

### Added
- Context ingestion (`ingest_context.py`, `context-ingest` skill): Word, PowerPoint, PDF, draw.io, Visio, SVG, images, Security Hub, Prowler, ScoutSuite, Defender, GCP SCC, Checkov/SARIF, CSV exports; `[documented]` label and documented-vs-observed tables.
- Multi-cloud IaC checks (public storage, wildcard IAM, encryption/TLS off, open ingress) and cloud resource inventory.
- Advisory lookups: `advisory_lookup: off | osv | snyk | osv,snyk`; a `security.snyk.io` link for every dependency.

## 0.1.0

### Added
- First release: 8 knowledge skills, 6 `/ckb:*` commands, 5 agents, hooks (execution/write guard, citation/Mermaid/redaction checks), stdlib-only scripts (safe fetch, inventory, 33-check supply-chain scanner, citation verifier, output checker, incremental hash index), fixtures, evals, CI templates.
