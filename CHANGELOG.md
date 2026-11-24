# Changelog

Versions follow `plugin.json`. Newest first.

## Unreleased

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
