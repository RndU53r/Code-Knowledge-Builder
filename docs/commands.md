# Command reference

All commands are slash commands of the `ckb` plugin. Each starts the same way (see [pipeline](../shared/pipeline.md)): parse sources → ask the **one** authorization question → register the sources → work → verify every output. `<out>` below is the output directory (default `<target>/.ckb`).

Sources: a local folder, a workspace folder of git repos, `https://`/`ssh://`/`git@` URLs, `github:org/repo`, `gitlab:group/repo`, `ado:ORG/PROJECT/REPO`. `--context <paths...>` adds documents, diagrams, images, notes, IaC or CSPM exports as supporting context.

## Pipelines

| Command | Arguments | What it does | Main outputs |
| --- | --- | --- | --- |
| `/ckb:auto` | `[targets...] [--ref BRANCH] [--context paths...]` | Probes the environment and code, chooses everything, runs the whole pipeline. Targets may also be `ado:ORG/PROJECT`, `github-org:NAME`, `gitlab-group:PATH`. See [Auto mode](auto-mode.md) | everything below |
| `/ckb:full` | `<sources...> [--context ...]` | The whole pipeline with the sources you name (no planning step) | `index.md`, `system/*`, `repos/*`, `graph/*`, `evidence/*` |
| `/ckb:analyze` | `<sources...> [--context ...]` | Inventory, per-repo flows/HLD/LLD, cross-repo data flows, outputs and conditions, knowledge graph | `repos/<repo>/*`, `system/hld.md`, `system/data-flows.md`, `system/outputs-and-conditions.md` |
| `/ckb:threat-model` | `[sources...] [--context ...]` | STRIDE threat model (runs the analysis first if needed); a rule-based draft refined by the threat-modeler agent | `system/threat-model.md` |
| `/ckb:context` | `[sources...]` | Scanner-ready `context.md` per repo and for the system (nine fixed sections + front matter) | `repos/<repo>/context.md`, `system/context.md` |
| `/ckb:supply-chain` | `<sources...>` | Static supply-chain and prompt-injection audit; needs no prior analysis | `repos/<repo>/supply-chain.md`, `system/supply-chain-report.md` |
| `/ckb:update` | `[output_dir]` | Re-fetch sources, diff content hashes, re-run only stale stages, re-verify everything | refreshed outputs |

## Graph and queries

| Command | Arguments | What it does |
| --- | --- | --- |
| `/ckb:graph` | `[build\|view\|serve\|check\|export ua\|cypher\|csv\|graphml\|neo4j] [--incremental]` | `build` builds the graph, enrichment, call graphs and the viewer; `view` writes `graph/index.html` (works offline); `serve` starts a live, read-only, token-protected page on `127.0.0.1`; `check` validates schema and citations; `export` writes other formats; `neo4j` checks connectivity and pushes **only after you confirm** |
| `/ckb:ask` | `<question>` | Turns the question into graph queries (or Cypher if Neo4j is configured), opens the cited lines to confirm, answers with citations. Saves to `answers/<slug>.md` for long answers |
| `/ckb:impact` | `<file\|symbol\|node-id ...>` or `--diff <rev>` | Multi-hop blast radius across repos: affected callers, endpoints, consumers, readers, plus unsafe sinks, threats and findings in scope. Writes `system/impact-<slug>.md` |
| `/ckb:tour` | `list`, `<name>`, or `create [audience]` | Lists, walks, or creates guided tours (ordered steps over real nodes with notes and citations) |

## Knowledge skills (they also trigger on ordinary requests)

Ask in plain words and the matching skill loads: "how do these services talk to each other?" (cross-repo-flow-mapping), "is this repo safe to npm install?" (supply-chain-audit), "document the architecture" (architecture-docs), "what does this endpoint return when…" (outputs-and-conditions), "who calls get_order?" (knowledge-graph), and so on.

| Skill | Produces |
| --- | --- |
| `repo-inventory` | `repos/<repo>/overview.md`: languages, frameworks, entry points, dependencies, infra |
| `code-analysis` | `repos/<repo>/flows.md`: inbound, outbound, shared state, call graph, polyglot edges |
| `cross-repo-flow-mapping` | `system/data-flows.md`: matched producers and consumers across repos |
| `architecture-docs` | HLD (system and per repo) and LLD with Mermaid diagrams |
| `outputs-and-conditions` | what each output is, how it is produced, and every condition (`condition \| effect \| default \| source`) |
| `threat-modeling` | `system/threat-model.md` (draft first, then refined) |
| `security-context` | `context.md` files for scanners |
| `supply-chain-audit` | ranked, cited findings and a dependency inventory |
| `context-ingest` | converts supplied docs/diagrams/IaC/CSPM into citable context and records documented-vs-observed drift |
| `knowledge-graph` | builds and queries the graph; call graphs; proposals format |

## Agents (dispatched by the commands)

`repo-analyzer` and `supply-chain-auditor` (one per repo, in parallel), `flow-tracer`, `threat-modeler` (refines the draft), `graph-curator` (summaries and tours), `context-reader` (images and scanned PDFs), `citation-verifier` (checks that citations exist and support the claims).

## Hooks (always on when the plugin is enabled)

* **PreToolUse (Bash)**: blocks install/build/run/test commands, git commands that run hooks, and shell writes against any registered target.
* **PreToolUse (Write/Edit)**: blocks writes into a registered target outside its `.ckb/`.
* **PostToolUse (Write/Edit)**: verifies citations, Mermaid, links and redaction in every `.ckb/*.md` written, and verifies graph proposal files.
* **PostToolUse (Bash), opt-in** (`graph_autoupdate: on`): refreshes the structural graph after `git commit`.

## MCP server

`ckb-graph` (stdio, read-only) is registered by the plugin. Tools: `ckb_status`, `ckb_search`, `ckb_explain`, `ckb_neighbors`, `ckb_path`, `ckb_impact`, `ckb_taint`, `ckb_callgraph`, `ckb_tour`. The graph location comes from `CKB_OUT`, then `output_dir` in settings, then `./.ckb`; every tool also accepts `out`.

## Command-line scripts

Every step is also a plain script you can run yourself: see the [script reference](scripts.md).
