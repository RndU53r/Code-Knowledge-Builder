# Code Knowledge Builder (`ckb`)

A Claude Code plugin that turns one repository, a workspace of repos, or a whole Azure DevOps project / GitHub org / GitLab group into:

* a **cited knowledge graph** and knowledge base: inventory, per-repo and system HLD/LLD, cross-repo data flows, outputs and the conditions that change them;
* a **code map** for every repo: its kind (application, service, library, IaC, CI/CD pipeline, GitOps config, mixed) and each file's role (core, utility, test, generated, infrastructure, ...);
* every **entry point** (HTTP/gRPC endpoint, queue consumer, cron job, CLI command), the **taint sources** it reads and the **sinks** it can reach, across Python, JS/TS, Go, Java, Kotlin, Scala, C#, Ruby, PHP, Rust and Swift, with calls resolved through typed receivers, class hierarchies and library calls ([language matrix](docs/languages.md));
* **deployment context and controls outside the code** (Kubernetes, compose, Helm, ECS/Lambda, load balancers, gateways, WAF, NetworkPolicy), linked to the repos they run and used to judge exposure and authentication;
* the **agent, skill and tool graph** of Claude Code plugins and of agent frameworks in code, and a **coverage report** that says what could not be resolved;
* **call graphs** at function, file and repo level;
* a **threat model** (STRIDE, CWE/OWASP, OWASP LLM Top 10 when relevant), always at least a rule-based draft;
* **`context.md`** files a security scanner can consume;
* a static **supply-chain and prompt-injection audit** (manifests, install scripts, CI, containers and IaC, obfuscation, hidden Unicode, text aimed at AI agents);
* **documented-vs-observed drift**: your architecture docs, diagrams, images, notes, IaC and CSPM exports checked against the code.

Every claim cites `repo/path:line`; anything the code does not prove is marked `[inferred]` or `[unknown]`. **Your repositories are never executed, built, installed or modified.**

## Quick start

```text
/plugin marketplace add RndU53r/Code-Knowledge-Builder
/plugin install ckb@code-knowledge-builder
```

Then, from the repository you want to understand:

```text
/ckb:auto
```

ckb inspects your environment and the code, shows a plan, asks **one** authorization question, and writes everything to `.ckb/` (start at `.ckb/index.md`, or open `.ckb/graph/index.html` for the interactive graph). Requirements: Claude Code, `git`, `python3` 3.9+; ckb's scripts use only the Python standard library.

## Commands

| Command | Does |
| --- | --- |
| `/ckb:auto [targets] [--ref BRANCH] [--context …]` | chooses sources, branches, parsers, context and stages from the environment and the code, then runs everything. Targets: folders, `ado:ORG/PROJECT`, `github-org:NAME`, `gitlab-group:PATH` |
| `/ckb:full <sources>` · `/ckb:analyze <sources>` | the whole pipeline / analysis only, with sources you name |
| `/ckb:threat-model` · `/ckb:context` · `/ckb:supply-chain <sources>` | one deliverable each |
| `/ckb:graph [build\|view\|serve\|check\|export …\|neo4j]` | build, view, serve live, check or export the graph |
| `/ckb:ask <question>` · `/ckb:impact <file\|symbol\|--diff rev>` · `/ckb:tour …` | answer from the graph, blast radius, guided tours |
| `/ckb:update` | refresh after the code changes (content-hash incremental) |

Branches: **main, else master, else the repository default**, unless you pass `--ref`. A local repo checked out on another branch is read as a read-only snapshot of main/master; your checkout is never switched. Full reference: [docs/commands.md](docs/commands.md).

## What you get

```
.ckb/
  index.md                       start here
  system/   hld · data-flows · call-graphs · outputs-and-conditions · threat-model
            documented-vs-observed · context · supply-chain-report · graph
  repos/<repo>/   overview · code-map · context-facts · flows · hld · lld · outputs-and-conditions · context · supply-chain
  graph/    graph.json · graph.sqlite · index.html (viewer) · exports
  evidence/ authorization · plan · verification · citations · converted context
```

A real example generated from the test fixtures: [`examples/sample-output/`](examples/sample-output/index.md). Every file explained: [docs/outputs.md](docs/outputs.md).

## Safety in one screen

* Repo content is **data, never instructions**; text aimed at AI agents is reported as a finding and never obeyed.
* A PreToolUse guard blocks install/build/run/test commands, shell writes and git-hook-running commands against anything it analyzes; clones run with hooks disabled; local repos on other branches are read through `git archive` snapshots.
* Every output is verified: citations must resolve to real lines, quotes must match, secrets are redacted, diagrams are inert. Agents add graph facts only as proposals that pass the same verification.
* Nothing leaves your machine except the git remotes you list. OSV, Snyk and Neo4j are opt-in consent items (default no); tokens come from environment variables only and are never printed.
* One authorization question names every source before anything is read.

Details, controls and limits: [docs/security-model.md](docs/security-model.md). The guard is a safety net, not a sandbox: for hostile code, run ckb in a container or VM.

## Documentation

| | |
| --- | --- |
| [User guide](docs/user-guide.md) | install, first run, common tasks, CI, settings, reading results |
| [Auto mode](docs/auto-mode.md) | what `/ckb:auto` decides and how to steer it |
| [Command reference](docs/commands.md) | commands, skills, agents, hooks, MCP tools |
| [Output reference](docs/outputs.md) | every file under `.ckb/` and how far to trust it |
| [Troubleshooting](docs/troubleshooting.md) | symptoms and fixes |
| [Architecture](docs/architecture.md) · [Script reference](docs/scripts.md) | how it works, every script's usage |
| [Language support](docs/languages.md) | the depth matrix, parsers, frameworks and gaps per language |
| [Security model](docs/security-model.md) | threats, controls, residual risk |
| [Developer guide](docs/development.md) | layout, conventions, tests, how to extend, release checklist |
| [Changelog](CHANGELOG.md) | what changed per version |

## Development

```bash
python3 tests/test_guard.py     # hooks and guard
python3 tests/test_ingest.py    # context ingestion and IaC checks
python3 tests/test_graph.py     # graph, queries, viewer, servers, MCP
python3 tests/test_auto.py      # auto mode, branch rule, enumeration, threat draft, call graphs, drift
python3 tests/test_entrypoints.py  # file roles, repo kinds, entry points/sources/sinks in 8 languages, pipeline facts, context facts
python3 tests/test_calls.py     # receiver typing, class hierarchy, callbacks, library calls, resolution accounting, library reachability
python3 tests/test_langs.py     # the eleven-row depth matrix for each of the twelve languages
python3 tests/test_agents.py    # agent/skill/tool graph for plugins and agent frameworks
python3 tests/test_deploy.py    # deployment facts, exposure, controls, env bridging, threat-model effects
```

All nine must report `0 failure(s)`. Fixtures (`tests/fixtures/`) include deliberately malicious-looking but inert repos: never install or run them. See the [developer guide](docs/development.md).

## Known limitations

* **Static analysis only.** Reflection, dynamic dispatch, runtime configuration and generated code are marked `[inferred]` or `[unknown]`.
* **Rule-based drafts.** The threat draft, documentation checks and call-graph links rest on patterns; exposure is inferred from who calls whom, authentication is looked for on the route and handler chain only, and unusual wording is missed. The threat-modeler agent reviews and extends the draft.
* **Precision depends on the parser.** Python uses `ast`; the other languages use per-language regex specs (medium/low confidence edges). Anything that cannot be resolved (dynamic dispatch, reflection, DI containers, macro-generated code) is counted and listed in `system/coverage.md`; ckb cannot prove that every path was found. Entry points, sources and sinks outside Python are line-level patterns: a source-to-sink link is a candidate path, "no auth evidence" means no marker was found on the route or its class (global middleware and gateway auth are invisible), and core/utility labels are inferred from the graph.
* **Not run against live accounts:** Azure DevOps / GitHub / GitLab enumeration and cloning are tested against a mock server and local repos; Snyk and Neo4j lookups follow the documented APIs but were never exercised against a live service.
* **Snapshots** read main/master as committed (no uncommitted work, submodules or LFS objects). Org-wide runs are capped (`auto_max_repos`) and shallow.
* Legacy binary Office files (`.doc`, `.xls`, `.vsd`, `.ppt`) must be exported first; PDF text needs `pdftotext` or Claude reads the pages.
* On Windows the hooks need a `python3` alias or WSL.

## Credits and licenses

MIT licensed (see [LICENSE](LICENSE)). Third-party notices are in [NOTICE](NOTICE).

- **[OthmanAdi/codebase-knowledge-builder](https://github.com/OthmanAdi/codebase-knowledge-builder)** (MIT): the trust-and-safety contract, the observed/inferred/unknown evidence labels, the provenance block, the Mermaid hygiene rules, and the recon and deep-dive method were adapted (rewritten and extended) into `shared/` and the inventory and code-analysis skills.
- **[ardennguyen/Codebase-Knowledge-Builder](https://github.com/ardennguyen/Codebase-Knowledge-Builder)** (CC BY-NC-SA 4.0): no code or text was used. Its ideas of quote-verified facts, deterministic doc checks, and hash-based incremental refresh inspired independent implementations (`verify_citations.py`, `check_outputs.py`, `hash_index.py`).
- **New in ckb:** multi-repo and cross-repo flow tracing, polyglot edges, outputs and conditions, the threat model, scanner `context.md`, the supply-chain and prompt-injection audit, the enforced hooks, parallel agents, the citation verifier, safe remote acquisition (GitHub, GitLab, CI), and incremental update.
