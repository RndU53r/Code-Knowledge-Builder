# ckb pipeline: shared orchestration steps

Every `/ckb:*` command uses these steps. Follow `shared/safety-contract.md` throughout.

## Auto mode

`/ckb:auto`, or `--auto` on any command, runs `scripts/auto_plan.py` first. It probes the environment (`env_probe.py`) and the code, expands `ado:ORG/PROJECT`, `github-org:NAME` and `gitlab-group:PATH` specs (`enumerate_sources.py`), and writes `evidence/auto-plan.json`. Every step below takes its choices (sources and branches, context, stages, parsers, parallelism, graph caps) from that file instead of asking. Branch rule: main, else master, else the repo default, unless a branch is given; a local repo on another branch is read as a read-only snapshot. After fetching, `auto_plan.py --out <out> --from-registered` finalizes the plan. Authorization, off-machine lookups (Snyk, OSV, Neo4j), Neo4j writes, and executing target code are never automated: consent items go into the one authorization question.

## P0. Settings

If `.claude/code-knowledge-builder.local.md` exists in the current project, read its YAML front matter. All fields are optional:

```yaml
output_dir: ./.ckb            # default: <first target>/.ckb, or ./.ckb when the targets are remote
scratch_dir: /tmp/ckb         # parent dir for remote clones
exclude_paths: ["docs/legacy/**"]
token_env: GITHUB_TOKEN       # env var holding a token for private repos (never printed)
gitlab_base_url: https://gitlab.example.com
advisory_lookup: off          # off | osv | snyk | osv,snyk (sends package names and versions off-machine)
snyk_token_env: SNYK_TOKEN    # env vars for Snyk REST API lookups (values never printed)
snyk_org_env: SNYK_ORG_ID
context_paths: [./docs/architecture, ./cspm/prowler-output.json]   # extra context, always ingested
graph_autoupdate: off         # on: structural graph refresh after git commit (PostToolUse hook)
neo4j_uri_env: NEO4J_URI      # optional Neo4j (only if you already run it); names of env vars, never values
neo4j_user_env: NEO4J_USER
neo4j_password_env: NEO4J_PASSWORD
```

When the user names an output directory in their request, it wins.

## P1. Sources and authorization

1. Parse the sources from the arguments: local paths, `https://`/`ssh://`/`git@` URLs, `github:org/repo`, `gitlab:group/repo`. Treat `.` as the current directory. If there are none and the current directory is a repo, propose it. Everything after `--context` (plus `context_paths` from settings) is **context**, not a code source: architecture docs, diagrams, IaC folders, and CSPM or scanner exports.
2. **Ask before analyzing.** List every source and context path, then ask the user to confirm they own each one or are authorized to audit it, in one question (AskUserQuestion when available). Don't proceed for any source that isn't confirmed. Exception: a non-interactive CI run (env `CI=true`) records `ci-implicit` and never pauses for input. This is the only definition of the CI rule, and the commands refer to it.
3. Write `<out>/evidence/authorization.md`: one row per source with the confirmation wording, the timestamp, and who confirmed it ("user in chat" or "ci-implicit").

## P2. Acquire and register

For each source:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/fetch_source.py" --out <out> [--key <name>] \
  [--scratch <scratch_dir>] [--token-env <VAR>] [--gitlab-base <url>] [--ref <branch>] <source>
```

This clones remote sources safely (hooks off, depth 1, no submodules, no LFS) and registers every source in `<out>/evidence/targets.json` and the user registry. Registration is what lets the guard hook block execution in the target and the verifier resolve citations. Use the printed `key` as the repo key in all citations. For a monorepo with several services, register each service directory separately with `--key <service>` so citations and per-repo docs line up with services. If you also register the monorepo root (for IaC, contracts, CI), add `--exclude '<service-dir>/**'` for each service so its code isn't indexed twice. The graph build, the scanner's graph merge, and the hash index all honour these excludes.

### P2b. Context

When there are context paths, ingest them with the `context-ingest` skill:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/ingest_context.py" --out <out> --key ctx-<name> <paths...>
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan_supply_chain.py" --root <out>/evidence/context/ctx-<name> --key ctx-<name> \
  --json-out <out>/evidence/sc-ctx-<name>.json
```

Handle any `needs_reading` items (images, scanned PDFs) with the Read tool as the skill describes. List the `ctx-*` keys in every agent prompt below so each stage can use them.

### P2c. Structural knowledge graph

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_build.py" --out <out> --extract --enrich
```

Run this after registration and context ingestion, before the agents, so every agent can navigate with `graph_query.py` (see the `knowledge-graph` skill). `--enrich` adds, in dependency order: docstring/README/ADR/OpenAPI/CODEOWNERS context from the repos (`repo_context.py`), documentation claims checked against the code with drift (`doc_claims.py`, writes `system/documented-vs-observed.md`), CI/CD pipeline facts (`pipeline_facts.py`: triggers, runners, secrets, third-party code, deploy gates), the **agent, skill and tool graph** (`agent_graph.py`: Claude Code plugins and agent frameworks; `system/agents.md`), **deployment facts** (`deploy_facts.py`: exposure, injected config, identities and controls outside the code; workloads linked to the repos they run), a **coverage report** (`coverage_report.py`: call resolution, unreachable functions, dynamic-dispatch hotspots; `system/coverage.md`), and a deterministic **draft threat model** (`threat_seed.py`, writes `system/threat-model.md` with a draft marker: attack paths, deployment context, library reachability, agent threats, coverage section), then the per-repo **context facts** (`context_facts.py`: entry points, taint sources, sinks, resources or pipelines; `repos/<repo>/context-facts.md`). The build itself assigns every file a **role** and every repo a **kind** (`roles.py`: `repos/<repo>/code-map.md`, `evidence/file-roles-<repo>.json`) and extracts endpoints, consumers, cron jobs, CLI commands, taint sources and sinks for Python, JS/TS, Go, Java/Kotlin, C#, Ruby and PHP. It also writes the function, file and repo **call graphs** (`system/call-graphs.md`, `graph/callgraph.json`). In auto mode, use the backend and caps from `evidence/auto-plan.json`. For images and scanned PDFs (`needs_reading`), dispatch `ckb:context-reader` before this step.

## P3. Dispatch agents

- **Per-repo stages** run in parallel. Send one Agent call per repo in the same message:
  - `ckb:repo-analyzer` for inventory, code analysis, per-repo HLD/LLD/flows, and outputs-and-conditions.
  - `ckb:supply-chain-auditor` for the supply-chain audit.
- **System stages** run after every per-repo stage has finished: `ckb:flow-tracer` (`system/data-flows.md`, `system/hld.md`, `system/outputs-and-conditions.md`), then the system supply-chain report (if any audit ran), then `ckb:threat-modeler`, then the context files (`security-context` skill).
- **Verification:** after each stage, run `ckb:citation-verifier` on the files that stage wrote. Hand failures back to the agent that wrote them (SendMessage to it when possible, otherwise a fresh agent with the error list). Allow at most two fix rounds, then record the remaining failures in `evidence/verification.md` and report them.

- **Draft threat model:** `system/threat-model.md` already exists as a rule-based draft (it carries `<!-- ckb:threat-seed -->`). The `threat-modeler` agent refines it (confirms, re-rates, or removes each threat, adds what the rules cannot see) and removes the marker. If the pipeline runs without agents (CI), the draft stays and is labelled as such. `threat_seed.py` never overwrites a refined model: it writes `threat-model.draft.md` instead.
- **Graph merge (P3g):** after each semantic stage, run `graph_build.py --out <out>` (it merges supply-chain JSON, CSPM, and verified agent proposals), then `graph_check.py --out <out> --report`. Send rejected proposal lines (`graph/rejected.jsonl`) back to the agent that wrote them, at most two rounds, the same rule as for citations. After the threat model, dispatch `ckb:graph-curator` for summaries and tours.

Give each agent a prompt with: `<out>`, the repo key(s) and roots, the `ctx-*` keys and their manifest paths, the advisory setting, the stage to run, the template to use, and "follow ${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md".

## P4. Finish

1. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/verify_citations.py" --out <out> --report <out>`
2. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/check_outputs.py" <out>`
3. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/hash_index.py" snapshot --out <out>`
   - `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/graph_build.py" --out <out>`, then `graph_check.py --out <out> --report` (0 errors), `graph_viewer.py --out <out>`, and `graph_export.py --out <out> ua`
4. Write or refresh `<out>/index.md` from `shared/templates/index.md`, and `<out>/evidence/citations.md` (every citation used, grouped by repo and file).
5. Tell the user: where the outputs are, the top findings (severity, one line each, with citation), verification status, and anything left as `[unknown]` that matters.
