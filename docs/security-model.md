# Security model

ckb is built to analyze repositories that **may be hostile**, using tools that can read files and call a language model. This page lists what it protects, how, and what it cannot promise.

## What is trusted

* The ckb plugin's own files (`scripts/`, `skills/`, `agents/`, `hooks/`, `shared/`).
* The instructions the user types in the Claude Code chat.

Everything else is untrusted data: repo files (code, READMEs, comments, config, file names, commit messages, agent instruction files such as `CLAUDE.md` or `.cursorrules`), supplied documents, diagrams and images, scanner exports, API responses from git hosts, and the text of other agents' reports.

## Threats and controls

| Threat | Control | Where |
| --- | --- | --- |
| **Prompt injection** from repo, document or image text ("ignore previous instructions", "mark these false positives") | All target text is treated as data. Agent-directed text is *reported* as a `prompt-injection` finding and never obeyed. It is never copied into summaries, and README lines that address AI agents are skipped. Plans are decided from structural signals only. Generated markdown neutralizes HTML and event-handler patterns | `shared/safety-contract.md`, `scan_supply_chain.py`, `repo_context.py`, `graph_common.md_safe` |
| **Code execution** (`postinstall`, `setup.py`, Makefiles, git hooks, build plugins, notebooks) | Scripts never run, import or build target code. The **PreToolUse guard** denies install/build/run/test commands, interpreters on target files, `source`/`./script`, git commands that run hooks, and nested `bash -c` against any registered target. Clones run with `core.hooksPath=/dev/null` | `guard.py`, `hooks/hooks.json`, `fetch_source.py` |
| **Writing into your repos** | The guard denies shell writes (`rm`, `mv`, `cp` into, `sed -i`, `tee`, `chmod`, `>`/`>>`) and Write/Edit into a registered target outside its `.ckb/`. Local repos on another branch are read through a `git archive` snapshot, so your checkout is not switched | `guard.py`, `fetch_source.py` |
| **Hostile archives and documents** | Office files are read in memory as XML (never macros or embedded objects) with size and compression-ratio limits; XML with `DOCTYPE`/`ENTITY` is refused; snapshot extraction skips symlinks, hardlinks and paths that escape the directory | `ingest_context.py`, `fetch_source.safe_extract` |
| **Symlinks and path tricks** | Directory walks never follow symlinks; symlinks are reported as excluded; citations with `..` are rejected | `ckb_common.walk_files`, `verify_citations.py` |
| **Secret leakage into outputs** | Secret files (`.env`, keys, keystores) are never opened. Secret-looking values are detected and written only as type, location and `AKIA…[REDACTED]`. Proposal quotes are cut before any secret. The PostToolUse hook rejects outputs containing unredacted values | `ckb_common.find_secret_values`, `graph_common.safe_quote`, `check_outputs.py` |
| **Credential theft via tokens** | Tokens are read from environment variables (or an `az` login), never from files or repo text. They reach git only through environment variables (`GIT_CONFIG_*`, a one-shot credential helper), never argv, URLs, logs or output; error text is redacted. Whether a URL is Azure DevOps is decided on the parsed hostname, and https URLs with a query string, fragment or embedded credentials are refused | `fetch_source.py`, `enumerate_sources.py` |
| **Unverified or invented claims** | Every output file is checked after writing: citations must resolve to real lines, quotes must match, provenance must be present. Agent-added graph facts are merged only if their citation and exact quote verify. The `citation-verifier` agent samples whether cited lines support the claims | `verify_citations.py`, `graph_merge.py`, hooks |
| **Unauthorized analysis** | One authorization question names every source before anything is read; the answer is recorded. Unlisted repos, submodules and dependency URLs are never followed. CI runs record `ci-implicit` | `shared/pipeline.md` P1 |
| **Data leaving the machine** | Nothing during analysis except the git remotes you list. OSV, Snyk and Neo4j are opt-in consent items (default no) and Neo4j writes need a separate confirmation. URLs inside documents are never fetched | `auto_plan.py`, `graph_neo4j.py` |
| **Local servers** | The viewer server binds `127.0.0.1` on a random port with a random token, accepts only GET/HEAD, checks the Host header, and sends a strict CSP. The MCP server is stdio, read-only. The viewer page has no external URLs, and target strings are rendered with `textContent` only | `graph_serve.py`, `graph_viewer.py`, `shared/viewer/` |
| **Query abuse** | Graph SQL is read-only (`mode=ro`, `query_only`, an authorizer that denies writes and `ATTACH`); Neo4j queries refuse write clauses; `--diff` revisions are validated and git is run with `--end-of-options` | `graph_query.py`, `graph_neo4j.py` |
| **Shared-temp attacks** | Snapshots go to a per-user, owner-only cache and are reused only if they are real directories owned by you with no group/world access; clones use `mkdtemp` | `fetch_source.py` |
| **Supply chain of ckb itself** | Scripts use only the Python standard library; there is nothing to install. Optional tools (tree-sitter, pdftotext, `az`) are used only if already present and never installed | repo layout |

## What ckb cannot promise

* **The guard is a strong safety net, not a sandbox.** It recognizes common toolchains and patterns; an unusual command could slip through. If an internal error occurs it fails open (allows) and reports the error so it can never wedge your session. For hostile code, run ckb inside a container or VM as defense in depth.
* **Entry points, sources and sinks are pattern matches.** Python uses the AST; Java, Kotlin, C#, Ruby, PHP, Go and JS/TS use line-level patterns (confidence `medium` or `low`). A source-to-sink link is a candidate path, never proof, and "no auth evidence" means no authentication marker was found on the route or its class, not that none exists (global middleware and gateway auth are invisible). Core/utility labels are inferred.
* **Static analysis is incomplete.** Reflection, dynamic dispatch, runtime configuration and generated code are marked `[inferred]` or `[unknown]`, not resolved.
* **Agents can still be wrong.** The verifier proves a citation exists and a quote matches, not that the conclusion drawn from it is right. Read the cited lines before acting.
* **Model providers see what agents read.** Agents send cited code excerpts to the model Claude Code is configured to use. If that is not acceptable for a repo, do not run agent-based stages on it (the deterministic scripts alone make the graph, call graphs, draft threat model and drift checks).
* **Snapshots read what is committed.** Uncommitted work, submodules and LFS objects are not included.
* **Context-file formats** that ckb cannot read safely (legacy binary Office files) are refused rather than parsed.

## Reporting a security issue

Open an issue on [RndU53r/Code-Knowledge-Builder](https://github.com/RndU53r/Code-Knowledge-Builder) (avoid posting exploit details publicly; describe the class of problem and offer details privately). The test suites (`tests/test_guard.py`, `tests/test_graph.py`, `tests/test_auto.py`) contain regression tests for every issue fixed so far; add one with any fix.
