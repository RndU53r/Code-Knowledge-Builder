# Changelog

Versions follow `plugin.json`. Newest first.

## 0.7.0

### Added
- **C, C++, Dart/Flutter, Perl and ABAP** at the same depth as the twelve languages of 0.6.0 (declarations, imports, calls through typed receivers and the class hierarchy, library calls, entry points, sources, sinks, authentication evidence, roles, coverage accounting), proven by the same eleven-row matrix plus framework-variant fixtures. [Language matrix](docs/languages.md).
  - C: civetweb, libevent, mongoose, libmicrohttpd, nginx module handlers, signal handlers, getopt; function-pointer tables and callbacks as `references`; `memory` (unbounded copy/format), `format` and `tls` sink types.
  - C++: classes/templates, `Class::method` definitions matched to the header, `override`, typed members (pointers, references, smart pointers) including those declared in the same-stem header; Pistache, cpp-httplib, Crow, Drogon, oatpp, gRPC services.
  - Dart/Flutter: `package:` imports via `pubspec.yaml`, Shelf/`shelf_router`, Dart Frog, Serverpod, Flutter named routes and `GoRoute`, `MethodChannel` platform channels as shared nodes.
  - Perl: packages, `use parent`/`base`/Mojo::Base inheritance, typed receivers from `Class->new`, Mojolicious (controller routes and Lite), Dancer2, Catalyst, PSGI, CGI; DBI/LWP/Storable/YAML sinks.
  - ABAP: class definitions/implementations, interfaces, `PERFORM`, `CALL FUNCTION` (RFC and SAP standard objects as library packages), REST routers, ICF handlers, OData, function groups, reports; `AUTHORITY-CHECK` counts as authentication evidence.
- New `scripts/graph_patterns_native.py` holds the entry points, sources and sink rules of these languages.
- Linker: methods defined in a different file from their class (C++ `.cpp`, Swift extensions, Go receivers) are found by qualified name, so overrides and typed-receiver calls work across files; calls into third-party libraries are attributed by the headers/packages a file imports; methods inherited from an external framework base class are external library calls; route handlers can be `Class.method` names or a REST resource class.

### Review pass
- Library attribution is conservative: a call is tied to a library only when its name matches an imported header/package; the only-third-party-library case is recorded as a low-confidence edge and still counted as unresolved. Quoted includes that are not in the sources, and generated headers, no longer become packages. Namespaces and Perl packages declared in the repo are never libraries; libc is matched by explicit function names.
- Methods defined in another file than their class are looked up across files only for C/C++, Swift and Go; other languages keep per-file class scoping.
- Calls after `&&`, `>` or `*` in C/C++ are no longer mistaken for declarations; callbacks passed to libc functions (`pthread_create`, `qsort`, `signal`) become `references`; commented-out ABAP/Perl calls and `NEW` inside message text are ignored; builtin skip lists no longer hide user-defined or library calls.
- Sinks: format-string detection is positional, numeric/`sizeof` lengths are constants, keyword-prefixed Perl identifiers no longer match, and rules that always fired (File::Copy, LaunchMode, HttpOverrides, `SSL_VERIFY_NONE` alone, ABAP quote/escape) were removed.
- Entry points: Dart/httplib client calls are not routes, Catalyst `:Private` actions are not endpoints, route handlers bound to a controller class use only the endpoint's verb, app screens and signal handlers are not reported as unauthenticated network endpoints.
- Linear-time hardening of the `.h` C++ detector, the C++ class pattern and Perl POD masking; coverage hotspots now include Perl, C and ABAP dynamic dispatch.

### Changed
- Memory-safety sinks map to CWE-787 / A04, disabled TLS verification to A07.
- `void` return types no longer hide C/C++/Dart functions; `.h` files that declare classes or namespaces are parsed as C++.

## 0.6.0

### Fixed (review pass)
- Call extraction no longer invents calls from `a < b` (JS/TS), `arr[i]` (Go), or trailing identifiers (JVM); calls inside nested Python functions belong to the nested function.
- Agent graph: agents without a `tools:` field are treated as holding every tool, a wildcard hook matcher covers all tools, manifest names are validated, long lines are bounded.
- Threat model: secret-like names that are paths/URLs/flags are no longer reported as literal secrets, a 0% resolution rate is no longer shown as 100%, package names are normalised when matching advisories to calls.
- Coverage hotspots match `eval(`/`exec(` calls only; paths with control characters are skipped; `ingest_context` no longer needs Python 3.12 f-string syntax.

### Added
- **Complete call resolution.** Calls are resolved through typed receivers (constructor assignments, annotations, injected fields, module-level instances), the class hierarchy (`super()`/`base`/`parent`, inherited methods, interface-to-implementation dispatch), static/constructor calls, callbacks and decorators. New edge kinds produced: `uses_type`, `overrides`, `implements`, `references`, `calls_lib` (code to external package with the API names). Every call is accounted for as resolved / library / ambiguous / dynamic / unresolved in `evidence/call-resolution-<repo>.json` and `graph.json` stats; nothing is dropped silently. Call-graph levels `class` and `library` join function, file and repo.
- **Twelve languages to the same depth.** `lang_specs.py` drives declarations, class spans, calls, imports, typed receivers and inheritance for JavaScript, TypeScript, Go, Java, Kotlin, Scala, C#, Ruby, PHP, Rust and Swift (Python keeps the AST path). Each passes the eleven-row matrix in `tests/test_langs.py`; `docs/languages.md` lists parsers, frameworks and gaps. New entry points: Rust (actix, axum, Rocket, warp, tonic, clap), Swift (Vapor), Ktor, Akka HTTP/http4s/Scalatra, Micronaut/Servlets/Vert.x, WordPress, Slim, Sidekiq, tRPC, Python routers with prefixes, aiohttp/Tornado/Starlette, gRPC servicers and Lambda handlers; Rust and Swift sinks and sources; sink types `memory`, `format`, `tls`, `unsafe_code` mapped to CWEs.
- **Agent, skill and tool graph** (`agent_graph.py`, `system/agents.md`, `ckb_agents`): Claude Code plugins (agents, skills, commands, hooks, MCP tools; `dispatches`/`invokes` edges resolved against a name index; orphans, dangling references, risk flags) and agent frameworks in code (LangGraph, CrewAI, AutoGen, OpenAI Agents, Claude Agent SDK, MCP servers).
- **Deployment context and controls outside code** (`deploy_facts.py`): workloads from Kubernetes, compose, Helm, ECS/Lambda/Cloud Run/Container Apps and Dockerfiles with exposure (Service, Ingress, load balancer, security group), injected environment (secret values never stored), identity, and controls (ingress/gateway authentication, WAF, mesh policy, NetworkPolicy, rate limits, listeners). Workloads are linked to the repos they run (`service` nodes, `deploys` and `configured_by` edges).
- **Coverage report** (`coverage_report.py`, `system/coverage.md`): resolution percentages, functions no entry point reaches, dynamic-dispatch hotspots, dormant unsafe sinks.
- **Threat model uses all of it:** an **Attack paths** table over every edge kind with exposure, controls in front and coverage; exposure and authentication from deployment facts (authentication outside the code is annotated, a public workload with no control is rated up, deployed toggle values replace code defaults); deployment threats (literal secrets, privileged workloads, missing NetworkPolicy, HTTP listeners, routes without authorizers); library reachability (an advisory on a package the code calls is rated up); OWASP LLM threats from the agent graph; coverage and blind-spot section and unknown-risk rows.
- `graph_query` ops `agents`, `roles`, `entrypoints`; viewer levels Class and Library; tests `test_calls.py`, `test_agents.py`, `test_deploy.py`, `test_langs.py`.

### Changed
- The `taint` op also starts from agents and commands and follows `references`, `dispatches`, `invokes` and `ffi` edges. `graph_merge` passes edge `attrs` through. Regex extraction produces `method` nodes with `Class.method` qualified names.
- Tree-sitter is only used for languages without a spec (none today); the specs are the parser.

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
