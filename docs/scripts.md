# Script reference

Every ckb step is a plain Python 3 script (standard library only) under `scripts/`. In a Claude Code session the commands call them for you; you can also run them directly, for example in CI or to debug a stage. `${CLAUDE_PLUGIN_ROOT}` is the plugin directory; `<out>` is the output directory (default `<target>/.ckb`).

None of these scripts executes, builds, installs or imports code from the repos they analyze. This page is generated from each script's own usage text by `tests/make_script_docs.py`; run any script with no arguments or `--help` for the same text.

## Planning

### `env_probe.py`

```text
Read-only probe of the local environment: which tools, logins and tokens ckb can use.

Usage:
  env_probe.py [--scratch DIR] [--check-network HOST ...] [--token-env NAME ...]

Reports names and booleans only. Secret values are never read into the output; `az` is asked only
whether a login exists. Network checks are a plain TCP connect to host:443 (no request, no data) and
only for hosts you pass. Nothing is installed or changed.
```

### `auto_plan.py`

```text
Auto mode planner: inspect the environment and the code, then choose sources, branches, parsers,
context, stages and graph settings. Reads files only.

Usage:
  auto_plan.py [--out OUT_DIR] [PATH_OR_SPEC ...]          (default: the current directory)
  auto_plan.py --out OUT_DIR --from-registered             (second pass: plan from already-fetched sources)

PATH_OR_SPEC: a local folder, a workspace folder holding several git repos, a monorepo, a git URL,
or a project/org spec expanded through enumerate_sources.py:
  ado:ORG/PROJECT   github-org:NAME   gitlab-group:PATH
Branches: main, else master, else the repo default, unless given. Local repos on another branch are
read as a read-only snapshot of main/master (fetch_source.py), never by switching your checkout.

Writes <out>/evidence/auto-plan.json (and prints it). Every decision carries the evidence (files) that
triggered it. Text inside a repo never changes the plan; only structural signals do.

Never decided automatically: authorization, off-machine lookups (Snyk/OSV/Neo4j: offered as consent
items, default no), Neo4j writes, executing target code.
```

### `enumerate_sources.py`

```text
List the repositories of an Azure DevOps project, GitHub org, or GitLab group (read-only API calls).

Usage:
  enumerate_sources.py SPEC [SPEC ...] [--include GLOB ...] [--exclude GLOB ...] [--max-repos N]
                       [--include-forks] [--include-archived] [--token-env VAR] [--api-base URL]
                       [--gitlab-base URL] [--ado-auth auto|az|pat|none]

SPEC is one of:
  ado:ORG/PROJECT          Azure DevOps project (dev.azure.com; Azure DevOps Server via --api-base)
  github-org:NAME          GitHub organization (GitHub Enterprise via --api-base)
  gitlab-group:PATH        GitLab group incl. subgroups (self-hosted via --gitlab-base)

Prints JSON: {"sources": [{"spec", "source", "key", "default_branch", "branch", "skipped": false, ...}],
              "skipped": [...], "capped": bool}
`source` is a shorthand fetch_source.py accepts. `branch` follows the ckb rule: main, else master, else
the repo's default branch. Archived/disabled repos and forks are skipped unless asked for.

Tokens are read from env vars (never printed or put in URLs): GitHub GITHUB_TOKEN/GH_TOKEN, GitLab
GITLAB_TOKEN, Azure DevOps an `az` login or AZURE_DEVOPS_EXT_PAT / ADO_PAT / SYSTEM_ACCESSTOKEN.
Plain http:// API bases are refused unless they point at localhost.
```

## Acquisition

### `fetch_source.py`

```text
Acquire a source for ckb analysis, safely and read-only.

Usage:
  fetch_source.py --out OUT_DIR [--key name] [--scratch dir] [--ref BRANCH] [--working-tree]
                  [--token-env VAR] [--auth auto|az|pat|none] [--gitlab-base URL] [--exclude GLOB ...] SOURCE

SOURCE is a local directory, an https:// or ssh:// git URL, a git@host:org/repo URL, or a shorthand:
  github:org/repo   gitlab:group/sub/repo   ado:org/project/repo
  https://dev.azure.com/ORG/PROJECT/_git/REPO   https://ORG.visualstudio.com/PROJECT/_git/REPO

Branch rule (when --ref is not given): main, else master, else the remote's default branch.
- Remote: shallow clone of that branch (hooks off, no submodules, no LFS smudge, file:// and ext::
  refused) into a fresh scratch dir.
- Local git repo: if the repo's current branch is not main/master, a READ-ONLY snapshot of main (else
  master) is exported with `git archive` into scratch; your checkout and working tree are never touched.
  Uncommitted work is not in a snapshot; use --working-tree to analyze the folder as it is on disk.
  Service sub-directories of a repo are resolved inside the same snapshot. Snapshots live in a per-user,
  owner-only (0700) cache under the scratch dir and are never reused unless owned by you and private. Folders that are not git
  repos, or repos with no main/master, are analyzed in place.

Auth (never printed, never in a URL or argv): --token-env VAR reads a token from that env var.
For Azure DevOps, --auth auto uses a logged-in `az` CLI session (Entra access token) if available,
otherwise a PAT from AZURE_DEVOPS_EXT_PAT / ADO_PAT / SYSTEM_ACCESSTOKEN. GitHub/GitLab tokens come
from --token-env. Tokens reach git through environment variables only.

The target is registered (evidence/targets.json + the per-user registry) so the ckb guard hook
protects it. Prints one JSON object describing the registered source.
```

## Extraction

### `inventory.py`

```text
Static inventory of one repo: languages, manifests, frameworks, entry-point and
edge candidates, contracts, infra artifacts, config reads. Reads files only.

Usage:
  inventory.py --root REPO_ROOT --key REPO_KEY [--json-out F] [--exclude GLOB ...]

Everything here is a CANDIDATE produced by regex. Agents must open the cited line
and confirm before stating it as fact. Each candidate carries a ckb citation.
```

### `graph_extract.py`

```text
Extract per-file graph fragments from one registered repo. Reads files only; never executes them.

Usage:
  graph_extract.py --out OUT_DIR --key REPO_KEY [--root ROOT] [--files rel1 rel2 ...] [--backend auto|ast|regex|tree-sitter]

Backends (provenance recorded on every node/edge):
  ast          Python files via the stdlib `ast` module (always available)
  tree-sitter  other languages, only if `tree_sitter_language_pack` or `tree_sitter_languages` is already
               installed (ckb never installs it); falls back to regex on any error
  regex        everything else (JS/TS, Go, Java, ...): function spans, routes, calls, env, SQL, queues

Writes <out>/graph/fragments/<key>/<sha256-of-path>.json, one per source file, containing nodes, edges
(intra-file, resolved) and refs (cross-file references the linker resolves in graph_build.py).
```

### `scan_supply_chain.py`

```text
Static supply-chain and injection scanner for one repo. Reads files only.

Usage:
  scan_supply_chain.py --root REPO_ROOT --key REPO_KEY [--json-out F] [--md-out F]
                       [--osv] [--exclude GLOB ...]

Emits JSON (stdout or --json-out) and optionally a markdown findings table whose
evidence column uses ckb citations (`key/path:line`). Never executes target code.
--advisories osv,snyk queries api.osv.dev and/or the Snyk REST API (SNYK_TOKEN + SNYK_ORG_ID)
with package names and exact versions (opt-in; sends data off-machine). Without it, advisory
status is "not checked". Every registry dependency always gets a security.snyk.io page link
(no network call) so a human can check it.
```

### `ingest_context.py`

```text
Ingest supporting context (architecture documents, diagrams, IaC, CSPM results) into a
citable, normalized form under <out>/evidence/context/<key>/ and register it as a ckb
source so citations like `ctx-arch/design.docx.md:42` verify.

Usage:
  ingest_context.py --out OUT_DIR [--key ctx-NAME] PATH [PATH ...]

Supported (Python stdlib only; nothing is executed, macros are never run):
  Diagrams   .drawio .drawio.xml .dio (incl. compressed pages), .vsdx (Visio), .svg (text labels),
             .excalidraw, Mermaid (.mmd), PlantUML (.puml), Gliffy (.gliffy)
  Documents  .docx .pptx .md .txt .rst .adoc .html .htm .eml .rtf (notes; email addresses omitted), .pdf (via `pdftotext` if installed,
             otherwise listed under needs_reading for Claude's Read tool), images
             (.png .jpg .jpeg .gif .webp) listed under needs_reading
  CSPM       AWS Security Hub ASFF, Prowler (JSON/OCSF/CSV), ScoutSuite, SARIF (Checkov/tfsec/
             KICS/Trivy...), Checkov JSON, Microsoft Defender for Cloud assessments, GCP Security
             Command Center findings, generic CSV with severity/resource/title columns
  IaC        .tf .tfvars .hcl .bicep, ARM templates, CloudFormation/SAM, GCP Deployment Manager,
             Kubernetes/Helm YAML, Pulumi/CDK sources: copied verbatim (citable by original line)

Every output file starts with a header naming the original file. Secret-looking values are
redacted. Archives (docx/pptx/vsdx) are read in memory with size limits; XML with DOCTYPE or
ENTITY declarations is refused. Prints a JSON manifest.
```

## Graph

### `graph_build.py`

```text
Build the ckb knowledge graph from fragments: link cross-file references, attach security findings,
merge verified agent proposals, carry over summaries, and write graph.json + graph.sqlite.

Usage:
  graph_build.py --out OUT_DIR [--extract] [--incremental] [--structural-only] [--enrich]

  --extract          run graph_extract.py for every registered code repo first (ctx-* keys are skipped)
  --incremental      with --extract: re-extract only files changed since the last hash snapshot
  --structural-only  skip proposals (used by the git-commit auto-update hook)
  --enrich           also run repo_context.py, doc_claims.py and threat_seed.py (draft threat model), then rebuild

Outputs: <out>/graph/graph.json, <out>/graph/graph.sqlite, <out>/system/graph.md
```

### `graph_merge.py`

```text
Verify and merge agent graph proposals (<out>/graph/proposals/*.jsonl) into the knowledge graph.

Proposal line format (one JSON object per line):
  {"op":"edge","src":ID,"kind":KIND,"dst":ID,"citation":"repo/path:L","quote":"exact text",
   "dst_citation":"repo/path:L"?, "confidence":"high|medium|low", "label":"observed|inferred|documented",
   "rationale":"..."}
  {"op":"node","kind":KIND,"repo":R,"path":P?,"qualname":Q,"name":N,"citation":"repo/path:L",
   "quote":"exact text", "confidence":..., "label":..., "summary":"..."?, "attrs":{...}?}
  {"op":"annotate","id":ID,"summary":"...","tags":[...],"layer":"..."}          (graph-curator)

Checks: JSON shape; kind allowed for extractor `llm`; citation resolves (E1-E4) and the quote matches
the cited lines; cross-repo edges need dst_citation; src/dst exist or are proposed in the same file;
strings redacted and capped; low confidence is forced to label `inferred`.

Usage:
  graph_merge.py --out OUT_DIR --check FILE.jsonl     # validate only (used by the PostToolUse hook)
graph_build.py calls merge_into() during a build.
```

### `graph_check.py`

```text
Validate the ckb knowledge graph: schema, IDs, dangling edges, provenance, citations, secrets.

Usage:
  graph_check.py --out OUT_DIR [--report] [--json]

Every node/edge citation (and dst_citation) is resolved with verify_citations.Verifier against the
registered repos; quotes on LLM edges are checked too. Writes <out>/evidence/graph-verification.md
with --report. Exit 1 on errors.
```

## Derivation

### `callgraph.py`

```text
Call graphs at three levels, rolled up from the ckb knowledge graph. Reads graph.json only.

Usage:
  callgraph.py --out OUT_DIR [--max-rows 80]

Levels
  function -> function   calls, HTTP calls resolved to the handler behind the endpoint, subprocess/FFI
                         spawns, and publish -> consume pairs over a topic
  file -> file           the function-level edges rolled up by containing file, plus import edges
  repo -> repo           HTTP/gRPC calls, topics (publisher repo -> consumer repo), shared tables
                         (writer repo -> reader repo), subprocess spawns, internal package dependencies
                         and calls to external systems

Every row keeps the citations of the edges it summarizes and the weakest confidence along the way.
Writes <out>/graph/callgraph.json, <out>/system/call-graphs.md, <out>/diagrams/callgraph-*.mmd.
```

### `threat_seed.py`

```text
Deterministic draft threat model from the ckb knowledge graph (so every run, even headless/CI, gets one).

Usage:
  threat_seed.py --out OUT_DIR [--force]

Reads graph.json (+ supply-chain JSON, CSPM/IaC nodes, drift nodes) and applies fixed rules:
  injection paths (taint candidates to unsafe SQL/command/SSRF/code/deserialization sinks), endpoints with
  no authentication evidence, security switches an env var can turn off, plaintext or identity-header trust
  between services, unauthenticated message channels and requeue-forever consumers, tables written by
  several repos, outbound calls with no timeout, cloud misconfigurations (IaC + CSPM), confirmed-suspicious
  supply-chain findings, documented-vs-observed drift, and LLM integrations (OWASP LLM Top 10).

Writes
  <out>/system/threat-model.md          draft (carries <!-- ckb:threat-seed -->; never overwrites a refined
                                        file that lacks the marker unless --force)
  <out>/graph/proposals/seed-threats.jsonl   threat / trust_boundary nodes + threatens / crosses_boundary
                                        edges, extractor "rule", verified by graph_merge.py like any proposal
Every threat cites code, IaC, or scan evidence. Ratings follow skills/threat-modeling/references/rating-rubric.md.
The threat-modeler agent then confirms, refines, or removes each draft threat.
```

### `doc_claims.py`

```text
Turn documentation, diagrams and notes into checkable claims and compare them with the code graph.

Usage:
  doc_claims.py --out OUT_DIR

Input: converted context under <out>/evidence/context/ctx-*/ (from ingest_context.py: draw.io, Visio,
Excalidraw, Mermaid, PlantUML, Gliffy, Word, PowerPoint, PDF, email/notes, agent-written *.notes.md for
images) and the built knowledge graph.

Claims it extracts (deterministic patterns, no model): components and their containers, documented
connections (A -> B : label), and controls: mTLS / TLS, encryption at rest, authentication on a
component, internal-only exposure. Each claim is matched to graph entities (repos, endpoints, cloud
resources) and checked:
  consistent | drift | not verifiable statically | unmatched
Every verdict cites the document line AND the code/IaC evidence. Documents record intent, so
documents never overrule code: disagreements are reported as drift.

Writes
  <out>/system/documented-vs-observed.md      the table the HLD and threat model include
  <out>/evidence/doc-claims.json              all claims, matches, verdicts
  <out>/graph/proposals/seed-docs.jsonl       doc_section nodes + documented_as edges, drift nodes +
                                              drifts_from edges (extractor "rule"; verified by graph_merge)
```

### `repo_context.py`

```text
Enrich the knowledge graph with context that lives in the repos themselves (deterministic, no model).

Usage:
  repo_context.py --out OUT_DIR

Reads, per registered repo: README (first real paragraph), ADRs, CODEOWNERS, OpenAPI/AsyncAPI specs
(summaries and descriptions per operation), and docker-compose service metadata. Function/class
summaries from docstrings and leading comments are already attached at extraction time (graph_extract).

Writes <out>/graph/proposals/seed-repo-context.jsonl (extractor "rule"): doc_section / contract_op nodes,
documented_as edges, and annotate lines (summary, tags). graph_merge verifies every line against the
source like any proposal, so rebuild afterwards. All text is untrusted: lines that address AI agents are
never used in a summary, secrets are redacted, strings are capped.
```

## Query, view and export

### `graph_query.py`

```text
Query the ckb knowledge graph. The GraphStore class is shared by this CLI, the MCP server
(graph_mcp.py) and the local viewer server (graph_serve.py). Read-only.

Usage:
  graph_query.py --out OUT_DIR status
  graph_query.py --out OUT_DIR search <text> [--kinds function,endpoint] [--repo R] [--limit N]
  graph_query.py --out OUT_DIR node <id>
  graph_query.py --out OUT_DIR explain <id|repo/path|name>
  graph_query.py --out OUT_DIR neighbors <id> [--dir out|in|both] [--kinds calls,...] [--depth 1..3]
  graph_query.py --out OUT_DIR path <src> <dst> [--kinds ...] [--max-depth 8] [--k 3]
  graph_query.py --out OUT_DIR impact <target ...> [--diff REV] [--depth 6]
  graph_query.py --out OUT_DIR taint [--source ID] [--sink ID] [--max-depth 10]
  graph_query.py --out OUT_DIR callgraph [function|file|repo] [--repo R] [--focus X] [--depth N]
  graph_query.py --out OUT_DIR tour [name]
  graph_query.py --out OUT_DIR sql "<SELECT ...>"
  graph_query.py --out OUT_DIR cypher "<MATCH ...>"      (only when Neo4j is configured; see graph_neo4j.py)

Targets accept a node id, `repo/path` (a file), a path suffix, or a symbol name.
```

### `graph_viewer.py`

```text
Generate the self-contained interactive graph viewer: <out>/graph/index.html

Usage:
  graph_viewer.py --out OUT_DIR [--cap 5000]

Vanilla JS, no CDN, no network: the graph JSON is embedded (with `</`, `<!--` and U+2028/2029 escaped)
and a strict Content-Security-Policy allows only the hashed inline script and style. Target-derived
strings are rendered with textContent only. graph_serve.py reuses render() for live mode.
```

### `graph_serve.py`

```text
Live (dynamic) graph viewer: a local, read-only HTTP server over the ckb graph.

Usage:
  graph_serve.py --out OUT_DIR [--port 0] [--no-open]

- Binds 127.0.0.1 only, random port by default; prints the URL including a one-time random token.
- Every request needs the token (?token= or X-CKB-Token header); GET/HEAD only; Host header must be
  127.0.0.1/localhost (DNS-rebinding guard); strict CSP; no file serving beyond the viewer and API.
- /            the viewer (same as graph/index.html) in live mode: it polls /api/status and reloads
               the graph when graph.sqlite changes (e.g. after /ckb:update or the auto-update hook)
- /api/<op>    GraphStore ops (status, search, explain, neighbors, path, impact, taint, tour, subgraph,
               graph); arguments as query parameters (lists comma-separated)
```

### `graph_mcp.py`

```text
ckb-graph MCP server (stdio, JSON-RPC 2.0). Read-only tools over the ckb knowledge graph.

Registered by the plugin's .mcp.json. The graph location is resolved from the CKB_OUT env var, then
`output_dir` in .claude/code-knowledge-builder.local.md, then ./.ckb (relative to the session's cwd);
every tool also accepts an explicit `out`. When no graph exists, tools say how to build one.
Never writes, never executes target code, no network.
```

### `graph_export.py`

```text
Export the ckb knowledge graph to other formats.

Usage:
  graph_export.py --out OUT_DIR ua        # graph/ua-knowledge-graph.json (Understand-Anything-style layout)
  graph_export.py --out OUT_DIR cypher    # graph/neo4j/load.cypher (parameterized UNWIND batches) + params JSON
  graph_export.py --out OUT_DIR csv       # graph/neo4j/nodes.csv, edges.csv (neo4j-admin import headers)
  graph_export.py --out OUT_DIR graphml   # graph/graph.graphml

Every exported node/edge keeps its ckb citation, extractor, confidence and label so evidence survives export.
The UA export follows Understand-Anything's published concepts (typed nodes with filePath/lineRange,
typed weighted edges, layers, tour); it is a compatibility format, not a copy of their code.
```

### `graph_neo4j.py`

```text
Optional Neo4j support for teams that already run Neo4j (HTTP transactional Cypher API, stdlib urllib).

Usage:
  graph_neo4j.py --out OUT_DIR check                 # connectivity + server version (read-only)
  graph_neo4j.py --out OUT_DIR push --yes            # load graph (MERGE nodes/edges). Only after the user confirms.
  graph_neo4j.py --out OUT_DIR query "<MATCH ...>"   # read-only Cypher; write clauses are refused

Connection from env vars whose NAMES come from settings (neo4j_uri_env / neo4j_user_env /
neo4j_password_env; defaults NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD; optional NEO4J_DATABASE). Values
are never printed. Use a read-only Neo4j user for querying. Plain http:// to a non-localhost host is
refused unless --allow-insecure. Neo4j results are navigation aids; cite graph.json/source lines, not Neo4j.
```

## Assurance

### `verify_citations.py`

```text
Verify ckb citations against the registered target repos.

Usage:
  verify_citations.py [--out OUT_DIR] [--report] [--json] PATH [PATH ...]

PATH is an output .md file or a directory (all .md files under it). OUT_DIR is the
ckb output dir holding evidence/targets.json; it is found automatically by walking
up from PATH when omitted.

Checks, per citation `repo/path:LINE` or `repo/path:START-END`:
  E1 unknown repo key           E2 file not found / outside repo root
  E3 line out of range          E4 quoted text «...» not found in cited lines (±2)
Per file:
  E5 no citations at all (except index.md and evidence/*)
  E6 missing provenance block   W1 section with content but no citation/marker

Exit 0 when no errors, 1 when errors, 2 on usage problems.
Quote matching idea inspired by arden/Codebase-Knowledge-Builder (independent code).
```

### `check_outputs.py`

```text
LLM-free checks over ckb output markdown.

Usage:
  check_outputs.py [--json] PATH [PATH ...]

Checks:
  M1 Mermaid block: unknown diagram type, unbalanced brackets/quotes, raw HTML/script,
     click/callback directives (blocked: diagrams must be inert)
  L1 broken relative markdown link (target file missing)
  S1 secret-looking value present (type only; value is never printed)
  H1 active HTML (<script>, <iframe>, on*= handlers, javascript: URLs)

Exit 0 clean, 1 problems found, 2 usage. Idea inspired by arden/Codebase-Knowledge-Builder
(deterministic doc checks); independent implementation.
```

### `hash_index.py`

```text
Content-hash index for incremental refresh (/ckb:update).

Usage:
  hash_index.py snapshot --out OUT_DIR          # record hashes for every registered repo
  hash_index.py diff --out OUT_DIR [--json]     # compare current files with the snapshot

The diff reports, per repo: added/removed/changed files, and which ckb stages are
stale, using a simple dependency map (manifests/CI/Docker → supply-chain; contracts
→ cross-repo flows; any source change → analysis, outputs, threat model, context).
Remote clones are refreshed by re-running fetch_source.py before diffing.
Idea inspired by arden/Codebase-Knowledge-Builder (incremental cache); independent code.
```

### `guard.py`

```text
ckb hook logic. Reads the hook event JSON on stdin.

  guard.py bash   PreToolUse(Bash): deny commands that would install, build, run, or
                  test code inside a registered target, or run its git hooks.
  guard.py write  PreToolUse(Write|Edit|MultiEdit|NotebookEdit): deny writes inside a
                  registered target except under its ckb output directory.
  guard.py post   PostToolUse(Write|Edit|MultiEdit): when a ckb output .md is written,
                  verify citations, provenance, Mermaid, links, and redaction; block
                  (send feedback to Claude) on errors.

Targets are registered by fetch_source.py in ~/.ckb/targets.json (CKB_HOME overrides).
Commands are only restricted when they touch a registered target, so the guard does
not interfere with unrelated work.
```

## Internal modules

Imported by the scripts above; not run directly.

* `ckb_common.py`: Shared helpers for ckb scripts. Python 3 standard library only.
* `graph_common.py`: Shared definitions for the ckb knowledge graph: schema, IDs, validation, safe strings.
* `graph_security.py`: Security layer for the ckb knowledge graph (imported by graph_build.py).
