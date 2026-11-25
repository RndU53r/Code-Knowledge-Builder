# Troubleshooting

## Installation and permissions

| Symptom | Cause and fix |
| --- | --- |
| Claude Code asks permission every time a ckb script runs | Expected on first use: command skills do not pre-approve `python3`. Allow only ckb's scripts, e.g. `Bash(python3 /path/to/ckb/scripts/*)`, in your settings |
| Hooks do nothing / `python3: command not found` | The hooks call `python3`. Install Python 3.9+ or, on Windows, use WSL or add a `python3` alias |
| `/ckb:context` shows Claude Code's built-in context usage | Type the full `/ckb:context`; plain `/context` is a different built-in command |
| Commands don't appear | Run `/plugin` and confirm `ckb` is enabled, or start Claude Code with `--plugin-dir /path/to/Code-Knowledge-Builder` |

## "ckb blocked my command"

The PreToolUse guard denies install/build/run/test commands, shell writes and git commands that run hooks **inside a registered analysis target**. That is the safety model working. To do something with the code, work on a copy that is not registered, or do it outside the ckb session. Targets are registered in `<out>/evidence/targets.json` and in `~/.ckb/targets.json` (or `$CKB_HOME`); delete a stale entry from the per-user file if a folder you no longer analyze is still protected. The guard also denies writes to a target outside its `.ckb/` directory: write outputs to the output directory.

## Sources and branches

| Symptom | Cause and fix |
| --- | --- |
| The analysis doesn't include my latest changes | You are probably on a feature branch: ckb read a snapshot of **main/master**. The plan says `source_mode: snapshot`. Merge or check out main, pass `--ref <branch>`, or register the folder as it is with `scripts/fetch_source.py --working-tree` |
| `branch 'x' not found` | The branch doesn't exist locally (for a local repo) or on the remote. Check `git branch -a` |
| Cloning fails with 401/403 | Set the token variable for that host (`GITHUB_TOKEN`, `GITLAB_TOKEN`, `AZURE_DEVOPS_EXT_PAT`) or run `az login` for Azure DevOps. Tokens are read only from environment variables |
| `Azure DevOps auth 'az' not available` | `az` isn't installed/logged in and no PAT variable is set. Anonymous access works only for public projects |
| `refused: https URL with a query string or fragment` | ckb refuses URLs that could point git at a different host than the one checked; use the plain clone URL |
| An org or project expands to too many repos | Auto mode is capped (`auto_max_repos`, default 50). Narrow with `--include 'api-*'`/`--exclude`, or name repos explicitly |
| `refusing API base 'http://…'` | API bases must be https (http only for localhost) |

## Output quality

| Symptom | Cause and fix |
| --- | --- |
| `verify_citations` reports **E1 unknown repo key** | The citation uses a key that is not registered in `evidence/targets.json`. Register the source with `fetch_source.py` first |
| **E2 file not found** / **E3 line out of range** | The code changed after the output was written (run `/ckb:update`), or the citation was wrong; fix the output |
| **E4 quote not found** | The quoted text isn't on or near the cited line; copy the exact text |
| **E5/E6** no citations / missing provenance block | Output files need citations (or `[inferred]`/`[unknown]`/`[n/a]`) and the provenance block from `shared/evidence-model.md` |
| `W1` warnings | A section has content but no citation or marker. Usually summary sections; add a marker or citation |
| Many `regex`-extractor edges with `low` confidence | Non-Python languages without tree-sitter use pattern matching. Install `tree-sitter-language-pack` yourself for better precision, and treat low-confidence edges as leads |
| A call or HTTP edge is missing | Dynamic dispatch, reflection or URLs built at runtime can't be resolved statically. Ask a question with `/ckb:ask`, or have an agent add a verified proposal (`skills/knowledge-graph/references/proposal-format.md`) |
| Proposals rejected (`graph/rejected.jsonl`) | Each line gives the reason: bad line number, quote not found, unknown node id, cross-repo edge without `dst_citation`, or an edge kind agents may not propose. Fix and rebuild |
| Summaries marked `[OUTDATED]` | The function's signature changed since the summary was written; re-annotate it (`/ckb:tour create`, graph-curator) or accept the old text as a hint |
| The threat model says draft | The threat-modeler agent has not refined it (no agents ran, e.g. in CI). Rows are rule-based leads: check the cited code |
| Threat nodes disappeared from the graph after refining | Intended: once `system/threat-model.md` has no draft marker and agents contributed their own threats, the rule-drafted ones are superseded |
| Documentation drift is reported but the document is right | Drift rows cite both the document and the code/IaC line; open the code line. If the setting lives outside the repo (mesh, cloud console), the row will say `not verifiable statically` instead |

## Context files

| Symptom | Cause and fix |
| --- | --- |
| PDF text missing | Install `pdftotext` (poppler) or let Claude read the PDF (`needs_reading`) |
| An image or scanned PDF is listed as `needs_reading` | Dispatch/let the `context-reader` agent describe it; it writes `<file>.notes.md` |
| `unsupported` for `.doc`, `.xls`, `.vsd`, `.ppt` | Legacy binary Office formats aren't parsed; export to .docx/.pdf/.vsdx/.csv |
| `refused: XML with DOCTYPE/ENTITY` or `suspicious compression ratio` | Deliberate protection against hostile files; inspect the file yourself |
| CSPM export parsed as plain JSON/CSV | The format wasn't recognized. Supported: Security Hub ASFF, Prowler (JSON/OCSF/CSV), ScoutSuite, Defender for Cloud, GCP SCC, Checkov, SARIF, CSV with severity/resource/title columns |

## Graph, viewer, servers

| Symptom | Cause and fix |
| --- | --- |
| `no graph at …/graph.sqlite` | Build it: `/ckb:graph build` or `python3 scripts/graph_build.py --out <out> --extract --enrich` |
| The viewer is empty or only shows a few nodes | It opens on an overview; use **All (capped)** or the Level selector. Very large graphs are capped at about 5,000 nodes |
| The viewer shows nothing in a restricted browser | Open `graph/index.html` directly from disk or use `/ckb:graph serve`; the page needs JavaScript but no network |
| `403` / `421` from the live server | Use the full URL with `?token=…` printed at start, and `127.0.0.1` or `localhost` as the host |
| MCP tools say "no graph" | Set `CKB_OUT` to your output directory, or run from the project folder that contains `.ckb/` |
| Neo4j push refused | `graph_neo4j.py push` needs `--yes` after you confirm; plain-http URLs to non-local hosts are refused (use https) |

## Call graph and coverage

* **Few call edges / low resolved percentage:** open `system/coverage.md` and `evidence/call-resolution-<repo>.json`. Typical causes: dynamic dispatch (reflection, DI containers, `getattr`), generated code, or a language construct the spec does not parse. The names listed under "top unresolved" show where to look.
* **A library call is missing:** `calls_lib` edges need an import or a typed receiver that resolves to an external class; a dynamically built name will not.
* **Deployment facts are empty:** the deployment files must be inside a registered source (an infra repo or a `deploy/` directory); workloads are linked to the application repo by image name, build context, chart name or name equality.
* **Agent graph shows no edges:** references are resolved against agent/skill/command names found in the sources; a plugin's namespace comes from `.claude-plugin/plugin.json`.

## CI

* In CI (`CI=true`) the authorization question is skipped and recorded as `ci-implicit`; off-machine lookups stay off unless `advisory_lookup` is set.
* Allow only what the job needs: the example workflows use `--allowedTools` with the plugin's scripts.
* If a run takes too long, run `/ckb:supply-chain` (static scan only) or split services across jobs; the deterministic scripts alone (`graph_build.py --extract --enrich`) need no model at all.

## Still stuck

Run the failing script directly with no arguments for its usage text ([script reference](scripts.md)), check `evidence/verification.md` and `evidence/graph-verification.md`, and open an issue with the command, the error, and the relevant lines of `evidence/auto-plan*.json` (it contains no secrets).
