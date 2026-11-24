# Auto mode

`/ckb:auto` looks at your **environment** and your **code**, decides what to analyze and how, asks one authorization question, then runs the whole pipeline. This page explains each decision so you can predict it and override it.

## What it decides

| Decision | How it is made | How to steer it |
| --- | --- | --- |
| **Which sources** | No argument: the current folder. A folder that contains several git repos (for example a checked-out Azure DevOps project) becomes one source per repo. A monorepo becomes one source per service (shallowest manifest directories) plus a `platform` source for IaC, contracts and CI that excludes the service directories, so code is never indexed twice. `ado:ORG/PROJECT`, `github-org:NAME`, `gitlab-group:PATH` are expanded through their APIs: archived/disabled repos and forks are skipped, and the list is capped at `auto_max_repos` (default 50) | pass explicit paths or specs; `--include`/`--exclude` globs and `include_forks` apply to org expansion |
| **Which branch** | **main, else master, else the repository's default branch.** A local repo checked out on another branch is read as a read-only snapshot of main/master; the checkout is never switched and uncommitted work is not included | `--ref BRANCH` |
| **Parser per language** | Python: stdlib `ast`. Other languages: tree-sitter if it is already installed, otherwise regex. Recorded on every node and edge | install `tree-sitter-language-pack` yourself if you want it |
| **Context** | finds scanner exports (SARIF, Security Hub, Prowler, Checkov…), diagrams (draw.io, Visio, Excalidraw, Mermaid, PlantUML, Gliffy, SVG), and documents or notes in folders named like `docs`, `architecture`, `design`, `adr`, `diagrams`, `runbooks`, `notes` | `--context paths...`, `context_paths` setting |
| **Stages** | inventory, analysis, knowledge graph, **call graphs**, repo context, supply chain, **threat model** are always on. Cross-repo flows run if there are several services or a broker/HTTP client. The cloud layer runs only if IaC exists. The OWASP LLM Top 10 runs only if an LLM SDK is imported | the plan lists every stage with the reason it is on or off |
| **Parallelism** | `min(CPUs, 6, number of sources)` agents at a time | — |
| **Remote auth** | GitHub/GitLab: a token from the environment variable you name. Azure DevOps: an `az login` session if present, else a PAT from `AZURE_DEVOPS_EXT_PAT`, `ADO_PAT` or `SYSTEM_ACCESSTOKEN`, else anonymous (public projects only) | `ado_token_env`, `token_env` |

## What the environment probe looks at

`scripts/env_probe.py` reports, without printing any secret value: whether `git`, `pdftotext`, `node`, `gh`, `glab`, `az` (and whether `az` is logged in) and a tree-sitter module are available; **which token variables exist, by name only** (`GITHUB_TOKEN`, `GITLAB_TOKEN`, ADO PAT variables, `SNYK_TOKEN` + `SNYK_ORG_ID`, `NEO4J_*`); whether the run is in CI; CPU count; free disk. Network reachability is a bare TCP connect to a host, and only for hosts you asked about.

## What is never automatic

* **The authorization question.** One question covers every source and context path; it is only skipped in CI (`CI=true`), where it is recorded as `ci-implicit`.
* **Anything that sends data off the machine.** Detected options are listed as *consent items* in that same question, each defaulting to **no**:

| Consent item | Offered when | What leaves the machine |
| --- | --- | --- |
| `remote_clone` | remote sources are in the plan | git requests, plus your token or login, to the host (required for those sources) |
| `osv` | there are dependency manifests | package names and exact versions to api.osv.dev |
| `snyk` | `SNYK_TOKEN` and `SNYK_ORG_ID` are set | package names and versions to api.snyk.io |
| `neo4j` | `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` are set | the graph (names, paths, citations, summaries) to your Neo4j |

  Items you already enabled in your settings file (`advisory_lookup`) show as pre-consented.
* **Neo4j writes** always need a separate explicit yes at push time.
* **Running target code**, ever.

Text inside a repo, document or image never changes the plan: only structural signals (manifests, file types, imports) do.

## The two-pass plan

1. `auto_plan.py [targets]` produces `evidence/auto-plan.json` from the local files (remote specs are only enumerated, not inspected, because nothing is fetched yet).
2. After sources are fetched, `auto_plan.py --out <out> --from-registered` produces `evidence/auto-plan-final.json` from what was actually registered (languages, services, IaC, stages) and is the plan the rest of the run follows.

## What you get

Everything under [Output reference](outputs.md), including: a **draft threat model** that the threat-modeler agent then reviews; **call graphs** at function, file and repo level; **documented-vs-observed drift** if you supplied documents or diagrams; summaries drawn from docstrings, READMEs, ADRs, CODEOWNERS and OpenAPI descriptions; and the interactive graph viewer.

## Example plan (abridged)

```json
{
  "sources": [
    {"key": "gateway", "languages": {"javascript": 2}, "git": {"source_mode": "in-place", "ref": "main"}},
    {"key": "orders", "languages": {"python": 5}, "git": {"source_mode": "snapshot", "ref": "main", "checked_out_branch": "feature/wip"}},
    {"key": "platform", "role": "platform", "exclude": ["gateway/**", "orders/**"]}
  ],
  "parsers": {"python": "ast", "javascript": "regex"},
  "stages": {"threat_model": {"run": true}, "cloud_layer": {"run": true, "why": "3 IaC file(s)"}, "owasp_llm_top10": {"run": false, "why": "no LLM SDK detected"}},
  "consent": [{"id": "osv", "what": "OSV.dev lookups", "default": "no"}]
}
```

Limits: exposure ("public candidate") is inferred from who calls whom; org-wide runs are capped and shallow; snapshots exclude submodules and LFS objects. See [Troubleshooting](troubleshooting.md) if the plan is not what you expected.
