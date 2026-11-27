# User guide

ckb turns one or more repositories into a cited knowledge base, a threat model, call graphs, scanner-ready `context.md` files and a supply-chain audit, **without running any of their code**. Every claim cites `repo/path:line`; anything the code does not prove is marked `[inferred]` or `[unknown]`.

## 1. Install

Requirements: Claude Code, `git`, and `python3` (3.9+) on your `PATH`. ckb's scripts use only the Python standard library, so there is nothing to `pip install`.

```text
/plugin marketplace add RndU53r/Code-Knowledge-Builder
/plugin install ckb@code-knowledge-builder
```

To try it from a checkout instead: `claude --plugin-dir /path/to/Code-Knowledge-Builder`.

Optional extras ckb uses **only if you already have them**: `tree-sitter-language-pack` (better parsing for non-Python languages), `pdftotext` (poppler, for PDFs), the `az` CLI (Azure DevOps login), `gh`/`glab`. ckb never installs anything.

Claude Code will ask permission the first time a ckb script runs. To skip the prompts, allow only ckb's own scripts in your settings, for example `Bash(python3 /path/to/ckb/scripts/*)`. On Windows, use WSL or provide a `python3` alias (the hooks call `python3`).

## 2. Your first run (about five minutes)

From inside the repository you want to understand:

```text
/ckb:auto
```

1. ckb looks at your environment and the code and shows a short plan: the sources it found, which stages will run (and which won't, with the reason), and any optional off-machine features it noticed (see [Auto mode](auto-mode.md)).
2. It asks **one** authorization question: do you own, or are you authorized to audit, these repos? Nothing is read before you answer.
3. It builds the knowledge graph, call graphs, a draft threat model, and the documents, then verifies every citation.
4. Open `.ckb/index.md`, or open `.ckb/graph/index.html` in a browser for the interactive graph.

Your repositories are never modified: ckb writes only under `.ckb/` (or the output directory you choose).

## 3. Common tasks

| I want to… | Run |
| --- | --- |
| understand a repo or a set of services end to end | `/ckb:auto` (or `/ckb:full <sources...>` to choose everything yourself) |
| analyze several local repos together | `/ckb:auto ./svc-a ./svc-b ./svc-c` (or a folder that contains them) |
| analyze a whole Azure DevOps project / GitHub org / GitLab group | `/ckb:auto ado:ORG/PROJECT`, `github-org:NAME`, `gitlab-group:PATH` |
| analyze a specific branch | `/ckb:auto ./repo --ref release/1.2` |
| add my architecture docs, diagrams, images, notes, IaC or CSPM exports | `/ckb:auto ./repo --context ./docs ./security/prowler.json` |
| only check whether a repo is safe to install | `/ckb:supply-chain <source>` |
| get a threat model | `/ckb:threat-model` (also part of every `/ckb:auto` run) |
| get a `context.md` for my scanner | `/ckb:context` |
| ask a question about the code | `/ckb:ask which endpoints can reach a SQL query built from user input?` |
| see what a change would affect | `/ckb:impact orders/app/db.py` or `/ckb:impact --diff origin/main` |
| explore visually | `/ckb:graph view` (static page) or `/ckb:graph serve` (live local page) |
| onboard someone | `/ckb:tour create new backend engineer` |
| refresh after the code changed | `/ckb:update` |
| run it in CI | see [CI](#4-running-in-ci) |

Sources can be a local folder, a git URL (`https://…`, `ssh://…`, `git@host:…`), or a shorthand: `github:org/repo`, `gitlab:group/repo`, `ado:ORG/PROJECT/REPO`. Full argument lists are in the [command reference](commands.md).

### Which branch is analyzed?

**main, else master, else the repository's default branch**, unless you pass `--ref`. If a local repo is currently checked out on some other branch, ckb reads a **read-only snapshot** of main/master instead (your checkout is never switched and uncommitted work is not included). To analyze the folder exactly as it is on disk (including uncommitted work), check out main/master first, or register the folder yourself with `scripts/fetch_source.py --working-tree`.

## 4. Running in CI

`ci/github-actions.yml` and `ci/gitlab-ci.yml` run `/ckb:full .` headless and upload `.ckb/` as an artifact. In CI (`CI=true`) ckb skips the authorization question (the job's presence in the repo is the authorization, recorded as `ci-implicit`) and never turns on off-machine lookups unless your settings file says so. Pin the action SHAs and the Claude Code version you trust.

## 5. Settings

Optional. Copy [`examples/code-knowledge-builder.local.md`](../examples/code-knowledge-builder.local.md) to `<project>/.claude/code-knowledge-builder.local.md` (it is git-ignored):

| Key | Default | Meaning |
| --- | --- | --- |
| `output_dir` | `<target>/.ckb` | where outputs go |
| `scratch_dir` | system temp | where clones and snapshots go |
| `exclude_paths` | built-in list | extra globs to skip |
| `token_env` / `ado_token_env` | `GITHUB_TOKEN`, `GITLAB_TOKEN` / `AZURE_DEVOPS_EXT_PAT` | **names** of environment variables holding tokens (values are never stored or printed) |
| `gitlab_base_url` | `https://gitlab.com` | self-hosted GitLab |
| `auto_max_repos` | `50` | cap when auto mode expands a project, org or group |
| `include_forks` | `false` | include forks when expanding an org |
| `context_paths` | none | folders/files always ingested as context |
| `advisory_lookup` | `off` | `off`, `osv`, `snyk`, or `osv,snyk` (sends package names and versions off-machine) |
| `snyk_token_env`, `snyk_org_env` | `SNYK_TOKEN`, `SNYK_ORG_ID` | env var names for Snyk lookups |
| `graph_autoupdate` | `off` | `on`: refresh the structural graph after each `git commit` |
| `neo4j_uri_env`, `neo4j_user_env`, `neo4j_password_env` | `NEO4J_*` | env var names for an existing Neo4j |

## 6. Reading the results

* Start at `.ckb/index.md`. [Output reference](outputs.md) explains every file.
* **Trust the citation, not the prose.** Every row ends with `` `repo/path:line` ``. Open the cited lines before acting on a finding.
* Labels: no marker = seen directly in the cited lines; `[inferred]` = a reasoned connection; `[unknown]` = not found or not provable; `[documented]` = stated only in a document or diagram (intent, not proof). Confidence is `high`, `medium` or `low`.
* The **draft threat model** is rule-based until the threat-modeler agent has refined it. Rows marked `[draft]` are leads to check.
* **Documented vs observed** (`system/documented-vs-observed.md`) lists where your documents and the code disagree. The code wins.

### Roles, repo kinds, entry points

* `repos/<repo>/code-map.md` tells you what kind of repo each source is (application, service, library, IaC, CI/CD pipeline, GitOps config, or a mix) and which files are core, utility, tests, generated or infrastructure. Core versus utility is inferred; the signals are listed.
* `repos/<repo>/context-facts.md` (also embedded in `context.md`) lists the entry points (HTTP and gRPC endpoints, queue consumers, cron jobs, CLI commands) with auth evidence and exposure, the user-controlled inputs they read, and the dangerous sinks they can reach. For IaC and pipeline repos it lists resources and pipelines instead.
* Ask the graph directly: `/ckb:ask which are the core files of orders?`, `/ckb:ask list the unauthenticated endpoints`, or use `graph_query.py roles` and `entrypoints`.

### Deployment context, agents and coverage

* `repos/<repo>/context-facts.md` has a "Deployment and controls outside application code" table when IaC, Kubernetes, compose or Helm files in the sources run that repo: exposure, injected config, identity and the controls in front of it. `system/threat-model.md` uses it (an Ingress with auth-url in front of a service is "authentication outside the code", not "no authentication").
* `system/agents.md` shows agents, skills, commands, hooks and tools (Claude Code plugins and agent frameworks): who calls whom, risky tool combinations, orphans, dangling references.
* `system/coverage.md` says how much of the code could be resolved. Read it before relying on the **Attack paths** table in the threat model: ckb cannot prove every path was found, and lists what it could not follow.
* Supported languages and depth: [language support](languages.md). Seventeen languages are covered to the same eleven-row standard. Three results need extra care: **C** has no classes (functions are the units and HTTP handler registrations do not say which verb they serve, so routes read `ANY`); **C++** and **Dart** attribute calls into third-party libraries by the headers/packages a file imports, and say so in `coverage.md` when only one library was in scope; **ABAP** lists the function modules of a function group as RFC *candidates* because the remote-enabled flag is metadata ckb does not parse.

## 7. What ckb will not do

It will not install, build, run or test anything in your repos, follow instructions found inside them, write inside them, open secret files, send data anywhere except the git remotes you list (plus lookups you turn on), or analyze a repo you haven't confirmed. Details: [Security model](security-model.md).

Something not working? [Troubleshooting](troubleshooting.md).
