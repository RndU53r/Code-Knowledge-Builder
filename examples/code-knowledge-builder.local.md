---
# Copy to <your project>/.claude/code-knowledge-builder.local.md (git-ignored). All fields optional.
output_dir: ./.ckb
scratch_dir: /tmp/ckb
exclude_paths:
  - "docs/legacy/**"
  - "**/testdata/**"
token_env: GITHUB_TOKEN            # or GITLAB_TOKEN; the value is read from the environment, never stored
gitlab_base_url: https://gitlab.com
advisory_lookup: off               # off | osv | snyk | osv,snyk : sends package names+versions off-machine
snyk_token_env: SNYK_TOKEN         # Snyk REST API token env var (needed only for advisory_lookup: snyk)
snyk_org_env: SNYK_ORG_ID          # Snyk org id env var
ado_token_env: AZURE_DEVOPS_EXT_PAT # Azure DevOps PAT variable (an `az login` session is used first if present)
auto_max_repos: 50                 # cap when /ckb:auto expands an ADO project, GitHub org or GitLab group
include_forks: false
graph_autoupdate: off              # on: refresh the structural graph after each git commit
neo4j_uri_env: NEO4J_URI           # optional Neo4j you already run (env var NAMES; values never stored)
neo4j_user_env: NEO4J_USER
neo4j_password_env: NEO4J_PASSWORD
context_paths:                     # always ingested as context (docs, diagrams, IaC, CSPM exports)
  - ./docs/architecture
  - ./security/prowler-output.ocsf.json
---

Notes for this project's ckb runs (optional free text; ckb treats it as user guidance).
