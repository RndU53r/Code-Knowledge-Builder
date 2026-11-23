---
# Copy to <your project>/.claude/code-knowledge-builder.local.md (git-ignored). All fields optional.
output_dir: ./.ckb
scratch_dir: /tmp/ckb
exclude_paths:
  - "docs/legacy/**"
  - "**/testdata/**"
token_env: GITHUB_TOKEN            # or GITLAB_TOKEN; the value is read from the environment, never stored
gitlab_base_url: https://gitlab.com
advisory_lookup: off               # on = send package names+versions to api.osv.dev for CVE lookups
---

Notes for this project's ckb runs (optional free text; ckb treats it as user guidance).
