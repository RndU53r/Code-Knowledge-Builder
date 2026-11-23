# ckb supply-chain check catalogue

| ID | Category | Check |
| --- | --- | --- |
| SC-M01 | manifests | floating or unpinned version (`^`, `~`, `*`, `latest`, `>=`, missing `==`, SNAPSHOT, Gradle `+`) |
| SC-M02 | manifests | missing lockfile (npm, pip without hashes or lock, go.sum, Cargo.lock for binaries, Gemfile.lock) |
| SC-M03 | manifests | git, URL, or path dependency; go `replace` |
| SC-M04 | manifests | typosquat-like name (one edit from a popular package, transpositions included) |
| SC-M05 | manifests | non-default registry or index, HTTP repositories, lockfile entries resolved off-registry |
| SC-M06 | manifests | dependency confusion (`--extra-index-url`, unmapped internal npm scopes) |
| SC-M07 | manifests | lockfile and manifest drift |
| SC-I01 | install-time | npm/composer lifecycle scripts (preinstall/install/postinstall/prepare) |
| SC-I02 | install-time | setup.py network, process, or dynamic execution; cmdclass overrides |
| SC-I03 | install-time | remote script piped to a shell (`curl \| sh`, `iwr \| iex`) |
| SC-I04 | install-time | Gradle remote `apply from`, exec tasks, Maven exec or antrun plugins, remote CI includes |
| SC-C01 | ci-cd | action pinned to a mutable ref instead of a 40-char SHA |
| SC-C02 | ci-cd | `pull_request_target` (critical when it checks out PR head) |
| SC-C03 | ci-cd | untrusted `${{ github.event.* }}` / `github.head_ref` inside `run:`; GitLab unquoted MR variables |
| SC-C04 | ci-cd | missing `permissions:`, `write-all`, broad write scopes |
| SC-C05 | ci-cd | secrets echoed, `secrets: inherit` |
| SC-D01 | containers-iac | image not pinned by digest (`latest` or no tag is worse) |
| SC-D02 | containers-iac | `ADD https://…` |
| SC-D03 | containers-iac | container runs as root |
| SC-D04 | containers-iac | binary downloaded without checksum or signature verification |
| SC-D05 | containers-iac | privileged pod settings; ingress 0.0.0.0/0 |
| SC-D06 | containers-iac | Terraform module without a pinned ref |
| SC-S01 | source-indicators | long base64/hex blobs (high when near a decoder or eval) |
| SC-S02 | source-indicators | eval/exec/Function of fetched or decoded content |
| SC-S03 | source-indicators | network or process calls in import-time or build-time files |
| SC-S04 | source-indicators | bidi controls (Trojan Source), zero-width characters, mixed-script identifiers |
| SC-S05 | source-indicators | recent commits touching build or CI files (needs history) |
| SC-S06 | source-indicators | committed binaries |
| SC-S07 | source-indicators | repo-managed git hooks (husky, lefthook, .githooks, pre-commit) |
| SC-S08 | secrets | secret-looking values (type and location only, value redacted) |
| SC-S09 | secrets | secret-bearing files committed (`.env`, keys, keystores) |
| SC-A01 | prompt-injection | text addressed to AI agents; hidden HTML comments with directives |
| SC-A02 | prompt-injection | agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions) and the commands they contain |
