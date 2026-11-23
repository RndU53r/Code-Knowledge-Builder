# ckb pipeline: shared orchestration steps

Every `/ckb:*` command uses these steps. Follow `shared/safety-contract.md` throughout.

## P0. Settings

If `.claude/code-knowledge-builder.local.md` exists in the current project, read its YAML front matter. All fields are optional:

```yaml
output_dir: ./.ckb            # default: <first target>/.ckb, or ./.ckb when the targets are remote
scratch_dir: /tmp/ckb         # parent dir for remote clones
exclude_paths: ["docs/legacy/**"]
token_env: GITHUB_TOKEN       # env var holding a token for private repos (never printed)
gitlab_base_url: https://gitlab.example.com
advisory_lookup: off          # on: send package names and versions to OSV.dev
```

When the user names an output directory in their request, it wins.

## P1. Sources and authorization

1. Parse the sources from the arguments: local paths, `https://`/`ssh://`/`git@` URLs, `github:org/repo`, `gitlab:group/repo`. Treat `.` as the current directory. If there are none and the current directory is a repo, propose it.
2. **Ask before analyzing.** List every source, then ask the user to confirm they own each one or are authorized to audit it, in one question (AskUserQuestion when available). Don't proceed for any source that isn't confirmed. Exception: a non-interactive CI run (env `CI=true`) records `ci-implicit` and never pauses for input. This is the only definition of the CI rule, and the commands refer to it.
3. Write `<out>/evidence/authorization.md`: one row per source with the confirmation wording, the timestamp, and who confirmed it ("user in chat" or "ci-implicit").

## P2. Acquire and register

For each source:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/fetch_source.py" --out <out> [--key <name>] \
  [--scratch <scratch_dir>] [--token-env <VAR>] [--gitlab-base <url>] [--ref <branch>] <source>
```

This clones remote sources safely (hooks off, depth 1, no submodules, no LFS) and registers every source in `<out>/evidence/targets.json` and the user registry. Registration is what lets the guard hook block execution in the target and the verifier resolve citations. Use the printed `key` as the repo key in all citations. For a monorepo with several services, register each service directory separately with `--key <service>` so citations and per-repo docs line up with services.

## P3. Dispatch agents

- **Per-repo stages** run in parallel. Send one Agent call per repo in the same message:
  - `ckb:repo-analyzer` for inventory, code analysis, per-repo HLD/LLD/flows, and outputs-and-conditions.
  - `ckb:supply-chain-auditor` for the supply-chain audit.
- **System stages** run after every per-repo stage has finished: `ckb:flow-tracer` (`system/data-flows.md`, `system/hld.md`, `system/outputs-and-conditions.md`), then the system supply-chain report (if any audit ran), then `ckb:threat-modeler`, then the context files (`security-context` skill).
- **Verification:** after each stage, run `ckb:citation-verifier` on the files that stage wrote. Hand failures back to the agent that wrote them (SendMessage to it when possible, otherwise a fresh agent with the error list). Allow at most two fix rounds, then record the remaining failures in `evidence/verification.md` and report them.

Give each agent a prompt with: `<out>`, the repo key(s) and roots, the stage to run, the template to use, and "follow ${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md".

## P4. Finish

1. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/verify_citations.py" --out <out> --report <out>`
2. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/check_outputs.py" <out>`
3. `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/hash_index.py" snapshot --out <out>`
4. Write or refresh `<out>/index.md` from `shared/templates/index.md`, and `<out>/evidence/citations.md` (every citation used, grouped by repo and file).
5. Tell the user: where the outputs are, the top findings (severity, one line each, with citation), verification status, and anything left as `[unknown]` that matters.
