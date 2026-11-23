# Severity rubric

- **critical:** code runs on install or CI that fetches and executes remote or obfuscated content; `pull_request_target` checking out PR code; agent-directed text combined with a dangerous imperative (fetch-and-run, exfiltrate, disable safety).
- **high:** script injection in CI, secrets printed, hidden or bidi Unicode in code, eval of decoded content, committed live-looking credentials, third-party actions on mutable refs, remote ADD, `--extra-index-url`, HTTP repositories, agent-directed text.
- **medium:** missing lockfiles, git/URL dependencies, lifecycle scripts without obvious network use, root containers, unverified downloads, typosquat-like names, `latest` images, privileged pods.
- **low:** caret or tilde ranges with a lockfile present, first-party actions on tags, missing `permissions:` block, tag-pinned (not digest-pinned) images, curl|sh in docs.
- **info:** agent instruction files with benign content, git hook configs, recent build/CI commits.

Raise one level when the item sits in a release or deploy path; lower one level when it's test-only and never runs in CI.
