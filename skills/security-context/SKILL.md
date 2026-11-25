---
name: security-context
description: >-
  Generates concise, machine-friendly context.md files (one per repo plus one system-level) that brief
  a security scanner or reviewer on purpose and tech stack, entry points and trust boundaries, the
  authn/authz model, sensitive data flows, dangerous sinks and existing sanitizers (to cut false
  positives), known-safe patterns and risky areas, inter-service contracts, behavior-changing config,
  and prioritized scanner focus areas, all cited, with a YAML front-matter header. Use whenever
  someone wants to prepare a codebase for a SAST or LLM security scanner, write security context or a
  "security brief" for reviewers, reduce scanner false positives, tell a scanner where to focus, or
  asks for a context.md. Part of the ckb pipeline (/ckb:context).
---

# Security context for scanners

Produce `repos/<repo>/context.md` for each repo and `system/context.md`. The reader is a scanner (SAST, LLM-based reviewer) or a security engineer with five minutes, so be concise, structured, and cited, and don't repeat the full threat model.

Follow `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`. Template: `${CLAUDE_PLUGIN_ROOT}/shared/templates/context.md`. Keep the nine numbered sections in order with their exact headings, because consumers parse them.

## When invoked outside a /ckb command

- If the user only wants an answer in chat (for example "how does X work?"), apply the method below and answer inline with `repo/path:line` citations. Write no files.
- If the user wants documents written, or a target isn't yet in `<out>/evidence/targets.json`, first run P0–P2 from `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`: settings, the authorization question, and `fetch_source.py` registration. Never skip the authorization question.
- `<out>` is the ckb output dir (pipeline.md P0; default `<target>/.ckb`). All `repos/…`, `system/…`, `diagrams/…`, and `evidence/…` paths are relative to `<out>`.

## Inputs

`repos/<repo>/context-facts.md` and `evidence/context-facts-<repo>.json` (run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/context_facts.py" --out <out>` if they are missing; `graph_build.py --enrich` writes them), `repos/<repo>/code-map.md`, `overview.md`, `flows.md`, `outputs-and-conditions.md`, `system/data-flows.md`, `system/threat-model.md`, and `supply-chain.md` if present. If the threat model is missing, run `threat-modeling` first: section 9 depends on it.

## Facts first, judgement beside them

The facts file is deterministic (from the knowledge graph), so do not re-derive or retype it:

1. Embed `repos/<repo>/context-facts.md` verbatim, markers included, under `## Facts (generated)`. `check_outputs.py` (check F1) fails the file if the block is edited or stale.
2. Copy `repo_kind`, `entry_points`, `sources`, `sinks`, `core_files`, `test_files` into the front matter from the facts JSON.
3. In the numbered sections, add what only reading can add: the boundary and real exposure of each entry point, the auth you verified, the sanitizer or guard at each sink and a final verdict, and which `[inferred]` rows you confirmed or dropped. Quote the facts tables' citations; do not paste their rows again.
4. Adapt to the repo kind. `application`/`service`/`library`: sections as below. `iac`/`gitops-config`: section 2 is provisioned resources and their exposure (public ingress, public storage, wildcard IAM, encryption off, unpinned module/image sources) and section 5 is the privileged operations they allow. `cicd-pipeline`: section 2 is triggers and blast radius (who can start each pipeline, with which token, on which runner, from forks or not), section 5 is privileged steps (deploys, secrets, service connections, third-party code and whether it is pinned). `mixed`: cover each part that has content. Keep the numbered headings exactly as in the template.
5. Core vs utility vs test labels are [inferred] from graph signals: use them to point the scanner at core files first and to tell it which files are tests or generated, not as facts.

## How to fill each section

Use the headings exactly as written in the template. The list below abbreviates them. Put front matter first, then the provenance block, then the sections.

1. **Purpose and tech stack:** two lines and a bullet list of language, framework, and datastore, each cited.
2. **Entry points and trust boundaries:** a table with exposure (internet, internal, admin, CI) and the boundary crossed.
3. **Authn/authz model:** where identity is established and checked, the role model, bypass toggles (with defaults), and service-to-service auth. Cite the check sites.
4. **Sensitive data:** each field or class, where it enters, where it's stored and sent, and how it's protected (or `none observed`).
5. **Dangerous sinks and sanitizers:** every SQL, command, eval, template, deserialization, SSRF, and path sink with its sanitizer or parameterization and a verdict (`safe: parameterized`, `UNSAFE: string-built`, `[unknown]`). This section exists so scanners stop flagging safe code and focus on the real issues, so be exact.
6. **Known-safe patterns and known-risky areas:** short bullets for each, cited.
7. **Inter-service contracts:** producer, consumer, contract file, and the auth on the channel.
8. **Config and env conditions:** only the `[security]` rows from outputs-and-conditions, in the same `condition | effect | default | source` form.
Cloud and context: section 2 includes internet exposure from IaC and CSPM, section 6 lists open CSPM findings and documented-vs-observed drift under known-risky areas, and section 9 prioritizes paths where drift or CSPM findings meet code sinks.

9. **Threat-model summary and scanner focus:** a prioritized table: priority, focus area, paths (globs or files), why, threat IDs. Put scanner-actionable items first.

**Front matter:** fill in `languages`, `repo_kind`, the counts from the facts JSON, and `focus_areas` (short kebab-case tags such as `sqli`, `ssrf`, `authz-bypass`, `idor`, `ci-pwn-request`). Also fill in `scope`, `revision`, and `generated`. Leave `ckb_context: 1` as is: it's the format version.

**System file:** the same nine sections across repos. Emphasize boundaries between services, shared datastores, and contracts. Link to each repo's context.md rather than repeating it.

Aim for a context.md that fits on two screens per repo. Put detail in the linked documents and keep the high-signal summary here.
