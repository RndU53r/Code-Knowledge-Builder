---
name: architecture-docs
description: >-
  Writes cited architecture documentation from static analysis, covering a system-level HLD
  (components, boundaries, external dependencies, deployment topology from infra files only) and, per
  repository, an HLD and an LLD (modules, key types and functions, Mermaid sequence diagrams for main
  flows, data models, error handling). Use whenever someone asks for architecture docs, an HLD or LLD,
  a system design write-up, component, sequence, or deployment diagrams, or to "document how this
  system is built" for one or many existing repos, including when they just want diagrams of a
  codebase. Builds on repo-inventory and code-analysis output and runs them first if missing. Part of
  the ckb pipeline (/ckb:analyze, /ckb:full).
---

# Architecture docs (HLD and LLD)

Turn the analysis evidence into three kinds of document:

| File | Scope | Built from |
| --- | --- | --- |
| `system/hld.md` | Whole system | `system/data-flows.md`, all `overview.md` files, infra artifacts |
| `repos/<repo>/hld.md` | One repo | its `overview.md`, `flows.md` |
| `repos/<repo>/lld.md` | One repo | `evidence/flows-<repo>.md` (per-flow notes from `code-analysis`), data models, error paths |

Follow `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`. Use the templates in `${CLAUDE_PLUGIN_ROOT}/shared/templates/` (`hld.md`, `lld.md`).

## When invoked outside a /ckb command

- If the user only wants an answer in chat (for example "how does X work?"), apply the method below and answer inline with `repo/path:line` citations. Write no files.
- If the user wants documents written, or a target isn't yet in `<out>/evidence/targets.json`, first run P0–P2 from `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`: settings, the authorization question, and `fetch_source.py` registration. Never skip the authorization question.
- `<out>` is the ckb output dir (pipeline.md P0; default `<target>/.ckb`). All `repos/…`, `system/…`, `diagrams/…`, and `evidence/…` paths are relative to `<out>`.

If `overview.md` or `flows.md` is missing, run `repo-inventory` and `code-analysis` first.

## HLD

- **Component diagram:** one component flowchart per HLD.
- **Components:** each runtime unit (service, worker, job, lambda, datastore, broker, gateway) with its responsibility in one sentence, its tech, and a citation.
- **Boundaries and externals:** network exposure (from ingress, gateway, compose ports, Terraform security groups), third-party APIs, managed services. If exposure can't be established, mark it `[unknown]`. Don't assume a service is internal or public.
- **Deployment topology:** only what the infra artifacts show (replicas, namespaces, images, env injection, ingress hosts). With no infra files, write `[unknown]: no deployment artifacts in scope` instead of drawing a guess.
- **Decisions and constraints:** only those evidenced in code or config, such as timeouts, body limits, idempotency keys, or retry policies.

## LLD

- **Modules:** packages or directories with their responsibility, key types and functions, and a citation for each.
- **Main flows:** one `sequenceDiagram` per main flow, with the numbered steps below it, each step cited. Include the error branch (`alt`/`else`) when the code has one.
- **Data models:** fields, with sensitive fields marked, and where they're persisted.
- **Error handling:** where errors arise, how they're handled (retry, fallback, propagate, swallow), and what the user or caller sees.
- **Polyglot edges:** copied from `flows.md`, with the build-target link.

## Diagram rules

Read `references/mermaid-rules.md` before writing any diagram. The short version: synthetic IDs, short labels you write yourself (never raw target strings), no `click` directives or HTML, one concept per diagram. Save each diagram's source to `diagrams/<scope>-<name>.mmd` as well as embedding it. `check_outputs.py` (run by the PostToolUse hook) rejects unbalanced or interactive diagrams.

Keep prose short. Tables and diagrams carry the structure, and citations carry the proof.
