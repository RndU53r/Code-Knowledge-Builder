---
name: outputs-and-conditions
description: >-
  Documents every meaningful output a codebase produces (API responses and error bodies, published
  events, DB and cache writes, files and reports, external calls, security-relevant logs and metrics),
  covering what is produced (shape and schema), how (the cited function chain), when (every condition,
  including env vars and their defaults, feature flags, config toggles, auth or role branches,
  validation, and error and retry paths, as a condition | effect | default | source table), and who
  consumes it across repos. Use when someone asks what a service returns or emits, under which
  conditions behavior changes, what a flag or env var does and what its default is, what a caller sees
  on error, or wants a behavior or contract reference, e.g. "what does this endpoint return when...",
  "what happens if PUBLISH_EVENTS is unset". Part of the ckb pipeline (/ckb:analyze, /ckb:full).
---

# Outputs and conditions

Produce `repos/<repo>/outputs-and-conditions.md` for each repo, and `system/outputs-and-conditions.md`, which indexes cross-repo outputs and their consumers.

Follow `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`. Template: `${CLAUDE_PLUGIN_ROOT}/shared/templates/outputs-and-conditions.md`.

## When invoked outside a /ckb command

- If the user only wants an answer in chat (for example "how does X work?"), apply the method below and answer inline with `repo/path:line` citations. Write no files.
- If the user wants documents written, or a target isn't yet in `<out>/evidence/targets.json`, first run P0–P2 from `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`: settings, the authorization question, and `fetch_source.py` registration. Never skip the authorization question.
- `<out>` is the ckb output dir (pipeline.md P0; default `<target>/.ckb`). All `repos/…`, `system/…`, `diagrams/…`, and `evidence/…` paths are relative to `<out>`.

## 1. Enumerate outputs

Start from `flows.md` (outbound edges and handler returns) and the inventory's config candidates. `references/output-catalogue.md` lists what counts. Skip trivial outputs such as debug logs with no data. Keep logs and metrics that carry sensitive data or drive alerts.

Give each output an ID (`O-<repo>-<n>`) and fill in:
- **What:** shape and schema. Cite the response model, serializer, schema file, struct, or SQL columns. If the shape is built ad hoc, list the keys you see and cite the construction site.
- **How:** the function chain from trigger to emission, `handler → service → repo.save`, each hop cited.
- **Who consumes:** cross-repo consumers from `system/data-flows.md`, cited at the consumer. Write `[unknown]` when no consumer is in scope. In the per-repo pass, if `system/data-flows.md` doesn't exist yet, write `[unknown]: pending system stage`. The system-index pass (§3) fills in consumers afterwards.

## 2. Enumerate conditions (the important part)

For each output, list every condition that changes whether it's produced or what it contains. Read the code paths around the emission and look for:
- env vars and config reads, and their **defaults** (`os.environ.get("X", "50")` has default `"50"`; a missing default means unset or crash, so check which);
- feature flags (flag-service calls, booleans from config);
- auth and role branches (missing token, wrong role, auth-disabled toggles);
- validation failures (status code and body);
- error, retry, and timeout paths (what's returned or emitted instead, retry counts, Nack/requeue/DLQ);
- optional fields (present only when ...);
- environment-specific behavior (dev vs prod checks).

Write them as a table, one row per condition:

| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `PUBLISH_EVENTS` != "true" | `order.created` not published; function returns False | `"true"` (published) | `orders/app/events.py:9` «PUBLISH_EVENTS = os.environ.get("PUBLISH_EVENTS", "true") == "true"» |

The **Default** column records what happens when nobody sets anything. Security reviewers and scanners rely on it most, because insecure defaults live there.

## 3. System index

`system/outputs-and-conditions.md` lists outputs that cross repo boundaries (events, APIs called by other repos, shared tables), linking to each repo's detailed entry. It also has a combined table of conditions that affect more than one repo (for example a flag that disables publishing and so starves a consumer).

Mark security-relevant conditions (auth bypass toggles, debug modes, permissive defaults, disabled verification) by starting the Condition cell with `[security]`. `threat-modeling` and section 8 of `security-context` pick these rows up.
