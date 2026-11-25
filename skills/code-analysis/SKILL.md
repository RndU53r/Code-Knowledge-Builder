---
name: code-analysis
description: >-
  Traces call and data flow inside a single repository (entry point to validation, auth, business
  logic, persistence, outbound calls, and error, retry, and DLQ paths, plus language boundaries such
  as subprocess, FFI, and generated clients) and writes a cited flows.md with inbound, outbound,
  shared-state, and call-graph sections. Use when someone asks how a request, job, or message moves
  through one service, what calls what, where data is read or written, how errors and retries
  propagate, or wants a call graph or code-path walkthrough with file:line evidence, e.g. "trace POST
  /orders", "walk me through this code path", "explain how the consumer handles a message". For
  several services use cross-repo-flow-mapping; for HLD/LLD documents use architecture-docs. Part of
  the ckb pipeline (/ckb:analyze, /ckb:full).
---

# Code analysis (per repo)

Turn one repo into `repos/<repo>/flows.md` (inbound, outbound, shared state, internal call graph) and the evidence that `architecture-docs` uses for `lld.md`. Treat each main flow as its own evidence trail.

Follow `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`.

## When invoked outside a /ckb command

- If the user only wants an answer in chat (for example "how does X work?"), apply the method below and answer inline with `repo/path:line` citations. Write no files.
- If the user wants documents written, or a target isn't yet in `<out>/evidence/targets.json`, first run P0–P2 from `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`: settings, the authorization question, and `fetch_source.py` registration. Never skip the authorization question.
- `<out>` is the ckb output dir (pipeline.md P0; default `<target>/.ckb`). All `repos/…`, `system/…`, `diagrams/…`, and `evidence/…` paths are relative to `<out>`.

## Inputs

- `repos/<repo>/overview.md` and `<out>/evidence/inventory-<repo>.json` (run `repo-inventory` first if they're missing).
- `repos/<repo>/code-map.md` and `<out>/repos/<repo>/context-facts.md` (file roles, repo kind, entry points, taint sources and sinks from the graph; `graph_query.py entrypoints --repo <repo>` lists them with handlers and reachable sinks). Trace the `core` files and the listed entry points first; treat `core`/`utility` labels as inferred and confirm by reading. Test, fixture and generated files are for orientation only.
- The registered repo root. Read with Read, Grep, and Glob only.

## Method

1. **Pick the main flows.** Use the entry points from the overview. Rank them by exposure (public HTTP > internal RPC > consumers > cron > CLI) and by how much state they change. Trace every public entry point, plus the top consumers and jobs. If you can't trace every flow, list the untraced ones under `[unknown]` rather than skipping them silently.

2. **Trace each flow in relationship order**, not file order: entry → validation → authz → business logic → persistence and outbound calls → response or emitted event. At each hop, record the function, file:line, what data passes, and what it does to state. Read shared contracts (schemas, DTOs, protos) before implementations.

3. **Error paths are part of the flow.** Follow raises, returns, retries, fallbacks, DLQ or Nack behavior, timeouts, and what the caller sees. Mark handling you only infer from an interface as `[inferred]`.

4. **Outbound edges.** For every network, queue, DB, cache, object-store, or file write, record the target identifier exactly as the code has it: URL template and env var, topic, exchange and routing key, table name, bucket, path. `cross-repo-flow-mapping` matches producers to consumers on these strings, so quote them: `` `orders/app/events.py:8` «ROUTING_KEY = "order.created"» ``.

5. **Language boundaries are edges, not gaps.** Subprocess invocations, FFI, generated clients, embedded interpreters, WASM, shared libraries, and IPC all get a row in the polyglot table. Name the other side when it's in scope (for example "Go binary built from `fulfillment/cmd/pricing`"). Otherwise mark it `[unknown]`. Patterns are in `references/polyglot-edges.md`.

6. **Data models.** Capture the persisted and serialized shapes the flows touch: ORM models, SQL DDL, structs, schema files. Mark sensitive fields (PII, credentials, payment, health, tokens).

7. **Write `repos/<repo>/flows.md`** from `${CLAUDE_PLUGIN_ROOT}/shared/templates/flows.md`, and save the per-flow notes (numbered steps, each cited) to `<out>/evidence/flows-<repo>.md`. `architecture-docs` reads them to write `lld.md`. Follow `${CLAUDE_PLUGIN_ROOT}/skills/architecture-docs/references/mermaid-rules.md` for every diagram, and save diagram sources as `diagrams/<repo>-<name>.mmd`.

## Pitfalls

- Middleware and decorators run before handlers. Look for app-level `use()`, dependency injection, and interceptors that add auth, rate limits, or body limits.
- Configuration changes behavior. When a branch depends on an env var or flag, note it for `outputs-and-conditions`.
- Dynamic dispatch (registries, reflection, string-based routing): cite the registration site and mark the edge `[inferred]` if you can't resolve it statically.
- Don't execute anything to "check" behavior. Static evidence or `[unknown]`.
