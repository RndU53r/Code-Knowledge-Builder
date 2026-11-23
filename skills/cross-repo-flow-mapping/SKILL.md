---
name: cross-repo-flow-mapping
description: >-
  Maps how multiple repositories or microservices talk to each other, matching producers to consumers
  across sync calls (REST, gRPC, GraphQL, SDKs), async messaging (Kafka, SQS, RabbitMQ, pub/sub,
  webhooks), shared state (databases, caches, buckets, files), shared contracts (OpenAPI, protobuf,
  schemas), and polyglot boundaries, into a cited system data-flow document with Mermaid diagrams. Use
  whenever someone has more than one repo or service and asks how they connect, who calls whom, who
  consumes an event or topic, what breaks if a service changes, or wants an end-to-end request trace
  across services, even without the words "cross-repo" or "data flow". Also use for "what external
  services or third-party APIs does this call". Part of the ckb pipeline.
---

# Cross-repo flow mapping

Produce `system/data-flows.md`: every edge between in-scope repos and to external systems, with producer and consumer evidence, plus end-to-end sequence diagrams of the main business flows.

Follow `${CLAUDE_PLUGIN_ROOT}/shared/safety-contract.md` and `${CLAUDE_PLUGIN_ROOT}/shared/evidence-model.md`.

## When invoked outside a /ckb command

- If the user only wants an answer in chat (for example "how does X work?"), apply the method below and answer inline with `repo/path:line` citations. Write no files.
- If the user wants documents written, or a target isn't yet in `<out>/evidence/targets.json`, first run P0–P2 from `${CLAUDE_PLUGIN_ROOT}/shared/pipeline.md`: settings, the authorization question, and `fetch_source.py` registration. Never skip the authorization question.
- `<out>` is the ckb output dir (pipeline.md P0; default `<target>/.ckb`). All `repos/…`, `system/…`, `diagrams/…`, and `evidence/…` paths are relative to `<out>`.

## Inputs

`repos/*/overview.md` (from `repo-inventory`) and `repos/*/flows.md` (from `code-analysis`) for every repo, the inventory JSONs in `evidence/`, contract files, and infra artifacts (compose, K8s, Helm, gateway, Terraform), which often name the services that code only references through env vars.

## Matching method

Build two lists from the per-repo flows: **producers** (outbound calls, publishes, writes) and **consumers** (routes, subscriptions, reads). Then match them by the identifiers in `references/matching-rules.md`:

1. **Resolve indirection first.** An outbound URL like `${ORDERS_URL}/orders` resolves through env and config: compose `environment:`, K8s `env:`, Helm values, `.env.example` (names only, never secret values), and defaults in code. Cite each hop. If it can't be resolved, the edge stays at medium or low confidence.
2. **Match on the strongest key available:** contract operation (OpenAPI path and method, proto service and method) > exact topic, queue, or routing key > table or bucket name > hostname or service name > naming similarity. Record which key matched.
3. **Unmatched sides are findings, not noise.** A producer with no consumer (or the reverse) goes in the "Unmatched endpoints" table with `[unknown]`. It may be external, dead code, or a bug.
4. **Shared state.** When two repos write or read the same table, cache key prefix, or bucket path, add a shared-state edge. Shared writers are a high-value input for the threat model.
5. **Contracts.** Check that the producer and consumer agree with the contract. Field-name or type drift between a publisher's payload and a consumer's struct is worth a row, cited at both ends.
6. **External systems.** Third-party APIs, SaaS, cloud services, and LLM providers become external nodes with the call-site citation.

## Output

Write `system/data-flows.md` from `${CLAUDE_PLUGIN_ROOT}/shared/templates/data-flows.md`:
- An edges table using the template's columns.
- One system flowchart with synthetic IDs, edges labeled by mechanism, and external systems visually distinct.
- A sequence diagram for each main business flow, end to end across repos.
- Unmatched endpoints.

Follow `${CLAUDE_PLUGIN_ROOT}/skills/architecture-docs/references/mermaid-rules.md`, and save each diagram as `diagrams/system-<name>.mmd`.

With only one repo in scope, the edges table holds just the edges to external systems and shared stores. Still write every section.

A high-confidence edge cites both ends. A single-sided edge is medium at best. Never create an edge from naming alone without labeling it `[inferred]` and low.
