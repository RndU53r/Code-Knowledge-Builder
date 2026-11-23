# Knowledge base: polyglot order platform + poisoned package

> **ckb provenance**
> - Sources: `gateway`, `orders`, `fulfillment`, `platform` (./polyglot), `poisoned` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `full`
> - Scope: five registered local sources · Excluded: none; no secret files, binaries or symlinks found
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Navigate

| Area | File | Summary |
| --- | --- | --- |
| System HLD | [system/hld.md](system/hld.md) | gateway → orders → RabbitMQ → fulfillment, shared Postgres; edge-only auth |
| Data flows | [system/data-flows.md](system/data-flows.md) | 10 edges (REST x2, AMQP, subprocess, shared table x2, externals), contract drift, unmatched endpoints |
| Outputs and conditions | [system/outputs-and-conditions.md](system/outputs-and-conditions.md) | cross-repo outputs; flags `AUTH_DISABLED`, `PUBLISH_EVENTS` |
| Threat model | [system/threat-model.md](system/threat-model.md) | 16 STRIDE threats; SQLi and CI pwn-request critical |
| Scanner context | [system/context.md](system/context.md) | sinks with verdicts and scanner focus |
| Supply-chain report | [system/supply-chain-report.md](system/supply-chain-report.md) | 47 findings; all 21 confirmed-suspicious in poisoned |

## Repos

| Repo | Role | Languages | Overview |
| --- | --- | --- | --- |
| gateway | public API, JWT auth, proxy | JavaScript | [overview](repos/gateway/overview.md) |
| orders | order service, pricing subprocess, events | Python | [overview](repos/orders/overview.md) |
| fulfillment | queue worker and pricing CLI | Go | [overview](repos/fulfillment/overview.md) |
| platform | monorepo root: contracts, deploy, CI | YAML/JSON | [overview](repos/platform/overview.md), [supply chain](repos/platform/supply-chain.md) |
| poisoned | hostile npm package (test fixture) | JavaScript | [overview](repos/poisoned/overview.md) |

## Top findings

| # | Finding | Severity | Confidence | Where |
| --- | --- | --- | --- | --- |
| 1 | SQL injection in orders read path, reachable via gateway (T1) | critical | high | `orders/app/db.py:23` |
| 2 | CI pwn request: `pull_request_target` + PR head checkout + script injection + secret echo (T13) | critical | high | `poisoned/.github/workflows/pr-label.yml:11` |
| 3 | Install/commit-time RCE: postinstall, husky hook, eval of encoded payload, host beacon (T14) | critical (supply chain) | high | `poisoned/package.json:5` `poisoned/scripts/setup.js:5` |
| 4 | Prompt injection aimed at AI agents in 4 files (T15) | critical (supply chain) | high | `poisoned/README.md:10` |
| 5 | SSRF in admin report (T2) | high | high | `gateway/src/server.js:32` |
| 6 | `AUTH_DISABLED` grants admin to all callers (T3) | high | high | `gateway/src/auth.js:8` |
| 7 | IDOR on order reads; unhandled rejection can crash gateway (T4, T5) | high | high / medium | `gateway/src/server.js:27` |
| 8 | Unauthenticated internal channels: orders API and broker events (T6, T7) | high | medium | `orders/app/main.py:19` |

## Evidence

- Citation index: [evidence/citations.md](evidence/citations.md)
- Verification report: [evidence/verification.md](evidence/verification.md)
- Authorization record: [evidence/authorization.md](evidence/authorization.md)
- Diagram sources: `diagrams/*.mmd` (16 files); targets: `evidence/targets.json`; hashes: `evidence/hashes.json`
