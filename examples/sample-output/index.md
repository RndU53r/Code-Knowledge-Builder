# Knowledge base: shop platform (gateway, orders, fulfillment, platform)

> **ckb provenance**
> - Sources: `gateway` @ `8c8444d`, `orders` @ `1de64cb` (read-only snapshot of main; checkout is on feature/wip), `fulfillment` @ `d2ffc20`, `platform` @ `f5659b3`; context `ctx-platform`
> - Generated: 2026-11-24T05:33:07Z by ckb 0.1.0, stage `index`
> - Scope: four local repos plus ingested architecture context · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Navigate

| Area | File | Summary |
| --- | --- | --- |
| System HLD | [system/hld.md](system/hld.md) | components, zones, cloud resources, documented vs observed |
| Data flows | [system/data-flows.md](system/data-flows.md) | 8 edges across REST, AMQP, subprocess, shared table |
| Outputs and conditions | [system/outputs-and-conditions.md](system/outputs-and-conditions.md) | response, event, DB write and their conditions |
| Threat model | [system/threat-model.md](system/threat-model.md) | refined: 27 threats after review, 6 added |
| Scanner context | [system/context.md](system/context.md) | nine-section brief for scanners |
| Supply-chain report | [system/supply-chain-report.md](system/supply-chain-report.md) | 0 critical, 6 high, 8 medium, 6 low; 1 prompt-injection item |
| Call graphs | [system/call-graphs.md](system/call-graphs.md) | function, file and repo call graphs |
| Documented vs observed | [system/documented-vs-observed.md](system/documented-vs-observed.md) | 11 drift rows |
| Knowledge graph | [system/graph.md](system/graph.md) | graph/index.html is the viewer |

## Repos

| Repo | Role | Languages | Overview |
| --- | --- | --- | --- |
| gateway | public edge | JavaScript | [overview](repos/gateway/overview.md) |
| orders | order API | Python | [overview](repos/orders/overview.md) |
| fulfillment | worker and pricing CLI | Go | [overview](repos/fulfillment/overview.md) |
| platform | IaC, contracts, docs | none (IaC) | [overview](repos/platform/overview.md) |

## Top findings

| # | Finding | Severity | Confidence | Where |
| --- | --- | --- | --- | --- |
| 1 | Public invoice bucket (T-04) | critical | high | `platform/deploy/terraform/aws/main.tf:8` |
| 2 | SQL injection in order lookup (T-14) | high | high | `orders/app/db.py:23` |
| 3 | orders has no authentication (T-29) | high | high | `orders/app/main.py:25` |
| 4 | Any user can read any order (T-33) | high | high | `gateway/src/server.js:27` |
| 5 | Negative quantity gives negative total (T-34) | high | high | `fulfillment/cmd/pricing/main.go:23` |

## Evidence

- Citation index: [evidence/citations.md](evidence/citations.md)
- Verification report: [evidence/verification.md](evidence/verification.md)
- Authorization record: [evidence/authorization.md](evidence/authorization.md)
