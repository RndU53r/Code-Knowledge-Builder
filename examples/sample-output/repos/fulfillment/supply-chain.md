# fulfillment: supply-chain and injection audit

> **ckb provenance**
> - Sources: `fulfillment` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `supply-chain`
> - Scope: fulfillment (6 files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Summary
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 0 |
| low | 0 | 2 |

Counts tally the triaged findings below; advisory status [unknown] (lookups off).

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| FULFILLMENT-SC-001 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:1` «FROM golang:1.22 AS build» | Pin by digest |
| FULFILLMENT-SC-002 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:6` «FROM gcr.io/distroless/static:nonroot» | Pin by digest |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| Go | github.com/lib/pq | v1.10.9 | yes (go.sum h1) | proxy | not checked | `fulfillment/go.mod:6` |
| Go | github.com/rabbitmq/amqp091-go | v1.10.0 | yes (go.sum h1) | proxy | not checked | `fulfillment/go.mod:7` |

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Manifests | go.sum presence | hashes present `fulfillment/go.sum:1-4` |
| Container | base pin, USER, multi-stage | distroless nonroot `fulfillment/Dockerfile:8` |
| Build | `COPY . .` in build stage | whole module context copied `fulfillment/Dockerfile:3`; no secrets files present |
| Obfuscation, hidden Unicode, secrets, agent text | scanner patterns | none found |

## Investigated, not an issue
- Final image is distroless and non-root. `fulfillment/Dockerfile:6-8`

## Limitations
- Not a git checkout: commit-history checks skipped `[unknown]` (scanner limitation; `evidence/sc-fulfillment.json`).
- Advisory lookups off: every dependency is "not checked" for known CVEs `[unknown]`.
