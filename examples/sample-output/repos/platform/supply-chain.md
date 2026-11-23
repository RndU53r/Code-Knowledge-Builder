# platform: supply-chain and injection audit

> **ckb provenance**
> - Sources: `platform` @ `unversioned (local ./polyglot)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `supply-chain`
> - Scope: platform root incl. service subdirectories (24 files scanned) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Summary
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 1 |
| low | 0 | 7 |

Counts tally the triaged findings below. Five scanner findings duplicate service-level findings because the platform root contains the service directories; they are cross-referenced, not double counted in the system report. Advisory status [unknown] (lookups off).

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| PLATFORM-SC-001 | SC-D03 | risky-practice | medium | high | `platform/orders/Dockerfile:1` root container (same as ORDERS-SC-001) | Add `USER` |
| PLATFORM-SC-002 | SC-D01 | risky-practice | low | high | `platform/deploy/k8s/gateway.yaml:15` «image: registry.example.com/shop/gateway:1.0.0» tag not digest | Deploy by digest |
| PLATFORM-SC-M01 | manual | risky-practice | low | high | `platform/deploy/docker-compose.yml:20` «image: postgres:16» and `platform/deploy/docker-compose.yml:22` tag-only images | Pin by digest |
| PLATFORM-SC-M02 | manual | risky-practice | low | medium | `platform/deploy/k8s/gateway.yaml:13-19` no `securityContext` (runAsNonRoot, readOnlyRootFilesystem) | Add a restrictive securityContext |
| PLATFORM-SC-003 | SC-D01 | risky-practice | low | high | `platform/fulfillment/Dockerfile:1` (same as FULFILLMENT-SC-001) | Pin by digest |
| PLATFORM-SC-004 | SC-D01 | risky-practice | low | high | `platform/fulfillment/Dockerfile:6` (same as FULFILLMENT-SC-002) | Pin by digest |
| PLATFORM-SC-005 | SC-D01 | risky-practice | low | high | `platform/gateway/Dockerfile:1` (same as GATEWAY-SC-001) | Pin by digest |
| PLATFORM-SC-006 | SC-D01 | risky-practice | low | high | `platform/orders/Dockerfile:1` (same as ORDERS-SC-002) | Pin by digest |
| PLATFORM-SC-007 | SC-M02 | risky-practice | low | medium | `platform/orders/requirements.txt:1` (same as ORDERS-SC-003) | Hash-pinned requirements |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub Actions | actions/checkout | commit SHA | yes | GitHub | not checked | `platform/.github/workflows/ci.yml:9` |
| GitHub Actions | actions/setup-go | commit SHA | yes | GitHub | not checked | `platform/.github/workflows/ci.yml:10` |
| Docker | postgres | 16 | tag only | Docker Hub | not checked | `platform/deploy/docker-compose.yml:20` |
| Docker | rabbitmq | 3-management | tag only | Docker Hub | not checked | `platform/deploy/docker-compose.yml:22` |
| service deps | see repos/gateway, repos/orders, repos/fulfillment supply-chain.md | n/a | n/a | n/a | not checked | `platform/gateway/package.json:6-10` |

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| CI/CD | unpinned actions, pull_request_target, script injection, token scope, secret echo | clean: SHA pins, `contents: read` `platform/.github/workflows/ci.yml:3-4` |
| Containers and IaC | base pins, USER, K8s images | tag-only images; orders root |
| Agent-targeted text | README, docs | none; README warning is benign `platform/README.md:4` |
| Obfuscation, hidden Unicode, secrets | scanner patterns | none found |

## Investigated, not an issue
- CI runs `go test` on `pull_request` (not `pull_request_target`) with read-only token, so fork PRs get no secrets. `platform/.github/workflows/ci.yml:2-4`
- `JWT_SECRET` in compose is an interpolation from the host env, not a committed value. `platform/deploy/docker-compose.yml:7`

## Limitations
- Not a git checkout: commit-history checks skipped `[unknown]` (scanner limitation; `evidence/sc-platform.json`).
- Advisory lookups off: every dependency is "not checked" for known CVEs `[unknown]`.
