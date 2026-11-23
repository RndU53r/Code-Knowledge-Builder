# platform: overview

> **ckb provenance**
> - Sources: `platform` @ `unversioned (local ./polyglot)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: platform root: contracts/, deploy/, .github/, README.md (service subdirectories are documented under their own keys) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Purpose
Monorepo root holding the three services plus shared contracts, deployment manifests, and CI. `platform/README.md:3` «Three services that talk over HTTP and a queue, plus a shared database and contract.»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Contract | OpenAPI | 3.0.3 | `platform/contracts/orders.openapi.yaml:1` «openapi: 3.0.3» |
| Contract | JSON Schema for `order.created` | n/a | `platform/contracts/order_created.schema.json:2` «"$id": "order.created",» |
| Deploy | docker compose (5 services) | n/a | `platform/deploy/docker-compose.yml:1-22` |
| Deploy | Kubernetes Deployment + Ingress (gateway only) | apps/v1, networking.k8s.io/v1 | `platform/deploy/k8s/gateway.yaml:1` `platform/deploy/k8s/gateway.yaml:21` |
| CI | GitHub Actions | n/a | `platform/.github/workflows/ci.yml:1-12` |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| CI | `ci` on push and pull_request | `go test` in fulfillment | `platform/.github/workflows/ci.yml:2` «on: [push, pull_request]» |
| ingress | `shop.example.com` → gateway:3000 | gateway | `platform/deploy/k8s/gateway.yaml:27-33` |
| service code | see `repos/gateway`, `repos/orders`, `repos/fulfillment` | n/a | `platform/README.md:6-8` |

## Dependencies (direct)
| Name | Version spec | Registry or source | Manifest |
| --- | --- | --- | --- |
| actions/checkout | SHA 692973e… | GitHub | `platform/.github/workflows/ci.yml:9` |
| actions/setup-go | SHA 0a12ed9… | GitHub | `platform/.github/workflows/ci.yml:10` |
| postgres image | 16 (tag) | Docker Hub | `platform/deploy/docker-compose.yml:20` «image: postgres:16» |
| rabbitmq image | 3-management (tag) | Docker Hub | `platform/deploy/docker-compose.yml:22` «image: rabbitmq:3-management» |

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| compose | only gateway publishes a port (3000); orders and fulfillment use separate DB users on one DB `shop` | `platform/deploy/docker-compose.yml:4` `platform/deploy/docker-compose.yml:11` `platform/deploy/docker-compose.yml:16` |
| compose | broker URLs carry no credentials; postgres has no password env | `platform/deploy/docker-compose.yml:12` `platform/deploy/docker-compose.yml:19-20` |
| K8s | gateway 2 replicas; no securityContext, NetworkPolicy, or JWT secret wiring in scope | `platform/deploy/k8s/gateway.yaml:6-19` |
| CI | token permissions restricted to `contents: read`; actions pinned by SHA | `platform/.github/workflows/ci.yml:3-4` |

## Exclusions and unknowns
- No prompt-injection text found. README line 4 is a benign warning not addressed to tools (`platform/README.md:4`).
- `[unknown]` K8s manifests for orders, fulfillment, postgres, rabbitmq: not in scope.
