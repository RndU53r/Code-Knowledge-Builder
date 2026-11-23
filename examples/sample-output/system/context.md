---
ckb_context: 1
scope: system
revision: unversioned (local)
generated: 2026-11-23T10:00:00Z
languages: [javascript, python, go]
entry_points: 15
focus_areas: [sqli, ssrf, authz-bypass, idor, missing-service-auth, message-spoofing, ci-pwn-request, install-time-rce, prompt-injection]
---
# Security context: system

> **ckb provenance**
> - Sources: `gateway`, `orders`, `fulfillment`, `platform`, `poisoned` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `context`
> - Scope: all five repos · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## 1. Purpose and tech stack
Order platform: Express gateway → FastAPI orders → RabbitMQ → Go fulfillment, sharing one Postgres; plus an unrelated hostile npm package (`poisoned`). Per-repo detail: [gateway](../repos/gateway/context.md), [orders](../repos/orders/context.md), [fulfillment](../repos/fulfillment/context.md), [poisoned](../repos/poisoned/context.md).
- JavaScript `gateway/package.json:7`, Python `orders/requirements.txt:1`, Go `fulfillment/go.mod:3`, Postgres 16 `platform/deploy/docker-compose.yml:20`, RabbitMQ 3 `platform/deploy/docker-compose.yml:22`.

## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| gateway routes (4) | internet | TB1 | `platform/deploy/k8s/gateway.yaml:27` `gateway/src/server.js:11-31` |
| orders routes (2) | internal | TB2 | `orders/app/main.py:25` `orders/app/main.py:37` |
| fulfillment queue + pricing CLI (2) | internal | TB3 | `fulfillment/internal/queue/consumer.go:30` `fulfillment/cmd/pricing/main.go:14` |
| poisoned install, hook, CI, library, agent text (5) | developer, CI, agents | TB6 | `poisoned/package.json:5` `poisoned/.github/workflows/pr-label.yml:3` |
| platform CI (1), ingress (1) | CI, internet | n/a | `platform/.github/workflows/ci.yml:2` |

## 3. Authn/authz model
- Edge-only JWT at gateway; internal hops unauthenticated. `gateway/src/auth.js:17` `orders/app/main.py:25`
- Bypass toggle `AUTH_DISABLED` (default off) yields admin. `gateway/src/auth.js:4-9`
- No ownership checks on order reads. `gateway/src/server.js:26-27`

## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| card_last4 | client → gateway → orders | Postgres | none observed | `orders/app/db.py:15` |
| shipping_address | client → orders | RabbitMQ → fulfillment → shipping API | HTTPS to shipping only | `orders/app/events.py:22` `fulfillment/cmd/worker/main.go:27` |
| JWT secret, shipping key | env | gateway, fulfillment | env only; K8s wiring [unknown] | `gateway/src/auth.js:3` `fulfillment/cmd/worker/main.go:23` |

## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Effective? | Source |
| --- | --- | --- | --- | --- |
| orders SELECT | SQL | none | UNSAFE: string-built | `orders/app/db.py:23` |
| orders INSERT | SQL | parameterized | safe: parameterized | `orders/app/db.py:15` |
| fulfillment UPDATE | SQL | parameterized | safe: parameterized | `fulfillment/cmd/worker/main.go:35` |
| gateway admin fetch | SSRF | admin role | UNSAFE: no allowlist | `gateway/src/server.js:32` |
| orders pricing exec | command | argv list | safe: no shell | `orders/app/pricing.py:10` |
| poisoned eval | eval | none | UNSAFE | `poisoned/scripts/setup.js:5` |

## 6. Known-safe patterns and known-risky areas
- Safe: parameterized writes; HS256 pinned `gateway/src/auth.js:17`; SHA-pinned CI with read-only token `platform/.github/workflows/ci.yml:3-10`.
- Risky: shared `orders` table with two writers `orders/app/db.py:15` `fulfillment/cmd/worker/main.go:35`; unauthenticated internal channels `platform/deploy/docker-compose.yml:12`.

## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| Orders OpenAPI | gateway | orders | none | `platform/contracts/orders.openapi.yaml:6-23` |
| `order.created` JSON Schema | orders | fulfillment | broker access only | `platform/contracts/order_created.schema.json:1-11` |
| pricing stdin/stdout | orders | pricing | local process | `orders/app/pricing.py:10` |
| `orders` table | orders, fulfillment | orders | DB users per service | `platform/deploy/docker-compose.yml:11` `platform/deploy/docker-compose.yml:16` |

## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `AUTH_DISABLED` = "true" | everyone admin | off | `gateway/src/auth.js:4` |
| `PUBLISH_EVENTS` != "true" | fulfillment starved | on | `orders/app/events.py:9` |
| `RABBITMQ_URL` unset in orders | default broker creds | `amqp…[REDACTED]` | `orders/app/events.py:6` |
| `JWT_SECRET` missing in K8s | all 401 [inferred] | unset | `platform/deploy/k8s/gateway.yaml:17-19` |

## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | SQL injection | orders/app/db.py | `orders/app/db.py:23` | T1 |
| 2 | CI pwn request | poisoned/.github/workflows/*.yml | `poisoned/.github/workflows/pr-label.yml:3` | T13 |
| 3 | Install-time RCE | poisoned/package.json, poisoned/scripts/* | `poisoned/package.json:5` | T14 |
| 4 | SSRF | gateway/src/server.js | `gateway/src/server.js:32` | T2 |
| 5 | Auth bypass and IDOR | gateway/src/*.js | `gateway/src/auth.js:8` `gateway/src/server.js:27` | T3, T4 |
| 6 | Internal spoofing | orders/app/main.py, fulfillment/internal/queue/* | `orders/app/main.py:19` `fulfillment/internal/queue/consumer.go:38` | T6, T7 |
| 7 | Prompt injection in repo text | poisoned/**/*.md, poisoned/src/* | `poisoned/README.md:10` | T15 |
