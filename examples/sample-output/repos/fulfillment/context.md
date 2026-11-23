---
ckb_context: 1
scope: fulfillment
revision: unversioned (local)
generated: 2026-11-23T10:00:00Z
languages: [go]
entry_points: 2
focus_areas: [message-spoofing, poison-message-dos, pii-third-party, error-handling]
---
# Security context: fulfillment

> **ckb provenance**
> - Sources: `fulfillment` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `context`
> - Scope: fulfillment · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## 1. Purpose and tech stack
Go worker that ships orders on `order.created`, plus a pricing CLI.
- Go 1.22 `fulfillment/go.mod:3`, lib/pq `fulfillment/go.mod:6`, amqp091-go `fulfillment/go.mod:7`, Postgres `fulfillment/cmd/worker/main.go:18`.

## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| queue `fulfillment.order-created` | internal | TB3 | `fulfillment/internal/queue/consumer.go:26` |
| pricing stdin | local process | orders container [inferred] | `fulfillment/cmd/pricing/main.go:18` |

## 3. Authn/authz model
- Inbound messages are not authenticated beyond broker access. `fulfillment/internal/queue/consumer.go:18` `fulfillment/internal/queue/consumer.go:38-44`
- Outbound: bearer `SHIPPING_API_KEY`. `fulfillment/cmd/worker/main.go:29`

## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| shipping_address | event | shipping API | HTTPS (per compose URL) | `fulfillment/cmd/worker/main.go:27` `platform/deploy/docker-compose.yml:18` |
| SHIPPING_API_KEY | env | Authorization header | not logged | `fulfillment/cmd/worker/main.go:23` |

## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Effective? | Source |
| --- | --- | --- | --- | --- |
| `db.Exec("UPDATE ... $1 ... $2")` | SQL | parameterized | safe: parameterized | `fulfillment/cmd/worker/main.go:35` |
| `http.NewRequest(POST, SHIPPING_API_URL+"/shipments")` | SSRF | URL from env only | safe: not user-controlled | `fulfillment/cmd/worker/main.go:28` |
| `json.Unmarshal(m.Body)` | deserialization | typed struct | safe | `fulfillment/internal/queue/consumer.go:39` |

## 6. Known-safe patterns and known-risky areas
- Safe: parameterized UPDATE; distroless nonroot image `fulfillment/Dockerfile:6-8`; HTTP timeout `fulfillment/cmd/worker/main.go:24`.
- Risky: infinite requeue `fulfillment/internal/queue/consumer.go:46`; ignored errors and unclosed body `fulfillment/cmd/worker/main.go:27-30`; negative pricing `fulfillment/cmd/pricing/main.go:23`.

## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| `order.created` | orders | fulfillment | broker access only | `fulfillment/internal/queue/consumer.go:30` |
| shipments API | fulfillment | external | bearer key | `fulfillment/cmd/worker/main.go:29` |

## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `SHIPPING_API_KEY` unset | empty bearer [inferred] | unset in compose | `fulfillment/cmd/worker/main.go:23` |
| `RABBITMQ_URL`, `DATABASE_URL` | targets | no defaults | `fulfillment/cmd/worker/main.go:18` `fulfillment/cmd/worker/main.go:26` |

## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | Message spoofing | fulfillment/internal/queue/*.go | no message auth `fulfillment/internal/queue/consumer.go:38` | T7 |
| 2 | Poison-message loop | fulfillment/internal/queue/consumer.go | `fulfillment/internal/queue/consumer.go:46` | T9 |
| 3 | Negative pricing | fulfillment/cmd/pricing/main.go | `fulfillment/cmd/pricing/main.go:23` | T8 |
| 4 | PII to third party | fulfillment/cmd/worker/main.go | `fulfillment/cmd/worker/main.go:27` | T10 |
