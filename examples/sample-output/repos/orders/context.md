---
ckb_context: 1
scope: orders
revision: unversioned (local)
generated: 2026-11-23T10:00:00Z
languages: [python]
entry_points: 2
focus_areas: [sqli, missing-authn, input-validation, root-container]
---
# Security context: orders

> **ckb provenance**
> - Sources: `orders` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `context`
> - Scope: orders · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## 1. Purpose and tech stack
FastAPI order service: prices via a Go subprocess, writes Postgres, publishes AMQP events.
- Python 3.12 `orders/Dockerfile:1`, FastAPI 0.111.0 `orders/requirements.txt:1`, psycopg2 `orders/requirements.txt:3`, pika `orders/requirements.txt:4`, Postgres `orders/app/db.py:5`.

## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| POST /orders | internal (via gateway) | TB2, TB3 | `orders/app/main.py:25` |
| GET /orders/{order_id} | internal (via gateway) | TB2, TB3 | `orders/app/main.py:37` |

## 3. Authn/authz model
- None. Routes have no auth dependency; `customer_id` comes from the body; `x-request-user` header is accepted and unused. `orders/app/main.py:19` `orders/app/main.py:26`
- Relies on gateway auth `[inferred]` from `gateway/src/server.js:13`.

## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| card_last4 | request | Postgres | none observed | `orders/app/db.py:15` |
| shipping_address | request | RabbitMQ event | none observed | `orders/app/events.py:22` |
| broker credentials | env / code default | pika | default creds in code (`amqp…[REDACTED]`) | `orders/app/events.py:6` |

## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Effective? | Source |
| --- | --- | --- | --- | --- |
| `cur.execute(f"SELECT ... '{order_id}'")` | SQL | none | UNSAFE: string-built | `orders/app/db.py:23` |
| `cur.execute("INSERT ... %s ...", params)` | SQL | parameterized | safe: parameterized | `orders/app/db.py:14-16` |
| `subprocess.run([PRICING_BIN, "--json"], input=...)` | command | argv list, no shell; data on stdin | safe: no shell | `orders/app/pricing.py:10` |
| `json.loads(proc.stdout)` | deserialization | JSON only | safe | `orders/app/pricing.py:13` |

## 6. Known-safe patterns and known-risky areas
- Safe: parameterized INSERT `orders/app/db.py:15`; argv subprocess `orders/app/pricing.py:10`; pydantic models `orders/app/main.py:13-22`.
- Risky: f-string SQL `orders/app/db.py:23`; unbounded `qty` `orders/app/main.py:15`; root container `orders/Dockerfile:6`; DB connections never closed `orders/app/main.py:31` [inferred].

## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| Orders OpenAPI | gateway | orders | none | `platform/contracts/orders.openapi.yaml:6-23` |
| `order.created` schema | orders | fulfillment | broker creds [inferred] | `platform/contracts/order_created.schema.json:2` |
| pricing stdin/stdout | orders | pricing CLI | n/a (local process) | `orders/app/pricing.py:10` |

## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `PUBLISH_EVENTS` != "true" | no events | `"true"` | `orders/app/events.py:9` |
| `RABBITMQ_URL` unset | default broker creds used | default creds | `orders/app/events.py:6` |
| `PRICING_BIN` | binary executed | `/usr/local/bin/pricing` | `orders/app/pricing.py:5` |
| `MAX_ITEMS` | item cap | `"50"` | `orders/app/main.py:10` |

## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | SQL injection | orders/app/db.py | `orders/app/db.py:23` reached from `orders/app/main.py:39` | T1 |
| 2 | Missing service auth | orders/app/main.py | `orders/app/main.py:25` | T6 |
| 3 | Input validation (qty) | orders/app/main.py | `orders/app/main.py:15` | T8 |
| 4 | Root container | orders/Dockerfile | `orders/Dockerfile:6` | T11 |
