---
ckb_context: 1
scope: orders
revision: 1de64cb
generated: 2026-11-24T05:32:39Z
languages: [python]
entry_points: 2
focus_areas: [sqli, authz-bypass, idor, business-logic, amqp-plaintext]
---
# Security context: orders

> **ckb provenance**
> - Sources: `orders` @ `1de64cb` (main snapshot)
> - Generated: 2026-11-24T05:32:39Z by ckb 0.1.0, stage `security-context`
> - Scope: orders · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (23 citations, 0 errors; see evidence/verification.md)

## 1. Purpose and tech stack
FastAPI order service: prices items via a Go subprocess, stores orders in Postgres, publishes `order.created`. `orders/app/main.py:25`
- Python 3.12, FastAPI 0.111.0 `orders/requirements.txt:1`
- Postgres via psycopg2 `orders/app/db.py:9`; RabbitMQ via pika `orders/app/events.py:15`
## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| POST /orders | internal (called by gateway) | gateway to orders HTTP | `orders/app/main.py:25` |
| GET /orders/{order_id} | internal (called by gateway) | gateway to orders HTTP | `orders/app/main.py:37` |
## 3. Authn/authz model
None in this service: no dependency or middleware on either route; the `x-request-user` header is accepted and never read. Identity is the caller-supplied `customer_id`. `orders/app/main.py:26` `orders/app/main.py:32`
## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| card_last4 | request body | table orders | last four digits only; DB unencrypted per IaC | `orders/app/db.py:15` |
| shipping_address | request body | broker event | plain AMQP by default | `orders/app/events.py:22` |
## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Verdict | Source |
| --- | --- | --- | --- | --- |
| `get_order` query | SQL | none | UNSAFE: string-built | `orders/app/db.py:23` |
| `insert_order` query | SQL | bound parameters | safe: parameterized | `orders/app/db.py:15` |
| `price_items` subprocess | command | argv list, fixed binary path from env, no shell | safe: no shell, input goes to stdin only | `orders/app/pricing.py:10` |
## 6. Known-safe patterns and known-risky areas
- Safe: parameterized insert `orders/app/db.py:15`; no shell in subprocess `orders/app/pricing.py:10`.
- Risky: SQL string build `orders/app/db.py:23`; unbounded `qty` `orders/app/main.py:15`; default broker credential in URL `orders/app/events.py:6`.
## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| `order.created` | orders | fulfillment | broker credentials only | `orders/app/events.py:24` |
| orders REST API | orders | gateway | none | `orders/app/main.py:25` |
## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `PUBLISH_EVENTS` not `true` | events skipped, orders stay pending | true | `orders/app/events.py:9` |
| `MAX_ITEMS` | caps item count | 50 | `orders/app/main.py:10` |
| `RABBITMQ_URL` | broker address and credentials | plain amqp, default account | `orders/app/events.py:6` |
## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | sqli | `app/db.py` | string-built query reached by GET /orders | T-14 |
| 2 | authz-bypass | `app/main.py` | no authentication in service | T-29 |
| 3 | business-logic | `app/main.py`, pricing | negative quantity | T-34 |
| 4 | amqp-plaintext | `app/events.py` | plain broker, default credential | T-15 |
