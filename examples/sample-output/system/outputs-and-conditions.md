# System: outputs and conditions

> **ckb provenance**
> - Sources: `gateway`, `orders`, `fulfillment`, `platform`, `poisoned` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `flow-trace`
> - Scope: cross-repo outputs only · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Output index
| ID | Kind | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |
| O-gateway-1 | external-call | POST /orders to orders ([detail](../repos/gateway/outputs-and-conditions.md)) | `gateway/src/server.js:15` | `orders/app/main.py:25` |
| O-gateway-2 | external-call | GET /orders/{id} to orders | `gateway/src/server.js:27` | `orders/app/main.py:37` |
| O-orders-1/2 | api-response | order responses relayed by gateway ([detail](../repos/orders/outputs-and-conditions.md)) | `orders/app/main.py:34` | `gateway/src/server.js:19` |
| O-orders-3 / O-fulfillment-2 | db-write | `orders` table: INSERT by orders, UPDATE by fulfillment ([detail](../repos/fulfillment/outputs-and-conditions.md)) | `orders/app/db.py:15` `fulfillment/cmd/worker/main.go:35` | `orders/app/db.py:23` |
| O-orders-4 | event | `order.created` | `orders/app/events.py:24` | `fulfillment/internal/queue/consumer.go:30` |
| O-orders-5 / O-fulfillment-4 | external-call | pricing subprocess | `orders/app/pricing.py:10` | `fulfillment/cmd/pricing/main.go:25` |
| O-fulfillment-1 | external-call | shipment to third party (PII) | `fulfillment/cmd/worker/main.go:28` | [unknown] external |

## Cross-repo conditions
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `PUBLISH_EVENTS` != "true" in orders | no `order.created`; fulfillment never ships; orders stay `pending` | `"true"` | `orders/app/events.py:9` `fulfillment/internal/queue/consumer.go:30` |
| `AUTH_DISABLED` = "true" in gateway | all internet callers become admin; reach orders and the SSRF endpoint | unset (auth on) | `gateway/src/auth.js:4` `gateway/src/auth.js:8` |
| `JWT_SECRET` not provided (K8s manifest lacks it) | every request 401 [inferred] | unset in K8s | `gateway/src/auth.js:3` `platform/deploy/k8s/gateway.yaml:17-19` |
| pricing binary absent from orders image | every POST /orders returns 500 [inferred] | `/usr/local/bin/pricing` | `orders/app/pricing.py:5` `fulfillment/Dockerfile:7` |
| negative `qty` accepted by orders | negative total persisted and sent in event | no bound | `orders/app/main.py:15` `fulfillment/cmd/pricing/main.go:23` |
| fulfillment DB error | message requeued indefinitely; status unchanged | n/a | `fulfillment/internal/queue/consumer.go:46` |
| broker URL in compose has no credentials; orders code default uses default credentials | any in-network client could publish `order.created` [inferred] | default creds (`amqp…[REDACTED]`) | `platform/deploy/docker-compose.yml:12` `orders/app/events.py:6` |

Security-relevant conditions flagged for the threat model: `AUTH_DISABLED`, missing `JWT_SECRET`, broker credentials, negative `qty`.
