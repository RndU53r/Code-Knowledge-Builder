# System: outputs and conditions

> **ckb provenance**
> - Sources: `gateway` @ `8c8444d`, `orders` @ `1de64cb` (main snapshot), `fulfillment` @ `d2ffc20`, `platform` @ `f5659b3`; context `ctx-platform`
> - Generated: 2026-11-24T05:27:54Z by ckb 0.1.0, stage `flow-tracing`
> - Scope: all four repos plus supplied context · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (12 citations, 0 errors; see evidence/verification.md)

## Output index
[inferred] Index of the sections below, each cited there.
| ID | Kind | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |
| O-1 | api-response | POST /orders 201 body | orders `create_order` | gateway, then client |
| O-2 | event | `order.created` | orders `publish_order_created` | fulfillment `Consume` |
| O-3 | db-write | order row insert and status update | orders `insert_order`, fulfillment handler | orders `get_order` |
| O-4 | external-call | shipment request | fulfillment handler | external shipping API |

## O-1: create order response
- **What:** id, status `pending`, total_cents. `orders/app/main.py:34` «return {"id": order_id, "status": "pending", "total_cents": total}»
- **How:** `create_order` → `price_items` → `insert_order` → `publish_order_created`. `orders/app/main.py:29`
- **Who consumes:** gateway relays status and body. `gateway/src/server.js:19`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| more than `MAX_ITEMS` items | 400 "too many items" | 50 | `orders/app/main.py:27` |
| pricing binary fails | RuntimeError, 500 | n/a | `orders/app/pricing.py:12` |
| `PUBLISH_EVENTS` is not `true` | no event, order stays pending | `true` | `orders/app/events.py:13` |
| `AUTH_DISABLED=true` at gateway | everyone is admin `dev` | off | `gateway/src/auth.js:7` |

## O-2: order.created event
- **What:** order_id, customer_id, total_cents, shipping_address. `orders/app/events.py:18`
- **Who consumes:** fulfillment queue `fulfillment.order-created`. `fulfillment/internal/queue/consumer.go:26`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| malformed JSON | message dropped | n/a | `fulfillment/internal/queue/consumer.go:41` |
| handler error (DB) | requeued, no limit | n/a | `fulfillment/internal/queue/consumer.go:46` |
| shipping API error or status 300 or more | status `failed`, acknowledged | n/a | `fulfillment/cmd/worker/main.go:32` |
