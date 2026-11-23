# orders: outputs and conditions

> **ckb provenance**
> - Sources: `orders` @ `unversioned (local)`, `fulfillment` @ `unversioned (local)`, `gateway` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: orders (all files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Output index
| ID | Kind | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |
| O-orders-1 | api-response | POST /orders 201 body | `orders/app/main.py:34` | gateway `gateway/src/server.js:19` |
| O-orders-2 | api-response | GET /orders/{id} body | `orders/app/main.py:42` | gateway `gateway/src/server.js:28` |
| O-orders-3 | db-write | INSERT into `orders` | `orders/app/db.py:14-18` | fulfillment updates the same rows `fulfillment/cmd/worker/main.go:35` |
| O-orders-4 | event | `order.created` on exchange `orders` | `orders/app/events.py:24` | fulfillment `fulfillment/internal/queue/consumer.go:30` «ch.QueueBind(q.Name, "order.created", "orders", false, nil)» |
| O-orders-5 | external-call | pricing subprocess | `orders/app/pricing.py:10` | pricing binary `fulfillment/cmd/pricing/main.go:14` |

## O-1: create order response
- **What:** `{"id", "status": "pending", "total_cents"}`. `orders/app/main.py:34` «return {"id": order_id, "status": "pending", "total_cents": total}»
- **How:** `create_order` → `price_items` → `insert_order` → `publish_order_created`. `orders/app/main.py:29-33`
- **Who consumes:** gateway relays it. `gateway/src/server.js:19`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| more than `MAX_ITEMS` items | 400 `too many items`, nothing written | `"50"` | `orders/app/main.py:10` `orders/app/main.py:27-28` |
| negative `qty` | accepted; pricing returns a negative total [inferred] | no bound | `orders/app/main.py:15` «qty: int» `fulfillment/cmd/pricing/main.go:23` «total += it.Qty * 999» |
| pricing exits non-zero | RuntimeError, 500 [inferred] | n/a | `orders/app/pricing.py:11-12` |
| env `PRICING_BIN` | path of binary run | `/usr/local/bin/pricing` | `orders/app/pricing.py:5` |
| broker publish fails | exception after commit; 500 but row persisted [inferred] | n/a | `orders/app/main.py:32-33` |
| caller identity | `customer_id` taken from body; `x-request-user` header accepted but unused | n/a | `orders/app/main.py:19` `orders/app/main.py:26` |

## O-2: read order response
- **What:** `{"id", "status", "total_cents"}` from the row tuple. `orders/app/main.py:42`
- **How:** `read_order` → `get_order` (f-string SQL). `orders/app/main.py:39` `orders/app/db.py:23`
- **Who consumes:** gateway. `gateway/src/server.js:28`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| no row | 404 `not found` | n/a | `orders/app/main.py:40-41` |
| id contains SQL metacharacters | interpreted as SQL (injection) | no sanitizer | `orders/app/db.py:23` |

## O-3: orders row insert
- **What:** columns id, customer_id, total_cents, card_last4, status=`pending`. `orders/app/db.py:15`
- **How:** `create_order` → `insert_order` → commit. `orders/app/main.py:32` `orders/app/db.py:18`
- **Who consumes:** fulfillment updates status. `fulfillment/cmd/worker/main.go:35`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| env `DATABASE_URL` | target DB | `postgresql://orders@db:5432/shop` | `orders/app/db.py:5` |
| `card_last4` omitted | stored as NULL [inferred] | `None` | `orders/app/main.py:21` |

## O-4: order.created event
- **What:** JSON `order_id, customer_id, total_cents, shipping_address`; schema `platform/contracts/order_created.schema.json:4-9`. `orders/app/events.py:18-23`
- **How:** `create_order` → `publish_order_created` → `basic_publish`. `orders/app/main.py:33` `orders/app/events.py:24`
- **Who consumes:** fulfillment worker. `fulfillment/internal/queue/consumer.go:26` «ch.QueueDeclare("fulfillment.order-created", true, false, false, false, nil)»

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `PUBLISH_EVENTS` != "true" | not published; returns False; fulfillment never sees the order | `"true"` (published) | `orders/app/events.py:9` «PUBLISH_EVENTS = os.environ.get("PUBLISH_EVENTS", "true") == "true"» `orders/app/events.py:13-14` |
| env `RABBITMQ_URL` unset | code default uses the broker's well-known default credentials (value `amqp…[REDACTED]`) | default credentials | `orders/app/events.py:6` |
| `shipping_address` omitted | field sent as null [inferred] | `None` | `orders/app/main.py:22` |

## O-5: pricing subprocess call
- **What:** argv `[PRICING_BIN, "--json"]`, stdin JSON list of `{sku, qty}`. `orders/app/pricing.py:10`
- **How:** `create_order` → `price_items`. `orders/app/main.py:29`
- **Who consumes:** Go `pricing` main. `fulfillment/cmd/pricing/main.go:18`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| runtime over 5s | `TimeoutExpired`, 500 [inferred] | 5s | `orders/app/pricing.py:10` |

Security-relevant: string-built SQL, no auth on orders, default broker credentials, unbounded `qty`.
