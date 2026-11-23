# fulfillment: outputs and conditions

> **ckb provenance**
> - Sources: `fulfillment` @ `unversioned (local)`, `orders` @ `unversioned (local)`, `platform` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: fulfillment (all files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Output index
| ID | Kind | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |
| O-fulfillment-1 | external-call | POST shipments | `fulfillment/cmd/worker/main.go:28-30` | external shipping API [unknown] (out of scope) |
| O-fulfillment-2 | db-write | UPDATE `orders.status` | `fulfillment/cmd/worker/main.go:35` | orders reads status `orders/app/db.py:23` |
| O-fulfillment-3 | event | Ack / Nack to broker | `fulfillment/internal/queue/consumer.go:41-49` | RabbitMQ |
| O-fulfillment-4 | api-response | pricing stdout `{total_cents}` | `fulfillment/cmd/pricing/main.go:25` | orders `orders/app/pricing.py:13` «return json.loads(proc.stdout)["total_cents"]» |
| O-fulfillment-5 | log | bad message / handle failed logs (include order id) | `fulfillment/internal/queue/consumer.go:45` | [unknown] log pipeline |

## O-1: shipment request
- **What:** JSON `{order_id, address}`, header `Authorization: Bearer <SHIPPING_API_KEY>`. `fulfillment/cmd/worker/main.go:27-29`
- **How:** `Consume` → handler → `client.Do`. `fulfillment/internal/queue/consumer.go:44` `fulfillment/cmd/worker/main.go:30`
- **Who consumes:** external shipping API `[unknown]`.

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| env `SHIPPING_API_URL` unset | URL becomes `/shipments`; request fails, status `failed` [inferred] | unset (compose sets it) | `fulfillment/cmd/worker/main.go:22` `platform/deploy/docker-compose.yml:18` |
| env `SHIPPING_API_KEY` unset | header `Bearer ` with empty key [inferred] | unset (not in compose) | `fulfillment/cmd/worker/main.go:23` |
| transport error or status >= 300 | status `failed`, no retry | n/a | `fulfillment/cmd/worker/main.go:32-33` |
| response slower than 10s | timeout, status `failed` | 10s | `fulfillment/cmd/worker/main.go:24` |

## O-2: order status update
- **What:** `status` = `shipped` or `failed` for `id = evt.OrderID`. `fulfillment/cmd/worker/main.go:35`
- **How:** handler after shipping call. `fulfillment/cmd/worker/main.go:31-35`
- **Who consumes:** orders GET returns status. `orders/app/main.py:42`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| env `DATABASE_URL` | target DB (no default) | compose: user `fulfillment` | `fulfillment/cmd/worker/main.go:18` `platform/deploy/docker-compose.yml:16` |
| order id not in table | UPDATE affects 0 rows, still Ack [inferred] | n/a | `fulfillment/cmd/worker/main.go:35-36` |

## O-3: Ack / Nack
- **What:** broker acknowledgement. `fulfillment/internal/queue/consumer.go:49`
- **How:** consume loop. `fulfillment/internal/queue/consumer.go:37-50`
- **Who consumes:** RabbitMQ.

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| JSON decode fails | Nack, no requeue (dropped) | n/a | `fulfillment/internal/queue/consumer.go:39-41` |
| handler returns error | Nack with requeue | n/a | `fulfillment/internal/queue/consumer.go:44-46` |

## O-4: pricing output
- **What:** `{"total_cents": int}`. `fulfillment/cmd/pricing/main.go:25`
- **How:** decode → loop → encode. `fulfillment/cmd/pricing/main.go:18-25`
- **Who consumes:** orders `price_items`. `orders/app/pricing.py:13`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| stdin not a JSON list | exit 2 | n/a | `fulfillment/cmd/pricing/main.go:18-19` |
| negative qty | negative total | no bound | `fulfillment/cmd/pricing/main.go:23` |
| `--json` flag | parsed but ignored | true | `fulfillment/cmd/pricing/main.go:15` |

## O-5: logs
- **What:** decode errors and order IDs on failure. `fulfillment/internal/queue/consumer.go:40` `fulfillment/internal/queue/consumer.go:45`
- **How:** `log.Printf`.
- **Who consumes:** [unknown].

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| any failure | line logged | stderr | `fulfillment/internal/queue/consumer.go:45` |
