# Call graphs

> **ckb provenance**
> - Sources: `fulfillment` @ `unversioned`, `gateway` @ `unversioned`, `orders` @ `unversioned`, `platform` @ `unversioned`
> - Generated: 2026-11-27T01:30:47Z by ckb callgraph, stage `callgraph`
> - Scope: registered code repos · Excluded: vendored, generated, binaries, symlinks
> - Method: rolled up from the knowledge graph (static analysis; no target code executed); confidence is the weakest edge on each row
> - Verification: see evidence/graph-verification.md

## Summary

| Level | Nodes | Edges |
| --- | --- | --- |
| function → function | 14 | 12 |
| file → file | 9 | 13 |
| repo → repo | 6 | 7 |

[n/a] counts above are derived from the tables below.

Mechanisms: `call` (resolved call), `http`/`grpc` (client call matched to the endpoint's handler), `spawn` (subprocess or binary), `event:<topic>` (publisher to consumer over a topic), `table:<name>` (writer repo to reader repo), `import`, `package` (internal dependency). Dashed arrows and `inferred` rows rest on medium/low-confidence links: confirm them in the cited code.

## Repo → repo

| From | To | Mechanism | Count | Confidence | Source |
| --- | --- | --- | --- | --- | --- |
| gateway | orders | http | 2 | medium | `gateway/src/server.js:15` `gateway/src/server.js:27` `orders/app/main.py:25` |
| fulfillment | orders | table:orders | 1 | high | `fulfillment/cmd/worker/main.go:35` `orders/app/db.py:23` |
| orders | fulfillment | event:order.created | 1 | high | `orders/app/events.py:24` `fulfillment/internal/queue/consumer.go:30` |
| orders | fulfillment | spawn | 1 | medium | `orders/app/pricing.py:10` `fulfillment/cmd/pricing/main.go:1` |
| fulfillment | /shipments | http:external | 1 | low | `fulfillment/cmd/worker/main.go:28` |
| gateway | req.query.source | http:external | 1 | low | `gateway/src/server.js:32` |
| platform | gateway | deploy | 1 | low | `platform/k8s/gateway.yaml:4` |

### Shared stores

| Store | Writers | Readers | Source |
| --- | --- | --- | --- |
| orders | fulfillment, orders | orders | `fulfillment/cmd/worker/main.go:35` `orders/app/db.py:14` `orders/app/db.py:23` |

```mermaid
flowchart LR
  N1["gateway"]
  N2["orders"]
  N3["fulfillment"]
  N4["/shipments"]
  N5["req.query.source"]
  N6["platform"]
  N1 -->|"http"| N2
  N3 -->|"table:orders"| N2
  N2 -->|"event:order.created"| N3
  N2 -->|"spawn"| N3
  N3 -.->|"http:external"| N4
  N1 -.->|"http:external"| N5
  N6 -.->|"deploy"| N1
```

## File → file

Top 13 of 13 by weight.

| From | To | Mechanism | Count | Confidence | Source |
| --- | --- | --- | --- | --- | --- |
| orders/app/main.py | orders/app/db.py | call | 4 | high | `orders/app/main.py:32` `orders/app/main.py:31` |
| gateway/src/server.js | orders/app/main.py | http | 2 | medium | `gateway/src/server.js:15` `gateway/src/server.js:27` |
| fulfillment/cmd/worker/main.go | fulfillment/internal/queue/consumer.go | import | 1 | high | `fulfillment/cmd/worker/main.go:14` |
| gateway/src/server.js | gateway/src/auth.js | import | 1 | high | `gateway/src/server.js:3` |
| orders/app/events.py | fulfillment/internal/queue/consumer.go | event:order.created | 1 | high | `orders/app/events.py:24` `fulfillment/internal/queue/consumer.go:30` |
| orders/app/main.py | orders/app/db.py | import | 1 | high | `orders/app/main.py:7` |
| orders/app/main.py | orders/app/events.py | import | 1 | high | `orders/app/main.py:7` |
| orders/app/main.py | orders/app/events.py | call | 1 | high | `orders/app/main.py:33` |
| orders/app/main.py | orders/app/pricing.py | import | 1 | high | `orders/app/main.py:7` |
| orders/app/main.py | orders/app/pricing.py | call | 1 | high | `orders/app/main.py:29` |
| fulfillment/cmd/worker/main.go | fulfillment/internal/queue/consumer.go | call | 1 | medium | `fulfillment/cmd/worker/main.go:26` |
| gateway/src/server.js | gateway/src/auth.js | call | 1 | medium | `gateway/src/server.js:31` |
| orders/app/pricing.py | fulfillment/cmd/pricing/main.go | spawn | 1 | medium | `orders/app/pricing.py:10` `fulfillment/cmd/pricing/main.go:1` |

## Function → function

Top 12 of 12: cross-file and cross-repo edges first.

| From | To | Mechanism | Count | Confidence | Source |
| --- | --- | --- | --- | --- | --- |
| orders: publish_order_created | fulfillment: Consume | event:order.created | 1 | high | `orders/app/events.py:24` `fulfillment/internal/queue/consumer.go:30` |
| gateway: route GET /orders/:id | orders: read_order | http | 1 | medium | `gateway/src/server.js:27` `orders/app/main.py:37` |
| gateway: route POST /orders | orders: create_order | http | 1 | medium | `gateway/src/server.js:15` `orders/app/main.py:25` |
| orders: price_items | fulfillment: main | spawn | 1 | medium | `orders/app/pricing.py:10` `fulfillment/cmd/pricing/main.go:1` |
| orders: create_order | orders: get_conn | call | 1 | high | `orders/app/main.py:31` |
| orders: create_order | orders: insert_order | call | 1 | high | `orders/app/main.py:32` |
| orders: create_order | orders: publish_order_created | call | 1 | high | `orders/app/main.py:33` |
| orders: create_order | orders: price_items | call | 1 | high | `orders/app/main.py:29` |
| orders: read_order | orders: get_conn | call | 1 | high | `orders/app/main.py:39` |
| orders: read_order | orders: get_order | call | 1 | high | `orders/app/main.py:39` |
| fulfillment: main | fulfillment: Consume | call | 1 | medium | `fulfillment/cmd/worker/main.go:26` |
| gateway: route GET /admin/report | gateway: requireRole | call | 1 | medium | `gateway/src/server.js:31` |

## Class → class

Calls between methods of different classes, instantiation (`new`), inheritance, interface implementation, overrides and type use; receiver types come from constructors, annotations and injected fields.

| From | To | Mechanism | Count | Confidence | Source |
| --- | --- | --- | --- | --- | --- |
| [unknown] none | | | | | |

## Library calls (file → package)

External packages the code calls, with the API names seen. Unresolved externals are listed in `evidence/call-resolution-<repo>.json`.

| File | Package | APIs | Count | Source |
| --- | --- | --- | --- | --- |
| gateway/src/server.js | axios | get | 2 | `gateway/src/server.js:27` `gateway/src/server.js:32` |
| orders/app/main.py | fastapi | FastAPI | 2 | `orders/app/main.py:9` |
| fulfillment/cmd/pricing/main.go | encoding/json | NewDecoderNewEncoder | 1 | `fulfillment/cmd/pricing/main.go:18` |
| fulfillment/cmd/pricing/main.go | flag | BoolParse | 1 | `fulfillment/cmd/pricing/main.go:15` |
| fulfillment/cmd/pricing/main.go | os | Exit | 1 | `fulfillment/cmd/pricing/main.go:19` |
| fulfillment/cmd/worker/main.go | bytes | NewReader | 1 | `fulfillment/cmd/worker/main.go:28` |
| fulfillment/cmd/worker/main.go | database/sql | Open | 1 | `fulfillment/cmd/worker/main.go:18` |
| fulfillment/cmd/worker/main.go | encoding/json | Marshal | 1 | `fulfillment/cmd/worker/main.go:27` |
| fulfillment/cmd/worker/main.go | log | Fatal | 1 | `fulfillment/cmd/worker/main.go:20` |
| fulfillment/cmd/worker/main.go | net/http | NewRequest | 1 | `fulfillment/cmd/worker/main.go:28` |
| fulfillment/cmd/worker/main.go | os | Getenv | 1 | `fulfillment/cmd/worker/main.go:18` |
| fulfillment/internal/queue/consumer.go | encoding/json | Unmarshal | 1 | `fulfillment/internal/queue/consumer.go:39` |
| fulfillment/internal/queue/consumer.go | github.com/rabbitmq/amqp091-go | Dial | 1 | `fulfillment/internal/queue/consumer.go:18` |
| fulfillment/internal/queue/consumer.go | log | Printf | 1 | `fulfillment/internal/queue/consumer.go:40` |
| gateway/src/auth.js | jsonwebtoken | verify | 1 | `gateway/src/auth.js:17` |
| gateway/src/server.js | axios | post | 1 | `gateway/src/server.js:15` |
| orders/app/db.py | psycopg2 | connect | 1 | `orders/app/db.py:9` |
| orders/app/events.py | json | dumps | 1 | `orders/app/events.py:18` |
| orders/app/events.py | pika | BlockingConnectionURLParameter | 1 | `orders/app/events.py:25` |
| orders/app/main.py | fastapi | HTTPExceptionHeaderpost | 1 | `orders/app/main.py:25` |
| orders/app/main.py | fastapi | HTTPExceptionget | 1 | `orders/app/main.py:37` |
| orders/app/main.py | uuid | uuid4 | 1 | `orders/app/main.py:30` |
| orders/app/pricing.py | json | dumpsloads | 1 | `orders/app/pricing.py:13` |
| orders/app/pricing.py | subprocess | run | 1 | `orders/app/pricing.py:10` |

Full machine-readable data: `graph/callgraph.json`. Per-repo diagrams: `diagrams/callgraph-<level>-<repo>.mmd`.
