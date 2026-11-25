# Analysis coverage and blind spots

> **ckb provenance**
> - Sources: `fulfillment`, `gateway`, `orders`, `platform`
> - Generated: 2026-11-25T22:12:20Z by ckb coverage_report, stage `coverage`
> - Method: counts from the graph build and a text scan for dynamic dispatch; static analysis cannot prove that every path was found, so this page lists what was and was not resolved.

## fulfillment

| Measure | Value |
| --- | --- |
| Calls seen | 34 (resolved 1, library 19, ambiguous 0, dynamic 0, unresolved 14) |
| Resolved or library | 58.8% |
| Entry points | 1 (`fulfillment/internal/queue/consumer.go:30`) |
| Functions reachable from an entry point | 1 of 3 |
| Unsafe sinks reached by an entry point | 0 of 0 |
| Parsers | go / regex: 3 |

Top unresolved calls:

| Name | Count | First seen |
| --- | --- | --- |
| m.Nack | 2 | `fulfillment/internal/queue/consumer.go:41` |
| map | 2 | `fulfillment/cmd/pricing/main.go:25` |
| conn.Channel | 1 | `fulfillment/internal/queue/consumer.go:22` |
| ch.QueueDeclare | 1 | `fulfillment/internal/queue/consumer.go:26` |
| ch.QueueBind | 1 | `fulfillment/internal/queue/consumer.go:30` |
| ch.Consume | 1 | `fulfillment/internal/queue/consumer.go:33` |
| handle | 1 | `fulfillment/internal/queue/consumer.go:44` |
| m.Ack | 1 | `fulfillment/internal/queue/consumer.go:49` |
| items | 1 | `fulfillment/cmd/pricing/main.go:17` |
| req.Header.Set | 1 | `fulfillment/cmd/worker/main.go:29` |
| client.Do | 1 | `fulfillment/cmd/worker/main.go:30` |
| db.Exec | 1 | `fulfillment/cmd/worker/main.go:35` |

Functions no entry point reaches (2; dead code, library API, or reached only through dynamic dispatch):

- `main` (`fulfillment/cmd/pricing/main.go:14-26`)
- `main` (`fulfillment/cmd/worker/main.go:17-41`)

Classes nothing instantiates, extends or references: `OrderCreated`, `item`

## gateway

| Measure | Value |
| --- | --- |
| Calls seen | 24 (resolved 1, library 4, ambiguous 0, dynamic 0, unresolved 19) |
| Resolved or library | 20.8% |
| Entry points | 4 (`gateway/src/server.js:11`, `gateway/src/server.js:13`, `gateway/src/server.js:26`, `gateway/src/server.js:31`) |
| Functions reachable from an entry point | 6 of 6 |
| Unsafe sinks reached by an entry point | 1 of 1 |
| Parsers | javascript / regex: 2 |

Top unresolved calls:

| Name | Count | First seen |
| --- | --- | --- |
| res.status | 5 | `gateway/src/auth.js:14` |
| next | 3 | `gateway/src/auth.js:9` |
| app.get | 3 | `gateway/src/server.js:11` |
| res.json | 3 | `gateway/src/server.js:11` |
| header.startsWith | 1 | `gateway/src/auth.js:12` |
| header.slice | 1 | `gateway/src/auth.js:12` |
| app.post | 1 | `gateway/src/server.js:13` |
| app.listen | 1 | `gateway/src/server.js:36` |
| console.log | 1 | `gateway/src/server.js:36` |

## orders

| Measure | Value |
| --- | --- |
| Calls seen | 35 (resolved 6, library 16, ambiguous 0, dynamic 0, unresolved 13) |
| Resolved or library | 62.9% |
| Entry points | 2 (`orders/app/main.py:25`, `orders/app/main.py:37`) |
| Functions reachable from an entry point | 7 of 7 |
| Unsafe sinks reached by an entry point | 1 of 1 |
| Parsers | python / ast: 4 |

Top unresolved calls:

| Name | Count | First seen |
| --- | --- | --- |
| conn.cursor | 2 | `orders/app/db.py:13` |
| cur.execute | 2 | `orders/app/db.py:14` |
| conn.commit | 1 | `orders/app/db.py:18` |
| cur.fetchone | 1 | `orders/app/db.py:24` |
| int | 1 | `orders/app/main.py:10` |
| str | 1 | `orders/app/main.py:30` |
| len | 1 | `orders/app/main.py:27` |
| i.model_dump | 1 | `orders/app/main.py:29` |
| ch.exchange_declare | 1 | `orders/app/events.py:17` |
| ch.basic_publish | 1 | `orders/app/events.py:24` |
| RuntimeError | 1 | `orders/app/pricing.py:12` |

Dynamic-dispatch hotspots (paths through these are invisible to the call graph):

| What | Source |
| --- | --- |
| exec | `orders/app/db.py:14` |
| exec | `orders/app/db.py:23` |

Classes nothing instantiates, extends or references: `Item`

## platform

| Measure | Value |
| --- | --- |
| Calls seen | 0 (resolved 0, library 0, ambiguous 0, dynamic 0, unresolved 0) |
| Resolved or library | None% |
| Entry points | 0 (parsed, for example: `platform/azure/main.bicep:1-36`) |
| Functions reachable from an entry point | 0 of 0 |
| Unsafe sinks reached by an entry point | 0 of 0 |
| Parsers | iac / regex: 5 |

