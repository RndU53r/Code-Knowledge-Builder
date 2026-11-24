# orders: overview

> **ckb provenance**
> - Sources: `orders` @ `1de64cb` (read-only snapshot of `main`; checkout is on `feature/wip`, not read)
> - Generated: 2026-11-24T05:25:46Z by ckb 0.1.0, stage `repo-analysis`
> - Scope: orders main snapshot, 6 files · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (28 citations, 0 errors; see evidence/verification.md)

## Purpose
FastAPI service that creates and reads orders. It prices items by spawning a Go binary, writes the order to Postgres, then publishes `order.created` to RabbitMQ. `orders/app/main.py:25` «@app.post("/orders", status_code=201)» `orders/app/pricing.py:10` «subprocess.run([PRICING_BIN, "--json"]» `orders/app/events.py:24` «ch.basic_publish(exchange=EXCHANGE, routing_key=ROUTING_KEY, body=body)»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Language | Python 3.12 | 3.12-slim image | `orders/Dockerfile:1` «FROM python:3.12-slim» |
| Framework | FastAPI + uvicorn | 0.111.0 / 0.30.1 | `orders/requirements.txt:1` `orders/requirements.txt:2` |
| Libraries | psycopg2-binary, pika, pydantic | 2.9.9 / 1.3.2 / 2.7.4 | `orders/requirements.txt:3` `orders/requirements.txt:4` `orders/requirements.txt:5` |
| Build | Docker, `pip install` (not run) | n/a | `orders/Dockerfile:4` |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| http | POST /orders | `create_order` | `orders/app/main.py:25` |
| http | GET /orders/{order_id} | `read_order` | `orders/app/main.py:37` |

Neither route has an authentication dependency; the only identity input is an unused `x-request-user` header parameter. `orders/app/main.py:26` «x_request_user: str | None = Header(default=None)»

## Dependencies (direct)
| Name | Version spec | Registry or source | Manifest |
| --- | --- | --- | --- |
| fastapi | ==0.111.0 | PyPI | `orders/requirements.txt:1` |
| uvicorn | ==0.30.1 | PyPI | `orders/requirements.txt:2` |
| psycopg2-binary | ==2.9.9 | PyPI | `orders/requirements.txt:3` |
| pika | ==1.3.2 | PyPI | `orders/requirements.txt:4` |
| pydantic | ==2.7.4 | PyPI | `orders/requirements.txt:5` |

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| Dockerfile | no non-root USER, so the service runs as root; binds 0.0.0.0:8000 | `orders/Dockerfile:6` |
| Dockerfile | copies only `app`; the `pricing` binary is not copied in, so `PRICING_BIN` must be supplied elsewhere [unknown] | `orders/Dockerfile:5` |
| platform compose | orders gets `DATABASE_URL` and a plain `amqp://` broker URL | `platform/deploy/docker-compose.yml:11` `platform/deploy/docker-compose.yml:12` |

## Cloud resources declared in this repo
[n/a] none; cloud resources live in `platform`.

## Exclusions and unknowns
- The `feature/wip` checkout was not read; analysis is of the `main` snapshot. The snapshot contains no `wip` text (verified by grep).
- Config knobs: `DATABASE_URL`, `RABBITMQ_URL`, `PUBLISH_EVENTS`, `PRICING_BIN`, `MAX_ITEMS`. `orders/app/db.py:5` `orders/app/events.py:6` `orders/app/events.py:9` `orders/app/pricing.py:5` `orders/app/main.py:10`
- A default broker URL embeds credentials (`guest:guest`); recorded as type only. `orders/app/events.py:6`
- No text addressed to AI tools found in this repo.
