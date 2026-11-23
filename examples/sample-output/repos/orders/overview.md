# orders: overview

> **ckb provenance**
> - Sources: `orders` @ `unversioned (local)`, `platform` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: orders (all files); platform deploy and contracts for context · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Purpose
Python/FastAPI service that creates and reads orders: it prices items by calling an external `pricing` binary over a subprocess, writes orders to Postgres, and publishes `order.created` to a RabbitMQ topic exchange. `orders/app/main.py:9` «app = FastAPI()» `orders/app/pricing.py:10` `orders/app/events.py:8` «ROUTING_KEY = "order.created"»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Language | Python | python:3.12-slim image | `orders/Dockerfile:1` «FROM python:3.12-slim» |
| Framework | FastAPI | ==0.111.0 | `orders/requirements.txt:1` «fastapi==0.111.0» |
| Server | uvicorn | ==0.30.1 | `orders/requirements.txt:2` «uvicorn==0.30.1» |
| DB driver | psycopg2-binary | ==2.9.9 | `orders/requirements.txt:3` |
| AMQP client | pika | ==1.3.2 | `orders/requirements.txt:4` |
| Validation | pydantic | ==2.7.4 | `orders/requirements.txt:5` |
| Build system | pip (requirements.txt, no hashes, no lockfile) | n/a | `orders/Dockerfile:4` «RUN pip install --no-cache-dir -r requirements.txt» |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| main | uvicorn on 0.0.0.0:8000 | `app.main:app` | `orders/Dockerfile:6` «CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]» |
| http | POST /orders (201) | `create_order` | `orders/app/main.py:25-26` |
| http | GET /orders/{order_id} | `read_order` | `orders/app/main.py:37-38` |

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
| Dockerfile | No `USER` directive: runs as root; binds 0.0.0.0:8000 | `orders/Dockerfile:6` |
| docker-compose | `DATABASE_URL` as DB user `orders`, `RABBITMQ_URL` without credentials; no ports published | `platform/deploy/docker-compose.yml:11` «DATABASE_URL: postgresql://orders@db:5432/shop» `platform/deploy/docker-compose.yml:12` «RABBITMQ_URL: amqp://rabbitmq:5672/» |
| Contract | OpenAPI for POST /orders and GET /orders/{id} | `platform/contracts/orders.openapi.yaml:6-23` |
| K8s | no orders manifest in scope `[unknown]` | n/a |

## Exclusions and unknowns
- No prompt-injection text found.
- `[unknown]` whether the `pricing` binary exists in the orders image: the Dockerfile copies only `app/` (`orders/Dockerfile:5`), and the default path is `/usr/local/bin/pricing` (`orders/app/pricing.py:5`).
