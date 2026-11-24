# fulfillment: overview

> **ckb provenance**
> - Sources: `fulfillment` @ `d2ffc20` (main, in place)
> - Generated: 2026-11-24T05:26:33Z by ckb 0.1.0, stage `repo-analysis`
> - Scope: fulfillment, 3 Go files · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (16 citations, 0 errors; see evidence/verification.md)

## Purpose
Go worker that consumes `order.created` from RabbitMQ, calls an external shipping API, and updates the order status in Postgres. It also contains the `pricing` CLI that orders spawns. `fulfillment/internal/queue/consumer.go:30` «ch.QueueBind(q.Name, "order.created", "orders", false, nil)» `fulfillment/cmd/worker/main.go:35` «db.Exec("UPDATE orders SET status = $1 WHERE id = $2", status, evt.OrderID)»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Language | Go | 1.22 | `fulfillment/go.mod:3` |
| Library | lib/pq | v1.10.9 | `fulfillment/go.mod:6` |
| Library | amqp091-go | v1.10.0 | `fulfillment/go.mod:7` |
| Build | multi-stage Docker, distroless nonroot runtime | n/a | `fulfillment/Dockerfile:6` |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| main | worker | `main` in `cmd/worker` | `fulfillment/cmd/worker/main.go:17` |
| consumer | queue `fulfillment.order-created` | `queue.Consume` | `fulfillment/internal/queue/consumer.go:17` |
| cli | pricing (stdin JSON) | `main` in `cmd/pricing` | `fulfillment/cmd/pricing/main.go:14` |

## Dependencies (direct)
| Name | Version spec | Registry or source | Manifest |
| --- | --- | --- | --- |
| github.com/lib/pq | v1.10.9 | Go modules | `fulfillment/go.mod:6` |
| github.com/rabbitmq/amqp091-go | v1.10.0 | Go modules | `fulfillment/go.mod:7` |

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| Dockerfile | builds both binaries; the image ships only the worker as entrypoint | `fulfillment/Dockerfile:4` `fulfillment/Dockerfile:9` |
| platform compose | `SHIPPING_API_URL` set; `SHIPPING_API_KEY` not set there | `platform/deploy/docker-compose.yml:18` |

## Cloud resources declared in this repo
[n/a] none.

## Exclusions and unknowns
- Secrets by name only: `SHIPPING_API_KEY` is sent as a bearer token. `fulfillment/cmd/worker/main.go:23` `fulfillment/cmd/worker/main.go:29`
- No text addressed to AI tools found in this repo.
