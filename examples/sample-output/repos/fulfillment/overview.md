# fulfillment: overview

> **ckb provenance**
> - Sources: `fulfillment` @ `unversioned (local)`, `platform` @ `unversioned (local)`, `orders` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: fulfillment (all files incl. go.sum) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Purpose
Go module with two binaries: a `worker` that consumes `order.created` from RabbitMQ, calls an external shipping API, and updates order status in Postgres; and a `pricing` CLI that orders invokes as a subprocess. `fulfillment/cmd/worker/main.go:26` `fulfillment/cmd/pricing/main.go:14`

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Language | Go | 1.22 | `fulfillment/go.mod:3` «go 1.22» |
| DB driver | github.com/lib/pq | v1.10.9 | `fulfillment/go.mod:6` |
| AMQP client | github.com/rabbitmq/amqp091-go | v1.10.0 | `fulfillment/go.mod:7` |
| Build system | go build (multi-stage Docker) | golang:1.22 | `fulfillment/Dockerfile:4` |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| main / consumer | worker, queue `fulfillment.order-created` bound to `orders`/`order.created` | `queue.Consume` handler | `fulfillment/cmd/worker/main.go:17` `fulfillment/internal/queue/consumer.go:26-30` |
| cli | pricing `--json` (stdin/stdout) | `main` | `fulfillment/cmd/pricing/main.go:14-16` |
| container | ENTRYPOINT `/worker` | worker | `fulfillment/Dockerfile:9` «ENTRYPOINT ["/worker"]» |

## Dependencies (direct)
| Name | Version spec | Registry or source | Manifest |
| --- | --- | --- | --- |
| github.com/lib/pq | v1.10.9 | Go proxy | `fulfillment/go.mod:6` |
| github.com/rabbitmq/amqp091-go | v1.10.0 | Go proxy | `fulfillment/go.mod:7` |

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| Dockerfile | Builds worker and pricing, but copies only worker into distroless nonroot image | `fulfillment/Dockerfile:4` `fulfillment/Dockerfile:7` «COPY --from=build /out/worker /worker» `fulfillment/Dockerfile:8` «USER nonroot» |
| docker-compose | DB user `fulfillment`, broker URL without credentials, `SHIPPING_API_URL` set; no `SHIPPING_API_KEY` | `platform/deploy/docker-compose.yml:16-18` |
| CI | `go test ./...` in fulfillment with SHA-pinned actions | `platform/.github/workflows/ci.yml:12` «- run: cd fulfillment && go test ./...» |

## Exclusions and unknowns
- No prompt-injection text found.
- `[unknown]` source of `SHIPPING_API_KEY` at runtime (not in compose, `platform/deploy/docker-compose.yml:13-18`).
- `[unknown]` where the `pricing` binary is shipped: not copied into the final image (`fulfillment/Dockerfile:7`).
