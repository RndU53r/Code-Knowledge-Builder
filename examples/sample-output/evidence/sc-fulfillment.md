| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| FULFILLMENT-SC-001 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:1` | base image golang:1.22 not pinned by digest — `FROM golang:1.22 AS build` | Pin base images by digest (image@sha256:...). |
| FULFILLMENT-SC-002 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:6` | base image gcr.io/distroless/static:nonroot not pinned by digest — `FROM gcr.io/distroless/static:nonroot` | Pin base images by digest (image@sha256:...). |

| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Snyk page | Manifest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| go | github.com/lib/pq | v1.10.9 | yes | registry | not checked | <https://security.snyk.io/package/golang/github.com%2Flib%2Fpq/1.10.9> | `fulfillment/go.mod:6` |
| go | github.com/rabbitmq/amqp091-go | v1.10.0 | yes | registry | not checked | <https://security.snyk.io/package/golang/github.com%2Frabbitmq%2Famqp091-go/1.10.0> | `fulfillment/go.mod:7` |

Informational:

- recent commit d2ffc20 (2026-11-24) touched build/CI file `fulfillment/Dockerfile:1`
