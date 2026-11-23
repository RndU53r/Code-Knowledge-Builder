| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| FULFILLMENT-SC-001 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:1` | base image golang:1.22 not pinned by digest — `FROM golang:1.22 AS build` | Pin base images by digest (image@sha256:...). |
| FULFILLMENT-SC-002 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:6` | base image gcr.io/distroless/static:nonroot not pinned by digest — `FROM gcr.io/distroless/static:nonroot` | Pin base images by digest (image@sha256:...). |

| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| go | github.com/lib/pq | v1.10.9 | yes | registry | not checked | `fulfillment/go.mod:6` |
| go | github.com/rabbitmq/amqp091-go | v1.10.0 | yes | registry | not checked | `fulfillment/go.mod:7` |

Limitations:

- not a git checkout: commit history checks skipped
