| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PLATFORM-SC-001 | SC-D03 | risky-practice | medium | high | `platform/orders/Dockerfile:1` | container runs as root (no non-root USER) | Add a non-root USER and drop privileges. |
| PLATFORM-SC-002 | SC-D01 | risky-practice | low | high | `platform/deploy/k8s/gateway.yaml:15` | workload image registry.example.com/shop/gateway:1.0.0 not pinned by digest — `image: registry.example.com/shop/gateway:1.0.0` | Pin base images by digest (image@sha256:...). |
| PLATFORM-SC-003 | SC-D01 | risky-practice | low | high | `platform/fulfillment/Dockerfile:1` | base image golang:1.22 not pinned by digest — `FROM golang:1.22 AS build` | Pin base images by digest (image@sha256:...). |
| PLATFORM-SC-004 | SC-D01 | risky-practice | low | high | `platform/fulfillment/Dockerfile:6` | base image gcr.io/distroless/static:nonroot not pinned by digest — `FROM gcr.io/distroless/static:nonroot` | Pin base images by digest (image@sha256:...). |
| PLATFORM-SC-005 | SC-D01 | risky-practice | low | high | `platform/gateway/Dockerfile:1` | base image node:20-alpine not pinned by digest — `FROM node:20-alpine` | Pin base images by digest (image@sha256:...). |
| PLATFORM-SC-006 | SC-D01 | risky-practice | low | high | `platform/orders/Dockerfile:1` | base image python:3.12-slim not pinned by digest — `FROM python:3.12-slim` | Pin base images by digest (image@sha256:...). |
| PLATFORM-SC-007 | SC-M02 | risky-practice | low | medium | `platform/orders/requirements.txt:1` | requirements without --hash pins or a lockfile (installs are not reproducible) | Commit the ecosystem lockfile and install with the frozen/locked mode in CI. |

| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| go | github.com/lib/pq | v1.10.9 | yes | registry | not checked | `platform/fulfillment/go.mod:6` |
| go | github.com/rabbitmq/amqp091-go | v1.10.0 | yes | registry | not checked | `platform/fulfillment/go.mod:7` |
| npm | express | 4.19.2 | yes | registry | not checked | `platform/gateway/package.json:7` |
| npm | axios | 1.7.2 | yes | registry | not checked | `platform/gateway/package.json:8` |
| npm | jsonwebtoken | 9.0.2 | yes | registry | not checked | `platform/gateway/package.json:9` |
| pypi | fastapi | ==0.111.0 | yes | registry | not checked | `platform/orders/requirements.txt:1` |
| pypi | uvicorn | ==0.30.1 | yes | registry | not checked | `platform/orders/requirements.txt:2` |
| pypi | psycopg2-binary | ==2.9.9 | yes | registry | not checked | `platform/orders/requirements.txt:3` |
| pypi | pika | ==1.3.2 | yes | registry | not checked | `platform/orders/requirements.txt:4` |
| pypi | pydantic | ==2.7.4 | yes | registry | not checked | `platform/orders/requirements.txt:5` |

Limitations:

- not a git checkout: commit history checks skipped
