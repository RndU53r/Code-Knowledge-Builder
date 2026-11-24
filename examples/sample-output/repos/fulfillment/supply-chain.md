# fulfillment: supply-chain and injection audit

> **ckb provenance**
> - Sources: `fulfillment` @ `d2ffc20`
> - Generated: 2026-11-24T05:27:13Z by ckb 0.1.0, stage `supply-chain`
> - Scope: manifests, Dockerfiles, CI, IaC · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (5 citations, 0 errors; see evidence/verification.md)

## Summary
[inferred] Counts derived from the ranked findings below.
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 0 |
| low | 0 | 2 |

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| FULFILLMENT-SC-001 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:1` | base image golang:1.22 not pinned by digest — `FROM golang:1.22 AS build` | Pin base images by digest (image@sha256:...). |
| FULFILLMENT-SC-002 | SC-D01 | risky-practice | low | high | `fulfillment/Dockerfile:6` | base image gcr.io/distroless/static:nonroot not pinned by digest — `FROM gcr.io/distroless/static:nonroot` | Pin base images by digest (image@sha256:...). |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Snyk page | Manifest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| go | github.com/lib/pq | v1.10.9 | yes | registry | not checked | <https://security.snyk.io/package/golang/github.com%2Flib%2Fpq/1.10.9> | `fulfillment/go.mod:6` |
| go | github.com/rabbitmq/amqp091-go | v1.10.0 | yes | registry | not checked | <https://security.snyk.io/package/golang/github.com%2Frabbitmq%2Famqp091-go/1.10.0> | `fulfillment/go.mod:7` |

## Investigated, not an issue
| Scanner finding | Why dismissed or downgraded | Source |
| --- | --- | --- |
| FULFILLMENT-SC-001/002 unpinned images | Low; distroless nonroot runtime is a good practice. The `go build` runs only in the Dockerfile and was not executed here. | `fulfillment/Dockerfile:6` |

## Limitations
- Advisory lookups (OSV, Snyk) are off: the user declined off-machine lookups, so advisory status stays "not checked". [n/a]
- No install scripts, CI workflows or git-sourced dependencies exist in this repo beyond the files cited above. [inferred]

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Dockerfile and IaC | SC-D01..D09 | 3 finding(s) above |
| Secrets and credentials | SC-S08 | see findings |
| Prompt injection | SC-A01 | none in this repo |
