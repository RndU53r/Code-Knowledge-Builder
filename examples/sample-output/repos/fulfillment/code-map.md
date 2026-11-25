# Code map: fulfillment

> **ckb provenance**
> - Sources: `fulfillment` (file roles from `evidence/file-roles-fulfillment.json`)
> - Method: path/content rules for most roles; graph signals for core vs utility (always [inferred])
> - Excluded: vendored, binaries, symlinks, secret files (listed, not read)

## Repo kind

- **service** [inferred], confidence high
- Signals: application share 70%; 1 consumer

## Files by role

| Role | Files |
| --- | --- |
| core | 3 |
| build | 2 |
| generated | 1 |

## Core application files [inferred]

| File | Why | Fan-in |
| --- | --- | --- |
| `internal/queue/consumer.go` | defines an entry point | 1 |
| `cmd/pricing/main.go` | no entry-point, I/O or helper signal; default | 0 |
| `cmd/worker/main.go` | owns I/O (data store, queue, outbound call, sink) | 0 |

## Utility files [inferred]

| File | Why |
| --- | --- |
| [n/a] none | |

## Tests

0 test file(s) [unknown] none found

Core files with no `tested_by` link (3): `internal/queue/consumer.go`, `cmd/pricing/main.go`, `cmd/worker/main.go`
(a missing link can also mean the tests call the code in a way the extractor could not resolve)
