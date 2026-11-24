# orders: supply-chain and injection audit

> **ckb provenance**
> - Sources: `orders` @ `1de64cb` (snapshot of `main`)
> - Generated: 2026-11-24T05:27:13Z by ckb 0.1.0, stage `supply-chain`
> - Scope: manifests, Dockerfiles, CI, IaC · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (11 citations, 0 errors; see evidence/verification.md)

## Summary
[inferred] Counts derived from the ranked findings below.
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 2 |
| low | 0 | 2 |

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ORDERS-SC-001 | SC-D03 | risky-practice | medium | high | `orders/Dockerfile:1` | container runs as root (no non-root USER) | Add a non-root USER and drop privileges. |
| ORDERS-SC-002 | SC-S08 | risky-practice | medium | medium | `orders/app/events.py:6` | credentials embedded in a URL (may be a default like guest:guest; still a hardcoded credential) — `RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp…[REDACTED]rabbitmq:5672/")` | Rotate the credential, remove it from history, and load it from a secret manager. |
| ORDERS-SC-003 | SC-D01 | risky-practice | low | high | `orders/Dockerfile:1` | base image python:3.12-slim not pinned by digest — `FROM python:3.12-slim` | Pin base images by digest (image@sha256:...). |
| ORDERS-SC-004 | SC-M02 | risky-practice | low | medium | `orders/requirements.txt:1` | requirements without --hash pins or a lockfile (installs are not reproducible) | Commit the ecosystem lockfile and install with the frozen/locked mode in CI. |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Snyk page | Manifest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| pypi | fastapi | ==0.111.0 | yes | registry | not checked | <https://security.snyk.io/package/pip/fastapi/0.111.0> | `orders/requirements.txt:1` |
| pypi | uvicorn | ==0.30.1 | yes | registry | not checked | <https://security.snyk.io/package/pip/uvicorn/0.30.1> | `orders/requirements.txt:2` |
| pypi | psycopg2-binary | ==2.9.9 | yes | registry | not checked | <https://security.snyk.io/package/pip/psycopg2-binary/2.9.9> | `orders/requirements.txt:3` |
| pypi | pika | ==1.3.2 | yes | registry | not checked | <https://security.snyk.io/package/pip/pika/1.3.2> | `orders/requirements.txt:4` |
| pypi | pydantic | ==2.7.4 | yes | registry | not checked | <https://security.snyk.io/package/pip/pydantic/2.7.4> | `orders/requirements.txt:5` |

## Investigated, not an issue
| Scanner finding | Why dismissed or downgraded | Source |
| --- | --- | --- |
| ORDERS-SC-002 credentials in URL | Default `guest:guest` broker URL is a hardcoded fallback credential, not a live secret; kept as medium because production could silently run with it. | `orders/app/events.py:6` |
| ORDERS-SC-001 root container | Confirmed: no USER in the Dockerfile. | `orders/Dockerfile:6` |

## Limitations
- Advisory lookups (OSV, Snyk) are off: the user declined off-machine lookups, so advisory status stays "not checked". [n/a]
- No install scripts, CI workflows or git-sourced dependencies exist in this repo beyond the files cited above. [inferred]

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Dockerfile and IaC | SC-D01..D09 | 4 finding(s) above |
| Secrets and credentials | SC-S08 | see findings |
| Prompt injection | SC-A01 | none in this repo |
