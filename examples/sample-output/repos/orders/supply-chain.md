# orders: supply-chain and injection audit

> **ckb provenance**
> - Sources: `orders` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `supply-chain`
> - Scope: orders (7 files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Summary
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 1 |
| low | 0 | 3 |

Counts tally the triaged findings below; advisory status [unknown] (lookups off).

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| ORDERS-SC-001 | SC-D03 | risky-practice | medium | high | `orders/Dockerfile:1-6` no `USER`; container runs as root | Add a non-root user and `USER` |
| ORDERS-SC-002 | SC-D01 | risky-practice | low | high | `orders/Dockerfile:1` «FROM python:3.12-slim» | Pin by digest |
| ORDERS-SC-003 | SC-M02 | risky-practice | low | medium | `orders/requirements.txt:1` exact pins but no `--hash` and no lockfile | Use `pip-compile --generate-hashes` and `pip install --require-hashes` |
| ORDERS-SC-M01 | manual | risky-practice | low | high | `orders/app/events.py:6` code-default broker URL embeds the well-known default credentials (`amqp…[REDACTED]`) | Remove the default; require `RABBITMQ_URL` |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| PyPI | fastapi | ==0.111.0 | yes (no hash) | registry | not checked | `orders/requirements.txt:1` |
| PyPI | uvicorn | ==0.30.1 | yes (no hash) | registry | not checked | `orders/requirements.txt:2` |
| PyPI | psycopg2-binary | ==2.9.9 | yes (no hash) | registry | not checked | `orders/requirements.txt:3` |
| PyPI | pika | ==1.3.2 | yes (no hash) | registry | not checked | `orders/requirements.txt:4` |
| PyPI | pydantic | ==2.7.4 | yes (no hash) | registry | not checked | `orders/requirements.txt:5` |

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Manifests | floating ranges, hashes, git/URL deps, typosquat | exact pins, no hashes `orders/requirements.txt:1-5` |
| Container | base pin, USER | root user `orders/Dockerfile:6` |
| Subprocess | runtime exec of `PRICING_BIN` (argv list, no shell) | not a supply-chain issue; env-controlled path `orders/app/pricing.py:5` |
| Obfuscation, hidden Unicode, secrets, agent text | scanner patterns | none found |

## Investigated, not an issue
- `subprocess.run` uses an argv list without `shell=True`, so item data cannot inject shell syntax. `orders/app/pricing.py:10`

## Limitations
- Not a git checkout: commit-history checks skipped `[unknown]` (scanner limitation; `evidence/sc-orders.json`).
- Advisory lookups off: every dependency is "not checked" for known CVEs `[unknown]`.
