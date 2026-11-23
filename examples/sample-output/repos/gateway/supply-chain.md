# gateway: supply-chain and injection audit

> **ckb provenance**
> - Sources: `gateway` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `supply-chain`
> - Scope: gateway (5 files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Summary
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 0 | 0 |
| low | 0 | 2 |

Counts tally the triaged findings below; advisory status [unknown] (lookups off).

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| GATEWAY-SC-001 | SC-D01 | risky-practice | low | high | `gateway/Dockerfile:1` «FROM node:20-alpine» base image not pinned by digest | Pin `node:20-alpine@sha256:…` |
| GATEWAY-SC-M01 | manual | risky-practice | low | high | `gateway/package-lock.json:12` lock entries have `resolved` but no `integrity` hash | Regenerate the lockfile with npm so integrity hashes are recorded |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| npm | express | 4.19.2 | yes (exact + lock) | registry | not checked | `gateway/package.json:7` |
| npm | axios | 1.7.2 | yes (exact + lock) | registry | not checked | `gateway/package.json:8` |
| npm | jsonwebtoken | 9.0.2 | yes (exact + lock) | registry | not checked | `gateway/package.json:9` |

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Manifests and lockfiles | floating ranges, lockfile presence, git/URL deps, typosquat | clean; lockfile present `gateway/package-lock.json:4` «"lockfileVersion": 3,» |
| Install-time execution | npm lifecycle scripts | none; only `start` and `test` `gateway/package.json:5` |
| Container | base pin, USER, remote ADD | non-root `gateway/Dockerfile:6`; scripts disabled `gateway/Dockerfile:4` |
| Obfuscation, hidden Unicode, secrets, agent text | scanner patterns | none found |

## Investigated, not an issue
- `npm ci --ignore-scripts` blocks dependency lifecycle scripts at build. `gateway/Dockerfile:4`

## Limitations
- Not a git checkout: commit-history checks skipped `[unknown]` (scanner limitation; `evidence/sc-gateway.json`).
- Advisory lookups off: every dependency is "not checked" for known CVEs `[unknown]`.
