# gateway: supply-chain and injection audit

> **ckb provenance**
> - Sources: `gateway` @ `8c8444d`
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
| low | 0 | 1 |

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GATEWAY-SC-001 | SC-D01 | risky-practice | low | high | `gateway/Dockerfile:1` | base image node:20-alpine not pinned by digest — `FROM node:20-alpine` | Pin base images by digest (image@sha256:...). |

## Dependency inventory (direct)
| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Snyk page | Manifest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| npm | express | 4.19.2 | yes | registry | not checked | <https://security.snyk.io/package/npm/express/4.19.2> | `gateway/package.json:7` |
| npm | axios | 1.7.2 | yes | registry | not checked | <https://security.snyk.io/package/npm/axios/1.7.2> | `gateway/package.json:8` |
| npm | jsonwebtoken | 9.0.2 | yes | registry | not checked | <https://security.snyk.io/package/npm/jsonwebtoken/9.0.2> | `gateway/package.json:9` |

## Investigated, not an issue
| Scanner finding | Why dismissed or downgraded | Source |
| --- | --- | --- |
| GATEWAY-SC-001 unpinned base image | Low risk: `npm ci --omit=dev --ignore-scripts` and a lockfile are used, and the image runs as `node`. Kept as low. | `gateway/Dockerfile:4` |

## Limitations
- Advisory lookups (OSV, Snyk) are off: the user declined off-machine lookups, so advisory status stays "not checked". [n/a]
- No install scripts, CI workflows or git-sourced dependencies exist in this repo beyond the files cited above. [inferred]

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Dockerfile and IaC | SC-D01..D09 | 3 finding(s) above |
| Secrets and credentials | SC-S08 | see findings |
| Prompt injection | SC-A01 | none in this repo |
