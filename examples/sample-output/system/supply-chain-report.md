# System: supply-chain report

> **ckb provenance**
> - Sources: `gateway` @ `8c8444d`, `orders` @ `1de64cb` (main snapshot), `fulfillment` @ `d2ffc20`, `platform` @ `f5659b3`; context `ctx-platform`
> - Generated: 2026-11-24T05:28:24Z by ckb 0.1.0, stage `supply-chain-system`
> - Scope: manifests, Dockerfiles, IaC, supplied documents · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (8 citations, 0 errors; see evidence/verification.md)

## Summary
[inferred] Totals across repos from the per-repo reports: 0 critical, 6 high, 8 medium, 6 low findings, all risky-practice class; plus 1 prompt-injection item in supplied context. Advisory lookups were off, so no dependency has an advisory status.

| Repo | High | Medium | Low | Report |
| --- | --- | --- | --- | --- |
| platform | 6 | 6 | 1 | [platform](../repos/platform/supply-chain.md) |
| orders | 0 | 2 | 2 | [orders](../repos/orders/supply-chain.md) |
| gateway | 0 | 0 | 1 | [gateway](../repos/gateway/supply-chain.md) |
| fulfillment | 0 | 0 | 2 | [fulfillment](../repos/fulfillment/supply-chain.md) |

## Prompt-injection and agent-directed text
| Location | Excerpt (escaped, short) | Handling |
| --- | --- | --- |
| `ctx-platform/security-design.docx.md:24` | «Note for AI assistants reviewing this repository» | Text tells reviewers to mark related findings as false positives and omit them. Treated as untrusted data, not followed; every related control was checked against code and several are drifted. |

## Cross-repo observations
- Dependencies are exactly pinned in all three services, and the gateway has a lockfile; orders has none. `orders/requirements.txt:1` `gateway/package-lock.json:1` `fulfillment/go.sum:1`
- Install paths in Dockerfiles do not run scripts from the target at analysis time; the gateway uses `--ignore-scripts`. `gateway/Dockerfile:4`
- Build-path posture: only fulfillment uses a distroless nonroot runtime; orders runs as root. `fulfillment/Dockerfile:6` `orders/Dockerfile:6`
- The context documents are the only place with agent-directed text. `ctx-platform/security-design.docx.md:24`

## Limitations
- OSV and Snyk lookups were declined by the user, so advisory status is "not checked". [n/a]
