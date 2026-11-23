# System: supply-chain report

> **ckb provenance**
> - Sources: `gateway`, `orders`, `fulfillment`, `platform`, `poisoned` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `supply-chain`
> - Scope: all five repos (platform findings de-duplicated against services) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Summary
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 5 | 0 |
| high | 15 | 2 |
| medium | 0 | 9 |
| low | 1 | 15 |

Totals after de-duplication: poisoned 36, orders 4, gateway 2, fulfillment 2, platform-only 3 (+1 medium in platform duplicates orders). All confirmed-suspicious items are in `poisoned`; the three services show only hygiene gaps. Advisory lookups off, so CVE status is [unknown] for all 14 package dependencies and 4 platform actions/images (47 findings in total).

## Cross-repo ranking (top findings)
| Rank | ID | Repo | Severity | Class | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | POISONED-SC-005 | poisoned | critical | confirmed-suspicious | postinstall with remote-script fallback `poisoned/package.json:5` | Never install; `--ignore-scripts` |
| 2 | POISONED-SC-004 | poisoned | critical | confirmed-suspicious | `pull_request_target` + PR head checkout `poisoned/.github/workflows/pr-label.yml:11` | Switch trigger |
| 3 | POISONED-SC-001/002/003 | poisoned | critical | confirmed-suspicious | agent-directed prompt injection `poisoned/README.md:10` `poisoned/docs/CONTRIBUTING.md:3` | Remove; report |
| 4 | POISONED-SC-016 | poisoned | high | confirmed-suspicious | eval of base64 payload `poisoned/scripts/setup.js:5` | Delete |
| 5 | POISONED-SC-M01 | poisoned | high | confirmed-suspicious | host-name beacon `poisoned/scripts/setup.js:4` | Delete |
| 6 | POISONED-SC-034 | poisoned | high | confirmed-suspicious | husky hook runs payload `poisoned/.husky/pre-commit:2` | Remove |
| 7 | POISONED-SC-010/011 | poisoned | high | confirmed-suspicious | CI script injection and secret echo `poisoned/.github/workflows/pr-label.yml:15-16` | Fix and rotate |
| 8 | POISONED-SC-017 | poisoned | high | confirmed-suspicious | Trojan Source bidi `poisoned/src/index.js:10` | Strip |
| 9 | ORDERS-SC-001 | orders | medium | risky-practice | root container `orders/Dockerfile:6` | Add USER |
| 10 | ORDERS-SC-M01 | orders | low | risky-practice | default broker creds in code `orders/app/events.py:6` (`amqp…[REDACTED]`) | Require env |

## Shared risky dependencies
| Dependency | Repos | Note | Source |
| --- | --- | --- | --- |
| express | gateway (4.19.2 exact), poisoned (`*`) | same package, opposite pinning discipline | `gateway/package.json:7` `poisoned/package.json:10` |
| none other | n/a | no other overlap across ecosystems | `fulfillment/go.mod:5-8` |

## Patterns repeated across repos
| Pattern | Where | Source |
| --- | --- | --- |
| Base images by tag, not digest | gateway, orders, fulfillment (x2), platform K8s and compose, poisoned | `gateway/Dockerfile:1` `orders/Dockerfile:1` `fulfillment/Dockerfile:1` `platform/deploy/k8s/gateway.yaml:15` `poisoned/Dockerfile:1` |
| Root containers | orders, poisoned | `orders/Dockerfile:1-6` `poisoned/Dockerfile:1-6` |
| No hash-pinned installs | orders (pip), poisoned (no lockfile), gateway lock lacks integrity | `orders/requirements.txt:1` `poisoned/package.json:1` `gateway/package-lock.json:12` |
| CI pinning | platform pins by SHA; poisoned uses tags/branches | `platform/.github/workflows/ci.yml:9` `poisoned/.github/workflows/pr-label.yml:12` |

## Exposure of the system to poisoned
No in-scope repo references `left-pad-utils`, `lodahs`, `internal-auth`, or `@acme/billing-client` (`gateway/package.json:6-10`, `orders/requirements.txt:1-5`, `fulfillment/go.mod:5-8`). Risk is to developers and agents who open, install, or contribute to it.

Per-repo reports: [gateway](../repos/gateway/supply-chain.md), [orders](../repos/orders/supply-chain.md), [fulfillment](../repos/fulfillment/supply-chain.md), [platform](../repos/platform/supply-chain.md), [poisoned](../repos/poisoned/supply-chain.md).
