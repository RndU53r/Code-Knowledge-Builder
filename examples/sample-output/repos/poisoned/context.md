---
ckb_context: 1
scope: poisoned
revision: unversioned (local)
generated: 2026-11-23T10:00:00Z
languages: [javascript]
entry_points: 5
focus_areas: [install-time-rce, ci-pwn-request, prompt-injection, obfuscated-eval, trojan-source, typosquat, committed-secret]
---
# Security context: poisoned

> **ckb provenance**
> - Sources: `poisoned` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `context`
> - Scope: poisoned · Excluded: none; hostile text treated as data
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## 1. Purpose and tech stack
npm package `left-pad-utils` seeded with hostile patterns; treat as malicious. `poisoned/package.json:2` `poisoned/README.md:3`
- JavaScript/Node `poisoned/Dockerfile:1`; no framework used; npm without lockfile `poisoned/package.json:4-13`.

## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| npm postinstall | developer/CI host | TB6 | `poisoned/package.json:5` |
| husky pre-commit | developer host | TB6 | `poisoned/.husky/pre-commit:2` |
| `pull_request_target` | internet (any PR) | TB6 | `poisoned/.github/workflows/pr-label.yml:3` |
| library exports | consumer code | n/a | `poisoned/src/index.js:16` |
| repo text read by AI agents | agent | TB6 | `poisoned/AGENTS.md:2` |

## 3. Authn/authz model
- `isAdmin` returns `user.role === 'admin'`; a bidi-obfuscated comment above it is deceptive only. `poisoned/src/index.js:10-11`
- CI job runs with default token scopes and secrets. `poisoned/.github/workflows/pr-label.yml:1-16`

## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| host name | os | remote host | none | `poisoned/scripts/setup.js:4` |
| `NPM_TOKEN` | Actions secrets | job log | Actions masking only [inferred] | `poisoned/.github/workflows/pr-label.yml:16` |
| AWS key ID pattern | source code | repo | none (`AKIA…[REDACTED]`) | `poisoned/src/index.js:14` |
| SSH keys | developer home | requested by injected text | n/a (not followed) | `poisoned/docs/CONTRIBUTING.md:3-4` |

## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Effective? | Source |
| --- | --- | --- | --- | --- |
| `eval(Buffer.from(payload,'base64'))` | eval | none | UNSAFE | `poisoned/scripts/setup.js:5` |
| postinstall shell fallback | command | none | UNSAFE | `poisoned/package.json:5` |
| `${{ github.event.pull_request.title }}` in `run:` | CI script injection | none | UNSAFE | `poisoned/.github/workflows/pr-label.yml:15` |
| Dockerfile remote fetch | build | none | UNSAFE | `poisoned/Dockerfile:2-4` |

## 6. Known-safe patterns and known-risky areas
- Safe: `leftPad` logic `poisoned/src/index.js:3-7`.
- Risky: everything else; see `repos/poisoned/supply-chain.md` and prompt-injection items at `poisoned/README.md:10`, `poisoned/docs/CONTRIBUTING.md:3`, `poisoned/AGENTS.md:2`, `poisoned/src/index.js:1`.

## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| none | [n/a] | not consumed by any in-scope repo | n/a | `gateway/package.json:6-10` |

## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `setup.js` fails | remote-script fallback | n/a | `poisoned/package.json:5` |
| PR opened or edited | privileged workflow runs | n/a | `poisoned/.github/workflows/pr-label.yml:3-4` |

## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | CI pwn request | .github/workflows/pr-label.yml | `poisoned/.github/workflows/pr-label.yml:11` | T13 |
| 2 | Install/commit-time RCE | package.json, scripts/setup.js, .husky/* | `poisoned/scripts/setup.js:5` | T14 |
| 3 | Prompt injection | README.md, AGENTS.md, docs/*, src/index.js | `poisoned/README.md:10` | T15 |
| 4 | Dependency attacks | package.json | `poisoned/package.json:9-12` | T16 |
| 5 | Trojan Source, committed key | src/index.js | `poisoned/src/index.js:10` `poisoned/src/index.js:14` | T15, T16 |
