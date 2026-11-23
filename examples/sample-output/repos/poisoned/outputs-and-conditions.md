# poisoned: outputs and conditions

> **ckb provenance**
> - Sources: `poisoned` @ `unversioned (local ./poisoned)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: poisoned (all files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Output index
| ID | Kind | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |
| O-poisoned-1 | external-call | host-name beacon | `poisoned/scripts/setup.js:4` | attacker host [unknown] |
| O-poisoned-2 | external-call | remote script execution (postinstall and eval) | `poisoned/package.json:5` `poisoned/scripts/setup.js:5` | local shell |
| O-poisoned-3 | log | CI log containing `NPM_TOKEN` | `poisoned/.github/workflows/pr-label.yml:16` | anyone with log access (Actions masks known secrets [inferred]) |
| O-poisoned-4 | api-response | `leftPad` / `isAdmin` return values | `poisoned/src/index.js:6` `poisoned/src/index.js:11` | library consumers [unknown] |

## O-1: host-name beacon
- **What:** GET with `?h=<hostname>`. `poisoned/scripts/setup.js:4`
- **How:** npm `postinstall` or husky pre-commit → `setup.js`. `poisoned/package.json:5` `poisoned/.husky/pre-commit:2`
- **Who consumes:** [unknown] remote host.

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `npm install` without `--ignore-scripts` | beacon and eval run | scripts enabled by npm default [inferred] | `poisoned/package.json:5` |
| husky installed and commit made | setup script runs | n/a | `poisoned/.husky/pre-commit:2` |

## O-2: remote script execution
- **What:** shell runs a downloaded script. `poisoned/package.json:5`
- **How:** `setup.js` eval → `child_process.exec` (decoded), or `||` fallback. `poisoned/scripts/setup.js:5`
- **Who consumes:** local shell.

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `setup.js` exits non-zero | fallback remote script runs | n/a | `poisoned/package.json:5` |

## O-3: CI secret in log
- **What:** `token=<NPM_TOKEN>` line. `poisoned/.github/workflows/pr-label.yml:16`
- **How:** `pull_request_target` → step `Greet`. `poisoned/.github/workflows/pr-label.yml:13-16`
- **Who consumes:** log readers.

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| PR opened or edited by anyone | workflow runs with secrets | n/a | `poisoned/.github/workflows/pr-label.yml:3-4` |
| PR title contains shell syntax | executed in runner | n/a | `poisoned/.github/workflows/pr-label.yml:15` |

## O-4: library returns
- **What:** padded string; boolean admin. `poisoned/src/index.js:3-12`
- **How:** direct call.
- **Who consumes:** [unknown]; no in-scope repo depends on `left-pad-utils` (`gateway/package.json:6-10`).

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `ch` omitted | pads with space | `' '` | `poisoned/src/index.js:3` |
