# gateway: overview

> **ckb provenance**
> - Sources: `gateway` @ `8c8444d` (main, in place)
> - Generated: 2026-11-24T05:26:33Z by ckb 0.1.0, stage `repo-analysis`
> - Scope: gateway, 5 source files · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (20 citations, 0 errors; see evidence/verification.md)

## Purpose
Express edge API: authenticates callers with a JWT, forwards order create/read to the orders service, and exposes an admin report fetch. `gateway/src/server.js:13` «app.post('/orders', requireAuth, async (req, res) => {» `gateway/src/auth.js:17` «jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Language | Node.js 20 (alpine) | 20 | `gateway/Dockerfile:1` «FROM node:20-alpine» |
| Framework | express | 4.19.2 | `gateway/package.json:7` |
| HTTP client | axios | 1.7.2 | `gateway/package.json:8` |
| Auth | jsonwebtoken | 9.0.2 | `gateway/package.json:9` |
| Build | `npm ci --omit=dev --ignore-scripts` (not run) | n/a | `gateway/Dockerfile:4` |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| http | GET /healthz | inline, no auth | `gateway/src/server.js:11` |
| http | POST /orders | `requireAuth` then inline | `gateway/src/server.js:13` |
| http | GET /orders/:id | `requireAuth` then inline | `gateway/src/server.js:26` |
| http | GET /admin/report | `requireAuth`, `requireRole('admin')` | `gateway/src/server.js:31` |

## Dependencies (direct)
| Name | Version spec | Registry or source | Manifest |
| --- | --- | --- | --- |
| express | 4.19.2 | npm | `gateway/package.json:7` |
| axios | 1.7.2 | npm | `gateway/package.json:8` |
| jsonwebtoken | 9.0.2 | npm | `gateway/package.json:9` |

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| Dockerfile | lockfile install, scripts ignored, runs as `node` user | `gateway/Dockerfile:6` «USER node» |
| platform compose | port 3000 published; `JWT_SECRET` from environment; `AUTH_DISABLED` not set | `platform/deploy/docker-compose.yml:4` `platform/deploy/docker-compose.yml:7` |
| platform k8s | Ingress for host `shop.example.com` to gateway:3000 | `platform/deploy/k8s/gateway.yaml:27` |

## Cloud resources declared in this repo
[n/a] none.

## Exclusions and unknowns
- `JWT_SECRET` and `AUTH_DISABLED` are read from the environment (names only). `gateway/src/auth.js:3` `gateway/src/auth.js:4`
- The JWT role claim comes from the token payload; who issues tokens is [unknown] (no issuer in scope).
- No text addressed to AI tools found in this repo.
