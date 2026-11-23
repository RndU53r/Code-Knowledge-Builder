# gateway: overview

> **ckb provenance**
> - Sources: `gateway` @ `unversioned (local ./polyglot/gateway)`, `platform` @ `unversioned (local ./polyglot)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: gateway/src, package.json, package-lock.json, Dockerfile; platform/deploy, platform/contracts for context · Excluded: none (no secrets files, binaries or symlinks found)
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Purpose
Public HTTP API (Node/Express) that authenticates callers with a bearer JWT and forwards order requests to the `orders` service over REST; it also exposes an admin-only report proxy. `gateway/src/server.js:1` «const express = require('express');» `gateway/src/server.js:5` «const ORDERS_URL = process.env.ORDERS_URL || 'http://orders:8000';»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| Language | JavaScript (Node.js) | node:20-alpine image | `gateway/Dockerfile:1` «FROM node:20-alpine» |
| Framework | Express | 4.19.2 | `gateway/package.json:7` «"express": "4.19.2"» |
| HTTP client | axios | 1.7.2 | `gateway/package.json:8` «"axios": "1.7.2"» |
| Auth | jsonwebtoken | 9.0.2 | `gateway/package.json:9` «"jsonwebtoken": "9.0.2"» |
| Build system | npm (lockfile, `npm ci --ignore-scripts`) | n/a | `gateway/Dockerfile:4` «RUN npm ci --omit=dev --ignore-scripts» |

## Entry points
| Kind | Name or route | Handler | Source |
| --- | --- | --- | --- |
| main | process start | `node src/server.js` | `gateway/Dockerfile:7` «CMD ["node", "src/server.js"]» |
| http | GET /healthz | inline | `gateway/src/server.js:11` «app.get('/healthz'» |
| http | POST /orders (requireAuth) | inline async handler | `gateway/src/server.js:13` «app.post('/orders', requireAuth» |
| http | GET /orders/:id (requireAuth) | inline async handler | `gateway/src/server.js:26` «app.get('/orders/:id', requireAuth» |
| http | GET /admin/report (requireAuth, requireRole admin) | inline async handler | `gateway/src/server.js:31` «app.get('/admin/report', requireAuth, requireRole('admin')» |
| listener | port from env `PORT` (default 3000) | app.listen | `gateway/src/server.js:6` «const PORT = process.env.PORT» |

## Dependencies (direct)
| Name | Version spec | Registry or source | Manifest |
| --- | --- | --- | --- |
| express | 4.19.2 (exact) | npm registry | `gateway/package.json:7` |
| axios | 1.7.2 (exact) | npm registry | `gateway/package.json:8` |
| jsonwebtoken | 9.0.2 (exact) | npm registry | `gateway/package.json:9` |

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| Dockerfile | Runs as non-root user `node`; install skips lifecycle scripts | `gateway/Dockerfile:6` «USER node» |
| docker-compose | Port 3000 published; `ORDERS_URL` and `JWT_SECRET` injected | `platform/deploy/docker-compose.yml:4` «ports: ["3000:3000"]» `platform/deploy/docker-compose.yml:7` «JWT_SECRET: ${JWT_SECRET}» |
| K8s Deployment | 2 replicas, image `shop/gateway:1.0.0`; only `ORDERS_URL` env set (no `JWT_SECRET`) | `platform/deploy/k8s/gateway.yaml:6` «replicas: 2» `platform/deploy/k8s/gateway.yaml:18` «- name: ORDERS_URL» |
| K8s Ingress | Internet host routes `/` to gateway:3000 | `platform/deploy/k8s/gateway.yaml:27` «- host: shop.example.com» |

## Exclusions and unknowns
- No prompt-injection text found in this repo.
- `[unknown]` how `JWT_SECRET` is provided in Kubernetes: the Deployment sets no such env var (`platform/deploy/k8s/gateway.yaml:17-19`); a Secret mounted elsewhere would resolve this.
- No tests or CI specific to gateway in scope.
