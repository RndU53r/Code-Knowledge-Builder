---
ckb_context: 1
scope: gateway
revision: unversioned (local)
generated: 2026-11-23T10:00:00Z
languages: [javascript]
entry_points: 4
focus_areas: [ssrf, authz-bypass, idor, unhandled-rejection-dos]
---
# Security context: gateway

> **ckb provenance**
> - Sources: `gateway` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `context`
> - Scope: gateway · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## 1. Purpose and tech stack
Public Express API that verifies JWTs and proxies to orders; also an admin URL-fetch report.
- Node.js 20 `gateway/Dockerfile:1`, Express 4.19.2 `gateway/package.json:7`, axios 1.7.2 `gateway/package.json:8`, jsonwebtoken 9.0.2 `gateway/package.json:9`. No datastore.

## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| POST /orders | internet | TB1 internet→gateway, TB2 →orders | `gateway/src/server.js:13` |
| GET /orders/:id | internet | TB1, TB2 | `gateway/src/server.js:26` |
| GET /admin/report | internet (admin) | TB1, TB5 →any URL | `gateway/src/server.js:31` |
| GET /healthz | internet | TB1 | `gateway/src/server.js:11` |

## 3. Authn/authz model
- Bearer JWT, HS256 only, secret `JWT_SECRET` from env. `gateway/src/auth.js:17` `gateway/src/auth.js:3`
- Roles: `req.user.role === 'admin'` for /admin/report only. `gateway/src/auth.js:26`
- Bypass: `AUTH_DISABLED=true` → user `dev` with role `admin`; default off. `gateway/src/auth.js:4` `gateway/src/auth.js:8`
- Service-to-service: none; forwards `x-request-user` header that orders ignores. `gateway/src/server.js:17`

## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| JWT | Authorization header | memory | HS256 verify | `gateway/src/auth.js:11-17` |
| order body (card_last4, shipping_address) | client | orders over HTTP | none observed (plain HTTP internally) | `gateway/src/server.js:5` `gateway/src/server.js:15` |

## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Effective? | Source |
| --- | --- | --- | --- | --- |
| `axios.get(req.query.source)` | SSRF | admin role only | UNSAFE: no allowlist | `gateway/src/server.js:32` |
| `axios.get(ORDERS_URL/orders/${id})` | path injection into internal URL | none | [unknown] encoded slashes may alter the upstream path | `gateway/src/server.js:27` |
| `axios.post(ORDERS_URL/orders)` | fixed URL | `customer_id` overwritten from token | safe: fixed target | `gateway/src/server.js:15` |

## 6. Known-safe patterns and known-risky areas
- Safe: JWT algorithm pinned `gateway/src/auth.js:17`; 100kb body limit `gateway/src/server.js:9`; non-root container `gateway/Dockerfile:6`; `--ignore-scripts` `gateway/Dockerfile:4`.
- Risky: async handlers without try/catch `gateway/src/server.js:26-34`; no ownership check `gateway/src/server.js:26-27`.

## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| Orders OpenAPI createOrder / getOrder | gateway | orders | none | `platform/contracts/orders.openapi.yaml:8` `platform/contracts/orders.openapi.yaml:23` |

## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `AUTH_DISABLED` = "true" | all callers admin | off | `gateway/src/auth.js:4` |
| `JWT_SECRET` unset | all tokens rejected [inferred] | unset in K8s | `gateway/src/auth.js:3` |
| `ORDERS_URL` | upstream base | `http://orders:8000` | `gateway/src/server.js:5` |

## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | SSRF | gateway/src/server.js | user-controlled URL fetch `gateway/src/server.js:32` | T2 |
| 2 | Auth bypass toggle | gateway/src/auth.js | admin for everyone when set `gateway/src/auth.js:8` | T3 |
| 3 | IDOR | gateway/src/server.js | no owner check `gateway/src/server.js:27` | T4 |
| 4 | Unhandled rejection DoS | gateway/src/server.js | `gateway/src/server.js:26-29` | T5 |
