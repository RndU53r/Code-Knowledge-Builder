---
ckb_context: 1
scope: gateway
revision: 8c8444d
generated: 2026-11-24T05:32:39Z
languages: [javascript]
entry_points: 4
focus_areas: [ssrf, authz-bypass, idor, dos-unhandled-rejection]
---
# Security context: gateway

> **ckb provenance**
> - Sources: `gateway` @ `8c8444d`
> - Generated: 2026-11-24T05:32:39Z by ckb 0.1.0, stage `security-context`
> - Scope: gateway · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (21 citations, 0 errors; see evidence/verification.md)

## 1. Purpose and tech stack
Express edge API with JWT auth that forwards to orders. `gateway/src/server.js:13`
- Node 20, express 4.19.2, axios 1.7.2, jsonwebtoken 9.0.2 `gateway/package.json:7`
## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| GET /healthz | internet | internet to gateway | `gateway/src/server.js:11` |
| POST /orders | internet, JWT | internet to gateway; gateway to orders | `gateway/src/server.js:13` |
| GET /orders/:id | internet, JWT | same | `gateway/src/server.js:26` |
| GET /admin/report | internet, JWT admin | gateway to arbitrary URL | `gateway/src/server.js:31` |
## 3. Authn/authz model
JWT HS256 verified with `JWT_SECRET` in `requireAuth`; role check in `requireRole`. Bypass: `AUTH_DISABLED=true` makes every caller `{sub:'dev', role:'admin'}` (default off). Service-to-service auth to orders: none (a plain header). `gateway/src/auth.js:17` `gateway/src/auth.js:7` `gateway/src/server.js:17`
## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| JWT subject | token | forwarded as customer_id and header | signature verified | `gateway/src/server.js:15` |
| order body | client | orders | 100kb body limit, no schema check | `gateway/src/server.js:9` |
## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Verdict | Source |
| --- | --- | --- | --- | --- |
| `axios.get(req.query.source)` | SSRF | admin role only; no host allowlist | UNSAFE: unvalidated URL (admin-gated) | `gateway/src/server.js:32` |
| `axios.get(.../orders/${req.params.id})` | request path | none; id is not encoded or validated | [unknown]: path injection possible, host fixed by env | `gateway/src/server.js:27` |
## 6. Known-safe patterns and known-risky areas
- Safe: algorithm pinned to HS256 `gateway/src/auth.js:17`; try/catch on POST route `gateway/src/server.js:20`.
- Risky: AUTH_DISABLED switch `gateway/src/auth.js:7`; routes without error handling `gateway/src/server.js:26`; no ownership check `gateway/src/server.js:27`.
## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| orders REST (OpenAPI) | gateway | orders | none | `gateway/src/server.js:15` |
## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `AUTH_DISABLED` is `true` | all callers are admin | off | `gateway/src/auth.js:4` |
| `ORDERS_URL` | orders base URL | `http://orders:8000` | `gateway/src/server.js:5` |
## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | idor | `src/server.js` | any user reads any order | T-33 |
| 2 | ssrf | `src/server.js` | admin URL fetch | T-01 |
| 3 | dos-unhandled-rejection | `src/server.js` | async routes without catch | T-35 |
| 4 | authz-bypass | `src/auth.js` | AUTH_DISABLED | T-07 |
