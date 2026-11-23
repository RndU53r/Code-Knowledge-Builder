# gateway: outputs and conditions

> **ckb provenance**
> - Sources: `gateway` @ `unversioned (local)`, `orders` @ `unversioned (local)`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `analyze`
> - Scope: gateway (all files) · Excluded: none
> - Method: static analysis only; no target code executed
> - Verification: passed (see evidence/verification.md)

## Output index
| ID | Kind | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |
| O-gateway-1 | external-call | POST orders (create) | `gateway/src/server.js:15` | orders `orders/app/main.py:25` «@app.post("/orders", status_code=201)» |
| O-gateway-2 | external-call | GET orders by id | `gateway/src/server.js:27` | orders `orders/app/main.py:37` «@app.get("/orders/{order_id}")» |
| O-gateway-3 | external-call | admin report fetch of `?source=` | `gateway/src/server.js:32` | [unknown] any host |
| O-gateway-4 | api-response | responses to clients (relayed order, report, 401/403/502) | `gateway/src/server.js:19-22` | internet clients |

## O-1: create order forwarded to orders
- **What:** JSON body = client body spread + `customer_id` from JWT `sub`; header `x-request-user`. `gateway/src/server.js:15-17`
- **How:** `requireAuth` → handler → `axios.post`. `gateway/src/auth.js:6` `gateway/src/server.js:13-15`
- **Who consumes:** orders `create_order`. `orders/app/main.py:26` «def create_order(req: OrderRequest, x_request_user: str | None = Header(default=None)):»

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| env `AUTH_DISABLED` == "true" | every request treated as `sub=dev, role=admin`; no token needed | unset → auth enforced | `gateway/src/auth.js:4` «const AUTH_DISABLED = process.env.AUTH_DISABLED === 'true';» `gateway/src/auth.js:7-9` |
| no `Bearer` token | 401, no upstream call | n/a | `gateway/src/auth.js:13-14` |
| env `JWT_SECRET` unset | `jwt.verify` throws for every token, so 401 for all [inferred] | unset in K8s manifest | `gateway/src/auth.js:3` «const JWT_SECRET = process.env.JWT_SECRET;» |
| env `ORDERS_URL` | upstream base URL | `http://orders:8000` | `gateway/src/server.js:5` |
| upstream error | relay upstream status, else 502 `upstream error` | n/a | `gateway/src/server.js:21-22` |

## O-2: read order
- **What:** GET with raw id in the path; response body relayed as is. `gateway/src/server.js:27-28`
- **How:** `requireAuth` → handler → `axios.get`. `gateway/src/server.js:26-27`
- **Who consumes:** orders `read_order`. `orders/app/main.py:38` «def read_order(order_id: str):»

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| authenticated (any user) | any order id readable; no ownership check | n/a | `gateway/src/server.js:26` |
| upstream 4xx/5xx | unhandled rejection; no response sent [inferred] | n/a | `gateway/src/server.js:27` |

## O-3: admin report fetch
- **What:** `{ report: <upstream body> }`. `gateway/src/server.js:33`
- **How:** `requireAuth` → `requireRole('admin')` → `axios.get(req.query.source)`. `gateway/src/server.js:31-32`
- **Who consumes:** [unknown] caller-chosen host.

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| role != admin | 403 | n/a | `gateway/src/auth.js:26-27` |
| `AUTH_DISABLED` true | any caller is admin, so SSRF is unauthenticated | false | `gateway/src/auth.js:8` |
| `source` any URL incl. internal hosts | fetched with 5s timeout | no allowlist | `gateway/src/server.js:32` |

## O-4: client responses
- **What:** relayed upstream JSON, or error objects. `gateway/src/server.js:19-22`
- **How:** Express `res.json`.
- **Who consumes:** internet clients via Ingress. `platform/deploy/k8s/gateway.yaml:27`

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `PORT` env | listen port | 3000 | `gateway/src/server.js:6` |

Security-relevant conditions for the threat model: `AUTH_DISABLED` (auth bypass with admin role), missing `JWT_SECRET`, unvalidated `source`.
