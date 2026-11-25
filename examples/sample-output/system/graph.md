# System knowledge graph

> **ckb provenance**
> - Sources: `fulfillment` @ `unversioned`, `gateway` @ `unversioned`, `orders` @ `unversioned`, `platform` @ `unversioned`
> - Generated: 2026-11-25T22:12:20Z by ckb graph 1, stage `graph`
> - Scope: registered code repos · Excluded: vendored, generated, binaries, symlinks, secret files
> - Method: static extraction (ast / tree-sitter if installed / regex); agent proposals merged only after citation verification
> - Verification: see evidence/graph-verification.md

## Size

| Item | Count |
| --- | --- |
| nodes: class | 4 |
| nodes: cloud_resource | 15 |
| nodes: consumer | 1 |
| nodes: cspm_finding | 10 |
| nodes: dir | 7 |
| nodes: doc_section | 14 |
| nodes: drift | 11 |
| nodes: endpoint | 6 |
| nodes: env_var | 13 |
| nodes: external | 3 |
| nodes: file | 14 |
| nodes: function | 16 |
| nodes: package | 21 |
| nodes: repo | 4 |
| nodes: sc_finding | 20 |
| nodes: service | 6 |
| nodes: sink | 6 |
| nodes: table | 1 |
| nodes: taint_source | 9 |
| nodes: threat | 36 |
| nodes: topic | 1 |
| nodes: trust_boundary | 7 |
| edges: affects | 19 |
| edges: calls | 8 |
| edges: calls_lib | 25 |
| edges: configured_by | 8 |
| edges: consumes | 1 |
| edges: contains | 56 |
| edges: crosses_boundary | 7 |
| edges: deploys | 7 |
| edges: documented_as | 14 |
| edges: drifts_from | 11 |
| edges: finding_at | 14 |
| edges: flows_to | 9 |
| edges: http_calls | 4 |
| edges: imports | 34 |
| edges: publishes | 1 |
| edges: reaches_sink | 6 |
| edges: reads | 1 |
| edges: reads_env | 16 |
| edges: references | 3 |
| edges: routes_to | 7 |
| edges: spawns | 2 |
| edges: threatens | 21 |
| edges: uses_type | 1 |
| edges: writes | 2 |

## Extractors

| Extractor | Nodes | Edges |
| --- | --- | --- |
| ast | 34 | 60 |
| context | 10 | 19 |
| regex | 87 | 116 |
| rule | 74 | 68 |
| scanner | 20 | 14 |

## Repo kinds [inferred]

| Repo | Kind | Signals |
| --- | --- | --- |
| fulfillment | service | application share 70%; 1 consumer |
| gateway | service | application share 60%; 4 endpoint |
| orders | service | application share 90%; 2 endpoint |
| platform | iac | iac share 67%; gitops-config share 17% |

## Entry points (endpoints)

| Endpoint | Repo | Source |
| --- | --- | --- |
| GET /healthz | gateway | `gateway/src/server.js:11` |
| POST /orders | gateway | `gateway/src/server.js:13` |
| GET /orders/:id | gateway | `gateway/src/server.js:26` |
| GET /admin/report | gateway | `gateway/src/server.js:31` |
| POST /orders | orders | `orders/app/main.py:25` |
| GET /orders/{order_id} | orders | `orders/app/main.py:37` |

## Unsafe sink candidates

| Sink | Type | Reason | Source |
| --- | --- | --- | --- |
| ssrf sink in route GET /admin/report | ssrf | request input controls the URL/host | `gateway/src/server.js:32` |
| sql sink in get_order | sql | string-built query | `orders/app/db.py:23` |

## Cross-repo edges

| From | Kind | To | Confidence | Source |
| --- | --- | --- | --- | --- |
| src/server.js:route POST /orders | http_calls | POST /orders | medium | `gateway/src/server.js:15` |
| src/server.js:route GET /orders/:id | http_calls | GET /orders/{order_id} | medium | `gateway/src/server.js:27` |
| app/pricing.py:price_items | spawns | cmd/pricing/main.go:main | medium | `orders/app/pricing.py:10` |
| defender-assessments.json.md:16 | affects | azure/main.bicep:Microsoft.Storage/storageAccounts.reports | medium | `ctx-platform/defender-assessments.json.md:16` |
| defender-assessments.json.md:16 | affects | terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/defender-assessments.json.md:16` |
| gcp-scc-findings.json.md:16 | affects | terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/gcp-scc-findings.json.md:16` |
| gcp-scc-findings.json.md:16 | affects | terraform/gcp/main.tf:google_compute_firewall.admin | medium | `ctx-platform/gcp-scc-findings.json.md:16` |
| gcp-scc-findings.json.md:17 | affects | terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/gcp-scc-findings.json.md:17` |
| gcp-scc-findings.json.md:17 | affects | terraform/gcp/main.tf:google_storage_bucket.exports | medium | `ctx-platform/gcp-scc-findings.json.md:17` |
| prowler-ocsf.json.md:18 | affects | terraform/aws/main.tf:aws_s3_bucket.invoices | medium | `ctx-platform/prowler-ocsf.json.md:18` |
| prowler-ocsf.json.md:18 | affects | terraform/aws/main.tf:aws_s3_bucket_public_access_block.invoices | medium | `ctx-platform/prowler-ocsf.json.md:18` |
| prowler-ocsf.json.md:18 | affects | terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/prowler-ocsf.json.md:18` |
| prowler-ocsf.json.md:19 | affects | terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/prowler-ocsf.json.md:19` |
| securityhub-asff.json.md:17 | affects | k8s/gateway.yaml:Deployment.gateway | medium | `ctx-platform/securityhub-asff.json.md:17` |
| securityhub-asff.json.md:17 | affects | k8s/gateway.yaml:Ingress.gateway | medium | `ctx-platform/securityhub-asff.json.md:17` |
| securityhub-asff.json.md:17 | affects | terraform/aws/main.tf:aws_security_group.gateway | medium | `ctx-platform/securityhub-asff.json.md:17` |
| securityhub-asff.json.md:18 | affects | terraform/aws/main.tf:aws_mq_broker.orders | medium | `ctx-platform/securityhub-asff.json.md:18` |
| securityhub-asff.json.md:18 | affects | terraform/aws/main.tf:aws_iam_policy.orders_app | medium | `ctx-platform/securityhub-asff.json.md:18` |
| securityhub-asff.json.md:18 | affects | terraform/gcp/main.tf:google_compute_firewall.admin | medium | `ctx-platform/securityhub-asff.json.md:18` |
| wiz-issues.csv.md:17 | affects | terraform/aws/main.tf:aws_mq_broker.orders | medium | `ctx-platform/wiz-issues.csv.md:17` |
| wiz-issues.csv.md:17 | affects | terraform/aws/main.tf:aws_iam_policy.orders_app | medium | `ctx-platform/wiz-issues.csv.md:17` |
| wiz-issues.csv.md:17 | affects | terraform/gcp/main.tf:google_compute_firewall.admin | medium | `ctx-platform/wiz-issues.csv.md:17` |
| gateway | deploys | gateway | medium | `platform/docker-compose.yml:2` |
| ORDERS_URL | configured_by | gateway | medium | `platform/docker-compose.yml:6` |
| JWT_SECRET | configured_by | gateway | medium | `platform/docker-compose.yml:7` |
| orders | deploys | orders | medium | `platform/docker-compose.yml:8` |
| DATABASE_URL | configured_by | orders | medium | `platform/docker-compose.yml:11` |
| RABBITMQ_URL | configured_by | orders | medium | `platform/docker-compose.yml:12` |
| fulfillment | deploys | fulfillment | medium | `platform/docker-compose.yml:13` |
| DATABASE_URL | configured_by | fulfillment | medium | `platform/docker-compose.yml:16` |
| RABBITMQ_URL | configured_by | fulfillment | medium | `platform/docker-compose.yml:17` |
| SHIPPING_API_URL | configured_by | fulfillment | medium | `platform/docker-compose.yml:18` |
| gateway | deploys | gateway | medium | `platform/k8s/gateway.yaml:2` |
| ORDERS_URL | configured_by | gateway | medium | `platform/k8s/gateway.yaml:18` |

## Merge and carry-over

- Security nodes attached: {"cloud_resources": 15, "sc_findings": 20, "cspm_findings": 10, "cspm_linked": 19} [inferred]
- Agent proposals: {"accepted": 143, "rejected": 0, "annotations": 3} [inferred]
- Summary carry-over: {"kept": 3, "outdated": 0, "moved": 0, "dropped": 0} [inferred]

Query it with `/ckb:ask`, `/ckb:impact`, the viewer (`graph/index.html`), or the `ckb-graph` MCP server.
