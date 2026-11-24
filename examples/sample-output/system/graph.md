# System knowledge graph

> **ckb provenance**
> - Sources: `fulfillment` @ `d2ffc2095810`, `gateway` @ `8c8444d8b08d`, `orders` @ `1de64cbb1f39`, `platform` @ `f5659b33e1f9`
> - Generated: 2026-11-24T05:34:58Z by ckb graph 1, stage `graph`
> - Scope: registered code repos · Excluded: vendored, generated, binaries, symlinks, secret files
> - Method: static extraction (ast / tree-sitter if installed / regex); agent proposals merged only after citation verification
> - Verification: see evidence/graph-verification.md

## Size

| Item | Count |
| --- | --- |
| nodes: class | 4 |
| nodes: cloud_resource | 15 |
| nodes: contract_op | 2 |
| nodes: cspm_finding | 10 |
| nodes: dir | 7 |
| nodes: doc_section | 16 |
| nodes: drift | 11 |
| nodes: endpoint | 6 |
| nodes: env_var | 13 |
| nodes: external | 3 |
| nodes: file | 14 |
| nodes: function | 16 |
| nodes: package | 20 |
| nodes: repo | 4 |
| nodes: sc_finding | 20 |
| nodes: sink | 6 |
| nodes: table | 1 |
| nodes: threat | 6 |
| nodes: topic | 1 |
| nodes: trust_boundary | 7 |
| edges: affects | 19 |
| edges: calls | 8 |
| edges: consumes | 1 |
| edges: contains | 56 |
| edges: crosses_boundary | 7 |
| edges: documented_as | 20 |
| edges: drifts_from | 11 |
| edges: finding_at | 14 |
| edges: http_calls | 4 |
| edges: imports | 34 |
| edges: publishes | 1 |
| edges: reaches_sink | 6 |
| edges: reads | 1 |
| edges: reads_env | 16 |
| edges: routes_to | 6 |
| edges: spawns | 2 |
| edges: threatens | 5 |
| edges: writes | 2 |

## Extractors

| Extractor | Nodes | Edges |
| --- | --- | --- |
| ast | 32 | 48 |
| context | 10 | 19 |
| llm | 6 | 5 |
| regex | 78 | 89 |
| rule | 36 | 38 |
| scanner | 20 | 14 |

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
| ssrf sink in GET /admin/report | ssrf | request input controls the URL/host | `gateway/src/server.js:32` |
| sql sink in get_order | sql | string-built query | `orders/app/db.py:23` |

## Cross-repo edges

| From | Kind | To | Confidence | Source |
| --- | --- | --- | --- | --- |
| src/server.js:route POST /orders | http_calls | POST /orders | medium | `gateway/src/server.js:15` |
| src/server.js:route GET /orders/:id | http_calls | GET /orders/{order_id} | medium | `gateway/src/server.js:27` |
| app/pricing.py:price_items | spawns | cmd/pricing/main.go:main | medium | `orders/app/pricing.py:10` |
| defender-assessments.json.md:16 | affects | deploy/azure/main.bicep:Microsoft.Storage/storageAccounts.reports | medium | `ctx-platform/defender-assessments.json.md:16` |
| defender-assessments.json.md:16 | affects | deploy/terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/defender-assessments.json.md:16` |
| gcp-scc-findings.json.md:16 | affects | deploy/terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/gcp-scc-findings.json.md:16` |
| gcp-scc-findings.json.md:16 | affects | deploy/terraform/gcp/main.tf:google_compute_firewall.admin | medium | `ctx-platform/gcp-scc-findings.json.md:16` |
| gcp-scc-findings.json.md:17 | affects | deploy/terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/gcp-scc-findings.json.md:17` |
| gcp-scc-findings.json.md:17 | affects | deploy/terraform/gcp/main.tf:google_storage_bucket.exports | medium | `ctx-platform/gcp-scc-findings.json.md:17` |
| prowler-ocsf.json.md:18 | affects | deploy/terraform/aws/main.tf:aws_s3_bucket.invoices | medium | `ctx-platform/prowler-ocsf.json.md:18` |
| prowler-ocsf.json.md:18 | affects | deploy/terraform/aws/main.tf:aws_s3_bucket_public_access_block.invoices | medium | `ctx-platform/prowler-ocsf.json.md:18` |
| prowler-ocsf.json.md:18 | affects | deploy/terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/prowler-ocsf.json.md:18` |
| prowler-ocsf.json.md:19 | affects | deploy/terraform/aws/main.tf:aws_db_instance.shop | medium | `ctx-platform/prowler-ocsf.json.md:19` |
| securityhub-asff.json.md:17 | affects | deploy/k8s/gateway.yaml:Deployment.gateway | medium | `ctx-platform/securityhub-asff.json.md:17` |
| securityhub-asff.json.md:17 | affects | deploy/k8s/gateway.yaml:Ingress.gateway | medium | `ctx-platform/securityhub-asff.json.md:17` |
| securityhub-asff.json.md:17 | affects | deploy/terraform/aws/main.tf:aws_security_group.gateway | medium | `ctx-platform/securityhub-asff.json.md:17` |
| securityhub-asff.json.md:18 | affects | deploy/terraform/aws/main.tf:aws_mq_broker.orders | medium | `ctx-platform/securityhub-asff.json.md:18` |
| securityhub-asff.json.md:18 | affects | deploy/terraform/aws/main.tf:aws_iam_policy.orders_app | medium | `ctx-platform/securityhub-asff.json.md:18` |
| securityhub-asff.json.md:18 | affects | deploy/terraform/gcp/main.tf:google_compute_firewall.admin | medium | `ctx-platform/securityhub-asff.json.md:18` |
| wiz-issues.csv.md:17 | affects | deploy/terraform/aws/main.tf:aws_mq_broker.orders | medium | `ctx-platform/wiz-issues.csv.md:17` |
| wiz-issues.csv.md:17 | affects | deploy/terraform/aws/main.tf:aws_iam_policy.orders_app | medium | `ctx-platform/wiz-issues.csv.md:17` |
| wiz-issues.csv.md:17 | affects | deploy/terraform/gcp/main.tf:google_compute_firewall.admin | medium | `ctx-platform/wiz-issues.csv.md:17` |

## Merge and carry-over

- Security nodes attached: {"cloud_resources": 15, "sc_findings": 20, "cspm_findings": 10, "cspm_linked": 19} [inferred]
- Agent proposals: {"accepted": 140, "rejected": 0, "annotations": 24, "superseded_draft_threats_dropped": 32} [inferred]
- Summary carry-over: {"kept": 22, "outdated": 0, "moved": 0, "dropped": 0} [inferred]

Query it with `/ckb:ask`, `/ckb:impact`, the viewer (`graph/index.html`), or the `ckb-graph` MCP server.
