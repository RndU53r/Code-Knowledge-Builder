# Documented vs observed

> **ckb provenance**
> - Sources: code `fulfillment`, `gateway`, `orders`, `platform`; context `ctx-platform`, `ctx-platform-src`
> - Generated: 2026-11-27T00:54:02Z by ckb doc_claims, stage `context-from-docs`
> - Scope: claims extracted from supplied documents, diagrams and notes · Excluded: statements the patterns do not recognize
> - Method: deterministic claim extraction and checks against the knowledge graph; documents record intent, code and IaC record what is built
> - Verification: drift items are mirrored as graph proposals (graph/proposals/seed-docs.jsonl), verified by graph_merge

## Summary

[inferred] 15 control claim(s) and 15 documented connection(s) extracted: 6 consistent, 11 drift; 2 claim(s) matched no code entity.

## Documented vs observed

| Claim (documented) | Source | Observed | Evidence | Verdict |
| --- | --- | --- | --- | --- |
| 'Private VPC (no public ingress)' is documented as private / no public ingress (contains: API Gateway (Express), Orders service, Fulfillment worker, RabbitMQ (T | `ctx-platform/architecture.drawio.md:13` | 3 ingress rule(s) open to the internet in IaC (e.g. 'sourceAddressPrefix: 'Internet'') | `platform/azure/main.bicep:28` `platform/terraform/aws/main.tf:22` | **drift** |
| 'RabbitMQ (TLS)' is documented as TLS-protected | `ctx-platform/architecture.drawio.md:18` | broker URL default uses plain 'amqp://' (no TLS) in orders | `orders/app/events.py:6` | **drift** |
| 'Postgres shop (encrypted)' is documented as encrypted | `ctx-platform/architecture.drawio.md:19` | IaC disables encryption/TLS for aws_db_instance shop: 'storage_encrypted = false' | `platform/terraform/aws/main.tf:30` `ctx-platform/defender-assessments.json.md:16` | **drift** |
| API Gateway (Express) → Orders service documented as mTLS REST | `ctx-platform/architecture.drawio.md:24` | gateway calls orders with a plain-http default ('http://orders:8000'); no client certificate settings | `gateway/src/server.js:5` `gateway/src/server.js:15` | **drift** |
| Orders service → RabbitMQ (TLS) documented as AMQPS order.created | `ctx-platform/architecture.drawio.md:25` | broker URL default uses plain 'amqp://' (no TLS) in orders | `orders/app/events.py:6` | **drift** |
| API Gateway → Orders service documented as HTTPS | `ctx-platform/data-flow.mmd.md:20` | gateway calls orders with a plain-http default ('http://orders:8000'); no client certificate settings | `gateway/src/server.js:5` `gateway/src/server.js:15` | **drift** |
| Orders service → RabbitMQ documented as AMQPS | `ctx-platform/data-flow.mmd.md:22` | broker URL default uses plain 'amqp://' (no TLS) in orders | `orders/app/events.py:6` | **drift** |
| API Gateway → Orders service documented as HTTPS | `ctx-platform/deploy.puml.md:18` | gateway calls orders with a plain-http default ('http://orders:8000'); no client certificate settings | `gateway/src/server.js:5` `gateway/src/server.js:15` | **drift** |
| All service-to-service traffic uses mutual TLS (mTLS) issued by the internal CA. | `ctx-platform/security-design.docx.md:14` | gateway calls orders with a plain-http default ('http://orders:8000'); no client certificate settings | `gateway/src/server.js:5` `gateway/src/server.js:15` | **drift** |
| The orders service validates the caller JWT on every request before reading or writing orders. | `ctx-platform/security-design.docx.md:18` | 2 of 2 endpoint(s) in orders show no authentication evidence (e.g. POST /orders) | `orders/app/main.py:25` `orders/app/main.py:37` | **drift** |
| The database is encrypted at rest. | `ctx-platform/security-design.docx.md:22` | IaC disables encryption/TLS for aws_db_instance shop: 'storage_encrypted = false' | `platform/terraform/aws/main.tf:30` `ctx-platform/defender-assessments.json.md:16` | **drift** |
| API Gateway (Express) → Orders service (mTLS REST) | `ctx-platform/architecture.drawio.md:24` | connection exists in code (http); this row checks existence only | `gateway/src/server.js:15` `gateway/src/server.js:27` | **consistent** |
| API Gateway → Orders service (HTTPS) | `ctx-platform/data-flow.mmd.md:20` | connection exists in code (http); this row checks existence only | `gateway/src/server.js:15` `gateway/src/server.js:27` | **consistent** |
| API Gateway → Orders service (HTTPS) | `ctx-platform/deploy.puml.md:18` | connection exists in code (http); this row checks existence only | `gateway/src/server.js:15` `gateway/src/server.js:27` | **consistent** |
| The orders service must not be exposed publicly. | `ctx-platform/design-notes.eml.md:12` | orders's endpoints are only called by other services; no ingress routes to it | `gateway/src/server.js:15` | **consistent** |
| gateway → orders | `ctx-platform/network.vsdx.md:19` | connection exists in code (http); this row checks existence only | `gateway/src/server.js:15` `gateway/src/server.js:27` | **consistent** |
| The orders service is internal-only and is not reachable from the internet. | `ctx-platform/security-design.docx.md:16` | orders's endpoints are only called by other services; no ingress routes to it | `gateway/src/server.js:15` | **consistent** |

## Claims not matched to the code

| Claim | Source | Why |
| --- | --- | --- |
| Customer → API Gateway (Express) documented as HTTPS | `ctx-platform/architecture.drawio.md:23` | no repo, endpoint or cloud resource matched the named component |
| Fulfillment worker → Shipping API (3rd party) documented as HTTPS + API key | `ctx-platform/architecture.drawio.md:38` | no repo, endpoint or cloud resource matched the named component |

Drift on a security control becomes a threat in `system/threat-model.md` (the documented control is the claimed mitigation; the code or IaC is the gap).
