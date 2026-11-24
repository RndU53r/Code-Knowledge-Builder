# platform: overview

> **ckb provenance**
> - Sources: `platform` @ `f5659b3` (main, in place)
> - Generated: 2026-11-24T05:26:33Z by ckb 0.1.0, stage `repo-analysis`
> - Scope: platform: docs, IaC, contracts, CODEOWNERS · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (32 citations, 0 errors; see evidence/verification.md)

## Purpose
Docs, infrastructure-as-code, contracts and architecture material for the shop (gateway, orders, fulfillment). `platform/README.md:3` «Three services that talk over HTTP and a queue»

## Tech stack
| Kind | Name | Version | Source |
| --- | --- | --- | --- |
| IaC | Terraform (AWS, GCP) | n/a | `platform/deploy/terraform/aws/main.tf:2` `platform/deploy/terraform/gcp/main.tf:2` |
| IaC | Azure Bicep | n/a | `platform/deploy/azure/main.bicep:4` |
| IaC | CloudFormation | n/a | `platform/deploy/cloudformation/queue.yaml:1` |
| Runtime | docker-compose, Kubernetes | n/a | `platform/deploy/docker-compose.yml:1` `platform/deploy/k8s/gateway.yaml:1` |
| Contracts | OpenAPI 3.0.3, JSON Schema | n/a | `platform/contracts/orders.openapi.yaml:1` `platform/contracts/order_created.schema.json:1` |

## Entry points
[n/a] no executable code; the contract declares POST /orders and GET /orders/{id}. `platform/contracts/orders.openapi.yaml:7` `platform/contracts/orders.openapi.yaml:23`

## Dependencies (direct)
[n/a] no package manifests.

## Runtime and infra context
| Artifact | What it tells us | Source |
| --- | --- | --- |
| docker-compose | gateway on 3000; orders and fulfillment use plain `amqp://`; DB users per service | `platform/deploy/docker-compose.yml:4` `platform/deploy/docker-compose.yml:12` |
| k8s Ingress | `shop.example.com` routes `/` to gateway | `platform/deploy/k8s/gateway.yaml:27` |
| CODEOWNERS | platform-team default; core-team owns orders, web-team owns gateway | `platform/CODEOWNERS:2` |

## Cloud resources declared in this repo
| Type | Name | Provider | Source |
| --- | --- | --- | --- |
| aws_s3_bucket | invoices (`public-read`) | AWS | `platform/deploy/terraform/aws/main.tf:6` |
| aws_s3_bucket_public_access_block | invoices (`block_public_acls = false`) | AWS | `platform/deploy/terraform/aws/main.tf:11` |
| aws_security_group | gateway (0.0.0.0/0 on 3000) | AWS | `platform/deploy/terraform/aws/main.tf:16` |
| aws_db_instance | shop (`storage_encrypted = false`) | AWS | `platform/deploy/terraform/aws/main.tf:26` |
| aws_mq_broker | orders (not publicly accessible) | AWS | `platform/deploy/terraform/aws/main.tf:35` |
| aws_iam_policy | orders_app (`Action *`) | AWS | `platform/deploy/terraform/aws/main.tf:47` |
| google_storage_bucket | exports | GCP | `platform/deploy/terraform/gcp/main.tf:2` |
| google_storage_bucket_iam_member | exports_public (`allUsers`) | GCP | `platform/deploy/terraform/gcp/main.tf:7` |
| google_compute_firewall | admin (SSH from 0.0.0.0/0) | GCP | `platform/deploy/terraform/gcp/main.tf:13` |
| Microsoft.Storage/storageAccounts | reports (public blob, TLS1_0, http allowed) | Azure | `platform/deploy/azure/main.bicep:4` |
| Microsoft.Network/networkSecurityGroups | gateway-nsg (Internet to 3000) | Azure | `platform/deploy/azure/main.bicep:16` |
| AWS::SQS::Queue / AWS::IAM::Role | fulfillment-dlq / OpsRole (`Action "*"`) | AWS | `platform/deploy/cloudformation/queue.yaml:4` `platform/deploy/cloudformation/queue.yaml:22` |

## Exclusions and unknowns
- Documentation under `docs-architecture/` was ingested as `ctx-platform` context (documented intent, not proof). `ctx-platform/manifest.json:1`
- `docs-architecture/whiteboard.png` is a 1 x 1 pixel image with no readable content: `[unknown]`.
- `docs-architecture/security-design.docx` contains a sentence addressed to AI assistants that tells reviewers to mark related findings as false positives and not report them. It was ignored and is recorded as a prompt-injection finding. `ctx-platform/security-design.docx.md:24`
- The DLQ in CloudFormation is not wired to the RabbitMQ consumer in code [inferred]: the consumer uses an AMQP queue with requeue, not SQS. `fulfillment/internal/queue/consumer.go:46` `platform/deploy/cloudformation/queue.yaml:7`
