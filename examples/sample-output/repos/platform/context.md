---
ckb_context: 1
scope: platform
revision: f5659b3
generated: 2026-11-24T05:32:39Z
languages: []
entry_points: 0
focus_areas: [iac-public-storage, iac-wildcard-iam, iac-open-ingress, doc-drift]
---
# Security context: platform

> **ckb provenance**
> - Sources: `platform` @ `f5659b3`
> - Generated: 2026-11-24T05:32:39Z by ckb 0.1.0, stage `security-context`
> - Scope: platform · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (20 citations, 0 errors; see evidence/verification.md)

## 1. Purpose and tech stack
IaC, contracts and docs for the shop. `platform/README.md:3`
- Terraform AWS and GCP, Bicep, CloudFormation, compose, K8s `platform/deploy/terraform/aws/main.tf:2`
## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| K8s Ingress shop host | internet | internet to gateway | `platform/deploy/k8s/gateway.yaml:27` |
| AWS SG gateway 3000 | internet | edge | `platform/deploy/terraform/aws/main.tf:22` |
| Azure NSG 3000 | internet | edge | `platform/deploy/azure/main.bicep:28` |
| GCP firewall SSH | internet | admin access | `platform/deploy/terraform/gcp/main.tf:16` |
## 3. Authn/authz model
IAM: orders app policy and ops role allow every action on every resource. `platform/deploy/terraform/aws/main.tf:51` `platform/deploy/cloudformation/queue.yaml:22`
## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| order rows | orders | RDS shop | storage not encrypted | `platform/deploy/terraform/aws/main.tf:30` |
| invoices | [unknown] | S3 invoices | public-read | `platform/deploy/terraform/aws/main.tf:8` |
## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Verdict | Source |
| --- | --- | --- | --- | --- |
| [n/a] no code sinks | n/a | n/a | [n/a] | `platform/README.md:3` |
## 6. Known-safe patterns and known-risky areas
- Safe: Amazon MQ broker is not publicly accessible `platform/deploy/terraform/aws/main.tf:40`; SQS encryption on `platform/deploy/cloudformation/queue.yaml:8`.
- Risky (IaC and CSPM agree): public S3 and GCS, Azure public blob, unencrypted RDS, open SSH, wildcard IAM `platform/deploy/terraform/aws/main.tf:8` `platform/deploy/terraform/gcp/main.tf:10` `platform/deploy/azure/main.bicep:10`.
- Drift: documents claim private VPC, encrypted database, mTLS; see `system/documented-vs-observed.md`.
## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| orders OpenAPI | orders | gateway | none described | `platform/contracts/orders.openapi.yaml:5` |
| order.created JSON Schema | orders | fulfillment | none described | `platform/contracts/order_created.schema.json:1` |
## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| compose `RABBITMQ_URL` | plain amqp | set | `platform/deploy/docker-compose.yml:12` |
| `JWT_SECRET` | passed from the environment | required | `platform/deploy/docker-compose.yml:7` |
## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | iac-public-storage | `deploy/terraform/**`, `deploy/azure/**` | public buckets and blobs | T-04, T-02, T-05 |
| 2 | iac-wildcard-iam | `deploy/terraform/aws`, `deploy/cloudformation` | Action star | T-24 |
| 3 | iac-open-ingress | `deploy/terraform/gcp` | SSH open | T-25 |
| 4 | doc-drift | `docs-architecture/**` | documents overstate controls | T-20, T-32 |
