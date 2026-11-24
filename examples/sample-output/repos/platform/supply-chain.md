# platform: supply-chain and injection audit

> **ckb provenance**
> - Sources: `platform` @ `f5659b3`
> - Generated: 2026-11-24T05:27:13Z by ckb 0.1.0, stage `supply-chain`
> - Scope: manifests, Dockerfiles, CI, IaC · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (15 citations, 0 errors; see evidence/verification.md)

## Summary
[inferred] Counts derived from the ranked findings below.
| Severity | Confirmed suspicious | Risky practice |
| --- | --- | --- |
| critical | 0 | 0 |
| high | 0 | 6 |
| medium | 0 | 6 |
| low | 0 | 1 |

## Findings (ranked)
| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PLATFORM-SC-001 | SC-D07 | risky-practice | high | medium | `platform/deploy/azure/main.bicep:10` | Azure: storage or service publicly accessible — `allowBlobPublicAccess: true` | Block public access (S3 Block Public Access, Azure allowBlobPublicAccess=false, no allUsers bindings); front with authenticated access. |
| PLATFORM-SC-002 | SC-D07 | risky-practice | high | medium | `platform/deploy/terraform/aws/main.tf:8` | Terraform/AWS: storage or service publicly accessible — `acl    = "public-read"` | Block public access (S3 Block Public Access, Azure allowBlobPublicAccess=false, no allUsers bindings); front with authenticated access. |
| PLATFORM-SC-003 | SC-D07 | risky-practice | high | medium | `platform/deploy/terraform/aws/main.tf:13` | Terraform/AWS: storage or service publicly accessible — `block_public_acls = false` | Block public access (S3 Block Public Access, Azure allowBlobPublicAccess=false, no allUsers bindings); front with authenticated access. |
| PLATFORM-SC-004 | SC-D07 | risky-practice | high | medium | `platform/deploy/terraform/gcp/main.tf:10` | Terraform/GCP: storage or service publicly accessible — `member = "allUsers"` | Block public access (S3 Block Public Access, Azure allowBlobPublicAccess=false, no allUsers bindings); front with authenticated access. |
| PLATFORM-SC-005 | SC-D08 | risky-practice | high | medium | `platform/deploy/cloudformation/queue.yaml:22` | AWS CloudFormation: wildcard IAM action — `Action: "*"` | Replace wildcard IAM actions/roles with least-privilege, resource-scoped permissions. |
| PLATFORM-SC-006 | SC-D08 | risky-practice | high | medium | `platform/deploy/terraform/aws/main.tf:51` | Terraform/AWS: wildcard IAM action — `Statement = [{ Effect = "Allow", "Action" : "*", Resource = "*" }]` | Replace wildcard IAM actions/roles with least-privilege, resource-scoped permissions. |
| PLATFORM-SC-007 | SC-D05 | risky-practice | medium | medium | `platform/deploy/azure/main.bicep:28` | Azure: ingress open to the internet — `sourceAddressPrefix: 'Internet'` | Avoid privileged containers, host networking, and running as UID 0. |
| PLATFORM-SC-008 | SC-D05 | risky-practice | medium | medium | `platform/deploy/terraform/aws/main.tf:22` | ingress open to 0.0.0.0/0 — `cidr_blocks = ["0.0.0.0/0"]` | Avoid privileged containers, host networking, and running as UID 0. |
| PLATFORM-SC-009 | SC-D05 | risky-practice | medium | medium | `platform/deploy/terraform/gcp/main.tf:16` | Terraform/GCP: ingress open to the internet — `source_ranges = ["0.0.0.0/0"]` | Avoid privileged containers, host networking, and running as UID 0. |
| PLATFORM-SC-010 | SC-D09 | risky-practice | medium | medium | `platform/deploy/azure/main.bicep:11` | Azure: encryption or TLS disabled — `minimumTlsVersion: 'TLS1_0'` | Enable encryption at rest and enforce TLS 1.2+ / HTTPS-only. |
| PLATFORM-SC-011 | SC-D09 | risky-practice | medium | medium | `platform/deploy/azure/main.bicep:12` | Azure: encryption or TLS disabled — `supportsHttpsTrafficOnly: false` | Enable encryption at rest and enforce TLS 1.2+ / HTTPS-only. |
| PLATFORM-SC-012 | SC-D09 | risky-practice | medium | medium | `platform/deploy/terraform/aws/main.tf:30` | Terraform/AWS: encryption or TLS disabled — `storage_encrypted = false` | Enable encryption at rest and enforce TLS 1.2+ / HTTPS-only. |
| PLATFORM-SC-013 | SC-D01 | risky-practice | low | high | `platform/deploy/k8s/gateway.yaml:15` | workload image registry.example.com/shop/gateway:1.0.0 not pinned by digest — `image: registry.example.com/shop/gateway:1.0.0` | Pin base images by digest (image@sha256:...). |

## Dependency inventory (direct)
[n/a] no package manifests.

## Investigated, not an issue
| Scanner finding | Why dismissed or downgraded | Source |
| --- | --- | --- |
| PLATFORM-SC-005 CloudFormation wildcard IAM | Confirmed in the OpsRole inline policy. | `platform/deploy/cloudformation/queue.yaml:22` |
| PLATFORM-SC-001..012 IaC posture | All confirmed against the IaC lines; several are also reported by the CSPM exports under `ctx-platform`. | `platform/deploy/terraform/aws/main.tf:8` |

## Limitations
- Advisory lookups (OSV, Snyk) are off: the user declined off-machine lookups, so advisory status stays "not checked". [n/a]
- No install scripts, CI workflows or git-sourced dependencies exist in this repo beyond the files cited above. [inferred]

## Checks run
| Category | Checks | Result |
| --- | --- | --- |
| Dockerfile and IaC | SC-D01..D09 | 13 finding(s) above |
| Secrets and credentials | SC-S08 | see findings |
| Prompt injection | SC-A01 | none in this repo |
