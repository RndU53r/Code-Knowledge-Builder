<!-- ckb context: converted from checkov.sarif (CSPM/IaC scan results: SARIF (Checkov)); original path recorded in manifest.json -->
# Context: checkov.sarif

- Kind: CSPM/IaC scan results: SARIF (Checkov)
- Converted: 2026-11-24T05:23:26Z · 2 finding(s), 2 not passing
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Severity counts

- high: 2

## Findings (one per line; cite this file:line)

| # | Provider | Check/ID | Severity | Status | Resource | Title |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | iac/sarif | CKV_AZURE_44 | high | fail | deploy/azure/main.bicep:4 | Ensure Storage Account is using the latest version of TLS encryption |
| 2 | iac/sarif | CKV_GCP_28 | high | fail | deploy/terraform/gcp/main.tf:7 | Ensure that Cloud Storage bucket is not anonymously or publicly accessible |
