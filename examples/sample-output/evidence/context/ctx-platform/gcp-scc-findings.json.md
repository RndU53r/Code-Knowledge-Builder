<!-- ckb context: converted from gcp-scc-findings.json (CSPM/IaC scan results: GCP Security Command Center); original path recorded in manifest.json -->
# Context: gcp-scc-findings.json

- Kind: CSPM/IaC scan results: GCP Security Command Center
- Converted: 2026-11-24T05:23:26Z · 2 finding(s), 2 not passing
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Severity counts

- high: 2

## Findings (one per line; cite this file:line)

| # | Provider | Check/ID | Severity | Status | Resource | Title |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | gcp | f1 | high | ACTIVE | //compute.googleapis.com/projects/shop/global/firewalls/allow-admin | OPEN_SSH_PORT |
| 2 | gcp | f2 | high | ACTIVE | //storage.googleapis.com/shop-exports-fixture | PUBLIC_BUCKET_ACL |
