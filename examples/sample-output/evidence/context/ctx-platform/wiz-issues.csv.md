<!-- ckb context: converted from wiz-issues.csv (CSPM/IaC scan results: CSV export); original path recorded in manifest.json -->
# Context: wiz-issues.csv

- Kind: CSPM/IaC scan results: CSV export
- Converted: 2026-11-24T05:23:26Z · 2 finding(s), 1 not passing
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Severity counts

- critical: 1
- low: 1

## Findings (one per line; cite this file:line)

| # | Provider | Check/ID | Severity | Status | Resource | Title |
| --- | --- | --- | --- | --- | --- | --- |
| 1 |  | wiz-001 | critical | Open | arn:aws:iam::111122223333:policy/orders-app | Admin-equivalent IAM policy attached to workload |
| 2 |  | wiz-002 | low | Resolved | gateway-sg | Security group allows ingress from internet |
