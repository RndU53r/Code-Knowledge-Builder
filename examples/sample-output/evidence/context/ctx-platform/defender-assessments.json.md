<!-- ckb context: converted from defender-assessments.json (CSPM/IaC scan results: Microsoft Defender for Cloud); original path recorded in manifest.json -->
# Context: defender-assessments.json

- Kind: CSPM/IaC scan results: Microsoft Defender for Cloud
- Converted: 2026-11-24T05:23:26Z · 1 finding(s), 1 not passing
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Severity counts

- medium: 1

## Findings (one per line; cite this file:line)

| # | Provider | Check/ID | Severity | Status | Resource | Title |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | azure | a1b2 | medium | Unhealthy | /subscriptions/0000/resourceGroups/shop-dr/providers/Microsoft.Storage/storageAccounts/shopreportsfixture | Storage account public access should be disallowed |
