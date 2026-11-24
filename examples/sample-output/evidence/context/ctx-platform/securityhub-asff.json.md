<!-- ckb context: converted from securityhub-asff.json (CSPM/IaC scan results: AWS Security Hub (ASFF)); original path recorded in manifest.json -->
# Context: securityhub-asff.json

- Kind: CSPM/IaC scan results: AWS Security Hub (ASFF)
- Converted: 2026-11-24T05:23:26Z · 2 finding(s), 2 not passing
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Severity counts

- critical: 1
- high: 1

## Findings (one per line; cite this file:line)

| # | Provider | Check/ID | Severity | Status | Resource | Title |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | aws | arn:aws:securityhub:eu-west-1:111122223333:finding/ec2-sg-open-3000 | high | FAILED | arn:aws:ec2:eu-west-1:111122223333:security-group/sg-0abc | EC2.19 Security groups should not allow unrestricted access to high-risk ports (gateway-sg 3000/tcp from 0.0.0.0/0) |
| 2 | aws | arn:aws:securityhub:eu-west-1:111122223333:finding/iam-star | critical | FAILED | arn:aws:iam::111122223333:policy/orders-app | IAM.1 IAM policies should not allow full administrative privileges (orders-app) |
