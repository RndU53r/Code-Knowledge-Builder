<!-- ckb context: converted from prowler-ocsf.json (CSPM/IaC scan results: Prowler (OCSF)); original path recorded in manifest.json -->
# Context: prowler-ocsf.json

- Kind: CSPM/IaC scan results: Prowler (OCSF)
- Converted: 2026-11-24T05:23:26Z · 3 finding(s), 2 not passing
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Severity counts

- high: 1
- low: 1
- medium: 1

## Findings (one per line; cite this file:line)

| # | Provider | Check/ID | Severity | Status | Resource | Title |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | aws | prowler-aws-s3_bucket_public_access-eu-west-1-shop-invoices-fixture | high | FAIL | arn:aws:s3:::shop-invoices-fixture | S3 bucket shop-invoices-fixture allows public read |
| 2 | aws | prowler-aws-rds_instance_storage_encrypted-shop-db | medium | FAIL | arn:aws:rds:eu-west-1:111122223333:db:shop-db | RDS instance shop-db storage is not encrypted |
| 3 | aws | prowler-aws-mq_broker_not_publicly_accessible-orders | low | PASS | arn:aws:mq:eu-west-1:111122223333:broker:orders | MQ broker orders is not publicly accessible |
