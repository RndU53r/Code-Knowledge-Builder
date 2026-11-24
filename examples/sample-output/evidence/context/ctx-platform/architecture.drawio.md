<!-- ckb context: converted from architecture.drawio (draw.io diagram); original path recorded in manifest.json -->
# Context: architecture.drawio

- Kind: draw.io diagram
- Converted: 2026-11-24T05:23:26Z · 2 page(s)
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Page: Logical

### Shapes

- shape `z1`: Internet · style: swimlane
- shape `z2`: Private VPC (no public ingress) · style: swimlane
- shape `u`: Customer · in: Internet · style: actor
- shape `gw`: API Gateway (Express) · in: Private VPC (no public ingress)
- shape `or`: Orders service · in: Private VPC (no public ingress)
- shape `fu`: Fulfillment worker · in: Private VPC (no public ingress)
- shape `mq`: RabbitMQ (TLS) · in: Private VPC (no public ingress) · style: cylinder
- shape `db`: Postgres shop (encrypted) · in: Private VPC (no public ingress) · style: cylinder

### Connectors

- `Customer` -> `API Gateway (Express)` : HTTPS
- `API Gateway (Express)` -> `Orders service` : mTLS REST
- `Orders service` -> `RabbitMQ (TLS)` : AMQPS order.created
- `RabbitMQ (TLS)` -> `Fulfillment worker`
- `Orders service` -> `Postgres shop (encrypted)` : SQL

## Page: External

### Shapes

- shape `a`: Shipping API (3rd party) · style: cloud
- shape `b`: Fulfillment worker

### Connectors

- `Fulfillment worker` -> `Shipping API (3rd party)` : HTTPS + API key

