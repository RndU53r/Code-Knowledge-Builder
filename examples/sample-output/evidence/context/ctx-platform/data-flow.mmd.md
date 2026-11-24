<!-- ckb context: converted from data-flow.mmd (Mermaid diagram); original path recorded in manifest.json -->
# Context: data-flow.mmd

- Kind: Mermaid diagram
- Converted: 2026-11-24T05:23:26Z
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Page: main

### Shapes

- shape `DB`: Postgres shop
- shape `FU`: Fulfillment worker
- shape `GW`: API Gateway
- shape `MQ`: RabbitMQ
- shape `OR`: Orders service

### Connectors

- `API Gateway` -> `Orders service` : HTTPS
- `Orders service` -> `Postgres shop` : SQL
- `Orders service` -> `RabbitMQ` : AMQPS
- `RabbitMQ` -> `Fulfillment worker`

