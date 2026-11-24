<!-- ckb context: converted from deploy.puml (PlantUML diagram); original path recorded in manifest.json -->
# Context: deploy.puml

- Kind: PlantUML diagram
- Converted: 2026-11-24T05:23:26Z
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

## Page: main

### Shapes

- shape `gw`: API Gateway
- shape `orders`: Orders service
- shape `db`: Postgres shop

### Connectors

- `API Gateway` -> `Orders service` : HTTPS
- `Orders service` -> `Postgres shop` : SQL

