# What counts as an output

| Kind | Examples | Where its shape lives |
| --- | --- | --- |
| API response | REST/GraphQL/gRPC replies, including error bodies and status codes | response models, serializers, `res.status().json()` sites, proto messages |
| Event / message | Kafka, RabbitMQ, SQS/SNS, pub/sub, webhooks sent | payload construction site, schema registry files, AsyncAPI |
| DB write | INSERT/UPDATE/DELETE, ORM save, migrations that seed data | SQL, models, migrations |
| Cache write | SET/HSET with TTL | key construction + TTL |
| File / report | CSV/PDF/JSON exports, uploads to object storage | writer code, bucket/key template |
| External call | requests to third-party APIs, email/SMS sends, LLM calls | client call site, request body construction |
| Log / audit | structured logs carrying identifiers or PII, audit trails | logger calls with fields |
| Metric / trace | counters, histograms, spans with attributes | metric registration + increment sites |
| Process exit / CLI output | exit codes, stdout formats consumed by other programs | `sys.exit`, `os.Exit`, printed JSON |
| Side effects | emails, payments, provisioning | SDK calls |
