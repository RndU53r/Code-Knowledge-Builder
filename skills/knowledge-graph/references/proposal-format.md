# Graph proposal format (agents)

Append one JSON object per line to `<out>/graph/proposals/<stage>-<repo>.jsonl`.

```json
{"op":"edge","src":"function:gateway:src/server.js:route POST /orders","kind":"http_calls","dst":"endpoint:orders::POST /orders","citation":"gateway/src/server.js:15","quote":"axios.post(`${ORDERS_URL}/orders`","dst_citation":"orders/app/main.py:25","confidence":"high","label":"observed","rationale":"ORDERS_URL=http://orders:8000 in deploy/docker-compose.yml"}
{"op":"node","kind":"threat","repo":"_system","qualname":"T1-sqli-get-order","name":"T1 SQL injection in order lookup","citation":"orders/app/db.py:23","quote":"WHERE id = '{order_id}'","confidence":"high","label":"observed","attrs":{"stride":"Tampering","cwe":"CWE-89","priority":"critical"}}
{"op":"edge","src":"threat:_system::T1-sqli-get-order","kind":"threatens","dst":"function:orders:app/db.py:get_order","citation":"orders/app/db.py:23","quote":"cur.execute(f\"SELECT","confidence":"high","label":"observed"}
{"op":"annotate","id":"function:orders:app/db.py:get_order","summary":"Fetch one order by id (string-built SQL).","tags":["data-access"],"layer":"persistence"}
{"op":"tour","name":"onboarding","title":"How an order flows","audience":"new engineers","steps":[{"node_id":"endpoint:gateway::POST /orders","note":"Public entry point; JWT checked in requireAuth.","citation":"gateway/src/server.js:13"}]}
```

**Rules** (enforced by `graph_merge.py` and the PostToolUse hook)
- `quote` must appear in the cited lines (±2 lines). Copy it exactly.
- Node IDs must already exist in the graph or be proposed earlier in the same file. Use `graph_query.py search` to find exact IDs.
- Agents may add only these node kinds: threat, trust_boundary, asset, drift, service, external, contract_op, doc_section, queue, topic, table, bucket, cache, endpoint, consumer, taint_source. Code structure comes only from extractors.
- These edge kinds are reserved for the extractors and scanners: contains, defines, imports, reads_env, finding_at, depends_on.
- A cross-repo edge needs `dst_citation`.
- Low confidence is always stored as `inferred`.
- Never put secret values in any field.
