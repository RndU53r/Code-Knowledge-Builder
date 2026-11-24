# Question → query recipes

| Question | Query |
| --- | --- |
| How many functions in `orders/app/db.py`? | `sql "SELECT count(*) FROM nodes WHERE kind IN ('function','method') AND repo='orders' AND path='app/db.py'"` |
| Where is env var `DATABASE_URL` read? | `explain env_var:orders::DATABASE_URL` (incoming `reads_env`) |
| Who calls `get_order`? | `neighbors function:orders:app/db.py:get_order --dir in --kinds calls --depth 3` |
| Which endpoints reach unsafe SQL? | `taint` (filter `sink_type == sql`) |
| What breaks if I change `db.py`? | `impact orders/app/db.py` |
| What does this PR affect? | `impact --diff origin/main` |
| How does a gateway request reach the fulfillment worker? | `path gateway/src/server.js fulfillment/internal/queue/consumer.go` |
| Who writes the `orders` table? | `sql "SELECT src, citation FROM edges WHERE kind='writes' AND dst='table:_system::orders'"` |
| Which cloud resources have open CSPM findings? | `sql "SELECT e.dst, n.name, n.citation FROM edges e JOIN nodes n ON n.id=e.src WHERE e.kind='affects'"` |
| Callers up to depth N (recursive SQL) | `sql "WITH RECURSIVE up(id,d) AS (SELECT 'function:orders:app/db.py:get_order',0 UNION SELECT e.src,d+1 FROM edges e JOIN up ON e.dst=up.id WHERE e.kind='calls' AND d<5) SELECT DISTINCT id FROM up"` |

The SQL tables are `nodes(id, kind, repo, path, start, end, name, qualname, confidence, extractor, label, citation, json)`, `edges(id, src, dst, kind, confidence, extractor, label, citation, json)`, and `nodes_fts` (full text). The connection is read-only: writes and ATTACH are denied.
