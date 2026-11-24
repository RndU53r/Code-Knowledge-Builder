# Neo4j (optional)

**Load:** run `graph_export.py --out <out> cypher`, then `cypher-shell -f graph/neo4j/load.cypher`. Or, after the user confirms, `graph_neo4j.py --out <out> push --yes`, with `NEO4J_URI`, `NEO4J_USER` and `NEO4J_PASSWORD` set (variable names configurable in settings). Every node has the label `CkbNode` plus its kind (e.g. `Function`), and relationship types are the upper-case edge kinds. Each node and edge keeps `citation`, `extractor`, `confidence` and `label`.

| Question | Cypher |
| --- | --- |
| Functions in a file (the article's example) | `MATCH (f:File {repo:'orders', path:'app/db.py'})-[:CONTAINS]->(fn:Function) RETURN count(fn)` |
| Callers of get_order, up to 5 hops | `MATCH p=(c)-[:CALLS*1..5]->(t {id:'function:orders:app/db.py:get_order'}) RETURN p` |
| Endpoint → unsafe SQL | `MATCH p=(e:Endpoint)-[:ROUTES_TO\|CALLS\|HTTP_CALLS*1..8]->(f)-[:REACHES_SINK]->(s:Sink) WHERE s.attrs CONTAINS '"safe": false' RETURN p` |
| Files using a variable (the article's example) | `MATCH (fn)-[:READS_ENV]->(v:EnvVar {name:'DATABASE_URL'}) RETURN fn.path, fn.citation` |

`graph_neo4j.py query` refuses write clauses (CREATE, MERGE, SET, DELETE, REMOVE, DROP, LOAD CSV, admin CALLs). Use a read-only Neo4j user. Neo4j results are navigation aids: cite the `citation` property and open the source lines.
