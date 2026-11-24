# ckb graph schema (v1.0)

**Top level:** `schema_version, generator, generated, repos{key:{revision,dirty}}, nodes[], edges[], layers[], tours[], stats`

**Node:** `id, kind, name, repo, path, range{start,end}, citation, provenance{extractor,tool_version,run}, confidence, label`, plus optional `qualname, signature, sig_hash, summary, summary_status (fresh|OUTDATED), tags, layer, attrs`.

**Edge:** `id, src, dst, kind, citation (reference site), provenance, confidence, label, verified{status,by}`, plus optional `quote` (required for llm), `dst_citation` (required for cross-repo llm edges), `rationale, attrs`.

**IDs**

| Shape | Example |
| --- | --- |
| `kind:repo:path:qualname` | `function:orders:app/db.py:get_order` |
| `kind:repo::name` (not code) | `endpoint:orders::POST /orders`, `env_var:orders::DATABASE_URL` |
| `kind:_system::name` (shared across repos) | `table:_system::orders`, `topic:_system::order.created` |
| `sink:repo:path:qual.type.n` | `sink:orders:app/db.py:get_order.sql.1` |

| Group | Node kinds |
| --- | --- |
| Structure | repo, dir, file, module, class, interface, function, method, field, variable |
| Interfaces | endpoint, consumer, topic, queue, contract_op, cli_command, cron_job |
| State/config | table, cache, bucket, env_var, config_flag, package, cloud_resource, service, external |
| Security | taint_source, sink (`attrs.sink_type` sql/command/ssrf/code/deserialization, `attrs.safe`), threat, sc_finding, cspm_finding, trust_boundary, asset, drift |
| Docs | doc_section |

| Edge kind | Meaning | Allowed extractors |
| --- | --- | --- |
| contains, defines | structure | ast, tree-sitter, regex, context, scanner |
| imports | file→file or file→package | ast, tree-sitter, regex |
| calls | function→function | ast, tree-sitter, regex, llm |
| inherits, implements, overrides, uses_type, references | type relations | ast, tree-sitter, (regex), llm |
| routes_to | endpoint→handler | ast, tree-sitter, regex, llm |
| http_calls, grpc_calls | caller→endpoint (cross-repo) | regex, ast, tree-sitter, llm |
| publishes, consumes | function↔topic | ast, regex, tree-sitter, llm |
| reads, writes | function↔table | ast, regex, tree-sitter, llm |
| reads_env | function→env_var | ast, regex, tree-sitter |
| spawns, ffi | language boundary | ast, regex, llm |
| reaches_sink | function→sink | ast, regex, tree-sitter, llm |
| flows_to | data flow (taint) | ast, llm |
| finding_at | sc_finding→code or resource | scanner |
| affects | cspm_finding→cloud_resource | context, scanner, llm |
| threatens, mitigated_by, crosses_boundary, inside_boundary | threat model | llm |
| documented_as, drifts_from | doc vs code | llm, context |
| depends_on, deploys, tested_by | other | scanner/regex/context/llm |

**Confidence.** High: both ends resolved statically (or an exact AST fact). Medium: resolved by unique name, convention, or templated URL. Low: a guess (a regex near-match or ambiguous name), always labelled `inferred`.
