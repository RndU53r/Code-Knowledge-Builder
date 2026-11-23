# {{scope_name}}: outputs and conditions

> **ckb provenance**
> - Sources: {{sources_with_revisions}}
> - Generated: {{iso8601}} by ckb {{version}}, stage `{{stage}}`
> - Scope: {{scope}} · Excluded: {{exclusions}}
> - Method: static analysis only; no target code executed
> - Verification: {{verification_status}}

## Output index
| ID | Kind (api-response/event/file/db-write/log/metric/external-call) | Name | Producer | Consumers |
| --- | --- | --- | --- | --- |

## O-{{n}}: {{output name}}
- **What:** shape and schema (cite the model, schema, or serializer)
- **How:** function chain `a → b → c` (each cited)
- **Who consumes:** (cross-repo, cited at the consumer)

**When**
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| env `X` unset | | | |
| feature flag | | | |
| role or auth branch | | | |
| error or retry path | | | |
