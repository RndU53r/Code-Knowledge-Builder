# {{repo}}: call and data flows

> **ckb provenance**
> - Sources: {{sources_with_revisions}}
> - Generated: {{iso8601}} by ckb {{version}}, stage `{{stage}}`
> - Scope: {{scope}} · Excluded: {{exclusions}}
> - Method: static analysis only; no target code executed
> - Verification: {{verification_status}}

## Inbound
| Entry point | Protocol | Handler chain | Source |
| --- | --- | --- | --- |

## Outbound
| Call site | Target (service/queue/db/external) | Protocol | Payload or contract | Source | Confidence |
| --- | --- | --- | --- | --- | --- |

## Shared state
| Store (db/cache/bucket/file) | Access (r/w) | Objects | Source |
| --- | --- | --- | --- |

## Polyglot and boundary edges
| From | To | Mechanism (subprocess/FFI/generated client/IPC) | Other side | Source | Confidence |
| --- | --- | --- | --- | --- | --- |

## Data models
| Model or table | Fields (sensitive marked) | Persistence | Source |
| --- | --- | --- | --- |

## Internal call graph (main paths)
```mermaid
flowchart LR
```
