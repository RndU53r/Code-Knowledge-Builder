# Output reference

Everything ckb writes goes under the output directory (default `<target>/.ckb`). Nothing is written into the analyzed repos. A real example, generated from the test fixtures, is in [`examples/sample-output/`](../examples/sample-output/index.md).

```
.ckb/
  index.md                          entry point: navigation, top findings, evidence links
  system/
    hld.md                          system high-level design: components, boundaries, topology, documented vs observed
    data-flows.md                   cross-repo edges (REST/gRPC/queues/shared stores/contracts/polyglot) + sequence diagrams
    call-graphs.md                  function→function, file→file, repo→repo call graphs with citations + Mermaid
    outputs-and-conditions.md       cross-repo outputs and conditions that affect more than one repo
    threat-model.md                 STRIDE threat model (draft first, then refined)
    documented-vs-observed.md       what your documents claim vs what the code/IaC shows, per claim
    context.md                      system-level scanner context (9 sections + front matter)
    supply-chain-report.md          cross-repo ranking of supply-chain and injection findings
    graph.md                        graph size, extractor mix, endpoints, unsafe sinks, cross-repo edges
    impact-<slug>.md                one per /ckb:impact run
  repos/<repo>/
    overview.md                     languages, frameworks, entry points, dependencies, infra, cloud resources
    flows.md                        inbound/outbound/shared-state/polyglot edges and call graph
    hld.md  lld.md                  per-repo design; LLD has sequence diagrams, data models, error handling
    outputs-and-conditions.md       each output: what, how, when (condition | effect | default | source), who consumes
    context.md                      per-repo scanner context
    supply-chain.md                 ranked findings, dependency inventory
  graph/
    graph.json                      the citable knowledge graph (source of truth)
    graph.sqlite                    the same graph for fast queries
    callgraph.json                  rolled-up call graphs
    index.html                      self-contained interactive viewer (works offline)
    proposals/*.jsonl               graph facts proposed by agents or rule engines (verified before merge)
    rejected.jsonl                  proposals that failed verification, with the reason
    annotations.json  tours.json    summaries and tours that survive rebuilds
    ua-knowledge-graph.json         Understand-Anything-compatible export (after `export ua`)
    neo4j/                          Cypher/CSV export (after `export cypher|csv`)
  answers/<slug>.md                 /ckb:ask answers that were saved
  diagrams/*.mmd                    Mermaid sources of every diagram
  evidence/
    targets.json                    registered sources: root, revision, branch, source mode, exclusions
    authorization.md                who confirmed what, and when
    auto-plan.json, auto-plan-final.json   the auto-mode plan and its post-fetch revision
    verification.md                 citation check results (mechanical + semantic review)
    graph-verification.md           graph check results
    citations.md                    every citation used, by repo and file
    doc-claims.json                 claims extracted from documents and their verdicts
    inventory-*.json, sc-*.json     raw script output (inventory, supply-chain scan)
    context/ctx-*/                  converted documents, diagrams, scan exports (each cited as ctx-*/file:line)
    hashes.json                     content hashes used by /ckb:update
```

## How to read a file

Every output starts with a **provenance block**: sources and revisions, generation time and stage, scope and exclusions, method ("static analysis only; no target code executed"), and verification status.

| Marker | Meaning |
| --- | --- |
| `` `repo/path:LINE` `` or `:START-END` | seen in those lines; verified to exist. `` «quoted text» `` after it was checked against the line |
| `[inferred]` | a reasoned connection between cited observations |
| `[unknown]` | not found, excluded, or not provable statically |
| `[documented]` | stated only in a document or diagram (intent, not proof) |
| `[n/a]` | the section does not apply |
| `[draft]` | produced by rules, not yet reviewed (threat model rows) |
| `[OUTDATED]` | a summary written for an earlier version of the code |

Confidence: **high** = observed at both ends; **medium** = one end observed, the other inferred from naming or config; **low** = a pattern match only.

Precedence when sources disagree: **code and IaC** (what is built) > **CSPM results** (what was deployed when scanned) > **documents and diagrams** (what someone intended). Disagreements are reported as drift, never silently resolved.

## Citations to context files

Converted context is cited like code: `` `ctx-arch/security-design.docx.md:14` `` points at line 14 of the converted file under `evidence/context/ctx-arch/`, not at the original document. The original path is recorded in `evidence/context/<key>/manifest.json`.

## The graph in one paragraph

Nodes (files, functions, endpoints, topics, tables, env vars, cloud resources, sinks, threats, findings…) and edges (calls, routes, HTTP calls, publish/consume, reads/writes, subprocess, reaches-sink, threatens, …) each carry a citation, the extractor that produced them (`ast`, `tree-sitter`, `regex`, `llm`, `rule`, `scanner`, `context`) and a confidence. IDs are stable (`function:orders:app/db.py:get_order`) and never contain line numbers. Full schema: [graph schema](../skills/knowledge-graph/references/schema.md).

## Verification state

`evidence/verification.md` and `evidence/graph-verification.md` tell you whether the outputs were checked: every citation must resolve to a real line (and quoted text must match), every output file must carry a provenance block, secret-looking values must be redacted, and diagrams must be inert. Warnings of the "section has no citation" kind are usually summary sections; errors mean the output should not be trusted until fixed.
