# Evidence model

The evidence labels and provenance block are adapted from OthmanAdi/codebase-knowledge-builder (MIT). See `NOTICE`.

## Citations

- **Format:** `` `repo/path/to/file.ext:LINE` `` or `` `repo/path/to/file.ext:START-END` ``. `repo` is the repo key registered in `<out>/evidence/targets.json`, and the path is relative to that repo root.
- **Optional quote:** right after a citation, add the exact source text in guillemets: `` `orders/app/main.py:42` «@app.post("/orders")» ``. `scripts/verify_citations.py` checks that the quoted text (whitespace collapsed) appears within the cited lines. Quote whenever a claim depends on a specific token, such as a route, topic name, env var, or sink call.
- **Placement:** cite every consequential claim. In tables, put citations in a `Source` column.
- **Do not** cite directories, whole files without a line, or line numbers you did not read.

## Labels

| Marker | Use when | Required support |
| --- | --- | --- |
| (none) | Directly observed in the cited lines | Citation |
| `[inferred]` | Best explanation that connects observations | Citations of the observations + one-line reasoning |
| `[unknown]` | Evidence missing, excluded, contradictory, or out of budget | What evidence would resolve it |
| `[n/a]` | The section does not apply | Brief reason |

## Confidence

Each finding, threat, flow edge, and supply-chain item carries `confidence: high | medium | low`.

- **high:** observed directly at both ends (for example both the client call and the server route are cited).
- **medium:** one end observed, the other inferred from naming, config, or convention.
- **low:** pattern or heuristic match only. Needs human review.

## Provenance block (top of every output file)

```markdown
> **ckb provenance**
> - Sources: `orders` @ `a1b2c3d` (github.com/acme/orders), `gateway` @ `local, dirty`
> - Generated: 2026-11-23T10:00:00Z by ckb 0.1.0, stage `<stage>`
> - Scope: <included> · Excluded: <vendored, generated, binaries, symlinks, …>
> - Method: static analysis only; no target code executed
> - Verification: <pending | passed (N citations) | failed (see evidence/verification.md)>
```

## Never guess

If you cannot find it, write `[unknown]`. A blank cell, an invented function name, or a "probably" without the `[inferred]` marker counts as a defect, and the citation verifier will send it back.
