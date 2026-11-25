# Code map: orders

> **ckb provenance**
> - Sources: `orders` (file roles from `evidence/file-roles-orders.json`)
> - Method: path/content rules for most roles; graph signals for core vs utility (always [inferred])
> - Excluded: vendored, binaries, symlinks, secret files (listed, not read)

## Repo kind

- **service** [inferred], confidence high
- Signals: application share 90%; 2 endpoint

## Files by role

| Role | Files |
| --- | --- |
| core | 4 |
| build | 1 |
| docs | 1 |
| other | 1 |

## Core application files [inferred]

| File | Why | Fan-in |
| --- | --- | --- |
| `app/db.py` | owns I/O (data store, queue, outbound call, sink) | 1 |
| `app/events.py` | owns I/O (data store, queue, outbound call, sink) | 1 |
| `app/pricing.py` | owns I/O (data store, queue, outbound call, sink) | 1 |
| `app/main.py` | defines an entry point | 0 |

## Utility files [inferred]

| File | Why |
| --- | --- |
| [n/a] none | |

## Tests

0 test file(s) [unknown] none found

Core files with no `tested_by` link (4): `app/db.py`, `app/events.py`, `app/pricing.py`, `app/main.py`
(a missing link can also mean the tests call the code in a way the extractor could not resolve)
