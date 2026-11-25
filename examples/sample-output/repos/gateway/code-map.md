# Code map: gateway

> **ckb provenance**
> - Sources: `gateway` (file roles from `evidence/file-roles-gateway.json`)
> - Method: path/content rules for most roles; graph signals for core vs utility (always [inferred])
> - Excluded: vendored, binaries, symlinks, secret files (listed, not read)

## Repo kind

- **service** [inferred], confidence high
- Signals: application share 60%; 4 endpoint

## Files by role

| Role | Files |
| --- | --- |
| build | 2 |
| core | 2 |
| generated | 1 |

## Core application files [inferred]

| File | Why | Fan-in |
| --- | --- | --- |
| `src/auth.js` | reached from an entry point | 1 |
| `src/server.js` | defines an entry point | 0 |

## Utility files [inferred]

| File | Why |
| --- | --- |
| [n/a] none | |

## Tests

0 test file(s) [unknown] none found

Core files with no `tested_by` link (2): `src/auth.js`, `src/server.js`
(a missing link can also mean the tests call the code in a way the extractor could not resolve)
