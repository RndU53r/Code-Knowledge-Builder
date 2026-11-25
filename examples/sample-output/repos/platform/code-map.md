# Code map: platform

> **ckb provenance**
> - Sources: `platform` (file roles from `evidence/file-roles-platform.json`)
> - Method: path/content rules for most roles; graph signals for core vs utility (always [inferred])
> - Excluded: vendored, binaries, symlinks, secret files (listed, not read)

## Repo kind

- **iac** [inferred], confidence high
- Signals: iac share 67%; gitops-config share 17%

## Files by role

| Role | Files |
| --- | --- |
| iac | 5 |
| build | 1 |

## Core application files [inferred]

| File | Why | Fan-in |
| --- | --- | --- |
| [n/a] none | | |

## Utility files [inferred]

| File | Why |
| --- | --- |
| [n/a] none | |

## Infrastructure and pipeline files

| Kind | Files |
| --- | --- |
| iac/bicep | 1 |
| iac/cloudformation | 1 |
| iac/kubernetes | 1 |
| iac/terraform | 2 |

## Tests

0 test file(s) [unknown] none found

Core files with no `tested_by` link (0): none
(a missing link can also mean the tests call the code in a way the extractor could not resolve)
