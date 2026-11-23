| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GATEWAY-SC-001 | SC-D01 | risky-practice | low | high | `gateway/Dockerfile:1` | base image node:20-alpine not pinned by digest — `FROM node:20-alpine` | Pin base images by digest (image@sha256:...). |

| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Manifest |
| --- | --- | --- | --- | --- | --- | --- |
| npm | express | 4.19.2 | yes | registry | not checked | `gateway/package.json:7` |
| npm | axios | 1.7.2 | yes | registry | not checked | `gateway/package.json:8` |
| npm | jsonwebtoken | 9.0.2 | yes | registry | not checked | `gateway/package.json:9` |

Limitations:

- not a git checkout: commit history checks skipped
