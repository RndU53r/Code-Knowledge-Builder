| ID | Check | Class | Severity | Confidence | Evidence | Finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ORDERS-SC-001 | SC-D03 | risky-practice | medium | high | `orders/Dockerfile:1` | container runs as root (no non-root USER) | Add a non-root USER and drop privileges. |
| ORDERS-SC-002 | SC-S08 | risky-practice | medium | medium | `orders/app/events.py:6` | credentials embedded in a URL (may be a default like guest:guest; still a hardcoded credential) — `RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp…[REDACTED]rabbitmq:5672/")` | Rotate the credential, remove it from history, and load it from a secret manager. |
| ORDERS-SC-003 | SC-D01 | risky-practice | low | high | `orders/Dockerfile:1` | base image python:3.12-slim not pinned by digest — `FROM python:3.12-slim` | Pin base images by digest (image@sha256:...). |
| ORDERS-SC-004 | SC-M02 | risky-practice | low | medium | `orders/requirements.txt:1` | requirements without --hash pins or a lockfile (installs are not reproducible) | Commit the ecosystem lockfile and install with the frozen/locked mode in CI. |

| Ecosystem | Name | Version spec | Pinned? | Source | Advisory status | Snyk page | Manifest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| pypi | fastapi | ==0.111.0 | yes | registry | not checked | <https://security.snyk.io/package/pip/fastapi/0.111.0> | `orders/requirements.txt:1` |
| pypi | uvicorn | ==0.30.1 | yes | registry | not checked | <https://security.snyk.io/package/pip/uvicorn/0.30.1> | `orders/requirements.txt:2` |
| pypi | psycopg2-binary | ==2.9.9 | yes | registry | not checked | <https://security.snyk.io/package/pip/psycopg2-binary/2.9.9> | `orders/requirements.txt:3` |
| pypi | pika | ==1.3.2 | yes | registry | not checked | <https://security.snyk.io/package/pip/pika/1.3.2> | `orders/requirements.txt:4` |
| pypi | pydantic | ==2.7.4 | yes | registry | not checked | <https://security.snyk.io/package/pip/pydantic/2.7.4> | `orders/requirements.txt:5` |

Limitations:

- not a git checkout: commit history checks skipped
