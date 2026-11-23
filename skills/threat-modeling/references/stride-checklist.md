# STRIDE prompts (look for evidence, not hypotheticals)

| Category | Ask | Typical evidence |
| --- | --- | --- |
| **S**poofing | Can a caller pretend to be another user or service? | missing or optional auth middleware; JWT `verify` without algorithm pinning; trusted identity headers (`x-user`, `x-request-user`) accepted from the network; shared static API keys; no mTLS between services; webhook routes without signature checks |
| **T**ampering | Can data be modified in transit or at rest by someone who shouldn't? | plain HTTP between services; unsigned messages on shared queues; mass assignment (`{...req.body}` into models); writable shared tables from several services; unpinned build inputs |
| **R**epudiation | Can actions happen without a trustworthy record? | no audit log on admin or state-changing actions; logs missing the actor ID; logs writable by the app user |
| **I**nformation disclosure | Can data leak? | verbose errors and stack traces; PII in logs; IDOR (lookups by ID without an ownership check); SSRF reaching metadata endpoints; secrets in env dumps or responses; overly broad CORS |
| **D**enial of service | Can availability be degraded cheaply? | no body or size limits; unbounded loops on user input; no timeouts on outbound calls; requeue-forever on poison messages; missing rate limits on expensive endpoints |
| **E**levation of privilege | Can someone gain capabilities? | role checks only in the UI or gateway but not the service; auth-disable toggles; command or template injection; deserialization of untrusted data; containers running as root or privileged; CI `pull_request_target` with secrets |

For each data flow crossing a boundary, also ask: is the channel authenticated, encrypted, integrity-protected, and is the payload validated at the receiver?
