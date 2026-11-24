---
ckb_context: 1
scope: fulfillment
revision: d2ffc20
generated: 2026-11-24T05:32:39Z
languages: [go]
entry_points: 3
focus_areas: [amqp-trust, business-logic, dos-requeue]
---
# Security context: fulfillment

> **ckb provenance**
> - Sources: `fulfillment` @ `d2ffc20`
> - Generated: 2026-11-24T05:32:39Z by ckb 0.1.0, stage `security-context`
> - Scope: fulfillment · Excluded: vendored, generated, binaries, symlinks (none present)
> - Method: static analysis only; no target code executed
> - Verification: passed (15 citations, 0 errors; see evidence/verification.md)

## 1. Purpose and tech stack
Go worker consuming `order.created`, calling a shipping API and updating order status; also the pricing CLI. `fulfillment/cmd/worker/main.go:26`
- Go 1.22, lib/pq 1.10.9, amqp091-go 1.10.0 `fulfillment/go.mod:3`
## 2. Entry points and trust boundaries
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
| queue fulfillment.order-created | internal (broker) | broker to worker | `fulfillment/internal/queue/consumer.go:26` |
| pricing CLI | internal (spawned by orders) | process boundary | `fulfillment/cmd/pricing/main.go:18` |
## 3. Authn/authz model
No message authentication; trust rests on broker credentials. Outbound shipping call uses a bearer key from `SHIPPING_API_KEY`. `fulfillment/cmd/worker/main.go:29`
## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
| shipping_address | event | shipping API | HTTPS by deployment value | `fulfillment/cmd/worker/main.go:27` |
| SHIPPING_API_KEY | env | Authorization header | env only (name recorded, value never) | `fulfillment/cmd/worker/main.go:23` |
## 5. Dangerous sinks and sanitizers already in place
| Sink | Kind | Sanitizer or guard | Verdict | Source |
| --- | --- | --- | --- | --- |
| status UPDATE | SQL | bound parameters | safe: parameterized | `fulfillment/cmd/worker/main.go:35` |
| shipping POST | outbound HTTP | URL from env, not from the message | safe: not attacker-controlled | `fulfillment/cmd/worker/main.go:28` |
## 6. Known-safe patterns and known-risky areas
- Safe: parameterized UPDATE; typed JSON decode `fulfillment/internal/queue/consumer.go:39`.
- Risky: unlimited requeue `fulfillment/internal/queue/consumer.go:46`; flat pricing with unbounded qty `fulfillment/cmd/pricing/main.go:23`.
## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
| `order.created` | orders | fulfillment | broker credentials | `fulfillment/internal/queue/consumer.go:30` |
## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
| `SHIPPING_API_URL` | shipping target | unset | `fulfillment/cmd/worker/main.go:22` |
| `RABBITMQ_URL` | broker | unset | `fulfillment/cmd/worker/main.go:26` |
## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
| 1 | amqp-trust | `internal/queue` | unauthenticated events drive status changes | T-06 |
| 2 | dos-requeue | `internal/queue` | poison message loop | T-27 |
| 3 | business-logic | `cmd/pricing` | flat price, negative qty | T-34 |
