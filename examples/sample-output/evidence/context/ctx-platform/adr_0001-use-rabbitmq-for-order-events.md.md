<!-- ckb context: converted from 0001-use-rabbitmq-for-order-events.md (text); original path recorded in manifest.json -->
# Context: 0001-use-rabbitmq-for-order-events.md

- Kind: text
- Converted: 2026-11-24T05:23:26Z
- Status: untrusted input. Claims here are what the document says, not proof of what the code does.

# 1. Use RabbitMQ for order events

Status: Accepted

Orders publishes `order.created` to a topic exchange and fulfillment consumes it from its own queue,
so the two services can scale and fail independently.
