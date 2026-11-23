# Polyglot fixture (ckb test data)

Three services that talk over HTTP and a queue, plus a shared database and contract.
Test data for ckb only. Never install or run it.

- gateway (Node/Express): public API, forwards /orders to orders over REST
- orders (Python/FastAPI): writes orders to Postgres, publishes `order.created` to RabbitMQ, calls the Go `pricing` binary via subprocess
- fulfillment (Go): consumes `order.created`, updates order status in Postgres, calls an external shipping API
