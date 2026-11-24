# 1. Use RabbitMQ for order events

Status: Accepted

Orders publishes `order.created` to a topic exchange and fulfillment consumes it from its own queue,
so the two services can scale and fail independently.
