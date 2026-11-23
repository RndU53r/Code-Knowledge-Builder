import json
import os

import pika

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
EXCHANGE = "orders"
ROUTING_KEY = "order.created"
PUBLISH_EVENTS = os.environ.get("PUBLISH_EVENTS", "true") == "true"


def publish_order_created(order_id, customer_id, total_cents, shipping_address):
    if not PUBLISH_EVENTS:
        return False
    conn = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
    ch = conn.channel()
    ch.exchange_declare(exchange=EXCHANGE, exchange_type="topic", durable=True)
    body = json.dumps({
        "order_id": order_id,
        "customer_id": customer_id,
        "total_cents": total_cents,
        "shipping_address": shipping_address,
    })
    ch.basic_publish(exchange=EXCHANGE, routing_key=ROUTING_KEY, body=body)
    conn.close()
    return True
