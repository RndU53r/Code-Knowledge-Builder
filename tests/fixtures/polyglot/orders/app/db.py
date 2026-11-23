import os

import psycopg2

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://orders@db:5432/shop")


def get_conn():
    return psycopg2.connect(DATABASE_URL)


def insert_order(conn, order_id, customer_id, total_cents, card_last4):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO orders (id, customer_id, total_cents, card_last4, status) VALUES (%s, %s, %s, %s, 'pending')",
            (order_id, customer_id, total_cents, card_last4),
        )
    conn.commit()


def get_order(conn, order_id):
    with conn.cursor() as cur:
        cur.execute(f"SELECT id, status, total_cents FROM orders WHERE id = '{order_id}'")
        return cur.fetchone()
