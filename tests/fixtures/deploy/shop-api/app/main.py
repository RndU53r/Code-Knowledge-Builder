import os
from fastapi import FastAPI

app = FastAPI()
DEBUG = os.environ.get("DEBUG", "false")
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "false")
DATABASE_URL = os.environ.get("DATABASE_URL")


@app.get("/orders")
def list_orders(order_id: str):
    cur = connection.cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return cur.fetchall()
