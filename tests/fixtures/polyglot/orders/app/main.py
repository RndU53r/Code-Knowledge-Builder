import os
import uuid

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import db, events, pricing

app = FastAPI()
MAX_ITEMS = int(os.environ.get("MAX_ITEMS", "50"))


class Item(BaseModel):
    sku: str
    qty: int


class OrderRequest(BaseModel):
    customer_id: str
    items: list[Item]
    card_last4: str | None = None
    shipping_address: str | None = None


@app.post("/orders", status_code=201)
def create_order(req: OrderRequest, x_request_user: str | None = Header(default=None)):
    if len(req.items) > MAX_ITEMS:
        raise HTTPException(status_code=400, detail="too many items")
    total = pricing.price_items([i.model_dump() for i in req.items])
    order_id = str(uuid.uuid4())
    conn = db.get_conn()
    db.insert_order(conn, order_id, req.customer_id, total, req.card_last4)
    events.publish_order_created(order_id, req.customer_id, total, req.shipping_address)
    return {"id": order_id, "status": "pending", "total_cents": total}


@app.get("/orders/{order_id}")
def read_order(order_id: str):
    row = db.get_order(db.get_conn(), order_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return {"id": row[0], "status": row[1], "total_cents": row[2]}
