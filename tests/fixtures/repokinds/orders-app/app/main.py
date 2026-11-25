from fastapi import FastAPI

app = FastAPI()


@app.get("/orders/{order_id}")
def read_order(order_id: int):
    return {"id": order_id}


@app.post("/orders")
def create_order(payload: dict):
    return payload
