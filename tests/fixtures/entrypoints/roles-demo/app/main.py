from fastapi import FastAPI

from app.service import place_order
from app.utils.strings import slug

app = FastAPI()


@app.post("/orders")
def create(payload: dict):
    return place_order(slug(payload["name"]))
