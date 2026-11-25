import os
from fastapi import FastAPI

app = FastAPI()
DB_PASSWORD = os.environ.get("DB_PASSWORD")


@app.post("/pay")
def pay(amount: int):
    return {"ok": True}
