from fastapi import Depends, FastAPI

from app.auth import require_auth
from app.service import OrderService

app = FastAPI()
service = OrderService()


@app.post("/orders")
def create(payload: dict, user=Depends(require_auth)):
    return service.place(payload)
