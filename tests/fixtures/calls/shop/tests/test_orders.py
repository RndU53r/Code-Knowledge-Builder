from app.services.orders import OrderService
from app.repo.orders import OrderRepo


def test_place():
    assert OrderService(OrderRepo()).place({"a": 1})
