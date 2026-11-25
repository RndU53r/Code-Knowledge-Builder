from app.service import OrderService


def test_place():
    assert OrderService().place({"id": 1})
