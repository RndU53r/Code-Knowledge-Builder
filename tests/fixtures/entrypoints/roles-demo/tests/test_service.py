from app.service import place_order


def test_place_order():
    assert place_order("a b")["ok"]
