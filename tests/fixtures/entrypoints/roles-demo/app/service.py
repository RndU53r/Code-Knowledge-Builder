import sqlite3

from app.utils.strings import slug
from app.utils.money import cents


def place_order(name):
    db = sqlite3.connect("orders.db")
    db.execute("INSERT INTO orders (name, total) VALUES (?, ?)", (slug(name), cents(100)))
    return {"ok": True}
