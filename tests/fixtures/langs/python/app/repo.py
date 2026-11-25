import requests


class BaseRepo:
    def save(self, item):
        return item


class OrderRepo(BaseRepo):
    def save(self, item):
        requests.post("http://billing/charge", json=item)
        self.conn.cursor().execute(f"SELECT * FROM orders WHERE id = {item['id']}")
        return super().save(item)
