import json

import requests

from app.repo.base import BaseRepo


class OrderRepo(BaseRepo):
    def save(self, item):
        payload = json.dumps(item)
        requests.post("http://billing/charge", data=payload)
        return super().save(item)

    def find(self, order_id):
        return {"id": order_id}
