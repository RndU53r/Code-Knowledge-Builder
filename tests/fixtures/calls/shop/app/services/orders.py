from app.repo.orders import OrderRepo
from app.util import audit, log_call


class OrderService:
    def __init__(self, repo: OrderRepo):
        self.repo = repo

    @log_call
    def place(self, item):
        audit(item)
        return self.repo.save(item)

    def lookup(self, order_id):
        repo = OrderRepo()
        return repo.find(order_id)

    def dynamic(self, name):
        handlers = {"a": self.place}
        return handlers[name]().strip()
