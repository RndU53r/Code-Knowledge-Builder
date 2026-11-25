from app.repo import OrderRepo


class OrderService:
    def __init__(self):
        self.repo = OrderRepo()

    def place(self, item):
        return self.repo.save(item)
