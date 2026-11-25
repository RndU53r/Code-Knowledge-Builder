import threading

from app.services.orders import OrderService
from app.repo.orders import OrderRepo
from app.util import notify, audit

service = OrderService(OrderRepo())


def handle(item):
    notify(audit, item)
    threading.Thread(target=worker).start()
    return service.place(item)


def worker():
    return service.lookup(1)
