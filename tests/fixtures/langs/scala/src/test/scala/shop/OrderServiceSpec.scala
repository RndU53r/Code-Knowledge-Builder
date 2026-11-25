package shop

class OrderServiceSpec {
  def places(): Unit = {
    new OrderService(null).place("a")
  }
}
