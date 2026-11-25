package shop

class OrderService(repo: OrderRepo) {
  def place(item: String): String = {
    repo.save(item)
  }
}
