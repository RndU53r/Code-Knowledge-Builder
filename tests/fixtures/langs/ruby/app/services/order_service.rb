require_relative '../repos/order_repo'

class OrderService
  def initialize
    @repo = OrderRepo.new
  end

  def place(item)
    @repo.save(item)
  end
end
