require 'net/http'

class BaseRepo
  def save(item)
    item
  end
end

class OrderRepo < BaseRepo
  def save(item)
    Net::HTTP.get(URI('http://billing/charge'))
    ActiveRecord::Base.connection.execute("SELECT * FROM orders WHERE id = #{item}")
    super(item)
  end
end
