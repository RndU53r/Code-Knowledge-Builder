class OrdersController < ApplicationController
  before_action :authenticate_user!

  def initialize
    @service = OrderService.new
  end

  def create
    @service.place(params[:item])
  end
end
