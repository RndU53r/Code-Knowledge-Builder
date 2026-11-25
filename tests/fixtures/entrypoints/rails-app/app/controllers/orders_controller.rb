class OrdersController < ApplicationController
  before_action :authenticate_user!

  def index
    render json: Order.where(owner: current_user.id)
  end

  def show
    order = Order.find_by_sql("SELECT * FROM orders WHERE id = #{params[:id]}")
    render json: order
  end

  def create
    system("convert #{params[:file]} out.png")
    redirect_to params[:next]
  end
end
