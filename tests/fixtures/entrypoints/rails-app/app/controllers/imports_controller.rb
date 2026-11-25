class ImportsController < ApplicationController
  skip_before_action :authenticate_user!

  def create
    data = Marshal.load(request.body.read)
    render json: data
  end
end
