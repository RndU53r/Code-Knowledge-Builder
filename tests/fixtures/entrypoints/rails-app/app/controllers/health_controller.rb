class HealthController < ApplicationController
  def ping
    render plain: "ok"
  end
end
