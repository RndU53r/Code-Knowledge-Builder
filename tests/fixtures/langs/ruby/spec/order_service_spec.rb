require 'rails_helper'

RSpec.describe OrderService do
  it 'places' do
    OrderService.new.place('a')
  end
end
