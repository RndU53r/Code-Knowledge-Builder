Rails.application.routes.draw do
  get '/ping' => 'health#ping'
  namespace :api do
    resources :orders, only: [:index, :show, :create]
    post '/import', to: 'imports#create'
  end
end
