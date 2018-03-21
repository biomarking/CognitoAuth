CognitoAuth::Engine.routes.draw do

  namespace :v1, defaults: { format: :json } do
    resources :sessions, only: [:create]
    resources :users, only: [:create] do
      member do
        get 'activate'
      end
    end
  end
end
