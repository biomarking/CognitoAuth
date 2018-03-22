CognitoAuth::Engine.routes.draw do

  namespace :v1, defaults: { format: :json } do
    resources :sessions, only: [:create]
    resources :users, only: [:create] do
      collection do
        post 'activate'
      end
    end
  end
end
