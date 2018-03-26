CognitoAuth::Engine.routes.draw do

  namespace :v1, defaults: { format: :json } do
    
    resources :sessions, only: [:create] do
      collection do
        post 'destroy'
      end
    end

    resources :users, only: [:create] do
      collection do
        post 'activate'
        post 'forgot'
        post 'update'
      end
    end
  end
end
