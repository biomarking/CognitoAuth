CognitoAuth::Engine.routes.draw do

  namespace :v1, defaults: { format: :json } do

    resources :sessions, only: [:create] do
      collection do
        post 'destroy'
        post 'verify'
      end
    end

    resources :users, only: [:create] do
      collection do
        post 'activate'
        post 'forgot'
        post 'update'
        post 'change_password'
        post 'update_attribute'
      end
    end
  end
end
