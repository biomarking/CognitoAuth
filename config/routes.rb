CognitoAuth::Engine.routes.draw do

  namespace :v2, defaults: { format: :json } do
    resources :users, only:[:create] do
    end
  end
  namespace :v1, defaults: { format: :json } do

    resources :sessions, only: [:create] do
      collection do
        post 'destroy'
        post 'verify'
        post 'refresh_token'
      end
    end

    resources :users, only: [:create] do
      collection do
        post 'activate'
        post 'forgot'
        post 'update'
        post 'change_password_doctor'
        post 'change_password'
        post 'update_attribute'
        post 'confirm'
        post 'resend_code'
      end
    end
  end
end
