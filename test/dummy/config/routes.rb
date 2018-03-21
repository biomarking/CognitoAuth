Rails.application.routes.draw do
  mount CognitoAuth::Engine => "/cognito_auth"
end
