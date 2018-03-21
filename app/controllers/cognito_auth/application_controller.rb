module CognitoAuth
  class ApplicationController < ActionController::API
    # protect_from_forgery with: :exception
    attr_reader :client
    
    def initiate_auth
      @client = CognitoAuth::Engine
    end
  end
end
