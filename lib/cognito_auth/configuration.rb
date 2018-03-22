module CognitoAuth
  class Configuration
    attr_accessor :client_id, :client_secret, :pool_id, :jwks, :sender

    def initialize
      @client_id
      @client_secret
      @pool_id
      @jwks
      @sender
    end
  end
end
