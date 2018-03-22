module CognitoAuth
  class Configuration
    attr_accessor :client_id, :client_secret, :pool_id, :sender

    def initialize
      @client_id
      @client_secret
      @pool_id
      @sender
    end
  end
end
