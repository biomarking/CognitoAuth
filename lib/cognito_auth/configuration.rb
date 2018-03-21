module CognitoAuth
  class Configuration
    attr_accessor :client_id, :client_secret, :pool_id

    def initialize
      @client_id
      @client_secret
      @pool_id
    end
  end
end
