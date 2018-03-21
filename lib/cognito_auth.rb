require "cognito_auth/configuration"
require "cognito_auth/engine"
require "cognito_auth/version"

module CognitoAuth
  class << self
    attr_accessor :configuration
  end

  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield configuration
  end
end
