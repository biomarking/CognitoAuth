require "cognito_auth/configuration"
require "cognito_auth/engine"
require "cognito_auth/version"
require 'encryption'
require 'aws-sdk-cognitoidentityprovider'

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
