require "cognito_auth/configuration"
require "cognito_auth/engine"
require "cognito_auth/client"
require "cognito_auth/migration"
require "cognito_auth/version"
require 'encryption'
require 'jwt'
require 'json/jwt'
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
