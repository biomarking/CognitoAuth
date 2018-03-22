
module CognitoAuth
  class Engine < ::Rails::Engine
    isolate_namespace CognitoAuth
    attr_accessor :client, :client_id, :client_secret, :pool_id

    initializer :append_migrations do |app|
      unless app.root.to_s.match(root.to_s)
        config.paths["db/migrate"].expanded.each do |p|
          app.config.paths["db/migrate"] << p
        end
      end
    end

    def client_signin(options={})
      begin
        initialize
        res = client.initiate_auth({
          client_id: client_id,
          auth_flow: "USER_PASSWORD_AUTH",
          auth_parameters: auth_parameters(options)
          # {
          #   "SECRET_HASH" => hmac(options[:username]),
          #   "USERNAME" => options[:username],
          #   "PASSWORD" => options[:password]
          # }
        })
        res.to_h
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        # rescues all service API errors
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_signup(options={})
      begin
        initialize
        res = client.sign_up({
            client_id: client_id,
            secret_hash: hmac(options[:username]), #Base64.encode64(OpenSSL::HMAC.digest('sha256', ENV["AWS_COGNITO_SECRET"], "#{username}#{clientid}")).strip(),
            username: options[:username], # required
            password: options[:password], # required
            user_attributes: [
              {
                name: "email", # required
                value: options[:username],
              },
              {
                name: "phone_number",
                value: options[:phone_number]
              }
            ],
            validation_data: [
              {
                name: "Email", # required
                value: "AttributeValueType",
              },
            ]
          })


        # res = client.initiate_auth({
        #   client_id: client_id,
        #   auth_flow: "USER_PASSWORD_AUTH",
        #   auth_parameters: #auth_parameters(options)
        #   {
        #     "SECRET_HASH" => hmac(options[:username]),
        #     "USERNAME" => options[:username],
        #     "PASSWORD" => options[:password]
        #   }
        # })
        res.to_h
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        # rescues all service API errors
        p "====#{e.inspect}"
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_confirm(username)
      begin
        initialize
        res = client.admin_confirm_sign_up({
          user_pool_id: pool_id, # required
          username: username, # required
        })
        res.to_h
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    private
    def initialize
      @client = Aws::CognitoIdentityProvider::Client.new
      @client_id = CognitoAuth.configuration.client_id
      @client_secret = CognitoAuth.configuration.client_secret
      @pool_id = CognitoAuth.configuration.pool_id
    end

    def auth_parameters(options={})
      {
        "SECRET_HASH" => hmac(options[:username]),
        "USERNAME" => options[:username],
        "PASSWORD" => options[:password]
      }
    end

    def hmac(username)
      data = "#{username}#{client_id}"
      digest = OpenSSL::HMAC.digest('sha256', client_secret, data)
      hmac = Base64.encode64(digest).strip()
      hmac
    end
  end
end
