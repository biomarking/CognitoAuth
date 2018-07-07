module CognitoAuth
  class Client < ::Rails::Engine
    isolate_namespace CognitoAuth

    attr_accessor :client, :client_id, :client_secret, :pool_id

    def init
      @client = Aws::CognitoIdentityProvider::Client.new
      @client_id = CognitoAuth.configuration.client_id
      @client_secret = CognitoAuth.configuration.client_secret
      @pool_id = CognitoAuth.configuration.pool_id
      self
    end

    def validate_token(jwt)
      # begin
        token = JWT.decode jwt, nil, false
        kid = token[1]["kid"]
        jwk1 = CognitoAuth.configuration.jwks["keys"].detect { |jwk| jwk["kid"] == kid }
        jwk = JSON::JWK.new jwk1
        js = JSON::JWT.decode jwt, jwk
        iss = "https://cognito-idp.#{ENV["AWS_REGION"]}.amazonaws.com/#{pool_id}"
        unless js[:token_use] == :access || js[:iss] == iss
          raise ExceptionHandler::AuthenticationError
        end
        token
      # rescue => e
      #   raise ExceptionHandler::AuthenticationError, e
    end

    def login(options={})
        res = client.initiate_auth({
          client_id: client_id,
          auth_flow: "USER_PASSWORD_AUTH",
          auth_parameters: auth_parameters(options)
        })
        res = res.to_h
    end

    def client_signup(options={})
        res = client.sign_up({
            client_id: client_id,
            secret_hash: hmac(options[:username]),
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
                value: options[:username],
              },
            ]
          })
        res.to_h
    end

    def client_add_to_group(options={})
        res = client.admin_add_user_to_group({
          user_pool_id: pool_id, # required
          username: options[:username], # required
          group_name: options[:group], # required
        })
        res.to_h
    end

    def resend_code username
        client.resend_confirmation_code({
          client_id: client_id,
          secret_hash: hmac( username ),
          username: username
        })
      # rescue => e
        # p e.inspect
    end

    def confirm_user_signup( options={} )
        resp = client.confirm_sign_up({
          client_id: client_id, # required
          secret_hash: hmac( options[:username] ),
          username: options[:username], # required
          confirmation_code: options[:code],
          force_alias_creation: false
        })
    end

    def client_forgotpassword( username )
        res = client.forgot_password({
          client_id: client_id, # required
          secret_hash: hmac( username ),
          username: username, # required
        })
        res.to_h
    end

    def reset_password ( options={} )
        resp = client.confirm_forgot_password({
          client_id: client_id, # required
          secret_hash: hmac( options[:username] ),
          username: options[:username], # required
          confirmation_code: options[:code],
          password: options[:password]
        })
        resp.to_h
    end

    def refresh_token( r_token, username )
        client.initiate_auth({
          client_id: client_id,
          auth_flow: "REFRESH_TOKEN",
          auth_parameters:{
            REFRESH_TOKEN: r_token,
            SECRET_HASH: hmac( username )
          }
        })
    end

    private
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
