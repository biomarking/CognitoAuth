
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

    def self.validate_user token
      validate_token token
    end

    def validate_token(jwt)
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
    rescue => e
        raise ExceptionHandler::AuthenticationError, e
    end

    def gracefull_password_update( options={})
      resp = client.change_password({
        previous_password: options[:params][:password], # required
        proposed_password: options[:params][:new_password], # required
        access_token: options[:token ], # required
      })
    end

    def force_update_password( options={} )
      begin
        initialize

        # verify that the user state is really NEW_PASSWORD_REQUIRED
        # this stage can be remove if all challenge requirement are sent to user but for security just verify and proceed to solve the challenge response
        res = client.initiate_auth({
          client_id: client_id,
          auth_flow: "USER_PASSWORD_AUTH",
          auth_parameters: auth_parameters(options)
        })

        #verify if the challenge requirement is NEW_PASSWORD_REQUIRED
        if res.challenge_name && res.challenge_name == "NEW_PASSWORD_REQUIRED"

          #process the challenge NEW_PASSWORD_REQUIRED

          resp = client.admin_respond_to_auth_challenge({
            user_pool_id: pool_id, # required
            client_id: client_id, # required
            challenge_name: "NEW_PASSWORD_REQUIRED",
            challenge_responses: {
              "USERNAME" =>res.challenge_parameters["USER_ID_FOR_SRP"],
              "NEW_PASSWORD" => options[:new_password],
              "SECRET_HASH" => hmac(res.challenge_parameters["USER_ID_FOR_SRP"]),
            },
            session: res.session
          })

          df = validate_token(resp.authentication_result.access_token)

          return {
            uuid:df[0]["sub"],
            token: resp.authentication_result.access_token
          }

        else

          df = validate_token(res[:authentication_result][:access_token])

          return {
            uuid:df[0]["sub"],
            token: res[:authentication_result][:access_token]
          }

        end
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        # rescues all service API errors
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def self.client_get_user_info(user)
      begin
        # initialize
        res = client.admin_get_user({
          user_pool_id: pool_id,
          username: user, # required
        })
        res = res.to_h
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_signin(options={})

      begin
        initialize

        res = client.initiate_auth({
          client_id: client_id,
          auth_flow: "USER_PASSWORD_AUTH",
          auth_parameters: auth_parameters(options)
        })
        res = res.to_h
        if res[:challenge_name] && res[:challenge_name] != nil
          res
        else
          res[:uuid] = validate_token(res[:authentication_result][:access_token])
          res
        end
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        # rescues all service API errors
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def admin_create_user( options={} )
      initialize
      resp = client.admin_create_user({
        user_pool_id: pool_id, # required
        username: options[:username], # required
        # user_attributes: [
        #   # {
        #   #   #name: "email", # required
        #   #   #value: options[:username],
        #   #   email_verified: true
        #   # },
        #   {
        #     name: "phone_number",
        #     value: options[:phone_number],
        #     phone_number_verified: true
        #   }
        # ],
        temporary_password: options[:password],
        force_alias_creation: false,
      })
      resp.to_h
    end

    def client_signup(options={})
      begin
        initialize
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
                value: "AttributeValueType",
              },
            ]
          })
        res.to_h
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        # rescues all service API errors
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

    def client_forgot_password(username)
      begin
        initialize
        res = client.admin_get_user({
          user_pool_id: pool_id, # required
          username: username, # required
        })
        res
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_add_to_group(options={})
      begin
        initialize
        res = client.admin_add_user_to_group({
          user_pool_id: pool_id, # required
          username: options[:username], # required
          group_name: options[:group], # required
        })
        res.to_h
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_sign_out(token)
      begin
        initialize
        res = client.global_sign_out({
          access_token: token, # required
        })
        res
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        {}
        # raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_change_password(params,token)
      begin
        resp = client.change_password({
          previous_password: params["password"], # required
          proposed_password: params["new_password"], # required
          access_token: token, # required
        })
      rescue Aws::CognitoIdentityProvider::Errors::ServiceError => e
        raise ExceptionHandler::AuthenticationError, e.message
      end
    end

    def client_update_attribute(params,token)
      df = validate_token(token)
      begin
        res = client.admin_update_user_attributes({
          user_pool_id: pool_id, # required
          username: df[0]["username"], # required
          user_attributes: [ # required
            {
              name: "email", # required
              value: params["email_address"],
            },
            {
              name: "phone_number", # required
              value: params["mobile"],
            },
            {
              name: "email_verified", # required
              value: "true",
            },
            {
              name: "phone_number_verified", # required
              value: "true",
            }
          ],
        })
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

    # def validate_token(jwt)
    #   token = JWT.decode jwt, nil, false
    #   kid = token[1]["kid"]
    #   jwk1 = CognitoAuth.configuration.jwks["keys"].detect { |jwk| jwk["kid"] == kid }
    #   jwk = JSON::JWK.new jwk1
    #   js = JSON::JWT.decode jwt, jwk
    #   iss = "https://cognito-idp.#{ENV["AWS_REGION"]}.amazonaws.com/#{pool_id}"
    #   unless js[:token_use] == :access || js[:iss] == iss
    #     raise ExceptionHandler::AuthenticationError
    #   end
    #   token
    # rescue => e
    #     raise ExceptionHandler::AuthenticationError, e
    # end

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
