class CognitoAuth::V2::SessionsController < CognitoAuth::ApplicationController
  
  def create
    #group is now require for authentication to avoid mixing authorities
    auth_group = request.headers['x-biomark-group']
    # initialize permission
    is_allowed = false
    # authenticate user
    begin
      res = auth_client.init.login(session_params)
    rescue Aws::CognitoIdentityProvider::Errors::UserNotFoundException => e
      # check old pool if exists
      if auth_client.init.pool_id != "ap-southeast-1_RnNZ6nMsv"
        # authenticate to our old cognito pool
        migrate_client = CognitoAuth::Migration.init(
          ENV['OLD_AWS_ACCESS_KEY_ID'],
          ENV['OLD_AWS_SECRET_ACCESS_KEY'],
          ENV['OLD_POOL_CLIENT_ID'],
          ENV['OLD_COGNITO_SECRET'],
          ENV['OLD_COGNITO_POOL_ID']
        )
        old_username = migrate_client.migrate({
            username: session_params[:username],
            password: session_params[:password]
        })

        res = auth_client.init.login(session_params)
      else
        raise e
      end
    end

    if res[:challenge_name] && res[:challenge_name] == "NEW_PASSWORD_REQUIRED"
      render json: {
        access_token:nil,
        message:res[:challenge_name]
      }
      return false
    end

    # for MFA check
    if res[:challenge_name] && res[:challenge_name] == "SOFTWARE_TOKEN_MFA"
      render json: {
        access_token:nil,
        message:res[:challenge_name]
      }
      return false
    end

      # validate json web token issuer
      jwks = auth_client.validate_token res[:authentication_result][:access_token]
      # check group if allowed
      jwks[0]["cognito:groups"].each do |group|
        if group == auth_group
          is_allowed = true
        end
      end

      if !is_allowed
        raise ExceptionHandler::InvalidGroup
        return false
      end
      puts "===== OLD USER ===="
      puts old_username
      login_user = jwks[0]["username"]
      login_user = old_username if old_username.present?

      user_login = User.find_by_uuid login_user

      # create new user
      if !user_login.present?
        user_login = add_record jwks[0]["username"]
      elsif old_username.present?
        # update uuid then clear cache
        Rails.cache.delete("User/#{user_login.uuid}")
        user_login.update(uuid: jwks[0]["username"], infra_version: 2)
      end

      if user_login.qr_code.nil?
        uid = user_login.id.to_s.rjust(5, '0')
        random = ('0'..'z').to_a.shuffle.first(4).join.upcase
        user_login.qr_code = "MD-#{random}#{uid}"
        user_login.save
      end

      # check if profile is present
      profile = user_login.present? ? user_login.profile.present? : false

      render json: {
        access_token:res[:authentication_result][:access_token],
        refresh_token:res[:authentication_result][:refresh_token],
        expires_in: res[:authentication_result][:expires_in],
        message:"Authenticated",
        first_login: !user_login.present?,
        has_profile: profile
      }
  end

  def update_password
    res = auth_client.init.client_update_password update_password_params
    p res.inspect
    render json: {
      access_token:res[:authentication_result][:access_token],
      refresh_token:res[:authentication_result][:refresh_token],
      expires_in: res[:authentication_result][:expires_in]
    }
  end

  def associate_token
    auth_group = request.headers['x-biomark-group']
    is_allowed = false

    resp = auth_client.init.associate_software_token associate_params

    res = auth_client.init.login(session_params)
    jwks = auth_client.validate_token res[:authentication_result][:access_token]
    p jwks
    # check group if allowed
    jwks[0]["cognito:groups"].each do |group|
      if group == auth_group
        is_allowed = true
      end
    end

    if !is_allowed
      raise ExceptionHandler::InvalidGroup
      return false
    end

    user_login = User.find_by_uuid jwks[0]["username"]
    # create new user
    if !user_login.present?
      user_login = add_record jwks[0]["username"]
    end
    
    render json: resp
  end

  def verify_token
    res = auth_client.init.verify_software_token associate_params
    mfa = auth_client.init.set_user_mfa_preference associate_params
    render json: res
  end

  def mfa_challenge
    auth_group = request.headers['x-biomark-group']
    is_allowed = false

    res = auth_client.init.mfa_challenge mfa_params
    #check if user exists
    jwks = auth_client.validate_token res[:authentication_result][:access_token]
    # check group if allowed
    jwks[0]["cognito:groups"].each do |group|
      if group == auth_group
        is_allowed = true
      end
    end

    if !is_allowed
      raise ExceptionHandler::InvalidGroup
      return false
    end

    user_login = User.find_by_uuid jwks[0]["username"]
    # create new user if user does not exist
    if !user_login.present?
      user_login = add_record jwks[0]["username"]
    end
    render json: res
  end

  private

  def update_password_params
    params.require(:session).permit(:username, :password, :new_password)
  end

  def session_params
    params.require(:session).permit(:username,:password,:group)
  end

  def associate_params
    params.require(:session).permit(:access_token,:secret_code,:username, :password)
  end

  def mfa_params
    params.require(:session).permit(:username,:password,:secret_code)
  end
end
