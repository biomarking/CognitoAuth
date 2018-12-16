class CognitoAuth::V2::SessionsController < CognitoAuth::ApplicationController

  # before_action :initiate_auth
  #
  # def create
  #   #group is now require for authentication to avoid mixing authorities
  #   auth_group = request.headers['x-biomark-group']
  #
  #   is_allowed = false
  #
  #   authentication = client.client_auth session_params
  #
  #   jwks = client.verify_claims authentication[:authentication_result][:access_token]
  #
  #   jwks[0]["cognito:groups"].each do |group|
  #     if group == auth_group
  #       is_allowed = true
  #     end
  #   end
  #
  #   if !is_allowed
  #     render json: {message: "Invalid account group"},status:403
  #     return false
  #   end
  #
  #   user_login = User.find_by_uuid jwks[0]["username"]
  #
  #   if !user_login.present?
  #     user_login = add_record jwks[0]["username"]
  #   end
  #   authentication[:authentication_result][:has_profile] = user_login.profile.present?
  #   render json: authentication[:authentication_result]
  # end

  def create
    #group is now require for authentication to avoid mixing authorities
    auth_group = request.headers['x-biomark-group']
    # initialize permission
    is_allowed = false
    # authenticate user
    res = auth_client.init.login(session_params)

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

      user_login = User.find_by_uuid jwks[0]["username"]
      # create new user
      if !user_login.present?
        user_login = add_record jwks[0]["username"]
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
    res = auth_client.init.mfa_challenge mfa_params
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
