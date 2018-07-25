class CognitoAuth::V2::UsersController < CognitoAuth::ApplicationController

  #instantiate AWS Cognito things
  # before_action :initiate_auth

  #added except to skip when update method is being called
  before_action :initiate_encryptor , except:[:update]

  def resend_code
    res = auth_client.init.resend_code params[:username]
    render json: {message: "Confirmation Code Sent!"}
  end

  def refresh_token
    res = auth_client.validate_token request.headers['x-biomark-token']
    token = auth_client.init.refresh_token params[:refresh_token],res[0]["username"]
    render json: {
      access_token: token[:authentication_result][:access_token],
      expires_in: token[:authentication_result][:expires_in]
    }

  end

  def reset_password
    res = auth_client.init.reset_password( reset_password_params )
    render json: {message: "Password has been changed"}
  end

  def confirm
    #group is now require for authentication to avoid mixing authorities
    auth_group = request.headers['x-biomark-group']
    # initialize permission
    is_allowed = false
      #confirm user
      cn = auth_client.init.confirm_user_signup(confirm_params)

      #auth user for continues operations
      res = client.init.login confirm_params
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
        # render json: {message: "Invalid account group"},status:403
        return false
      end

      user_login = User.find_by_uuid jwks[0]["username"]
      # create new user
      if !user_login.present?
        user_login = add_record jwks[0]["username"]
      end
      # check if profile is present
      profile = user_login.present? ? user_login.profile.present? : false

      #render output
      render json: {
        access_token:res[:authentication_result][:access_token],
        refresh_token:res[:authentication_result][:refresh_token],
        expires_in: res[:authentication_result][:expires_in],
        message:"Authenticated",
        first_login: !user_login.present?,
        has_profile: profile,
        confirmed: true
      }
  end

  def forgot
    res = auth_client.init.client_forgotpassword params[:username]

    p "===="
    p res
    p "----"
    render json: res
  end


  def create
    # check if user accept the terms of service
    if user_params[:terms].present? && user_params[:terms] == true
      unless user_params[:country_id]
        raise ActionController::ParameterMissing
      end

      begin
        country = Country.find user_params[:country_id]
      rescue ActiveRecord::RecordNotFound => e
        raise ExceptionHandler::CountryNotFound
      end

      unless user_params[:group].present?
        raise ActionController::ParameterMissing
      end

      if user_params[:mobile].present?
          params[:user][:phone_number] = "#{country.dial_code}#{user_params[:mobile]}"
      end

      # execute signup
      res = auth_client.init.client_signup user_params
      # attached user to specific group or default to users
      grp = user_params[:group].present? ? user_params[:group].downcase : :user
      data = { username: res[:user_sub], group: grp }
      group = auth_client.init.client_add_to_group(data)

      ###################################################
      ################### USER CREATE ###################
      ###################################################
      _user = User.new
      _user.uuid              = res[:user_sub]
      _user.first_login       = true
      _user.qr_code           = res[:user_sub]
      _user.verification_code = 4.times.map{ SecureRandom.random_number(9)}.join
      _user.marketing         = user_params[:marketing] if user_params[:marketing].present?
      _user.save

      render json: res
    else
      raise ExceptionHandler::TermsError
    end
  end


  private

  def reset_password_params
    params.require(:user).permit(:username, :password, :code)
  end

  def confirm_params
    params.require(:user).permit(:username, :password, :code)
  end

  def user_params
    params.require(:user).permit(:username,:password,:group,:phone_number,:terms,:marketing,:country_id, :mobile)
  end

end
