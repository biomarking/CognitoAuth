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
    # res = auth_client.init.client_forgotpassword_patient params[:username]

    # p "===="
    # p res
    # p "----"
    # render json: res
    begin
      res = auth_client.init.client.forgot_password({
          client_id: auth_client.init.client_id,
          secret_hash: hmac( params[:username]),
          username: params[:username]
      })
      puts "==== normal request"
      render json: res.to_h
    rescue Aws::CognitoIdentityProvider::Errors::UserNotFoundException
      puts "==== forgot error"
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
          res_user = migrate_client.forgot_migrate({
              username: params[:username]})

          if res_user.present?
              res = auth_client.init.client.forgot_password({
                  client_id: auth_client.init.client_id,
                  secret_hash: hmac( params[:username]),
                  username: params[:username]
              })

              user_login = User.find_by_uuid res_user[:old_user]
              # create new user
              if !user_login.present?
                  user_login = add_record res_user[:active_user][:user][:username], "patient"
              elsif res_user.present?
                  # update uuid then clear cache
                  Rails.cache.delete("User/#{user_login.uuid}")
                  user_login.update(uuid: res_user[:active_user][:user][:username], infra_version: 2)
              end

              if user_login.qr_code.nil?
                  uid = user_login.id.to_s.rjust(5, '0')
                  random = ('0'..'z').to_a.shuffle.first(4).join.upcase
                  user_login.qr_code = "MD-#{random}#{uid}"
                  user_login.save
              end

              if user_login.app_version == 1
                  user_login.app_version = 2
                  user_login.app_migrated_at = Time.zone.now
                  user_login.save
                  AppMigrationWorker.perform_async("medication",user_login.id)
              end
              render json: res.to_h
          end
      else
          raise e
      end
    end
  end

  def forgot_doctor
    res = auth_client.init.client_forgotpassword_doctor params[:username]

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
      _user.user_type_id      = user_params[:group] == "patient" ? 1 : 2
      _user.qr_code           = res[:user_sub]
      _user.infra_version     = 2 if auth_client.init.pool_id != "ap-southeast-1_RnNZ6nMsv"
      _user.verification_code = 4.times.map{ SecureRandom.random_number(9)}.join
      _user.marketing         = user_params[:marketing] if user_params[:marketing].present?
      _user.save

      render json: res
    else
      raise ExceptionHandler::TermsError
    end
  end

  def signup
    # check if user accept the terms of service
    if user_params[:terms].present? && user_params[:terms] == true

      unless user_params[:group].present?
        raise ActionController::ParameterMissing
      end
      
      if user_params[:username].starts_with?("+63") && user_params[:username][3].starts_with?("0")
        raise ExceptionHandler::InvalidMobile
      end

      # execute signup
      res = auth_client.init.client_create user_params
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
      _user.user_type_id      = user_params[:group] == "patient" ? 1 : 2
      _user.verification_code = 4.times.map{ SecureRandom.random_number(9)}.join
      _user.marketing         = user_params[:marketing] if user_params[:marketing].present?
      _user.save

      render json: res
    else
      raise ExceptionHandler::TermsError
    end
  end


  private

  def hmac(username)
    data = "#{username}#{auth_client.init.client_id}"
    digest = OpenSSL::HMAC.digest('sha256', auth_client.init.client_secret, data)
    hmac = Base64.encode64(digest).strip()
    hmac
  end

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
