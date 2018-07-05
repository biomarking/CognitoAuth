class CognitoAuth::V2::UsersController < CognitoAuth::ApplicationController

  #instantiate AWS Cognito things
  before_action :initiate_auth

  #added except to skip when update method is being called
  before_action :initiate_encryptor , except:[:update]


  def create
    # check if user accept the terms of service
    if user_params[:terms].present? && user_params[:terms] == true
      
      country = Country.find user_params[:country_id]

      params[:user][:phone_number] = "#{country.dial_code}#{user_params[:mobile]}"
      

      res = client.client_signup user_params
      # create encrypted username then pass to url
      username_encode = encrypt(user_params[:username])
      options = { username:user_params[:username], data:username_encode }
      # send confirmation link to user
      
      # attached user to specific group or default to users
      grp = user_params[:group].present? ? user_params[:group].downcase : :user
      data = { username: res[:user_sub], group: grp }
      group = client.client_add_to_group(data)

      ###################################################
      ################### USER CREATE ################### 
      ###################################################
      _user = User.new
      _user.uuid              = res[:user_sub]
      _user.first_login       = true
      _user.qr_code           = res[:user_sub]
      _user.verification_code = 4.times.map{ SecureRandom.random_number(9)}.join
      _user.save
      ################### EMAIL #########################
      CognitoAuth::SendMail.account_confirmation( options , _user.verification_code ).deliver_later
      ###################################################

      render json: res
    else
      render json: { message: "Must accept the terms of service." }, status: 422
    end
  end

  

  private
  
  def user_params
    params.require(:user).permit(:username,:password,:group,:phone_number,:terms,:marketing,:country_id, :mobile)
  end
  
end
