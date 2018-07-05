class CognitoAuth::V1::UsersController < CognitoAuth::ApplicationController

  #instantiate AWS Cognito things
  before_action :initiate_auth

  #added except to skip when update method is being called
  before_action :initiate_encryptor , except:[:update]

  #update user password when admin create a temp password
  def resend_code
      
      info = client.client_get_user_info params[:email]

      user = User.find_by_uuid info[:username]
      
      #generate a new verificationm code again
      user.verification_code =  4.times.map{ SecureRandom.random_number(9)}.join
      
      if user.save
        CognitoAuth::SendMail.resend_confirmation( params[:email] , user.verification_code ).deliver_later
        render json: {sent:true}
      end

  end

  def confirm
    
    info = client.client_get_user_info confirm_params[:username] 
    
    user = User.find_by_uuid info[:username]
  
    if user.verification_code == confirm_params[:code]
      
      client.client_confirm confirm_params[:username]
      
      res = client.client_signin confirm_params
      
      render json: {
        access_token:res[:authentication_result][:access_token],
        message:"Authenticated",
        first_login: user.first_login,
        has_profile: user.present?,
        confirmed:true
      }
    else
      render json: {confirmed:false,message:"Invalid Code"}
    end
   
  end
  def change_password_doctor
    begin
      resp = client.gracefull_password_update({token:request.headers['x-biomark-token'],params:session_params})
      render json: {status: true, message:"Update successful"}
    rescue Exception => e
      render json: {status:false,message:e}
    end

  end

  def update
    #response to the challenge
    resp = client.force_update_password session_params

    user_login = User.find_by_uuid resp[:uuid]

    #create a new record
    if !user_login.present?
      add_record resp[:uuid]
    end

    render json: {
      access_token:resp[:token],
      message:"Authenticated",
      first_login: !user_login.present?
    }

  end

  def create
    # check if user accept the terms of service
    if user_params[:terms].present? && user_params[:terms] == true
      
      country = Country.find user_params[:country_id]

      if user_params[:group] == "doctor" 
        params[:user][:phone_number] = "#{country.dial_code}#{user_params[:mobile]}"
      end

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

  def activate
    res = client.client_confirm decrypt(user_params[:username])
    render json: { message: "Activated" }
  end

  def forgot
    res = client.client_forgot_password user_params[:username]
    options = { username: user_params[:username], data: res.username}
    CognitoAuth::SendMail.account_forgot(options).deliver
    render json: { message: "Thank you. Please check your email." }
  end

  def change_password
    res = client.client_change_password session_params,request.headers['x-biomark-token']
    render json: { message: "Update successful"}
  end

  def update_attribute
    res = client.client_update_attribute(params,request.headers['x-biomark-token'])
    render json: { message: "Update successful" }
  end

  private
  
  def user_params
    params.require(:user).permit(:username,:password,:group,:phone_number,:terms,:marketing,:country_id, :mobile)
  end
  def session_params
    params.require(:user).permit(:username,:password, :new_password)
  end

  def confirm_params
    params.require(:user).permit(:username, :password, :code)
  end
end
