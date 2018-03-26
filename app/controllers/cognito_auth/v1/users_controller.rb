class CognitoAuth::V1::UsersController < CognitoAuth::ApplicationController
  
  #instantiate AWS Cognito things
  before_action :initiate_auth

  #added except to skip when update method is being called
  before_action :initiate_encryptor , except:[:update]

  #update user password when admin create a temp password 

  def update
    #response to the challenge
    resp = client.force_update_password session_params
    
    user_login = User.find_by_uuid resp[:uuid][0]["sub"]
      
    #create a new record
    if !user_login.present?
      add_record res[:uuid][0]["sub"]
    end

    render json: {
      access_token:resp.authentication_result.access_token,
      message:"Authenticated",
      first_login: !user_login.present?
    } 
    
  end

  def create
    # check if user accept the terms of service
    if user_params[:terms].present? && user_params[:terms] == true
      res = client.client_signup user_params
      # create encrypted username then pass to url
      username_encode = encrypt(user_params[:username])
      options = { username:user_params[:username], data:username_encode }
      # send confirmation link to user
      CognitoAuth::SendMail.account_confirmation(options).deliver
      # attached user to specific group or default to users
      data = { username: res[:user_sub], group: user_params[:group] || "Users" }
      group = client.client_add_to_group(data)
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

  private

  def user_params
    params.require(:user).permit(:username,:password,:group,:phone_number,:terms,:marketing)
  end
  def session_params
    params.require(:user).permit(:username,:password, :new_password)
  end
end
