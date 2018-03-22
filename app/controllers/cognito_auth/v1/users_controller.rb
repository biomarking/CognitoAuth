class CognitoAuth::V1::UsersController < CognitoAuth::ApplicationController
  before_action :initiate_auth
  before_action :initiate_encryptor

  def create
    # check if user accept the terms of service
    if user_params[:terms].present? && user_params[:terms] == true
      res = client.client_signup user_params
      username_encode = encrypt(user_params[:username])
      options = {username:user_params[:username],data:username_encode}
      SendMail.account_confirmation(options).deliver
      render json: res
    else
      render json: { message: "Must accept the terms of service." }, status: 422
    end
  end

  def activate
    res = client.client_confirm decrypt(user_params[:username])
    render json: { message: "Activated" }
  end

  private

  def user_params
    params.require(:user).permit(:username,:password,:phone_number,:terms,:marketing)
  end
end
