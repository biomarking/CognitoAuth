class CognitoAuth::V1::UsersController < CognitoAuth::ApplicationController
  before_action :initiate_auth

  def create
    res = client.client_signup user_params
    render json: res
  end

  def activate

  end

  private

  def user_params
    params.require(:user).permit(:username,:password)
  end
end
