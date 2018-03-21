class CognitoAuth::V1::SessionsController < CognitoAuth::ApplicationController
  before_action :initiate_auth

  def create
    res = client.client_signin session_params
    render json: res
  end

  private

  def session_params
    params.require(:session).permit(:username,:password)
  end
end
