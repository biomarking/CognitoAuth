class CognitoAuth::V1::SessionsController < CognitoAuth::ApplicationController
  before_action :initiate_auth

  def create
    res = client.client_signin session_params
    # if res[:authentication_result]
    #   # create a record for new login user
    # end
    render json: {
      access_token:res.authentication_result.access_token,
      message:"Authenticated"
    }
  end

  private

  def session_params
    params.require(:session).permit(:username,:password)
  end
end
