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

  def destroy
    # get the access_token from authorization header
    res = client.client_sign_out(request.headers['Authorization'])
    render json: {
      message: "You are now signed out"
    }
  end

  private

  def session_params
    params.require(:session).permit(:username,:password,:access_token)
  end
end
