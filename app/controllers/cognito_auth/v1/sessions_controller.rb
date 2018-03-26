class CognitoAuth::V1::SessionsController < CognitoAuth::ApplicationController
  before_action :initiate_auth
  
  def create
    res = client.client_signin session_params
   
    if res.challenge_name && res.challenge_name == "NEW_PASSWORD_REQUIRED"
      render json: {
        access_token:nil,
        message:res.challenge_name
      }
    else
      render json: {
        access_token:res.authentication_result.access_token,
        message:"Authenticated"
      }
    end
    
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
