class CognitoAuth::V2::SessionsController < CognitoAuth::ApplicationController
  
  before_action :initiate_auth

  def create
    #group is now require for authentication to avoid mixing authorities
    auth_group = request.headers['x-biomark-group']
    
    is_allowed = false
    
    authentication = client.client_auth session_params
    
    jwks = client.verify_claims authentication[:authentication_result][:access_token]
    
    jwks[0]["cognito:groups"].each do |group|
      if group == auth_group
        is_allowed = true
      end
    end

    if !is_allowed
      render json: {message: "Invalid account group"},status:403
      return false
    end
    
    user_login = User.find_by_uuid jwks[0]["username"]

    if !user_login.present?
      user_login = add_record jwks[0]["username"]
    end
    authentication[:authentication_result][:has_profile] = user_login.profile.present?
    render json: authentication[:authentication_result]
  end

  private

  def session_params
    params.require(:session).permit(:username,:password,:group)
  end
end
