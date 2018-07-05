class CognitoAuth::V2::SessionsController < CognitoAuth::ApplicationController
  
  before_action :initiate_auth

  def create
    #group is now require for authentication to avoid mixing authorities
    auth_group = request.headers['x-biomark-group']
    
    is_allowed = false

    user_info = client.client_get_user_info session_params[:username]
    
    user_group = client.get_group_for_user user_info[:username]
    
    p "========================================" 
    p "========================================"
    user_group.each do |u_group|
      if u_group[:group_name] == auth_group
        is_allowed = true
      end
    end

    if !is_allowed
      render json: {message: "Invalid account group"},status:403
      return false
    end
    p "========================================" 

    render json: user_info
  end

  private

  def session_params
    params.require(:session).permit(:username,:password,:group)
  end
end
