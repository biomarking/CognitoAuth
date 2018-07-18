class CognitoAuth::V1::SessionsController < CognitoAuth::ApplicationController
  before_action :initiate_auth

  def refresh_token
    res = client.validate_user request.headers['x-biomark-token']

    token = client.refresh_token params[:refresh_token],res[0]["username"]

    render json: {
      access_token: token[:authentication_result][:access_token],
      expires_in: token[:authentication_result][:expires_in]
    }
  end


  def verify
    client.validate_user( request.headers['x-biomark-token'] )

    render json: {
      message:"Verified"
    }

  end

  def create

    res = client.client_signin session_params

    if res[:challenge_name]

      case res[:challenge_name]
        #NEW_PASSWORD_REQUIRED
        when "NEW_PASSWORD_REQUIRED"
          render json: {
            access_token:nil,
            message:res[:challenge_name]
          }
      end

    else

      user_login = User.find_by_uuid res[:uuid][0]["sub"]

      #create a new record
      if !user_login.present?
        user_login = add_record res[:uuid][0]["sub"]
      end

      group = client.get_group_for_user res[:uuid][0]["sub"]

      grp_token = UserGroup.find_by_name group[0].group_name


      if grp_token.name == "patient"
        #check if invited
        p "------ check invitations"
        inv = Invitation.where("username = ? && status = ?",session_params[:username],false).last

        p "------ is invi #{inv.present?}"
        if inv.present?
          p "true"
          inv.status = true
          inv.save
          Link.create({doctor_id: inv.user_id, patient_id: user_login.id})
        end
      end

      profile = user_login.present? ? user_login.profile.present? : false
      #render
      render json: {
        access_token:res[:authentication_result][:access_token],
        refresh_token:res[:authentication_result][:refresh_token],
        expires_in: res[:authentication_result][:expires_in],
        message:"Authenticated",
        first_login: !user_login.present?,
        has_profile: profile,
        session: grp_token.token,
        group: grp_token.name
      }
    end

  end

  def destroy
    # get the access_token from authorization header
    res = client.client_sign_out(request.headers['x-biomark-token'])
    render json: {
      message: "You are now signed out"
    }
  end

  private

  def session_params
    params.require(:session).permit(:username,:password,:access_token)
  end
end
