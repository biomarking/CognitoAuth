module CognitoAuth
  class SendMail < ::ApplicationMailer

    def account_confirmation(params)
      @params = params
      mail(to:@params[:username], subject: "Account confirmation")
    end
  end
end
