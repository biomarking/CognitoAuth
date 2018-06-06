module CognitoAuth
  class SendMail < ::ApplicationMailer

    def account_confirmation(params, code )
      @params = params
      @code = code
      mail(to:@params[:username], subject: "Account confirmation")
    end

    def account_forgot(params)
      @params = params
      mail(to:@params[:username], subject: "Reset password")
    end
  end
end
