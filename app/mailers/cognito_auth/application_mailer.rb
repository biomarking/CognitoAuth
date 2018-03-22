module CognitoAuth
  class ApplicationMailer < ActionMailer::Base
    default from: CognitoAuth.configuration.sender #ENV["SMTP_SENDER"]
    layout 'mailer'
  end
end
