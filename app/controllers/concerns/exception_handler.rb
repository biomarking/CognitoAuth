module ExceptionHandler
  extend ActiveSupport::Concern

   # Define custom error subclasses - rescue catches `StandardErrors`
  class AuthenticationError < StandardError; end
  class AcessDenied < StandardError; end
  class MissingToken < StandardError; end
  class InvalidToken < StandardError; end
  class ExpiredSignature < StandardError; end
  class DecodeError < StandardError; end
  class TermsError < StandardError; end
  class CountryNotFound < StandardError; end

  included do
    # Define custom handlers
    rescue_from ActiveRecord::RecordInvalid, with: :four_twenty_two
    rescue_from ExceptionHandler::AuthenticationError, with: :unauthorized_request
    rescue_from ExceptionHandler::MissingToken, with: :four_twenty_two
    rescue_from ExceptionHandler::InvalidToken, with: :four_twenty_two
    rescue_from ExceptionHandler::ExpiredSignature, with: :four_ninety_eight
    rescue_from ExceptionHandler::DecodeError, with: :four_zero_one
    rescue_from ExceptionHandler::TermsError, with: :terms_error
    rescue_from ExceptionHandler::CountryNotFound, with: :country_error
    rescue_from ArgumentError, with: :argument_error
    rescue_from ExceptionHandler::AcessDenied, with: :unauthorized_access
    rescue_from Aws::CognitoIdentityProvider::Errors::UserNotFoundException, with: :unauthorized_access
    rescue_from Aws::CognitoIdentityProvider::Errors::NotAuthorizedException, with: :unauthorized_access
    rescue_from Aws::CognitoIdentityProvider::Errors::UserNotConfirmedException, with: :unconfirm_access
    rescue_from Aws::CognitoIdentityProvider::Errors::UsernameExistsException, with: :account_exist
    rescue_from Aws::CognitoIdentityProvider::Errors::CodeMismatchException, with: :code_mismatch
    rescue_from Aws::CognitoIdentityProvider::Errors::InvalidPasswordException, with: :invalid_password
    rescue_from Aws::CognitoIdentityProvider::Errors::ExpiredCodeException, with: :expired_code
    rescue_from ActionController::ParameterMissing, with: :argument_error
    rescue_from JSON::JWK::UnknownAlgorithm, with: :jwk_error
    rescue_from JWT::DecodeError, with: :invalid_token

    rescue_from ActiveRecord::RecordNotFound do |e|
     render json: { message: e.message }, status: :not_found
    end

    rescue_from ActiveRecord::RecordInvalid do |e|
      render json: { message: e.message }, status: :unprocessable_entity
    end

    rescue_from Aws::CognitoIdentityProvider::Errors::InvalidParameterException do |e|
      render json: {
        status:"error",
        code: 4007,
        message: e.message
      }, status: 422
    end
  end

  private

  # JSON response with message for missing parameters and argument error
  def argument_error
    render json: {
      status: "error",
      code: 4000,
      message: "Invalid parameters"
    },
    status: :unprocessable_entity
  end

  # JSON response with message for invalid account and password attempts
  def unauthorized_access(e)
    attempt = e.message != "Password attempts exceeded"
    render json: {
      status: "error",
      code: attempt ? 4001 : 4003,
      message: attempt ? "The email address or the password you inputted is incorrect. " : "Password attempts exceeded"
    },
    status: :unauthorized
  end

  # JSON response with message for unconfirmed account
  def unconfirm_access
    render json: {
      status: "error",
      code: 4002,
      message: "Account is not confirmed"
    },
    status: :unauthorized
  end

  # JSON response with message for jwk error
  def jwk_error
    render json: {
      status: "error",
      code: 4004,
      message: "Invalid request"
    },
    status: :unauthorized
  end

  # JSON response with message for terms error
  def terms_error
    render json: {
      status: "error",
      code: 4005,
      message: "You must accept our terms of service"
    },
    status: :unprocessable_entity
  end

  # JSON response with message for country error
  def country_error
    render json: {
      status: "error",
      code: 4006,
      message: "Country not found"
    },
    status: :unprocessable_entity
  end

  # # JSON response with message for invalid_parameter error
  # def invalid_parameter
  #   render json: {
  #     status: "error",
  #     code: 4007,
  #     message: "Invalid parameter or format"
  #   },
  #   status: :unprocessable_entity
  # end

  # JSON response with message for account exist error
  def account_exist
    render json: {
      status: "error",
      code: 4008,
      message: "An account with the given email already exists"
    },
    status: :unprocessable_entity
  end

  # JSON response with message for code_mismatch error
  def code_mismatch
    render json: {
      status: "error",
      code: 4009,
      message: "Invalid verification code provided"
    },
    status: :unprocessable_entity
  end

  # JSON response with message for invalid_password error
  def invalid_password
    render json: {
      status: "error",
      code: 4010,
      message: "Password must be 8 characters long"
    },
    status: :unprocessable_entity
  end

  # JSON response with message for expired_code error
  def expired_code
    render json: {
      status: "error",
      code: 4011,
      message: "Invalid code provided, please request a code again"
    },
    status: :unprocessable_entity
  end

  # JSON response with message for invalid token error
  def invalid_token
    render json: {
      status: "error",
      code: 4012,
      message: "Invalid token"
    },
    status: :unprocessable_entity
  end

  # JSON response with message; Status code 422 - unprocessable entity
  def four_twenty_two(e)
   render json: { message: e.message }, status: :unprocessable_entity
  end

# JSON response with message; Status code 401 - Unauthorized
  def four_ninety_eight(e)
    render json: { message: e.message }, status: :invalid_token
  end

  # JSON response with message; Status code 401 - Unauthorized
  def four_zero_one(e)
    render json: { message: e.message }, status: :invalid_token
  end

   # JSON response with message; Status code 401 - Unauthorized
  def unauthorized_request(e)
    render json: { message: e.message }, status: :unauthorized
  end
end
