
module CognitoAuth
  class ApplicationController < ActionController::API
    include ExceptionHandler
    # protect_from_forgery with: :exception
    attr_reader :client, :encryptor


    def initiate_auth
      @client = CognitoAuth::Engine
    end

    def encrypt(data)
      # Base64.encode64(encryptor.encrypt( data ))
      Base64.encode64(data)
    end

    def add_record uuid
      _user = User.new
      _user.uuid = uuid
      _user.save
    end

    def decrypt(data)
      decode = Base64.decode64(data)
      # encryptor.decrypt( decode )
    end

    def initiate_encryptor
      @encryptor = Encryption::Symmetric.new
      @encryptor.key = "\xD1\xEA\xB7\xC3\a\xB2\xE2\x11L\xD7n\xB35]\x00\xAB\x0FVhu\x06\xD2oY'a\xB8\x19\xFC\x85\xDF;" #ENV["APP_API_KEY"]
      @encryptor.iv = "\xD1\xEA\xB7\xC3\a\xB2\xE2\x11L\xD7n\xB35]\x00\xAB" #ENV["APP_API_KEY"]
    end
  end
end
