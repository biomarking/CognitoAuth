$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "cognito_auth/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "cognito_auth"
  s.version     = CognitoAuth::VERSION
  s.authors     = ["Biomark"]
  s.email       = [""]
  s.homepage    = "https://gitlab.com/biomark/CognitoAuth"
  s.summary     = "Cognito Authentication"
  s.description = "Cognito integration using ruby"
  s.license     = "MIT"

  s.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]

  s.add_dependency "aws-sdk-cognitoidentityprovider", "~> 1.3.0"
  s.add_dependency "encryption"
  s.add_dependency "json-jwt"
  s.add_dependency "jwt"

end
