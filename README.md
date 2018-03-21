# CognitoAuth
Short description and motivation.

## Usage
How to use my plugin.

## Installation
Add this line to your application's Gemfile:

```ruby
gem 'cognito_auth'
```

And then execute:
```bash
$ bundle
```

Or install it yourself as:
```bash
$ gem install cognito_auth
```

## Configuration

```ruby
# config/initializers/cognito_auth.rb

CognitoAuth.configure do |config|
  config.client_id = 'your_client_id'
  config.client_secret = 'your_client_secret_key'
  config.pool_id = 'your_pool_id'
end
```

## Notes
You will need to configure credentials and a region, either in configuration files or environment variables, to make API calls. It is recommended that you provide these via your environment. This makes it easier to rotate credentials and it keeps your secrets out of source control.

The SDK searches the following locations for credentials:

* `ENV['AWS_ACCESS_KEY_ID']`
* `ENV['AWS_SECRET_ACCESS_KEY']`
* `ENV['AWS_REGION']`

## Contributing
Contribution directions go here.

## License
The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
