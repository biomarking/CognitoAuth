# CognitoAuth::Engine

The blurb from Amazon's website on [Amazon Cognito](https://aws.amazon.com/cognito/):

> Amazon Cognito lets you easily add user sign-up and sign-in to your mobile
> and web apps. With Amazon Cognito, you can also authenticate users through
> social identity providers such as Facebook, Twitter, or Amazon, or by using
> your own identity solution. In addition, Amazon Cognito enables you to save
> data locally on users devices, allowing your applications to work even when
> the devices are offline. You can then synchronize data across users devices
> so that their app experience remains consistent regardless of the device they
> use.

> With Amazon Cognito, you can focus on creating great app experiences instead
> of worrying about building, securing, and scaling a solution to handle user
> management, authentication, and sync across devices.


## Usage
How to use this plugin.

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

## License
The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
