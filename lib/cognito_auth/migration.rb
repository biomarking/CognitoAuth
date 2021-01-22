module CognitoAuth
    class Migration < ::Rails::Engine
        isolate_namespace CognitoAuth

        attr_accessor :active_client, :active_client_id, :active_client_secret, :active_pool_id,
                    :old_client, :old_client_id, :old_client_secret, :old_pool_id

        def init(access_id, secret_id, client_id, client_secret, pool_id)
            # initialize new account
            @active_client = Aws::CognitoIdentityProvider::Client.new
            @active_client_id = CognitoAuth.configuration.client_id
            @active_client_secret = CognitoAuth.configuration.client_secret
            @active_pool_id = CognitoAuth.configuration.pool_id

            # initialize old account
            @old_client = Aws::CognitoIdentityProvider::Client.new(
                access_key_id: access_id,
                secret_access_key: secret_id
            )
            @old_client_id = client_id
            @old_client_secret = client_secret
            @old_pool_id = pool_id
            self
        end

        def forgot_migrate(options = {})
            # get user attributes
            old_user = old_client.admin_get_user({
                user_pool_id: old_pool_id,
                username: options[:username],
            })

            # create user
            active_user = active_client.admin_create_user({
                user_pool_id: active_pool_id,
                username: options[:username],
                user_attributes: old_user.user_attributes.delete_if { |h| h["name"] == "sub" },
                force_alias_creation: false,
                message_action: "SUPPRESS",
                desired_delivery_mediums: nil,
            })

            # set password
            active_client.admin_set_user_password({
                user_pool_id: active_pool_id,
                username: options[:username],
                password: "123412341234",
                permanent: true,
            })

            # list user group
            list = old_client.admin_list_groups_for_user({
                username: options[:username],
                user_pool_id: old_pool_id
            })
            
            # add user to group
            list.groups.each do |grp|
                active_client.admin_add_user_to_group({
                    user_pool_id: active_pool_id,
                    username: options[:username],
                    group_name: grp.group_name
                })
            end
            return {
                old_user: old_user.username,
                active_user: active_user.to_h
            }
        end

        def migrate(options = {})
            old_client.admin_initiate_auth({
                client_id: old_client_id,
                user_pool_id: old_pool_id,
                auth_flow: "ADMIN_USER_PASSWORD_AUTH",
                auth_parameters: {
                    SECRET_HASH: hmac(options[:username], old_client_id, old_client_secret),
                    USERNAME: options[:username],
                    PASSWORD: options[:password]
                }
            })
            # get user attributes
            old_user = old_client.admin_get_user({
                user_pool_id: old_pool_id,
                username: options[:username],
            })

            # create user
            active_client.admin_create_user({
                user_pool_id: active_pool_id,
                username: options[:username],
                user_attributes: old_user.user_attributes.delete_if { |h| h["name"] == "sub" },
                force_alias_creation: false,
                message_action: "SUPPRESS",
                desired_delivery_mediums: nil,
            })

            # set password
            active_client.admin_set_user_password({
                user_pool_id: active_pool_id,
                username: options[:username],
                password: options[:password],
                permanent: true,
            })

            # list user group
            list = old_client.admin_list_groups_for_user({
                username: options[:username],
                user_pool_id: old_pool_id
            })
            # add user to group
            list.groups.each do |grp|
                active_client.admin_add_user_to_group({
                    user_pool_id: active_pool_id,
                    username: options[:username],
                    group_name: grp.group_name
                })
            end
            return old_user.username
        end

        private

        def hmac(username, client_id, client_secret)
            data = "#{username}#{client_id}"
            digest = OpenSSL::HMAC.digest('sha256', client_secret, data)
            hmac = Base64.encode64(digest).strip()
            hmac
        end
    end
end