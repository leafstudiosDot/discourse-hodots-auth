# frozen_string_literal: true

# name: discourse-hodots-auth
# about: Login with your hodots. Account on your Discourse instance
# version: 0.1
# authors: aliamanuba
# url: https://github.com/leafstudiosDot/discourse-hodots-auth

enabled_site_setting :hodots_authentication_enabled

PLUGIN_NAME = "discourse-hodots-auth"

class Auth::HodotsAuthenticator < Auth::ManagedAuthenticator
    class HodotsStrategy < OmniAuth::Strategies::OAuth2
      option :name, "hodots"
      option :scope, "profile.read"
  
      option :client_options,
             site: "https://api.hodots.com",
             authorize_url: "apps/oauth2/authorize",
             token_url: "apps/token"
  
      option :authorize_options, %i[scope permissions]
  
      uid { raw_info["id"] }
  
      info do
        {
          name: raw_info["username"],
          email: raw_info["email"],
          image: "https://api.hodots.com/media/profilepic?user=#{raw_info["id"]}",
        }
      end
  
      extra { { "raw_info" => raw_info } }
  
      def raw_info
        @raw_info ||=
          access_token
            .get("accounts/profile/me")
            .parsed
      end
  
      def callback_url
        full_host + script_name + callback_path
      end
    end
  
    def name
      "hodots"
    end
  
    def enabled?
      SiteSetting.enable_hodots_logins?
    end
  
    def register_middleware(omniauth)
      omniauth.provider HodotsStrategy,
                        setup:
                          lambda { |env|
                            strategy = env["omniauth.strategy"]
                            strategy.options[:client_id] = SiteSetting.hodots_client_id
                            strategy.options[:client_secret] = SiteSetting.hodots_secret
                          }
    end
  
    def after_authenticate(auth_token, existing_account: nil)
        
      super
    end
  
    def primary_email_verified?(auth_token)
      true
    end
  end