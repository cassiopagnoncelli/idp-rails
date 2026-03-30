# frozen_string_literal: true

module MyAccount
  module JWT
    module Rails
      class Railtie < ::Rails::Railtie
        initializer "myaccount_jwt.configure" do
          # Auto-configure from Rails credentials or environment variables.
          MyAccount::JWT.configure do |config|
            config.jwks_url ||= ENV["MYACCOUNT_JWKS_URL"]
            config.issuer   ||= ENV.fetch("MYACCOUNT_JWT_ISSUER", "https://account.yourcompany.com")
            config.logger     = ::Rails.logger
          end
        end

        initializer "myaccount_jwt.revocation_subscriber" do
          # Start the revocation subscriber if Redis is configured.
          if MyAccount::JWT.configuration.redis
            MyAccount::JWT.configuration.validate!

            subscriber = RevocationSubscriber.new
            subscriber.start

            # Store reference for clean shutdown.
            ::Rails.application.config.myaccount_jwt_revocation_subscriber = subscriber

            at_exit { subscriber.stop }
          end
        end
      end
    end
  end
end
