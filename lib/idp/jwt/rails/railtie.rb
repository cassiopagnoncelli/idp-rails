# frozen_string_literal: true

module Idp
  module JWT
    module Rails
      class Railtie < ::Rails::Railtie
        initializer "idp_jwt.configure" do
          # Auto-configure from Rails credentials or environment variables.
          Idp::JWT.configure do |config|
            config.jwks_url ||= ENV.fetch("IDP_JWKS_URL", nil)
            config.issuer   ||= ENV.fetch("IDP_JWT_ISSUER", "https://account.yourcompany.com")
            config.logger     = ::Rails.logger
          end
        end

        initializer "idp_jwt.revocation_subscriber" do
          # Start the revocation subscriber if Redis is configured.
          if Idp::JWT.configuration.redis
            Idp::JWT.configuration.validate!

            subscriber = RevocationSubscriber.new
            subscriber.start

            # Store reference for clean shutdown.
            ::Rails.application.config.idp_jwt_revocation_subscriber = subscriber

            at_exit { subscriber.stop }
          end
        end
      end
    end
  end
end
