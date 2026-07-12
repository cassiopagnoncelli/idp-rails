# frozen_string_literal: true

module IdpRails
  module Rails
    class Railtie < ::Rails::Railtie
      initializer "idp_rails.configure" do
        # Auto-configure from Rails credentials or environment variables.
        IdpRails.configure do |config|
          config.jwks_url ||= ENV.fetch("IDP_JWKS_URL", nil)
          config.issuer   ||= ENV.fetch("IDP_JWT_ISSUER", "https://account.yourcompany.com")
          config.logger     = ::Rails.logger
        end
      end

      initializer "idp_rails.revocation_subscriber" do
        # Start the revocation subscriber if a transport (Redis or RabbitMQ) is configured.
        if IdpRails.configuration.rabbitmq_url || IdpRails.configuration.redis
          IdpRails.configuration.validate!

          subscriber = RevocationSubscriber.new
          subscriber.start

          # Store reference for clean shutdown.
          ::Rails.application.config.idp_rails_revocation_subscriber = subscriber

          at_exit { subscriber.stop }
        end
      end
    end
  end
end
