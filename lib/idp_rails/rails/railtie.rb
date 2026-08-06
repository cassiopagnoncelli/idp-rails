# frozen_string_literal: true

module IdpRails
  module Rails
    class Railtie < ::Rails::Railtie
      initializer "idp_rails.configure" do
        # Auto-configure from Rails credentials or environment variables.
        #
        # IDP_URL alone is enough now: jwks_uri, issuer and end_session_endpoint
        # all come off the discovery document it points at. The explicit vars
        # still win where an app sets them, so nothing changes for a consumer
        # until it drops them.
        #
        # Assigned rather than ||='d: both readers now answer with a fallback,
        # so `config.issuer ||= ...` would find DEFAULT_ISSUER already truthy
        # and quietly discard the env var — and `config.jwks_url ||= ...` would
        # put a discovery fetch on the boot path to find that out.
        IdpRails.configure do |config|
          config.discovery_url = ENV.fetch("IDP_URL", nil) if config.discovery_url.nil?
          config.jwks_url = ENV["IDP_JWKS_URL"] if ENV["IDP_JWKS_URL"]
          config.issuer = ENV["IDP_JWT_ISSUER"] if ENV["IDP_JWT_ISSUER"]
          config.logger = ::Rails.logger
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
