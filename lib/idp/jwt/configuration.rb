# frozen_string_literal: true

require "logger"

module Idp
  module JWT
    class Configuration
      # The Idp JWKS endpoint URL.
      # @return [String]
      attr_accessor :jwks_url

      # Expected issuer claim (iss). Tokens with a different issuer are rejected.
      # @return [String]
      attr_accessor :issuer

      # JWKS cache TTL in seconds. Keys are refreshed in the background after this period.
      # @return [Integer]
      attr_accessor :jwks_cache_ttl

      # Clock skew tolerance in seconds for exp/iat validation.
      # @return [Integer]
      attr_accessor :clock_skew

      # Redis configuration for the revocation subscriber.
      # Can be a Redis instance, a URL string, or a hash of Redis options.
      # Set to nil to disable revocation listening.
      # @return [Redis, String, Hash, nil]
      attr_accessor :redis

      # RabbitMQ connection URL for the revocation subscriber.
      # When set, RabbitMQ is used instead of Redis for revocation listening.
      # Example: "amqp://guest:guest@localhost:5672"
      # Set to nil to use Redis (default).
      # @return [String, nil]
      attr_accessor :rabbitmq_url

      # Redis pub/sub channel name for revocation events.
      # @return [String]
      attr_accessor :revocation_channel

      # HTTP open timeout for JWKS fetches (seconds).
      # @return [Integer]
      attr_accessor :http_open_timeout

      # HTTP read timeout for JWKS fetches (seconds).
      # @return [Integer]
      attr_accessor :http_read_timeout

      # Logger instance. Defaults to a null logger.
      # @return [Logger]
      attr_accessor :logger

      def initialize
        @jwks_url = nil
        @issuer = "https://account.yourcompany.com"
        @jwks_cache_ttl = 3600
        @clock_skew = 30
        @redis = nil
        @rabbitmq_url = nil
        @revocation_channel = "idp:token_revocations"
        @http_open_timeout = 5
        @http_read_timeout = 5
        @logger = Logger.new(IO::NULL)
      end

      def validate!
        raise Error, "jwks_url must be configured" unless jwks_url
        raise Error, "issuer must be configured" unless issuer
      end
    end
  end
end
