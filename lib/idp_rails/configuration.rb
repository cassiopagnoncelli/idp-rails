# frozen_string_literal: true

require "logger"

module IdpRails
  class Configuration
    # Placeholder used when neither explicit configuration nor discovery names
    # an issuer — kept so an app that configured neither behaves as it always
    # has, rather than newly failing on nil.
    DEFAULT_ISSUER = "https://account.yourcompany.com"

    # idp's base url. Setting it lets jwks_url, issuer and end_session_endpoint
    # come from the discovery document instead of from three env vars that can
    # drift apart. Explicit values below still win.
    # @return [String, nil]
    attr_accessor :discovery_url

    # How long the discovery document is cached (seconds). idp serves it with
    # max-age=3600 and this matches.
    # @return [Integer]
    attr_accessor :discovery_cache_ttl

    # The Idp JWKS endpoint URL. Falls back to the discovery document's
    # `jwks_uri` when discovery_url is set.
    # @return [String, nil]
    attr_writer :jwks_url

    def jwks_url
      @jwks_url || discovered("jwks_uri")
    end

    # Expected issuer claim (iss). Tokens with a different issuer are rejected.
    # @return [String]
    attr_writer :issuer

    def issuer
      @issuer || discovered("issuer") || DEFAULT_ISSUER
    end

    # RP-initiated logout endpoint. Published by idp; there is no reason for a
    # consumer to carry its own copy.
    # @return [String, nil]
    attr_writer :end_session_endpoint

    def end_session_endpoint
      @end_session_endpoint || discovered("end_session_endpoint")
    end

    # The discovery document, or nil when no discovery_url is configured.
    # @return [Discovery, nil]
    def discovery
      return nil unless discovery_url

      @discovery ||= Discovery.new(discovery_url, config: self)
    end

    # Expected audience claim (aud) — idp's single logical platform
    # audience (ADR-0001), which defaults to the issuer string on both
    # sides. Set explicitly only when idp runs with a custom JWT_AUDIENCE.
    # @return [String]
    attr_writer :audience

    def audience
      @audience || issuer
    end

    # JWKS cache TTL in seconds. Keys are refreshed in the background after this period.
    # @return [Integer]
    attr_accessor :jwks_cache_ttl

    # How long a revocation blocklist entry is retained (seconds). It only has
    # to outlive the newest token it could still be covering, so this must
    # match idp's access token TTL (JWT_ACCESS_TOKEN_TTL, itself 15 minutes by
    # default). Set it whenever idp's has been moved: too short and revoked
    # tokens come back to life before they expire.
    # @return [Integer]
    attr_accessor :blocklist_ttl

    # Clock skew tolerance in seconds for exp/iat validation.
    # @return [Integer]
    attr_accessor :clock_skew

    # Redis configuration for the revocation subscriber.
    # Can be a Redis instance, a URL string, or a hash of Redis options.
    # Set to nil to disable revocation listening.
    # @return [Redis, String, Hash, nil]
    attr_accessor :redis

    # Redis configuration for JWKS caching (L2 shared cache across pods).
    # Can be a Redis instance, a URL string, or a hash of Redis options.
    # Set to nil to disable Redis-based JWKS caching.
    # @return [Redis, String, Hash, nil]
    attr_accessor :cache_redis

    # Namespace prefix for Redis cache keys. When set, all cache keys are
    # prefixed with "namespace:" to avoid collisions with other apps.
    # @return [String, nil]
    attr_accessor :cache_redis_namespace

    # RabbitMQ connection URL for the revocation subscriber.
    # When set, RabbitMQ is used instead of Redis for revocation listening.
    # Example: "amqp://guest:guest@localhost:5672"
    # Set to nil to use Redis (default).
    # @return [String, nil]
    attr_accessor :rabbitmq_url

    # Redis pub/sub channel name for revocation events.
    # @return [String]
    attr_accessor :revocation_channel

    # Callable that asks idp for the revocations of a window, closing the one
    # gap no store can: every consumer process down when an event was
    # published, so nobody was there to write it through. The subscriber calls
    # it once at startup with the window start as unix seconds, and expects the
    # revocations from it onwards — an enumerable of { sub:, sid:, revoked_at: }
    # (string or symbol keys), the same three facts a live event carries.
    #
    # A callable rather than a url and a client id here on purpose: fetching
    # them means holding a service client's credentials, and this gem verifies
    # tokens — it has no business also being where secrets live. The consuming
    # app already has that client, so it passes a lambda that uses it.
    #
    #   c.revocation_catch_up = ->(since) { IdpApiClient.revocations(since: since) }
    #
    # Leave it nil to skip the catch-up: the in-memory blocklist and the shared
    # one behave exactly as before.
    # @return [#call, nil]
    attr_accessor :revocation_catch_up

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
      # nil, not DEFAULT_ISSUER: a placeholder here would satisfy the reader
      # before discovery ever got a look in.
      @issuer = nil
      @end_session_endpoint = nil
      @discovery_url = nil
      @discovery = nil
      @discovery_cache_ttl = 3600
      @jwks_cache_ttl = 3600
      @blocklist_ttl = RevocationSubscriber::BLOCKLIST_TTL
      @clock_skew = 30
      @redis = nil
      @cache_redis = nil
      @cache_redis_namespace = nil
      @rabbitmq_url = nil
      @revocation_channel = "idp:token_revocations"
      @revocation_catch_up = nil
      @http_open_timeout = 5
      @http_read_timeout = 5
      @logger = Logger.new(IO::NULL)
    end

    # Checks the raw settings rather than the resolved ones on purpose: this
    # runs per Verifier and at boot, and resolving would put a discovery fetch
    # on both paths.
    def validate!
      raise Error, "jwks_url must be configured (or discovery_url, to fetch it)" unless @jwks_url || discovery_url
    end

    private

    # A discovery document that cannot be fetched must not take the process
    # down: the explicit settings, if any, are still there, and the caller's
    # own error is more useful than one from three frames deeper.
    def discovered(key)
      discovery&.[](key)
    rescue StandardError => e
      logger.warn("[IdpRails] Discovery lookup for #{key} failed: #{e.message}")
      nil
    end
  end
end
