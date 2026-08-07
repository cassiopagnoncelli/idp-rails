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
      @jwks_url || required_from_discovery("jwks_uri")
    end

    # Expected issuer claim (iss). Tokens with a different issuer are rejected.
    # @return [String]
    attr_writer :issuer

    def issuer
      return @issuer if @issuer
      # DEFAULT_ISSUER is for an app that configured neither — never a stand-in
      # for a discovery lookup that failed, which would turn an outage into
      # InvalidIssuerError on every token and send the reader hunting for a
      # clock skew or a rotated key.
      return required_from_discovery("issuer") if discovery_url

      DEFAULT_ISSUER
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
    # to outlive the newest token it could still be covering, which is one of
    # idp's access token TTLs. Too short and revoked tokens come back to life
    # for the difference, still inside their own validity.
    #
    # The subscriber widens this at startup to whatever idp publishes as
    # `access_token_ttl` (see #discovered_access_token_ttl), so the two numbers
    # no longer have to be kept in step by hand. Setting a LONGER value here
    # still stands — that is a deliberate choice, and discovery only ever
    # raises the floor.
    # @return [Integer]
    attr_accessor :blocklist_ttl

    # idp's access token TTL in seconds, as published by its discovery
    # document, or nil when discovery is unconfigured, unreachable, or too old
    # to publish it.
    #
    # The one number a blocklist has to outlive and a consumer cannot guess:
    # it belongs to idp, it moves with idp's env, and before it was published
    # a consumer had no way to notice it had. Optional on purpose — an idp
    # that does not publish it leaves the configured retention exactly as it
    # was, so this refines a boot rather than becoming a new dependency of one.
    # @return [Integer, nil]
    def discovered_access_token_ttl
      ttl = discovered("access_token_ttl")
      return nil unless ttl.is_a?(Integer) || (ttl.is_a?(String) && ttl.match?(/\A\d+\z/))

      ttl = ttl.to_i
      ttl.positive? ? ttl : nil
    end

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

    # OPTIONAL keys. nil is a usable answer here — end_session_endpoint's
    # callers already treat a missing endpoint as "sign out locally" — so a
    # discovery that cannot be read costs the feature and nothing else.
    def discovered(key)
      discovery&.[](key)
    rescue StandardError => e
      logger.warn("[IdpRails] Discovery lookup for #{key} failed: #{e.message}")
      nil
    end

    # REQUIRED keys. nil is NOT a usable answer: handing one back to JwksClient
    # gets `URI(nil)` and an ArgumentError raised on the token-verification
    # path, three frames from anything that names discovery. Whoever reads that
    # backtrace at 3am deserves the actual sentence.
    def required_from_discovery(key)
      raise Error, "#{key} is not configured, and no discovery_url is set to fetch it from" unless discovery

      value =
        begin
          discovery[key]
        rescue StandardError => e
          raise Error, "Could not read #{key} from idp's discovery document at #{discovery_url}: #{e.message}"
        end
      return value if value

      raise Error, "idp's discovery document at #{discovery_url} does not publish #{key}"
    end
  end
end
