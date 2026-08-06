# frozen_string_literal: true

require "monitor"

module IdpRails
  # The OIDC discovery document (`/.well-known/openid-configuration`), fetched
  # on first use and cached.
  #
  # idp publishes its own jwks_uri, issuer, end_session_endpoint and token
  # endpoints, and keeps them correct by construction. Pinning each one as its
  # own env var in each consumer buys a chance per var, per deploy, to move one
  # and leave the others behind — and those failures are quiet ones. A stale
  # end_session_endpoint signs a user out of the app but not out of idp, which
  # looks exactly like a sign-out that worked.
  #
  # Explicit configuration still wins wherever it is set, so adopting this is a
  # per-consumer decision rather than a flag day.
  class Discovery
    include MonitorMixin

    PATH = "/.well-known/openid-configuration"

    def initialize(base_url, config: IdpRails.configuration)
      super()
      @base_url = base_url.to_s.sub(%r{/+\z}, "")
      @config = config
      @document = nil
      @fetched_at = nil
    end

    def issuer
      self["issuer"]
    end

    def jwks_uri
      self["jwks_uri"]
    end

    def end_session_endpoint
      self["end_session_endpoint"]
    end

    def token_endpoint
      self["token_endpoint"]
    end

    def revocation_endpoint
      self["revocation_endpoint"]
    end

    # @return [Object, nil] the published value, nil when idp does not publish it
    def [](key)
      document[key.to_s]
    end

    # Re-fetch from origin, bypassing the cache.
    def refresh!
      fetched = fetch_from_origin

      synchronize do
        @document = fetched
        @fetched_at = Time.now
      end

      fetched
    end

    def clear!
      synchronize do
        @document = nil
        @fetched_at = nil
      end
    end

    private

    def document
      cached = synchronize { @document if fresh? }
      cached || refresh!
    end

    def fresh?
      return false unless @document && @fetched_at

      (Time.now - @fetched_at) < @config.discovery_cache_ttl
    end

    def fetch_from_origin
      uri = URI("#{@base_url}#{PATH}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = @config.http_open_timeout
      http.read_timeout = @config.http_read_timeout

      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"

      response = http.request(request)
      raise Error, "Discovery fetch failed: HTTP #{response.code} from #{uri}" unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    end
  end
end
