# frozen_string_literal: true

require 'monitor'

module Idp
  module JWT
    # Fetches and caches JWKS (JSON Web Key Set) from the Idp identity provider.
    # Thread-safe with background refresh.
    class JwksClient
      include MonitorMixin

      def initialize(config = Idp::JWT.configuration)
        super() # MonitorMixin
        @config = config
        @keys = {} # kid => OpenSSL::PKey::EC
        @fetched_at = nil
        @refresh_thread = nil
      end

      # Get the public key for a given Key ID.
      # Fetches JWKS on first call; returns cached keys after that.
      # If kid is unknown, forces a refresh (key rotation may have happened).
      #
      # @param kid [String]
      # @return [OpenSSL::PKey::EC]
      # @raise [InvalidSignatureError] if kid is not found after refresh
      def public_key(kid)
        ensure_loaded

        key = synchronize { @keys[kid] }
        return key if key

        # Key not found — might be a new key from rotation. Force refresh once.
        refresh!
        key = synchronize { @keys[kid] }
        raise InvalidSignatureError, "Unknown signing key: #{kid}" unless key

        key
      end

      # Force a synchronous refresh of the JWKS cache.
      def refresh!
        fetch_and_cache
      end

      # Clear the cache (useful in tests).
      def clear!
        synchronize do
          @keys = {}
          @fetched_at = nil
        end
      end

      private

      def ensure_loaded
        needs_fetch = synchronize { @fetched_at.nil? }
        fetch_and_cache if needs_fetch
        schedule_background_refresh if stale?
      end

      def stale?
        synchronize do
          return false unless @fetched_at

          Time.now - @fetched_at > @config.jwks_cache_ttl
        end
      end

      def schedule_background_refresh
        synchronize do
          return if @refresh_thread&.alive?

          @refresh_thread = Thread.new do
            fetch_and_cache
          rescue StandardError => e
            @config.logger.error("[Idp::JWT] Background JWKS refresh failed: #{e.message}")
          end
        end
      end

      def fetch_and_cache
        uri = URI(@config.jwks_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = @config.http_open_timeout
        http.read_timeout = @config.http_read_timeout

        request = Net::HTTP::Get.new(uri)
        request['Accept'] = 'application/json'

        response = http.request(request)
        raise Error, "JWKS fetch failed: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        jwks = JSON.parse(response.body)
        keys = parse_keys(jwks)

        synchronize do
          @keys = keys
          @fetched_at = Time.now
        end

        @config.logger.info("[Idp::JWT] JWKS refreshed: #{keys.size} key(s)")
      end

      def parse_keys(jwks)
        keys = {}
        Array(jwks['keys']).each do |jwk|
          next unless jwk['kty'] == 'EC' && jwk['crv'] == 'P-256'

          kid = jwk['kid']
          next unless kid

          x = Base64.urlsafe_decode64(jwk['x'])
          y = Base64.urlsafe_decode64(jwk['y'])

          group = OpenSSL::PKey::EC::Group.new('prime256v1')
          point = OpenSSL::PKey::EC::Point.new(
            group,
            OpenSSL::BN.new("\u0004#{x}#{y}", 2)
          )

          # Build an EC key from the public point.
          asn1 = OpenSSL::ASN1::Sequence.new([
                                               OpenSSL::ASN1::Sequence.new([
                                                                             OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
                                                                             OpenSSL::ASN1::ObjectId.new('prime256v1')
                                                                           ]),
                                               OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed))
                                             ])

          keys[kid] = OpenSSL::PKey::EC.new(asn1.to_der)
        end
        keys
      end
    end
  end
end
