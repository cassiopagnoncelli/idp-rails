# frozen_string_literal: true

require "monitor"
require "net/http"
require "uri"
require "json"
require "base64"

module Idp
  module JWT
    # Acquires service tokens via the OAuth2 `client_credentials` grant
    # (RFC 6749 §4.4) and caches them in-process until shortly before
    # expiry. Thread-safe.
    #
    # @example
    #   client = Idp::JWT::ClientCredentialsClient.new(
    #     token_url: "https://account.test/oauth/token",
    #     client_id: ENV.fetch("IDP_CLIENT_ID"),
    #     client_secret: ENV.fetch("IDP_CLIENT_SECRET"),
    #     scope: "users:lookup"
    #   )
    #
    #   token = client.token  # cached, refreshed on demand
    #   Net::HTTP.get(URI("..."), { "Authorization" => "Bearer #{token}" })
    class ClientCredentialsClient
      include MonitorMixin

      # Refresh proactively this many seconds before the token's exp.
      DEFAULT_SKEW_SECONDS = 30

      Token = Struct.new(:access_token, :expires_at, :scope, keyword_init: true) do
        def expired?(skew: DEFAULT_SKEW_SECONDS)
          expires_at.nil? || Time.now + skew >= expires_at
        end
      end

      def initialize(token_url:, client_id:, client_secret:, scope: nil,
                     http_open_timeout: 5, http_read_timeout: 5,
                     skew_seconds: DEFAULT_SKEW_SECONDS)
        super()
        @token_url = token_url
        @client_id = client_id
        @client_secret = client_secret
        @scope = scope
        @http_open_timeout = http_open_timeout
        @http_read_timeout = http_read_timeout
        @skew_seconds = skew_seconds
        @cached = nil
      end

      # Returns a valid access token string, fetching or refreshing as needed.
      # @return [String]
      def token
        synchronize do
          @cached = fetch! if @cached.nil? || @cached.expired?(skew: @skew_seconds)
          @cached.access_token
        end
      end

      # Forces a fresh fetch, bypassing and replacing any cached token.
      # @return [Token]
      def fetch!
        body = { "grant_type" => "client_credentials" }
        body["scope"] = @scope if @scope && !@scope.empty?

        uri = URI.parse(@token_url)
        request = Net::HTTP::Post.new(uri.request_uri)
        request.basic_auth(@client_id, @client_secret)
        request["Accept"] = "application/json"
        request.set_form_data(body)

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = @http_open_timeout
        http.read_timeout = @http_read_timeout

        response =
          begin
            http.request(request)
          rescue StandardError => e
            raise ClientCredentialsError.new("Token request failed: #{e.message}",
                                             status: 502, code: "network_error")
          end

        payload =
          begin
            JSON.parse(response.body || "{}")
          rescue JSON::ParserError
            {}
          end

        unless response.is_a?(Net::HTTPSuccess)
          raise ClientCredentialsError.new(
            payload["error_description"] || "Token request failed (#{response.code})",
            status: response.code.to_i,
            code: payload["error"] || "request_failed"
          )
        end

        access_token = payload["access_token"]
        unless access_token.is_a?(String) && !access_token.empty?
          raise ClientCredentialsError.new("Idp response missing access_token",
                                           status: 502, code: "invalid_response")
        end

        expires_in = payload["expires_in"].to_i
        @cached = Token.new(
          access_token: access_token,
          expires_at: expires_in.positive? ? Time.now + expires_in : nil,
          scope: payload["scope"]
        )
      end

      # Drops any cached token. Useful in tests or when the client_id/secret
      # has been rotated.
      def reset!
        synchronize { @cached = nil }
      end
    end
  end
end
