# frozen_string_literal: true

require "jwt"
require "net/http"
require "json"
require "openssl"

require_relative "jwt/version"
require_relative "jwt/configuration"
require_relative "jwt/jwks_client"
require_relative "jwt/passport"
require_relative "jwt/verifier"
require_relative "jwt/revocation_subscriber"
require_relative "jwt/user_agent"

module MyAccount
  module JWT
    class Error < StandardError; end
    class VerificationError < Error; end
    class ExpiredTokenError < VerificationError; end
    class InvalidSignatureError < VerificationError; end
    class InvalidIssuerError < VerificationError; end
    class RevokedTokenError < VerificationError; end

    class << self
      def configuration
        @configuration ||= Configuration.new
      end

      def configure
        yield(configuration)
      end

      # Verify a JWT and return a Passport.
      #
      # @param token [String] raw JWT string (with or without "Bearer " prefix)
      # @return [Passport]
      # @raise [VerificationError]
      def verify!(token)
        Verifier.new.verify!(token)
      end

      # Verify a JWT, returning nil instead of raising on failure.
      #
      # @param token [String]
      # @return [Passport, nil]
      def verify(token)
        verify!(token)
      rescue VerificationError
        nil
      end

      def reset_configuration!
        @configuration = Configuration.new
      end
    end
  end
end
