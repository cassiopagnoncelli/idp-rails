# frozen_string_literal: true

require "jwt"
require "net/http"
require "json"
require "openssl"

require_relative "idp_rails/version"
require_relative "idp_rails/discovery"
require_relative "idp_rails/configuration"
require_relative "idp_rails/jwks_client"
require_relative "idp_rails/passport"
require_relative "idp_rails/verifier"
require_relative "idp_rails/revocation_subscriber"
require_relative "idp_rails/client_credentials_client"
require_relative "idp_rails/token_refresher"
require_relative "idp_rails/user_agent"

module IdpRails
  class Error < StandardError; end
  class VerificationError < Error; end
  class ExpiredTokenError < VerificationError; end
  class InvalidSignatureError < VerificationError; end
  class InvalidIssuerError < VerificationError; end
  class InvalidAudienceError < VerificationError; end
  class RevokedTokenError < VerificationError; end
  # Raised when a user-only accessor (e.g. #email) is called on a
  # service token. Not a VerificationError — the token is valid; the
  # caller is asking for something the token cannot provide.
  class NotAUserToken < Error; end
  class ClientCredentialsError < Error
    attr_reader :status, :code

    def initialize(message, status: nil, code: nil)
      super(message)
      @status = status
      @code = code
    end
  end

  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end

    # Shared JWKS client instance. Reused across all Verifier instances
    # so the JWKS cache is effective.
    def jwks_client
      @jwks_client ||= JwksClient.new(configuration)
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
      @jwks_client = nil
    end
  end
end
