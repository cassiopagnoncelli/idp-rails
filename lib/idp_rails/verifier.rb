# frozen_string_literal: true

module IdpRails
  class Verifier
    def initialize(config: IdpRails.configuration, jwks_client: nil, revocation_subscriber: nil)
      @config = config
      @jwks_client = jwks_client || default_jwks_client
      @revocation_subscriber = revocation_subscriber
    end

    # Verify a JWT access token and return a Passport.
    #
    # @param token [String] the encoded JWT (optionally prefixed with "Bearer ")
    # @return [Passport]
    # @raise [VerificationError]
    def verify!(token)
      @config.validate!

      raw_token = strip_bearer(token)

      # Decode header to get kid (without verification).
      header = ::JWT.decode(raw_token, nil, false).last
      kid = header["kid"]
      raise InvalidSignatureError, "Token missing kid header" unless kid

      # RFC 9068 §4: resource servers reject tokens that are not access
      # tokens. ID tokens and foreign JWTs die here regardless of signature.
      unless header["typ"] == "at+jwt"
        raise VerificationError, "Not an access token (typ=#{header["typ"].inspect})"
      end

      # Fetch the public key for this kid.
      public_key = @jwks_client.public_key(kid)

      # Decode and verify signature + standard claims, including the
      # platform audience (one logical audience for all resource servers).
      payload, = ::JWT.decode(
        raw_token,
        public_key,
        true,
        {
          algorithm: "ES256",
          iss: @config.issuer,
          verify_iss: true,
          aud: @config.audience,
          verify_aud: true,
          leeway: @config.clock_skew
        }
      )

      passport = Passport.new(payload)

      # Check revocation blocklist.
      check_revocation!(passport)

      passport
    rescue ::JWT::ExpiredSignature
      raise ExpiredTokenError, "Access token has expired"
    rescue ::JWT::InvalidIssuerError
      raise InvalidIssuerError, "Invalid token issuer"
    rescue ::JWT::InvalidAudError
      raise InvalidAudienceError, "Invalid token audience"
    rescue ::JWT::DecodeError => e
      raise VerificationError, "Token verification failed: #{e.message}"
    end

    private

    def strip_bearer(token)
      token.to_s.sub(/\ABearer\s+/i, "")
    end

    def check_revocation!(passport)
      return unless @revocation_subscriber
      # Service tokens (client_credentials) are short-lived and not
      # tracked in the revocation channel. Skip the lookup entirely.
      return if passport.service?

      return unless @revocation_subscriber.revoked?(passport.subject)

      raise RevokedTokenError, "Token has been revoked"
    end

    def default_jwks_client
      IdpRails.jwks_client
    end
  end
end
