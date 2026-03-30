# frozen_string_literal: true

module MyAccount
  module JWT
    class Verifier
      def initialize(config: MyAccount::JWT.configuration, jwks_client: nil, revocation_subscriber: nil)
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

        # Fetch the public key for this kid.
        public_key = @jwks_client.public_key(kid)

        # Decode and verify signature + standard claims.
        payload, = ::JWT.decode(
          raw_token,
          public_key,
          true,
          {
            algorithm: "ES256",
            iss: @config.issuer,
            verify_iss: true,
            leeway: @config.clock_skew
          }
        )

        passport = Passport.new(payload)

        # Validate account type if configured.
        validate_account_type!(passport)

        # Check revocation blocklist.
        check_revocation!(passport)

        passport
      rescue ::JWT::ExpiredSignature
        raise ExpiredTokenError, "Access token has expired"
      rescue ::JWT::InvalidIssuerError
        raise InvalidIssuerError, "Invalid token issuer"
      rescue ::JWT::DecodeError => e
        raise VerificationError, "Token verification failed: #{e.message}"
      end

      private

      def strip_bearer(token)
        token.to_s.sub(/\ABearer\s+/i, "")
      end

      def validate_account_type!(passport)
        accepted = @config.accepted_account_types
        return unless accepted
        return unless passport.account_selected?

        unless accepted.include?(passport.account_type)
          raise InvalidAudienceError,
            "Account type '#{passport.account_type}' is not accepted by this application"
        end
      end

      def check_revocation!(passport)
        return unless @revocation_subscriber

        if @revocation_subscriber.revoked?(passport.user_uuid)
          raise RevokedTokenError, "Token has been revoked"
        end
      end

      def default_jwks_client
        @default_jwks_client ||= JwksClient.new(@config)
      end
    end
  end
end
