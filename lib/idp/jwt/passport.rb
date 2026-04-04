# frozen_string_literal: true

module Idp
  module JWT
    # A decoded and verified JWT passport. Provides typed accessors
    # for all standard claims issued by Idp.
    #
    # @example
    #   passport = Idp::JWT.verify!(token)
    #   passport.user_uuid        # => "usr_a1b2c3d4"
    #   passport.email_verified?  # => true
    #   passport.mfa_verified?    # => true
    #   passport.platform_admin?  # => false
    class Passport
      attr_reader :claims

      def initialize(claims)
        @claims = deep_symbolize(claims)
      end

      # --- Standard JWT claims ---

      def issuer
        claims[:iss]
      end

      def subject
        claims[:sub]
      end
      alias user_uuid subject

      def issued_at
        claims[:iat] ? Time.at(claims[:iat]) : nil
      end

      def expires_at
        claims[:exp] ? Time.at(claims[:exp]) : nil
      end

      def jwt_id
        claims[:jti]
      end

      # --- User profile ---

      def email
        user_claims&.dig(:email)
      end

      def name
        user_claims&.dig(:name)
      end

      def locale
        user_claims&.dig(:locale)
      end

      def email_verified?
        raw = user_claims&.dig(:email_verified)
        raw = claims[:email_verified] if raw.nil?

        truthy_claim?(raw)
      end

      def mfa_verified?
        user_claims&.dig(:mfa_verified) == true
      end

      def platform_admin?
        user_claims&.dig(:platform_admin) == true
      end

      def platform_admin_root?
        user_claims&.dig(:platform_admin_root) == true
      end

      def user_status
        user_claims&.dig(:status)
      end

      def terms_version
        user_claims&.dig(:terms_version)
      end

      # --- Helpers ---

      def expired?
        return true unless expires_at

        Time.now.utc > expires_at
      end

      # Flipper integration — allows using the passport as a feature flag actor.
      def flipper_id
        "Passport:#{user_uuid}"
      end

      def to_h
        claims
      end

      private

      def user_claims
        claims[:user]
      end

      def deep_symbolize(obj)
        case obj
        when Hash
          obj.each_with_object({}) { |(k, v), h| h[k.to_sym] = deep_symbolize(v) }
        when Array
          obj.map { |v| deep_symbolize(v) }
        else
          obj
        end
      end

      def truthy_claim?(value)
        return true if value == true || value == 1

        return false unless value.is_a?(String)

        %w[true 1 yes].include?(value.strip.downcase)
      end
    end
  end
end
