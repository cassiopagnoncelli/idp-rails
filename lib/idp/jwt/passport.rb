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

      # The user UUID for user tokens. Raises for service tokens, where
      # `sub` is the client_id and not a user identifier — call #service?
      # before assuming the passport represents a user.
      def user_uuid
        require_user_token!(:user_uuid)
        subject
      end

      # --- Token type discriminator ---

      # @return [String, nil] "client" for service tokens (client_credentials),
      #   nil for user tokens issued by Idp.
      def token_use
        claims[:token_use]
      end

      def service?
        token_use == "client"
      end

      def user?
        !service?
      end

      def client_id
        claims[:client_id] || (service? ? subject : nil)
      end

      # @return [Array<String>] scopes granted to this token.
      def scopes
        claims[:scope].to_s.split
      end
      alias scope scopes

      def has_scope?(name)
        scopes.include?(name.to_s)
      end

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
      #
      # These accessors raise NotAUserToken for service tokens — service
      # callers don't have an email, MFA status, or admin role. Branch on
      # #service? / #user? before reading user fields.

      def email
        require_user_claims!(:email)
        user_claims[:email]
      end

      def name
        require_user_claims!(:name)
        user_claims[:name]
      end

      def locale
        require_user_claims!(:locale)
        user_claims[:locale]
      end

      def time_zone
        require_user_claims!(:time_zone)
        user_claims[:time_zone]
      end

      def phone_number
        require_user_claims!(:phone_number)
        user_claims[:phone_number] || user_claims[:mobile]
      end

      def created_at
        require_user_claims!(:created_at)
        user_claims[:created_at]
      end

      def confirmed_at
        require_user_claims!(:confirmed_at)
        user_claims[:confirmed_at]
      end

      def email_verified?
        require_user_claims!(:email_verified?)
        raw = user_claims[:email_verified]
        raw = claims[:email_verified] if raw.nil?

        truthy_claim?(raw)
      end

      def mfa_verified?
        require_user_claims!(:mfa_verified?)
        user_claims[:mfa_verified] == true
      end

      def platform_admin?
        require_user_claims!(:platform_admin?)
        user_claims[:platform_admin] == true
      end

      def platform_admin_root?
        require_user_claims!(:platform_admin_root?)
        user_claims[:platform_admin_root] == true
      end

      def user_status
        require_user_claims!(:user_status)
        user_claims[:status]
      end

      def terms_version
        require_user_claims!(:terms_version)
        user_claims[:terms_version]
      end

      # --- Helpers ---

      def expired?
        return true unless expires_at

        Time.now.utc > expires_at
      end

      # Flipper integration — allows using the passport as a feature flag actor.
      # Service tokens get a separate namespace so a client_id can never
      # collide with a user uuid.
      def flipper_id
        service? ? "Service:#{client_id}" : "Passport:#{subject}"
      end

      def to_h
        claims
      end

      private

      def user_claims
        claims[:user]
      end

      def require_user_token!(method_name)
        return unless service?

        raise NotAUserToken,
              "##{method_name} is only available on user tokens; this is a service token (client_id=#{client_id})"
      end

      def require_user_claims!(method_name)
        require_user_token!(method_name)
        return if user_claims

        raise NotAUserToken,
              "##{method_name} is only available on user tokens; this token has no user claims"
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
