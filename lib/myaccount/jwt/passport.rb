# frozen_string_literal: true

module MyAccount
  module JWT
    # A decoded and verified JWT passport. Provides typed accessors
    # for all standard claims issued by MyAccount.
    #
    # @example
    #   passport = MyAccount::JWT.verify!(token)
    #   passport.user_uuid        # => "usr_a1b2c3d4"
    #   passport.account_type     # => "Merchant"
    #   passport.role             # => "admin"
    #   passport.scopes           # => ["read", "write", "admin", "api_keys"]
    #   passport.mfa_verified?    # => true
    #   passport.platform_admin?  # => false
    #   passport.has_scope?("write") # => true
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
      alias_method :user_uuid, :subject

      def issued_at
        claims[:iat] ? Time.at(claims[:iat]) : nil
      end

      def expires_at
        claims[:exp] ? Time.at(claims[:exp]) : nil
      end

      def jwt_id
        claims[:jti]
      end

      # --- Account context ---

      def account_context
        claims[:act]
      end

      def account_type
        account_context&.dig(:type)
      end

      def account_id
        account_context&.dig(:id)
      end

      def account_uuid
        account_context&.dig(:uuid)
      end

      def membership_uuid
        account_context&.dig(:membership_uuid)
      end

      def role
        account_context&.dig(:role)
      end

      def membership_status
        account_context&.dig(:status)
      end

      def account_selected?
        !account_context.nil?
      end

      # Convenience: checks if the user's role in the current account is "admin" or "owner".
      def admin?
        %w[admin owner].include?(role)
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

      # --- Scopes ---

      def scopes
        Array(claims[:scopes])
      end

      def has_scope?(scope)
        scopes.include?(scope.to_s)
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
    end
  end
end
