# frozen_string_literal: true

module IdpRails
  # A decoded and verified JWT passport. Provides typed accessors
  # for all standard claims issued by Idp.
  #
  # Reads both passport generations (ADR-0001 in idp): the legacy shape
  # nests profile claims in a `user` envelope; the conformant OIDC /
  # RFC 9068 shape carries flat top-level claims (and drops profile
  # fields from access tokens entirely — re-source those from the ID
  # token or userinfo). Accessors prefer the envelope while it exists
  # and fall back to the flat claim, so callers stay agnostic across
  # the migration window.
  #
  # @example
  #   passport = IdpRails.verify!(token)
  #   passport.user_uuid        # => "usr_a1b2c3d4"
  #   passport.mfa_verified?    # => true
  #   passport.amr              # => ["pwd", "otp", "mfa"]
  #   passport.platform_role    # => "member"
  #   passport.platform_member? # => true
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

    # --- Session & authentication context ---

    # SSO session id the grant belongs to. Absent on service tokens.
    def sid
      claims[:sid]
    end

    # Authentication method references (RFC 8176) for the sign-in the
    # grant was born from, e.g. ["pwd", "otp", "mfa"]. Empty on tokens
    # that predate amr stamping.
    def amr
      Array(claims[:amr]).map(&:to_s)
    end

    # Authentication context class: "aal1"/"aal2" (NIST 800-63B semantics).
    def acr
      claims[:acr]
    end

    # Time of the authentication event the grant was born from.
    def auth_time
      claims[:auth_time] ? Time.at(claims[:auth_time]) : nil
    end

    # --- User profile ---
    #
    # These accessors raise NotAUserToken for service tokens — service
    # callers don't have an email, MFA status, or platform role. Branch
    # on #service? / #user? before reading user fields.
    #
    # Conformant access tokens no longer carry profile fields (email,
    # name, locale, zoneinfo, phone_number): these return nil there and
    # the data comes from the ID token or userinfo instead.

    def email
      require_user_token!(:email)
      profile_claim(:email)
    end

    def name
      require_user_token!(:name)
      profile_claim(:name)
    end

    def locale
      require_user_token!(:locale)
      profile_claim(:locale)
    end

    # Legacy envelope key is time_zone; the flat OIDC claim is zoneinfo.
    def time_zone
      require_user_token!(:time_zone)
      profile_claim(:time_zone, flat: :zoneinfo)
    end

    def phone_number
      require_user_token!(:phone_number)
      user_claims[:phone_number] || user_claims[:mobile] || claims[:phone_number]
    end

    # Legacy-envelope-only: conformant tokens dropped this claim.
    def created_at
      require_user_token!(:created_at)
      user_claims[:created_at]
    end

    # Legacy-envelope-only: conformant tokens dropped this claim —
    # #email_verified? asserts the fact the timestamp used to prove.
    def confirmed_at
      require_user_token!(:confirmed_at)
      user_claims[:confirmed_at]
    end

    def email_verified?
      require_user_token!(:email_verified?)
      truthy_claim?(profile_claim(:email_verified))
    end

    # Whether the sign-in behind this grant verified a second factor.
    # Conformant tokens assert it via amr (RFC 8176); legacy tokens via
    # the user.mfa_verified boolean.
    def mfa_verified?
      require_user_token!(:mfa_verified?)
      return amr.include?("mfa") if claims.key?(:amr)

      user_claims[:mfa_verified] == true
    end

    # Platform-wide role claim, ranked owner > admin > member > viewer
    # > none. The tiered predicates below are "at least" checks —
    # platform_admin? is true for owners too.
    def platform_role
      require_user_token!(:platform_role)
      profile_claim(:platform_role)
    end

    def platform_owner?
      platform_role == "owner"
    end

    # At least admin (owner or admin).
    def platform_admin?
      %w[owner admin].include?(platform_role)
    end

    # At least member (owner, admin, or member).
    def platform_member?
      %w[owner admin member].include?(platform_role)
    end

    # At least viewer (any role but none).
    def platform_viewer?
      %w[owner admin member viewer].include?(platform_role)
    end

    def no_platform?
      [ nil, "", "none" ].include?(platform_role)
    end

    def user_status
      require_user_token!(:user_status)
      profile_claim(:status)
    end

    # Legacy-envelope-only: conformant tokens dropped terms data.
    def terms_version
      require_user_token!(:terms_version)
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
      claims[:user] || {}
    end

    # Prefer the legacy envelope value while it exists; fall back to the
    # flat top-level claim of the conformant shape. A present-but-false
    # envelope value wins (nil is the only pass-through).
    def profile_claim(nested_key, flat: nested_key)
      value = user_claims[nested_key]
      value.nil? ? claims[flat] : value
    end

    def require_user_token!(method_name)
      return unless service?

      raise NotAUserToken,
            "##{method_name} is only available on user tokens; this is a service token (client_id=#{client_id})"
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
