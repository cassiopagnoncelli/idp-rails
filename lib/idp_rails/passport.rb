# frozen_string_literal: true

module IdpRails
  # A decoded and verified JWT passport. Provides typed accessors for the
  # conformant OIDC / RFC 9068 claims idp issues (ADR-0001): flat top-level
  # authorization data — platform_role, status, scope, amr/acr/auth_time,
  # sid. Access tokens carry no profile fields; the profile accessors below
  # yield values only when this class wraps an OIDC payload that has them
  # (an ID token or userinfo body) and return nil otherwise. Re-source
  # profile data from the ID token or userinfo, not the access token.
  #
  # (2.x also read a legacy nested `user` envelope; that shape is retired.)
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
    # grant was born from, e.g. ["pwd", "otp", "mfa"]. Empty when the
    # grant's context is unknown.
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
    # These accessors raise NotAUserToken for service tokens. Access
    # tokens carry no profile fields (they return nil there) — the values
    # come through only when wrapping an ID-token/userinfo payload.

    def email
      require_user_token!(:email)
      claims[:email]
    end

    def name
      require_user_token!(:name)
      claims[:name]
    end

    def locale
      require_user_token!(:locale)
      claims[:locale]
    end

    # The OIDC zoneinfo claim: an IANA tz name, absent when the user has
    # no stored preference ("Auto-detect").
    def time_zone
      require_user_token!(:time_zone)
      claims[:zoneinfo]
    end

    def phone_number
      require_user_token!(:phone_number)
      claims[:phone_number]
    end

    # Retired (ADR-0001): tokens carry no profile timestamps. Kept for
    # 2.x API compatibility; always nil.
    def created_at
      require_user_token!(:created_at)
      nil
    end

    # Retired (ADR-0001): #email_verified? asserts the fact the timestamp
    # used to prove. Kept for 2.x API compatibility; always nil.
    def confirmed_at
      require_user_token!(:confirmed_at)
      nil
    end

    def email_verified?
      require_user_token!(:email_verified?)
      truthy_claim?(claims[:email_verified])
    end

    # Whether the sign-in behind this grant verified a second factor
    # (amr contains "mfa", RFC 8176).
    def mfa_verified?
      require_user_token!(:mfa_verified?)
      amr.include?("mfa")
    end

    # Platform-wide role claim, ranked owner > admin > member > viewer
    # > none. The tiered predicates below are "at least" checks —
    # platform_admin? is true for owners too.
    def platform_role
      require_user_token!(:platform_role)
      claims[:platform_role]
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
      claims[:status]
    end

    # Retired (ADR-0001): terms left the token contract entirely. Kept
    # for 2.x API compatibility; always nil.
    def terms_version
      require_user_token!(:terms_version)
      nil
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
