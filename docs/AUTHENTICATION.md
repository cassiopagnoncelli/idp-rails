# idp-rails (Ruby gem)

Shared Ruby gem for sister apps to verify JWT passports issued by Idp. Handles JWKS fetching/caching, ES256 signature verification, and claim validation.

## Usage

```ruby
passport = IdpRails.verify(token)   # returns Passport or nil
passport = IdpRails.verify!(token)  # raises on invalid token
```

## Passport accessors

The `Passport` class wraps decoded JWT claims:

```ruby
# Standard JWT
passport.issuer            # iss
passport.user_uuid         # sub
passport.issued_at         # iat (Time)
passport.expires_at        # exp (Time)
passport.jwt_id            # jti
passport.expired?          # boolean

# User profile
passport.email
passport.name
passport.locale
passport.time_zone
passport.phone_number
passport.created_at         # Unix seconds integer
passport.confirmed_at       # Unix seconds integer or nil
passport.email_verified?
passport.mfa_verified?
passport.platform_role      # "owner" | "admin" | "member" | "viewer" | "none"
passport.platform_owner?
passport.platform_admin?    # at least admin
passport.platform_member?   # at least member
passport.platform_viewer?   # at least viewer
passport.no_platform?
passport.user_status        # retired (ADR-0002) — always "active"
passport.terms_version      # retired (ADR-0001) — always nil

# Raw claims
passport.to_h              # full claims hash
```

## Commands

- `bundle exec rspec` — run specs
