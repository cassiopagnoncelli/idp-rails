# idp-jwt (Ruby gem)

Shared Ruby gem for sister apps to verify JWT passports issued by Idp. Handles JWKS fetching/caching, ES256 signature verification, and claim validation.

## Usage

```ruby
passport = Idp::JWT.verify(token)   # returns Passport or nil
passport = Idp::JWT.verify!(token)  # raises on invalid token
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
passport.mfa_verified?
passport.platform_admin?
passport.platform_admin_root?
passport.user_status
passport.terms_version

# Raw claims
passport.to_h              # full claims hash
```

## Commands

- `bundle exec rspec` — run specs
