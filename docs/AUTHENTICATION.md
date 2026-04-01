# myaccount-jwt (Ruby gem)

Shared Ruby gem for sister apps to verify JWT passports issued by MyAccount. Handles JWKS fetching/caching, ES256 signature verification, and claim validation.

## Usage

```ruby
passport = MyAccount::JWT.verify(token)   # returns Passport or nil
passport = MyAccount::JWT.verify!(token)  # raises on invalid token
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
passport.mfa_verified?
passport.platform_admin?

# Account context (from act claim, nil when no account selected)
passport.account_type      # "Customer", "Merchant", "Partner"
passport.account_id        # numeric ID in the sister app (nullable)
passport.account_uuid      # UUID in the sister app (nullable)
passport.membership_uuid   # the membership's own identifier
passport.role              # "owner", "admin", "member", "viewer"
passport.account_selected? # true if act is present
passport.admin?            # true if role is "admin" or "owner"

# Scopes
passport.scopes            # ["read", "write", ...]
passport.has_scope?(scope) # boolean

# Raw claims
passport.to_h              # full claims hash
```

## Commands

- `bundle exec rspec` — run specs
