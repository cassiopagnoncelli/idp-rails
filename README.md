# idp-rails

JWT verification client for sister apps authenticating against the Idp identity provider.

Handles JWKS fetching/caching, ES256 signature verification, claim validation, and optional real-time token revocation via Redis pub/sub.

## Installation

Add to your Gemfile:

```ruby
gem "idp-rails", path: "../idp/gems/idp-rails"
```

For Rails apps, require the Rails integration instead of the base library:

```ruby
# config/application.rb or an initializer
require "idp_rails/rails"
```

The Railtie auto-configures from environment variables (`IDP_JWKS_URL`, `IDP_JWT_ISSUER`) and wires up the revocation subscriber if Redis is configured.

## Configuration

```ruby
IdpRails.configure do |c|
  # Required: the Idp JWKS endpoint.
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"

  # Required: must match the `iss` claim in tokens.
  c.issuer = "https://account.yourcompany.com"

  # Optional: the expected `aud` claim (idp's single platform audience).
  # Defaults to the issuer string, which matches idp's own default —
  # set explicitly only when idp runs with a custom JWT_AUDIENCE.
  # c.audience = "urn:platform:custom"

  # Optional: enable real-time revocation via Redis pub/sub.
  # When a user is suspended or changes their password, Idp
  # publishes to this channel. The subscriber maintains a 15-minute
  # in-memory blocklist so revoked tokens are rejected immediately
  # rather than waiting for natural expiry.
  # Set to nil (default) to disable.
  c.redis = ENV["REDIS_URL"]

  # --- Defaults (usually fine as-is) ---

  # JWKS cache TTL in seconds. After this period, keys are
  # refreshed in a background thread. Default: 3600 (1 hour).
  c.jwks_cache_ttl = 3600

  # Clock skew tolerance for exp/iat validation. Default: 30s.
  c.clock_skew = 30

  # Redis channel name for revocation events.
  c.revocation_channel = "idp:token_revocations"

  # HTTP timeouts for JWKS fetches (seconds).
  c.http_open_timeout = 5
  c.http_read_timeout = 5

  # Logger. Defaults to a null logger; Rails apps get Rails.logger
  # automatically via the Railtie.
  c.logger = Rails.logger
end
```

## Usage with Rails

Include the controller concern and call `authenticate!`:

```ruby
class ApplicationController < ActionController::API
  include IdpRails::Rails::ControllerConcern

  before_action :authenticate!
end
```

Then use `passport` in your controllers:

```ruby
class ProductsController < ApplicationController
  def show
    render json: {
      product: Product.find(params[:id]),
      accessed_by: passport.user_uuid
    }
  end
end
```

### Available controller helpers

| Method | Description |
|---|---|
| `authenticate!` | Verifies the Bearer token. Returns 401 on failure. |
| `passport` | The verified `Passport` object (available after `authenticate!`). |

### Error responses

All authentication errors return JSON:

```json
{ "error": "token_expired" }
```

| Error | Status | Meaning |
|---|---|---|
| `missing_token` | 401 | No `Authorization: Bearer ...` header. |
| `token_expired` | 401 | Access token has expired. Client should refresh. |
| `token_revoked` | 401 | User was revoked via Redis pub/sub. |

## Usage without Rails

```ruby
require "idp-rails"

IdpRails.configure do |c|
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"
  c.issuer   = "https://account.yourcompany.com"
end

# Returns a Passport or raises IdpRails::VerificationError
passport = IdpRails.verify!(token)

# Returns a Passport or nil
passport = IdpRails.verify(token)
```

## The Passport object

`IdpRails.verify!` returns a `Passport` with typed accessors for all token claims:

```ruby
passport = IdpRails.verify!(token)

# Identity
passport.user_uuid          # => "usr_a1b2c3d4"
# Profile accessors (email, name, locale, time_zone, phone_number,
# email_verified?) return values only when wrapping an ID-token/userinfo
# payload — access tokens carry no profile data (ADR-0001). Re-source
# profile display from the ID token or the userinfo endpoint.

# Security
passport.mfa_verified?      # => true   (amr contains "mfa")

# Session & authentication context (conformant tokens; ADR-0001)
passport.sid                # => "sid_9f8e7d"
passport.amr                # => ["pwd", "otp", "mfa"]  (RFC 8176; [] when absent)
passport.acr                # => "aal2"
passport.auth_time          # => 2026-03-30 11:58:00 UTC

# Platform role (ranked owner > admin > member > viewer > none);
# predicates are "at least" checks over that ranking.
passport.platform_role      # => "member"
passport.platform_owner?    # => false
passport.platform_admin?    # => false  (owner or admin)
passport.platform_member?   # => true   (owner, admin, or member)
passport.platform_viewer?   # => true   (any role but none)
passport.no_platform?       # => false

# Token metadata
passport.issuer             # => "https://account.yourcompany.com"
passport.issued_at          # => 2026-03-30 12:00:00 UTC
passport.expires_at         # => 2026-03-30 12:15:00 UTC
passport.expired?           # => false
passport.jwt_id             # => "tok_f9e8d7c6b5a4"

# Raw claims hash
passport.to_h               # => { iss: "...", sub: "...", ... }
```

## Token structure

Access tokens are ES256-signed JWTs in the conformant OIDC / RFC 9068 shape (ADR-0001 in idp) — header `typ: "at+jwt"`, verified along with `iss` and the platform `aud`:

```json
{
  "iss": "https://account.yourcompany.com",
  "sub": "usr_a1b2c3d4",
  "aud": "https://account.yourcompany.com",
  "client_id": "crm_web",
  "iat": 1711800000,
  "exp": 1711800900,
  "jti": "tok_f9e8d7c6b5a4",
  "sid": "sid_9f8e7d",
  "scope": "openid profile email",
  "auth_time": 1711799000,
  "amr": ["pwd", "otp", "mfa"],
  "acr": "aal2",
  "https://claims.entental.com/platform_role": "member"
}
```

- Access tokens carry authorization data only — the profile accessors return `nil` on them. Re-source profile data from the ID token or the userinfo endpoint (a Passport can wrap those payloads too).
- `mfa_verified?` derives from `amr` containing `"mfa"`. Use it to gate sensitive operations.
- `platform_role` is the platform-wide role (`owner`, `admin`, `member`, `viewer`, or `none`). Use the tiered predicates (`platform_admin?`, `platform_member?`, `platform_viewer?`) for "at least" checks. On the wire it is emitted under the namespaced key `https://claims.entental.com/platform_role` (idp ADR-0003) so it cannot collide with a federated token's claims; **always read it through `#platform_role`**, never by digging the raw claim. The accessor falls back to the bare `platform_role` key for any pre-flip token still in flight.
- There is no `status` claim (idp ADR-0002): idp issues a passport only to an active account, so holding one is the assertion. `user_status` is retired and always answers `"active"`.
- `amr` lists RFC 8176 authentication method references; `acr` is `"aal1"`/`"aal2"`; `auth_time` is the authentication event; `sid` is the SSO session id.

### `amr` vocabulary

The values idp emits in `amr` (RFC 8176 authentication method references). An unknown `amr` value is safely ignorable by RFC 8176, so this list can grow without breaking readers:

| Value | Meaning | Status |
|---|---|---|
| `pwd` | Password | RFC 8176 registered |
| `otp` | One-time code — TOTP or a backup code | RFC 8176 registered |
| `hwk` | Hardware-secured key — WebAuthn/passkey | RFC 8176 registered |
| `user` | User-presence/verification performed (e.g. WebAuthn UV) | RFC 8176 registered |
| `mfa` | The sign-in was multi-factor (`mfa_verified?` keys off this) | RFC 8176 registered |
| `fed` | Federated sign-in — Google SSO | Unregistered, conventional (Auth0/Entra) |
| `email` | Email-confirmation auto-login | Unregistered, conventional |

`fed` and `email` are intentionally non-registered but carry real information a step-up policy can use; IANA registration is a possible future upgrade.

### Service (client-credentials) tokens

A client-credentials token has no user identity — `sub` is the client id, and `#service?` returns true (`sub == client_id`, RFC 9068's own discriminator; idp ADR-0003 dropped the former `token_use: "client"` marker). User-only accessors raise `NotAUserToken`; use `#service?`, `#client_id`, `#scopes`, `#has_scope?` instead. `#token_use` is retired and always returns `nil`.

## Real-time revocation

When enabled, the gem subscribes to a Redis pub/sub channel and maintains an in-memory blocklist of revoked user UUIDs. Entries auto-expire after 15 minutes (the access token TTL).

An entry blocks the tokens that **existed when the revocation happened**, not the subject: it carries the event's `revoked_at`, and a token is refused only when its `iat` is at or before it. A token minted afterwards — the passport a user holds after signing back in — is untouched. Blocking the subject outright instead would refuse that passport too, for the rest of the window, and signing in again could not clear it.

Idp publishes to this channel when:
- A user's password is changed
- A user is suspended by an admin
- A session is ended (RP-initiated logout, `/oauth/revoke`, family replay)
- An admin triggers emergency revocation

If a sister app misses an event (restart, Redis blip), the access token still expires naturally within 15 minutes. This is a best-effort acceleration layer, not a hard guarantee.

```ruby
IdpRails.configure do |c|
  c.redis = ENV["REDIS_URL"]   # enables the subscriber
  # c.redis = { host: "redis.internal", port: 6379 }  # also works
  # c.redis = Redis.new(...)  # or pass an instance
end
```

The Railtie starts the subscriber automatically on boot and stops it on shutdown.

Without Rails, manage it manually:

```ruby
subscriber = IdpRails::RevocationSubscriber.new
subscriber.start   # spawns a background thread
subscriber.stop    # clean shutdown

# Wire it into the verifier
verifier = IdpRails::Verifier.new(revocation_subscriber: subscriber)
passport = verifier.verify!(token)
```

## Key rotation

The JWKS client handles key rotation automatically:

1. Keys are cached for 1 hour (configurable via `jwks_cache_ttl`).
2. After the TTL, keys are refreshed in a background thread (no request blocking).
3. If a token arrives signed with an unknown `kid`, the client forces an immediate refresh. This handles the window between Idp rotating a key and the cache expiring.
4. If the `kid` is still unknown after refresh, the token is rejected.

## Exceptions

All exceptions inherit from `IdpRails::Error`:

```
IdpRails::Error
  IdpRails::VerificationError
    IdpRails::ExpiredTokenError
    IdpRails::InvalidSignatureError
    IdpRails::InvalidIssuerError
    IdpRails::InvalidAudienceError
    IdpRails::RevokedTokenError
```

## Testing

In your test suite, you can build tokens directly without a running Idp instance:

```ruby
# spec/support/idp_rails.rb
module IdpRailsHelper
  KEY = OpenSSL::PKey::EC.generate("prime256v1")

  def build_test_passport(overrides = {})
    payload = {
      iss: "https://account.test",
      sub: "usr_test123",
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: "tok_test",
      user: { email: "test@example.com", name: "Test", platform_role: "none", mfa_verified: true }
    }.merge(overrides)

    token = JWT.encode(payload, KEY, "ES256", { kid: "test_key" })
    # Stub verification to skip JWKS fetch
    allow(IdpRails).to receive(:verify!).and_return(IdpRails::Passport.new(payload))
    token
  end
end

RSpec.configure do |config|
  config.include IdpRailsHelper, type: :request
end
```

Then in your request specs:

```ruby
RSpec.describe "Products API", type: :request do
  it "lists products" do
    token = build_test_passport

    get "/products", headers: { "Authorization" => "Bearer #{token}" }

    expect(response).to have_http_status(:ok)
  end
end
```
