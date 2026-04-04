# idp-jwt

JWT verification client for sister apps authenticating against the Idp identity provider.

Handles JWKS fetching/caching, ES256 signature verification, claim validation, and optional real-time token revocation via Redis pub/sub.

## Installation

Add to your Gemfile:

```ruby
gem "idp-jwt", path: "../idp/gems/idp-jwt"
```

For Rails apps, require the Rails integration instead of the base library:

```ruby
# config/application.rb or an initializer
require "idp/jwt/rails"
```

The Railtie auto-configures from environment variables (`IDP_JWKS_URL`, `IDP_JWT_ISSUER`) and wires up the revocation subscriber if Redis is configured.

## Configuration

```ruby
Idp::JWT.configure do |c|
  # Required: the Idp JWKS endpoint.
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"

  # Required: must match the `iss` claim in tokens.
  c.issuer = "https://account.yourcompany.com"

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
  include Idp::JWT::Rails::ControllerConcern

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
require "idp-jwt"

Idp::JWT.configure do |c|
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"
  c.issuer   = "https://account.yourcompany.com"
end

# Returns a Passport or raises Idp::JWT::VerificationError
passport = Idp::JWT.verify!(token)

# Returns a Passport or nil
passport = Idp::JWT.verify(token)
```

## The Passport object

`Idp::JWT.verify!` returns a `Passport` with typed accessors for all token claims:

```ruby
passport = Idp::JWT.verify!(token)

# Identity
passport.user_uuid          # => "usr_a1b2c3d4"
passport.email              # => "alice@example.com"
passport.name               # => "Alice"

# Security
passport.email_verified?    # => true
passport.mfa_verified?      # => true
passport.platform_admin?    # => false

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

Access tokens are ES256-signed JWTs with the following claims:

```json
{
  "iss": "https://account.yourcompany.com",
  "sub": "usr_a1b2c3d4",
  "iat": 1711800000,
  "exp": 1711800900,
  "jti": "tok_f9e8d7c6b5a4",
  "user": {
    "email": "alice@example.com",
    "name": "Alice",
    "email_verified": true,
    "platform_admin": false,
    "mfa_verified": true
  }
}
```

- `user.email_verified` indicates whether the user's email address has been verified.
- `user.mfa_verified` indicates whether the user completed 2FA during this session. Use this to gate sensitive operations.

## Real-time revocation

When enabled, the gem subscribes to a Redis pub/sub channel and maintains an in-memory blocklist of revoked user UUIDs. Entries auto-expire after 15 minutes (the access token TTL).

Idp publishes to this channel when:
- A user's password is changed
- A user is suspended by an admin
- An admin triggers emergency revocation

If a sister app misses an event (restart, Redis blip), the access token still expires naturally within 15 minutes. This is a best-effort acceleration layer, not a hard guarantee.

```ruby
Idp::JWT.configure do |c|
  c.redis = ENV["REDIS_URL"]   # enables the subscriber
  # c.redis = { host: "redis.internal", port: 6379 }  # also works
  # c.redis = Redis.new(...)  # or pass an instance
end
```

The Railtie starts the subscriber automatically on boot and stops it on shutdown.

Without Rails, manage it manually:

```ruby
subscriber = Idp::JWT::RevocationSubscriber.new
subscriber.start   # spawns a background thread
subscriber.stop    # clean shutdown

# Wire it into the verifier
verifier = Idp::JWT::Verifier.new(revocation_subscriber: subscriber)
passport = verifier.verify!(token)
```

## Key rotation

The JWKS client handles key rotation automatically:

1. Keys are cached for 1 hour (configurable via `jwks_cache_ttl`).
2. After the TTL, keys are refreshed in a background thread (no request blocking).
3. If a token arrives signed with an unknown `kid`, the client forces an immediate refresh. This handles the window between Idp rotating a key and the cache expiring.
4. If the `kid` is still unknown after refresh, the token is rejected.

## Exceptions

All exceptions inherit from `Idp::JWT::Error`:

```
Idp::JWT::Error
  Idp::JWT::VerificationError
    Idp::JWT::ExpiredTokenError
    Idp::JWT::InvalidSignatureError
    Idp::JWT::InvalidIssuerError
    Idp::JWT::InvalidAudienceError
    Idp::JWT::RevokedTokenError
```

## Testing

In your test suite, you can build tokens directly without a running Idp instance:

```ruby
# spec/support/idp_jwt.rb
module IdpJwtHelper
  KEY = OpenSSL::PKey::EC.generate("prime256v1")

  def build_test_passport(overrides = {})
    payload = {
      iss: "https://account.test",
      sub: "usr_test123",
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: "tok_test",
      user: { email: "test@example.com", name: "Test", platform_admin: false, mfa_verified: true }
    }.merge(overrides)

    token = JWT.encode(payload, KEY, "ES256", { kid: "test_key" })
    # Stub verification to skip JWKS fetch
    allow(Idp::JWT).to receive(:verify!).and_return(Idp::JWT::Passport.new(payload))
    token
  end
end

RSpec.configure do |config|
  config.include IdpJwtHelper, type: :request
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
