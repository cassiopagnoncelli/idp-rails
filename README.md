# myaccount-jwt

JWT verification client for sister apps authenticating against the MyAccount identity provider.

Handles JWKS fetching/caching, ES256 signature verification, claim validation, account type filtering, and optional real-time token revocation via Redis pub/sub.

## Installation

Add to your Gemfile:

```ruby
gem "myaccount-jwt", path: "../myaccount/gems/myaccount-jwt"
```

For Rails apps, require the Rails integration instead of the base library:

```ruby
# config/application.rb or an initializer
require "myaccount/jwt/rails"
```

The Railtie auto-configures from environment variables (`MYACCOUNT_JWKS_URL`, `MYACCOUNT_JWT_ISSUER`) and wires up the revocation subscriber if Redis is configured.

## Configuration

```ruby
MyAccount::JWT.configure do |c|
  # Required: the MyAccount JWKS endpoint.
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"

  # Required: must match the `iss` claim in tokens.
  c.issuer = "https://account.yourcompany.com"

  # Optional: restrict which account types this app accepts.
  # Tokens scoped to a different type are rejected with 403.
  # Set to nil (default) to accept any type.
  c.accepted_account_types = ["Merchant"]

  # Optional: enable real-time revocation via Redis pub/sub.
  # When a user is suspended or changes their password, MyAccount
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
  c.revocation_channel = "myaccount:token_revocations"

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
  include MyAccount::JWT::Rails::ControllerConcern

  before_action :authenticate!
  before_action :require_account!
end
```

Then use `passport` in your controllers:

```ruby
class ProductsController < ApplicationController
  before_action -> { require_scope!("write") }, only: [:create, :update]

  def index
    products = Product.where(merchant_uuid: passport.account_uuid)
    render json: products
  end

  def show
    render json: {
      product: Product.find(params[:id]),
      accessed_by: passport.user_uuid,
      role: passport.role
    }
  end
end
```

### Available controller helpers

| Method | Description |
|---|---|
| `authenticate!` | Verifies the Bearer token. Returns 401 on failure. |
| `passport` | The verified `Passport` object (available after `authenticate!`). |
| `require_account!` | Returns 403 if no account context is selected. |
| `require_scope!(scope)` | Returns 403 if the token lacks the given scope. |

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
| `account_not_selected` | 403 | Token has no account context (`act` is null). |
| `insufficient_scope` | 403 | Token lacks the required scope. |
| Account type mismatch | 403 | Token is for a different app (e.g., Customer token sent to Merchant app). |

## Usage without Rails

```ruby
require "myaccount-jwt"

MyAccount::JWT.configure do |c|
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"
  c.issuer   = "https://account.yourcompany.com"
end

# Returns a Passport or raises MyAccount::JWT::VerificationError
passport = MyAccount::JWT.verify!(token)

# Returns a Passport or nil
passport = MyAccount::JWT.verify(token)
```

## The Passport object

`MyAccount::JWT.verify!` returns a `Passport` with typed accessors for all token claims:

```ruby
passport = MyAccount::JWT.verify!(token)

# Identity
passport.user_uuid          # => "usr_a1b2c3d4"
passport.email              # => "alice@example.com"
passport.name               # => "Alice"

# Account context (nil if no account selected)
passport.account_selected?  # => true
passport.account_type       # => "Merchant"
passport.account_uuid       # => "mrc_x1y2z3"
passport.membership_uuid    # => "mbr_q1w2e3r4t5y6"
passport.role               # => "admin"

# Security
passport.mfa_verified?      # => true
passport.platform_admin?    # => false

# Scopes (derived from the membership role)
passport.scopes             # => ["read", "write", "admin", "api_keys"]
passport.has_scope?("write") # => true
passport.has_scope?("billing") # => false

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
  "act": {
    "type": "Merchant",
    "uuid": "mrc_x1y2z3",
    "membership_uuid": "mbr_q1w2e3r4t5y6",
    "role": "admin"
  },
  "user": {
    "email": "alice@example.com",
    "name": "Alice",
    "platform_admin": false,
    "mfa_verified": true
  },
  "scopes": ["read", "write", "admin", "api_keys"]
}
```

- `act` is `null` before the user selects an account. These tokens only carry `["identity:read"]` scopes.
- `user.mfa_verified` indicates whether the user completed 2FA during this session. Use this to gate sensitive operations.
- `scopes` are derived from the membership role: owner > admin > member > viewer.

## Real-time revocation

When enabled, the gem subscribes to a Redis pub/sub channel and maintains an in-memory blocklist of revoked user UUIDs. Entries auto-expire after 15 minutes (the access token TTL).

MyAccount publishes to this channel when:
- A user's password is changed
- A user is suspended by an admin
- An admin triggers emergency revocation

If a sister app misses an event (restart, Redis blip), the access token still expires naturally within 15 minutes. This is a best-effort acceleration layer, not a hard guarantee.

```ruby
MyAccount::JWT.configure do |c|
  c.redis = ENV["REDIS_URL"]   # enables the subscriber
  # c.redis = { host: "redis.internal", port: 6379 }  # also works
  # c.redis = Redis.new(...)  # or pass an instance
end
```

The Railtie starts the subscriber automatically on boot and stops it on shutdown.

Without Rails, manage it manually:

```ruby
subscriber = MyAccount::JWT::RevocationSubscriber.new
subscriber.start   # spawns a background thread
subscriber.stop    # clean shutdown

# Wire it into the verifier
verifier = MyAccount::JWT::Verifier.new(revocation_subscriber: subscriber)
passport = verifier.verify!(token)
```

## Key rotation

The JWKS client handles key rotation automatically:

1. Keys are cached for 1 hour (configurable via `jwks_cache_ttl`).
2. After the TTL, keys are refreshed in a background thread (no request blocking).
3. If a token arrives signed with an unknown `kid`, the client forces an immediate refresh. This handles the window between MyAccount rotating a key and the cache expiring.
4. If the `kid` is still unknown after refresh, the token is rejected.

## Exceptions

All exceptions inherit from `MyAccount::JWT::Error`:

```
MyAccount::JWT::Error
  MyAccount::JWT::VerificationError
    MyAccount::JWT::ExpiredTokenError
    MyAccount::JWT::InvalidSignatureError
    MyAccount::JWT::InvalidIssuerError
    MyAccount::JWT::InvalidAudienceError
    MyAccount::JWT::RevokedTokenError
```

## Testing

In your test suite, you can build tokens directly without a running MyAccount instance:

```ruby
# spec/support/myaccount_jwt.rb
module MyAccountJwtHelper
  KEY = OpenSSL::PKey::EC.generate("prime256v1")

  def build_test_passport(overrides = {})
    payload = {
      iss: "https://account.test",
      sub: "usr_test123",
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: "tok_test",
      act: { type: "Merchant", uuid: "mrc_test", membership_uuid: "mbr_test", role: "admin" },
      user: { email: "test@example.com", name: "Test", platform_admin: false, mfa_verified: true },
      scopes: ["read", "write", "admin", "api_keys"]
    }.merge(overrides)

    token = JWT.encode(payload, KEY, "ES256", { kid: "test_key" })
    # Stub verification to skip JWKS fetch
    allow(MyAccount::JWT).to receive(:verify!).and_return(MyAccount::JWT::Passport.new(payload))
    token
  end
end

RSpec.configure do |config|
  config.include MyAccountJwtHelper, type: :request
end
```

Then in your request specs:

```ruby
RSpec.describe "Products API", type: :request do
  it "lists products for the merchant" do
    token = build_test_passport(
      act: { type: "Merchant", uuid: "mrc_abc", membership_uuid: "mbr_1", role: "owner" }
    )

    get "/products", headers: { "Authorization" => "Bearer #{token}" }

    expect(response).to have_http_status(:ok)
  end
end
```
