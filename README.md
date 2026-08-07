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

The Railtie auto-configures from environment variables (`IDP_URL`, or the older `IDP_JWKS_URL` / `IDP_JWT_ISSUER`) and wires up the revocation subscriber if Redis is configured.

## Configuration

`discovery_url` is the short version: point it at idp and the JWKS endpoint,
issuer and RP-initiated logout endpoint all come from the document idp already
publishes, instead of from three settings that can drift apart. Anything set
explicitly still wins, so a consumer can adopt it on its own schedule.

Once a document has been fetched it is kept: a later refresh that fails serves
the last one rather than failing the token check with it, since these endpoints
change about never and idp being briefly unreachable is no reason to refuse
valid tokens. With nothing cached yet, `jwks_url` and `issuer` raise an error
naming discovery — they are load-bearing, and answering `nil` only relocates
the failure to `URI(nil)` somewhere far less informative. `end_session_endpoint`
does answer `nil`, because its callers already treat a missing endpoint as
"sign out locally".

```ruby
IdpRails.configure do |c|
  # idp's base url. With it, jwks_url / issuer / end_session_endpoint are
  # optional — they resolve from /.well-known/openid-configuration.
  c.discovery_url = "https://account.yourcompany.com"

  # Required unless discovery_url is set: the Idp JWKS endpoint.
  c.jwks_url = "https://account.yourcompany.com/.well-known/jwks.json"

  # Must match the `iss` claim in tokens. Published by discovery.
  c.issuer = "https://account.yourcompany.com"

  # RP-initiated logout endpoint. Published by discovery; set it only when
  # not using discovery.
  # c.end_session_endpoint = "https://account.yourcompany.com/oauth/end_session"

  # Optional: the expected `aud` claim (idp's single platform audience).
  # Defaults to the issuer string, which matches idp's own default —
  # set explicitly only when idp runs with a custom JWT_AUDIENCE.
  # c.audience = "urn:platform:custom"

  # Optional: enable real-time revocation. When a user is suspended or
  # changes their password, Idp publishes to this channel. The subscriber
  # maintains a 15-minute in-memory blocklist so revoked tokens are rejected
  # immediately rather than waiting for natural expiry. Leave both nil
  # (the default) to disable.
  #
  # RabbitMQ is preferred when both are set; Redis is the fallback for
  # deployments running one and not the other. Both follow the platform's
  # standard fallback chain: the IDP_-prefixed variable names the broker idp
  # publishes on, and the app's own broker is the default, since one broker
  # serves everything in most deployments.
  c.rabbitmq_url = ENV["IDP_RABBITMQ_URL"].presence || ENV["RABBITMQ_URL"].presence
  c.redis = ENV["IDP_REDIS_URL"].presence || ENV["REDIS_URL"].presence

  # --- Defaults (usually fine as-is) ---

  # JWKS cache TTL in seconds. After this period, keys are
  # refreshed in a background thread. Default: 3600 (1 hour).
  c.jwks_cache_ttl = 3600

  # Clock skew tolerance for exp/iat validation. Default: 30s.
  c.clock_skew = 30

  # Redis channel name for revocation events.
  c.revocation_channel = "idp:token_revocations"

  # Optional: how the subscriber asks idp, at startup, for the revocations
  # published while every process was down — the one case no store covers.
  # See "Not missing an event". Default: nil (skipped).
  # c.revocation_catch_up = ->(since) { IdpApiClient.revocations(since: since) }

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

It also honours the event's `sid` when there is one. Idp's RP-initiated logout revokes exactly one grant — one client, one SSO session — so the event names that session and the entry is scoped to it: signing out on a laptop does not refuse the same user's phone. Events that carry no `sid` are subject-wide, which covers both the revocations that genuinely end everything (password change, suspension, sign out everywhere) and an idp too old to publish one. A token carrying no `sid` of its own cannot be matched either way, so it fails closed against any session-scoped entry.

Entries are retained for `blocklist_ttl` (default 900s). An entry only has to outlive the newest token it could still be covering, and one shorter than the token lifetime lets revoked tokens come back to life for the difference — still inside their own validity.

Since 2.12.0 that is no longer yours to keep in step by hand. Idp publishes `access_token_ttl` in its discovery document, and the subscriber widens `blocklist_ttl` to it at startup when the published value is longer, logging when it moves. **Widen only**: a longer value configured here is a deliberate choice and a smaller published one will not undo it. An idp too old to publish it, or a discovery that cannot be read, leaves your configured value exactly as it is.

Before that the two numbers matched only by coincidence — 900 on each side, in two different systems, with nothing anywhere positioned to notice one had moved. Raising idp's `JWT_ACCESS_TOKEN_TTL` silently resurrected revoked tokens on every consumer.

Idp publishes to this channel when:
- A user's password is changed
- A user is suspended by an admin
- A session is ended (RP-initiated logout, `/oauth/revoke`, family replay)
- An admin triggers emergency revocation

```ruby
IdpRails.configure do |c|
  # Either transport enables the subscriber; RabbitMQ wins when both are set.
  c.rabbitmq_url = ENV["IDP_RABBITMQ_URL"].presence || ENV["RABBITMQ_URL"].presence
  c.redis = ENV["IDP_REDIS_URL"].presence || ENV["REDIS_URL"].presence
  # c.redis = { host: "redis.internal", port: 6379 }  # also works
  # c.redis = Redis.new(...)  # or pass an instance

  # Entry retention. Leave it alone: idp publishes its access token TTL and
  # the subscriber widens this to match. Set it only to retain LONGER than
  # idp's tokens live — a smaller published value never narrows it.
  # c.blocklist_ttl = 1800
end
```

The Railtie starts the subscriber automatically on boot and stops it on shutdown. The module helpers `IdpRails.verify` / `IdpRails.verify!` use it automatically (since 2.8.0 — before that they skipped revocation entirely, so callers had to build a `Verifier` by hand). Pass `revocation_subscriber:` to override; an explicit `nil` skips the check.

### The driver gem is yours to add

This gem carries neither `bunny` nor `redis` as a runtime dependency — they are
development dependencies here, and each is required at the point of use, so an
app on one transport never loads the other's driver. Configure a transport and
you must add its gem:

```ruby
gem "bunny"  # c.rabbitmq_url
gem "redis"  # c.redis, and the shared blocklist
```

Without it the subscriber warns and carries on: revocations are not received
(or, for the shared blocklist and the JWKS L2 cache, not shared) and nothing
else changes. Since 2.10.1 that is what actually happens — before it the
missing `bunny` gem surfaced as `uninitialized constant
IdpRails::RevocationSubscriber::Bunny`, which named a constant instead of the
gem, and a missing `redis` gem took the JWKS client's constructor down with an
unhandled `LoadError`.

`#stop` is also silent as of 2.10.1: it neither re-raises whatever killed the
subscriber thread nor closes a broker session that is still mid-handshake.
Consumers call it from `at_exit`, where either one is not a message but the
exit status of a process whose work has already finished — a `rails runner` or
a rake task that did its job and still exited 1.

### Not missing an event

Pub/sub replays nothing. Neither does the RabbitMQ path, which fans out to
`exclusive: true, auto_delete: true` queues that stop existing the moment a
consumer disconnects. A process that was starting, deploying or reconnecting
when a revocation went out simply never hears about it — and used to honour the
revoked token for the rest of its life. Three layers cover that, and each one
closes a case the layer above cannot:

| When the event is published | What saves it |
|---|---|
| Some sibling processes are up | They receive it normally |
| This process restarts afterwards | The **shared blocklist** — every received revocation is mirrored into Redis, and `#start` reads it back before the subscriber thread exists |
| **Every** consumer process is down | **The catch-up** — nobody was there to write anything through, so `#start` asks idp for the window instead |
| This process is up, but off the broker | Both of them again, on the **reconnect** (2.11.0) |
| The broker failed in a way nothing named | The **supervision loop** retries it anyway (2.12.0) |

The first two landed in 2.9.0; before them, a restart forgot every revocation
it had not re-heard.

That last row was a hole until 2.11.0. The loop has always retried a dropped
connection every five seconds, but it resubscribed and stopped there — so a
revocation published during an outage was honoured as though it had never
happened, for the rest of each affected token's life, with `#running?`
reporting perfect health throughout. A reconnect now replays exactly what a
start does.

On the RabbitMQ path that replay runs after the queue is bound and before it is
subscribed: from the bind onwards the broker is already holding everything
published, so that instant is the gap's far edge and the replay covers
everything before it. Redis pub/sub has no equivalent buffer, so there it runs
from the `subscribe` confirmation — as early as it can honestly be claimed that
nothing more is being missed.

The last row was the one that made the others conditional. Until 2.12.0 only
connection-class errors were retried; anything else — a Redis ACL refusing
SUBSCRIBE, a Bunny surprise, an auth failure that would have cleared on its own
— was logged once and the subscriber thread exited, permanently. The app went
on serving requests against a blocklist frozen at that instant, `#running?` was
consulted by nobody, and nothing anywhere said a word. Failing open is the
right policy for revocation; failing open *silently*, for the life of the
process, is not.

There is now one retry site, and it retries everything except `LoadError` — a
missing driver gem is the one failure no amount of waiting fixes. The wait
backs off from 5s to a 60s ceiling with jitter, so a permanent-looking failure
settles into a line a minute rather than one every five seconds, and a fleet
that lost the broker together does not come back in lockstep and knock it over
again.

The shared blocklist needs nothing but `cache_redis_namespace` (so two apps on
one Redis do not collide). Entries expire there exactly as they do in memory.

The catch-up needs a callable, because asking idp means holding a service
client's credentials and this gem verifies tokens — it should not also be where
secrets live. Point it at your own client:

```ruby
IdpRails.configure do |c|
  # Called once at subscriber startup with the window start as unix seconds.
  # Return the revocations from it onwards: an enumerable of
  # { sub:, sid:, revoked_at: } — the same three facts a live event carries.
  c.revocation_catch_up = ->(since) { IdpApiClient.revocations(since: since) }
end
```

Behind it is idp's `GET /api/v1/revocations?since=<unix ts>`, gated on the
`revocations:read` scope of a `client_credentials` grant.

Leaving it nil skips the catch-up, and since 2.12.0 the subscriber warns at
boot when a transport is configured without one. It is worth the line: the
catch-up is the *only* recovery from an outage that took every process of an
app down at once. The shared blocklist is written exclusively by a process that
received an event, so when none did, there is nothing in it to read back.

Both fills run *before* the subscriber thread is spawned, and therefore before
the first request can land: a blocklist filled in afterwards would leave open
exactly the window being closed. Both also degrade to a warning. An unreachable
Redis or idp costs this process the events it missed; it must never cost it the
ability to start.

A catch-up that could not reach idp is retried every 30s until it lands (2.12.0),
against the window it originally owed rather than a freshly computed one — that
would slide forward by however long idp stayed down and skip the oldest part of
the very gap being retried. Slower than the broker's own retry on purpose: a
catch-up is a paged server-to-server call, and an idp coming back up should not
be held down by its own clients. Before 2.12.0 the warning was the end of it,
and the window was lost for good.

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
