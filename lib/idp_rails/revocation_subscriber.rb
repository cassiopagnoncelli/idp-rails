# frozen_string_literal: true

require "monitor"

module IdpRails
  # Subscribes to token revocation events and maintains an in-memory
  # blocklist of revoked user UUIDs. Entries auto-expire after the access
  # token TTL (15 minutes by default).
  #
  # An entry blocks the tokens that EXISTED when the revocation happened, not
  # the subject itself: each one carries the revocation instant, and a token
  # is refused only when it was issued at or before it. Blocking the subject
  # outright is the same sentence with a much longer reach — it also refuses
  # every token minted afterwards, so a user who signs out and straight back
  # in presents a legitimately fresh passport and is turned away for the rest
  # of the window. Signing in again cannot clear that, because the next
  # sign-out re-arms it; the console reads the 401s as "your session has
  # expired" and says so on every surface at once.
  #
  # Supports two transports (exclusive-or):
  #   - RabbitMQ (preferred) — uses a fanout exchange with ephemeral queues
  #   - Redis pub/sub (fallback) — classic channel subscription
  #
  # If +rabbitmq_url+ is configured, RabbitMQ is used; otherwise Redis.
  #
  # Usage:
  #   subscriber = IdpRails::RevocationSubscriber.new(redis: Redis.new)
  #   subscriber.start  # spawns a background thread
  #
  #   subscriber.revoked?("usr_abc123", issued_at: passport.issued_at, sid: passport.sid)
  #
  #   subscriber.stop   # clean shutdown
  class RevocationSubscriber
    include MonitorMixin

    # Default retention for a blocklist entry (seconds). An entry only has to
    # outlive the newest token it could still be covering, which is one access
    # token TTL — configure `blocklist_ttl` to match idp's JWT_ACCESS_TOKEN_TTL
    # when that has been moved off its own 15-minute default, or revoked tokens
    # come back to life early.
    BLOCKLIST_TTL = 900 # 15 minutes

    # RabbitMQ fanout exchange name.
    EXCHANGE_NAME = "idp.token_revocations"

    # How long #stop waits for the subscriber thread before leaving it to the
    # process teardown (seconds).
    JOIN_TIMEOUT = 5

    # First wait before reconnecting to the broker (seconds), doubling from
    # there up to RECONNECT_MAX_DELAY.
    RECONNECT_BASE_DELAY = 5

    # Ceiling on the reconnect wait (seconds). A failure that is really
    # permanent should settle into a line a minute, not one every five seconds
    # for as long as the process lives.
    RECONNECT_MAX_DELAY = 60

    # How long to wait before asking idp again for a window whose replay
    # failed (seconds). Slower than the broker retry on purpose — see
    # #catch_up_retry_loop.
    CATCH_UP_RETRY_DELAY = 30

    # The key a subject-wide revocation is filed under: one that named no
    # session, so it covers every token the subject holds.
    ALL_SESSIONS = nil

    # How ALL_SESSIONS is spelled in the Redis hash, which has no nil field
    # name. idp's sids are alphanumeric, so this cannot collide with one.
    ALL_SESSIONS_FIELD = "*"

    # Key segment the shared blocklist lives under, after the configured
    # namespace: "<namespace>:revocations:<user_uuid>".
    REVOCATION_KEY_SEGMENT = "revocations"

    # @param store [Object, nil] a ready Redis-compatible connection for the
    #   shared blocklist. Built from the redis config when omitted; passing one
    #   is how an app hands over a pooled connection (and how specs hand over a
    #   double), never the connection SUBSCRIBE is blocking.
    # @param catch_up [#call, nil] asks idp for the revocations of a window —
    #   see #catch_up!. Injected rather than built here on purpose: fetching it
    #   needs a service client's id, secret and token endpoint, and a
    #   verification library has no business carrying credential config. The
    #   consuming app already has that client; it passes a callable that uses it.
    def initialize(redis: nil, channel: nil, config: IdpRails.configuration, store: nil,
                   catch_up: nil)
      super() # MonitorMixin
      @config = config
      @redis_config = redis || config.redis
      @rabbitmq_url = config.rabbitmq_url
      @channel = channel || config.revocation_channel
      @catch_up = catch_up || config.revocation_catch_up
      # { "usr_xxx" => { deadline: <monotonic>, cutoffs: { sid_or_nil => <unix secs> } } }
      @blocklist = {}
      @thread = nil
      @running = false
      # Set when the connection drops, cleared once the replay after it lands.
      # `start` has already rehydrated and caught up, so the FIRST subscribe
      # has nothing to replay — only a later one does.
      @reconnecting = false
      # The window a failed replay still owes, pinned at the moment it was
      # computed. Recomputing it on the retry would slide the window forward
      # by however long idp stayed down, and skip the oldest part of the very
      # gap being retried.
      @catch_up_owed_since = nil
      @catch_up_thread = nil
      @bunny_connection = nil
      # A SECOND connection, distinct from the one subscribe_loop_redis blocks
      # in SUBSCRIBE: a subscribed connection accepts no other commands.
      @store_redis = store || build_store_redis
    end

    # Is the given token revoked? The subject names WHOSE tokens were revoked,
    # `issued_at` says whether THIS one is old enough to be among them, and
    # `sid` says whether it belongs to the session that was ended.
    #
    # A token issued after the revocation instant post-dates the event and is
    # not covered by it — that is the fresh passport a user holds after
    # signing back in. Omitting `issued_at` cannot make that distinction, so
    # it fails closed and blocks the subject outright.
    #
    # A session-scoped event (idp named a `sid`) leaves the subject's OTHER
    # sessions alone: signing out on a laptop is not a reason to refuse the
    # phone. A token carrying no `sid` cannot be matched either way, so it
    # fails closed against any session-scoped entry.
    #
    # @param user_uuid [String]
    # @param issued_at [Time, Integer, nil] the token's `iat`
    # @param sid [String, nil] the token's `sid`
    # @return [Boolean]
    def revoked?(user_uuid, issued_at: nil, sid: nil)
      synchronize do
        entry = @blocklist[user_uuid]
        return false unless entry

        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > entry[:deadline]
          @blocklist.delete(user_uuid)
          return false
        end

        return true if issued_at.nil?

        covers?(entry[:cutoffs], issued_at.to_i, sid)
      end
    end

    # Start the background subscriber thread.
    #
    # Rehydrates first, then catches up. Revocations arrive over pub/sub, which
    # replays nothing: a process that was starting, deploying or reconnecting
    # when one was published never hears about it, and that once meant honouring
    # a revoked token for the rest of its lifetime.
    #
    # Reading the shared blocklist back covers every restart with a LIVE
    # SIBLING — some process received the event and wrote it through. Asking
    # idp covers the case no store can: every process down at once, so nobody
    # was there to write anything through and the event is simply gone.
    #
    # Both run before the subscriber thread exists, and therefore before the
    # first request can land. That ordering is the point — a blocklist filled
    # in afterwards would leave open exactly the window being closed.
    #
    # The `@running` claim comes FIRST, before either replay. Two reasons, and
    # both were bugs: a second `start` used to re-run a paged catch-up against
    # idp before discovering it had nothing to do, and a catch-up that failed
    # could not queue its own retry, because `schedule_catch_up_retry` rightly
    # refuses to arm one for a subscriber that is not up — which left the boot
    # replay, the exact path the retry exists for, as the one path without it.
    def start
      synchronize do
        return self if @running

        @running = true
      end

      adopt_published_retention!
      rehydrate!
      catch_up_from!(catch_up_window_start)

      synchronize do
        @thread = Thread.new { subscribe_loop }
        @thread.abort_on_exception = false
      end

      warn_missing_catch_up
      @config.logger.info("[IdpRails] Revocation subscriber started on channel: #{@channel}")
      self
    end

    # Stop the background subscriber thread.
    #
    # Shutdown never raises. Consumers call this from `at_exit`, where an
    # exception is not a message — it is the process's exit status, applied
    # after the work the process was run for has already succeeded. A rake task
    # that dropped both databases and printed so still exited 1, because the
    # subscriber it never used had died in the background.
    def stop
      synchronize { @running = false }

      close_transport
      await_thread
      await_catch_up_thread
      @config.logger.info("[IdpRails] Revocation subscriber stopped")
    end

    # Check if the subscriber is running.
    def running?
      synchronize { @running && @thread&.alive? }
    end

    # Manually add a user to the blocklist (useful for testing).
    #
    # `revoked_at` is the instant the grants were revoked — tokens issued at
    # or before it are refused, later ones are not. It defaults to now, which
    # is what a caller reaching for this without one means.
    #
    # `sid` narrows the entry to one session. Omit it for the revocations that
    # genuinely end everything (password change, suspension, sign out
    # everywhere) — which is also what an idp too old to publish `sid` means.
    def block!(user_uuid, ttl: nil, revoked_at: nil, sid: ALL_SESSIONS)
      cutoff = to_unix(revoked_at) || Time.now.to_i
      retention = ttl || @config.blocklist_ttl
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + retention

      merged = synchronize do
        entry = @blocklist[user_uuid] || { deadline: deadline, cutoffs: {} }
        # Overlapping revocations: the widest window and, per session, the
        # latest cutoff win, so an earlier event can never narrow a later one.
        entry[:deadline] = [ deadline, entry[:deadline] ].max
        entry[:cutoffs][sid] = [ cutoff, entry[:cutoffs][sid] ].compact.max
        @blocklist[user_uuid] = entry
        entry[:cutoffs][sid]
      end

      persist(user_uuid, sid, merged, retention)
    end

    # Remove a user from the blocklist (e.g., after a fresh login).
    def unblock!(user_uuid)
      synchronize { @blocklist.delete(user_uuid) }
      forget(user_uuid)
    end

    # Clear the blocklist (useful for testing).
    def clear!
      synchronize { @blocklist = {} }
      each_stored_key { |key| @store_redis.del(key) }
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not clear stored revocations: #{e.message}")
    end

    private

    # Closes whichever transport the subscriber opened, if it is in a state
    # that can be closed.
    #
    # `@bunny_connection` is assigned by `Bunny.new` — which only builds the
    # session — and the AMQP handshake happens later, inside `#start`. A Bunny
    # session reports `open?` while that handshake is still in flight, so a
    # short-lived process (`rails runner`, a one-shot rake task) that exits
    # mid-connect used to close a half-open session and wait for a close-ok
    # that nobody was ever going to send: `Timeout::Error`, out of `at_exit`,
    # on a process whose actual work had finished.
    #
    # A session that never finished connecting has nothing worth closing — the
    # socket dies with the process — so it is left alone. Anything else that
    # goes wrong on the way down is a warning: shutdown is the one path where
    # raising cannot help anyone.
    def close_transport
      if @bunny_connection
        return if @bunny_connection.respond_to?(:connecting?) && @bunny_connection.connecting?

        @bunny_connection.close if @bunny_connection.open?
      else
        @subscriber_redis&.close
      end
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not close the revocation transport: #{e.message}")
    end

    # Waits for the subscriber thread, without adopting its fate.
    #
    # `Thread#join` re-raises in the CALLER whatever killed the thread. The
    # subscribe loops log their own failures, so re-raising here adds nothing
    # but a non-zero exit status for a process that was only shutting down.
    # `Exception` rather than `StandardError` on purpose: a thread can just as
    # well have died on a `LoadError`, which is a `ScriptError`.
    def await_thread
      @thread&.join(JOIN_TIMEOUT)
    rescue Exception => e
      @config.logger.debug("[IdpRails] Revocation subscriber thread ended with: #{e.class}: #{e.message}")
    end

    # The one retry site, and the only thing standing between a transport
    # failure and a blocklist that never hears another word.
    #
    # It used to be two rescue ladders, one per transport, each retrying its
    # own connection-class errors and each ending in a bare `rescue
    # StandardError` that logged once and let the thread exit. Everything else
    # — a Redis ACL refusing SUBSCRIBE, a Bunny surprise, an auth failure that
    # was transient — killed the subscriber permanently. The app carried on
    # serving requests against a blocklist frozen at that instant, and
    # `running?` was never consulted by anyone, so nothing anywhere said so.
    # Failing open is the right policy for revocation; failing open SILENTLY,
    # for the rest of the process's life, is not.
    #
    # So: retry everything. The single exception is `LoadError`, which means
    # the driver gem is not installed — no amount of waiting installs it, and
    # a loop around that would be a log line every minute forever.
    def subscribe_loop
      attempt = 0

      while running_flag?
        begin
          @rabbitmq_url ? subscribe_rabbitmq : subscribe_redis
          # A subscribe that RETURNS rather than raises had its transport
          # closed from under it — `stop` does exactly that, and the loop
          # condition below is what tells the two cases apart.
          attempt = 0
        rescue LoadError
          # Permanent, and the only permanent one. Named per transport because
          # "uninitialized constant Bunny" is what a consumer used to get, and
          # it says nothing about the gem that is actually missing.
          @config.logger.warn(
            "[IdpRails] #{driver_gem} gem unavailable — revocations will not be received over #{transport_name}"
          )
          return
        rescue StandardError => e
          @config.logger.error("[IdpRails] Revocation subscriber error on #{transport_name}: #{e.class}: #{e.message}")
        end

        break unless running_flag?

        # Whatever ended the subscription, this process is off the channel and
        # the next successful subscribe owes a replay.
        note_disconnect

        delay = reconnect_delay(attempt)
        attempt += 1
        @config.logger.error("[IdpRails] Revocation subscriber reconnecting to #{transport_name} in #{delay.round(1)}s")
        sleep delay
      end
    end

    def running_flag?
      synchronize { @running }
    end

    def transport_name
      @rabbitmq_url ? "RabbitMQ" : "Redis pub/sub"
    end

    def driver_gem
      @rabbitmq_url ? "bunny" : "redis"
    end

    # Exponential backoff from the flat 5s this used to sleep, capped so a
    # permanent-looking failure (a wrong Redis ACL, a vhost that does not
    # exist) settles into a minute rather than logging every five seconds
    # forever. Half the delay is jitter, so a fleet that lost the broker
    # together does not come back in lockstep and knock it over again.
    def reconnect_delay(attempt)
      capped = [ RECONNECT_BASE_DELAY * (2**[ attempt, 8 ].min), RECONNECT_MAX_DELAY ].min
      (capped / 2.0) + (rand * capped / 2.0)
    end

    # Remember that this process went off the channel, so the next successful
    # subscribe knows to replay rather than simply carry on.
    def note_disconnect
      synchronize { @reconnecting = true }
    end

    def reconnecting?
      synchronize { @reconnecting }
    end

    # Replay what could not be heard while this process was off the channel.
    #
    # The same two sources `start` uses, for the same reasons: the shared
    # blocklist holds what a live sibling received and wrote through, and idp
    # still holds the window nobody was up to hear. Pub/sub redelivers neither.
    #
    # This was the hole: a reconnect resubscribed and nothing more, so every
    # revocation published during an outage was honoured as if it had never
    # happened — for the rest of each affected token's life, with the
    # subscriber reporting itself perfectly healthy throughout.
    #
    # Both sources already degrade to a warning of their own, so this cannot
    # fail the subscription it has just recovered.
    def recover_missed!
      @config.logger.info("[IdpRails] Reconnected — replaying revocations missed while away")
      rehydrate!
      catch_up_from!(catch_up_window_start)
      synchronize { @reconnecting = false }
    end

    # Neither of these rescues any more: the supervision loop above is the one
    # retry site, and a failure here is something it needs to see. They were
    # also where a subtle hazard lived — matching a `rescue` clause evaluates
    # the constants it names, so a `rescue Bunny::…` on the way out of a failed
    # `require "bunny"` raised "uninitialized constant Bunny" over the top of
    # the LoadError that was the actual news. With no per-transport clause
    # left, there is nothing to order wrongly.
    def subscribe_redis
      require "redis"

      @subscriber_redis = build_redis
      @subscriber_redis.subscribe(@channel) do |on|
        # Fires when the channel subscription is confirmed — the first moment
        # nothing more can be missed, and therefore the moment to replay what
        # already was. Redis has no pre-subscription buffer to bind to the way
        # the fanout does, so this is as early as the replay can honestly run.
        on.subscribe do
          recover_missed! if reconnecting?
        end

        on.message do |_channel, message|
          handle_message(message)
        end
      end
    end

    def subscribe_rabbitmq
      require "bunny"

      @bunny_connection = Bunny.new(@rabbitmq_url)
      @bunny_connection.start

      ch = @bunny_connection.create_channel
      exchange = ch.fanout(EXCHANGE_NAME, durable: true)
      queue = ch.queue("", exclusive: true, auto_delete: true)
      queue.bind(exchange)

      @config.logger.info("[IdpRails] Revocation subscriber bound to RabbitMQ exchange: #{EXCHANGE_NAME}")

      # After the bind and before the subscribe, which is the exact window this
      # belongs in: the broker holds everything published from the bind onwards,
      # so nothing more can be missed, and the replay below covers everything
      # before it. Draining the queue starts a moment later, none the worse for
      # the wait.
      recover_missed! if reconnecting?

      queue.subscribe(block: true) do |_delivery_info, _properties, payload|
        handle_message(payload)
      end
    end

    def handle_message(message)
      data = JSON.parse(message)
      return unless apply(data)

      sid = data["sid"].to_s.empty? ? ALL_SESSIONS : data["sid"]
      scope = sid ? "session #{sid}" : "all sessions"
      @config.logger.info("[IdpRails] User revoked: #{data['sub']} (#{scope}, reason: #{data['reason']})")
    rescue JSON::ParserError => e
      @config.logger.warn("[IdpRails] Invalid revocation message: #{e.message}")
    end

    # Records one revocation, whichever way it arrived.
    #
    # A live event and a replayed one are the same three facts, so they take
    # the same path — the catch-up cannot drift from the subscriber it is
    # backstopping. Either spelling of the keys is read: the live event is
    # JSON with string keys, while the catch-up callable belongs to the app,
    # and JSON parsers there commonly symbolize.
    #
    # idp stamps `revoked_at` off the same clock that stamps `iat`, so the two
    # compare exactly. An unreadable or absent stamp falls back to now, which
    # fails closed: the subject re-authenticates and the fresh token, issued
    # after the cutoff, is honoured.
    #
    # `sid` names the session idp actually ended. Absent, the revocation is
    # subject-wide — either one that genuinely ends everything, or an idp too
    # old to say which session, and both must fail closed.
    #
    # Anything that is not a mapping is refused rather than raised on. A
    # garbled payload must cost one message, never the subscribe loop it
    # arrived on.
    def apply(data)
      data = data.to_h if data.respond_to?(:to_h) && !data.is_a?(Array)
      return false unless data.is_a?(Hash)

      user_uuid = data["sub"] || data[:sub]
      return false unless user_uuid

      sid = (data["sid"] || data[:sid]).to_s
      block!(user_uuid,
             revoked_at: data["revoked_at"] || data[:revoked_at],
             sid: sid.empty? ? ALL_SESSIONS : sid)
      true
    end

    # Ask idp for the revocations of the window this blocklist retains, and
    # record the ones this process never heard.
    #
    # The last durability gap. Pub/sub is fire-and-forget, and the shared
    # blocklist is only ever written by a process that RECEIVED an event — so
    # when every consumer process was down at once, nobody wrote anything
    # through and the revocation is gone from both. idp still has it, because
    # every publish site stamps the row before it publishes. The fix is to ask.
    #
    # The callable takes the window start as unix seconds and returns the
    # revocations from it onwards — an enumerable of { sub:, sid:, revoked_at: },
    # the same three facts a live event carries. It is the app's, not the
    # gem's: fetching them needs a service client's credentials, and a
    # verification library has no business holding those.
    #
    # Degrades to a warning, like everything else on this path. An idp that
    # cannot be reached at boot costs this process the events it missed; it
    # must never cost it the ability to start. The return value is what stops
    # the warning being the end of the story — `catch_up_from!` keeps the
    # window owed until one of these comes back true.
    #
    # An idp that ANSWERED has caught this process up, whatever the answer
    # said: an empty window, entries whose shape has drifted, all of it. None
    # of those are fixed by asking the same question again.
    #
    # @return [Boolean] whether the window was actually replayed
    def catch_up!(since)
      return true unless @catch_up

      applied = Array(@catch_up.call(since)).count { |entry| apply(entry) }

      @config.logger.info(
        "[IdpRails] Caught up #{applied} revocation(s) from idp since #{since}"
      )
      true
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not catch up on revocations: #{e.message}")
      false
    end

    # The oldest revocation still worth asking for: one retention window back,
    # because an entry older than that has already lapsed everywhere.
    def catch_up_window_start
      Time.now.to_i - @config.blocklist_ttl
    end

    # Replay one window, and keep owing it until a replay actually lands.
    #
    # An unreachable idp used to cost the window permanently — one warning,
    # and the events nobody was up to hear were honoured for the rest of their
    # lives. It is now retried until it succeeds, which matters most in the
    # case the catch-up exists for: the whole fleet down at once, coming back
    # while idp is still on its way up.
    def catch_up_from!(since)
      # An outstanding window is never narrowed by a newer one. `catch_up!`
      # runs every entry through `apply`, which merges by max on both the
      # deadline and the per-session cutoff, so replaying more than is missing
      # costs nothing — while replaying less loses the difference for good.
      since = [ since, synchronize { @catch_up_owed_since } ].compact.min

      if catch_up!(since)
        synchronize { @catch_up_owed_since = nil }
        return
      end

      synchronize { @catch_up_owed_since = since }
      schedule_catch_up_retry
    end

    # One retry thread at a time, for as long as a window is owed and this
    # subscriber is up.
    #
    # A thread rather than a slot in the subscribe loop, because that loop
    # spends its life blocked in SUBSCRIBE and the two failures are
    # independent: a healthy broker with an unreachable idp is exactly the
    # shape this exists for, and it leaves the subscribe loop with nothing to
    # do and nowhere to notice.
    def schedule_catch_up_retry
      synchronize do
        return unless @running
        return if @catch_up_thread&.alive?

        @config.logger.warn(
          "[IdpRails] revocation catch-up still owed from #{@catch_up_owed_since}, " \
          "retrying every #{CATCH_UP_RETRY_DELAY}s"
        )
        @catch_up_thread = Thread.new { catch_up_retry_loop }
        @catch_up_thread.abort_on_exception = false
      end
    end

    # Ask again, on a slower cadence than the broker retry on purpose: a
    # catch-up is a paged server-to-server call whose window only grows while
    # it is owed, and hammering an idp that is still coming back up is how a
    # recovering identity provider gets held down by its own clients.
    def catch_up_retry_loop
      while running_flag?
        sleep CATCH_UP_RETRY_DELAY

        since = synchronize { @catch_up_owed_since }
        # A reconnect's own replay may have paid it in the meantime.
        break if since.nil?
        break unless running_flag?

        next unless catch_up!(since)

        synchronize { @catch_up_owed_since = nil }
        @config.logger.info("[IdpRails] revocation catch-up recovered the window owed since #{since}")
        break
      end
    end

    def await_catch_up_thread
      thread = synchronize { @catch_up_thread }
      thread&.kill
      thread&.join(JOIN_TIMEOUT)
    rescue Exception => e # rubocop:disable Lint/RescueException
      @config.logger.debug("[IdpRails] Revocation catch-up thread ended with: #{e.class}: #{e.message}")
    end

    # idp publishes the number a blocklist entry has to outlive. Adopt it when
    # it is longer than what this app configured, and never when it is shorter.
    #
    # The two numbers live in different systems and used to match only by
    # coincidence — idp's JWT_ACCESS_TOKEN_TTL and this gem's blocklist_ttl,
    # both 900 by default, with nothing anywhere to notice when one moved.
    # Raise idp's to 1800 and every consumer silently resurrected revoked
    # tokens for the last 15 minutes of their lives.
    #
    # Widen only: a longer retention configured here is someone's deliberate
    # choice and a smaller published value must not undo it. Discovery being
    # unreachable leaves the configured value exactly as it was — this refines
    # a boot, it does not become a new dependency of one.
    def adopt_published_retention!
      published = @config.discovered_access_token_ttl
      return if published.nil? || published <= @config.blocklist_ttl

      @config.logger.info(
        "[IdpRails] Widening blocklist retention #{@config.blocklist_ttl}s -> #{published}s: " \
        "idp mints access tokens valid that long, and a revoked one must not outlive its blocklist entry"
      )
      @config.blocklist_ttl = published
    end

    # The catch-up is optional, and it is also the ONLY recovery from an
    # outage that took every consumer process down at once — the shared
    # blocklist is written exclusively by a process that received an event, so
    # when none did, it holds nothing to rehydrate from. An app that
    # configured a transport and no catch-up has covered the common failure
    # and left the total one open, which is worth one line at boot.
    def warn_missing_catch_up
      return if @catch_up

      @config.logger.warn(
        "[IdpRails] No revocation_catch_up configured — revocations published while every " \
        "process of this app was down cannot be recovered, and will be honoured until they expire"
      )
    end

    # Do any of a subject's live revocations cover this token?
    #
    # A sid-less token cannot be matched to a session entry, so it is refused
    # by any of them — the same answer the subject-wide blocklist gave before
    # sessions were distinguished.
    def covers?(cutoffs, issued_at, sid)
      wide = cutoffs[ALL_SESSIONS]
      return true if wide && issued_at <= wide

      return cutoffs.any? { |key, cutoff| !key.nil? && issued_at <= cutoff } if sid.nil?

      cutoff = cutoffs[sid]
      !cutoff.nil? && issued_at <= cutoff
    end

    # Unix seconds from an ISO8601 string, a Time, or an integer. nil for
    # anything unreadable, so a malformed stamp falls back to arrival rather
    # than to 1970 (which would block nothing at all).
    def to_unix(value)
      case value
      when nil then nil
      when Time then value.to_i
      when Integer then value
      when String
        begin
          Time.at(Integer(value)).to_i
        rescue ArgumentError, TypeError
          begin
            require "time"
            Time.iso8601(value).to_i
          rescue ArgumentError
            nil
          end
        end
      end
    end

    # --- Shared blocklist ---------------------------------------------------
    #
    # The in-memory blocklist is per-process, so on its own it forgets every
    # revocation the instant a pod restarts. These keep a copy where the next
    # process can find it: one hash per subject, field = sid (or
    # ALL_SESSIONS_FIELD), value = that session's cutoff, and the key's TTL
    # carrying the retention window so an entry lapses in Redis exactly as it
    # does in memory.
    #
    # Every one of them degrades to a warning. An unreachable Redis costs
    # durability; it must never cost the in-memory blocklist already doing its
    # job on this process.

    def persist(user_uuid, sid, cutoff, retention)
      return unless @store_redis

      key = store_key(user_uuid)
      @store_redis.hset(key, sid || ALL_SESSIONS_FIELD, cutoff)
      # The key has to outlive the newest token any of its cutoffs could still
      # cover, so a longer window extends it and a shorter one leaves it be.
      current = @store_redis.ttl(key)
      @store_redis.expire(key, retention) if current.nil? || current < retention
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not persist revocation for #{user_uuid}: #{e.message}")
    end

    def forget(user_uuid)
      return unless @store_redis

      @store_redis.del(store_key(user_uuid))
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not drop stored revocation for #{user_uuid}: #{e.message}")
    end

    def rehydrate!
      return unless @store_redis

      restored = 0
      each_stored_key do |key|
        ttl = @store_redis.ttl(key)
        next unless ttl.is_a?(Integer) && ttl.positive?

        cutoffs = @store_redis.hgetall(key)
        next if cutoffs.nil? || cutoffs.empty?

        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ttl
        synchronize do
          @blocklist[key.delete_prefix(store_key_prefix)] = {
            deadline: deadline,
            cutoffs: cutoffs.to_h do |field, value|
              [ field == ALL_SESSIONS_FIELD ? ALL_SESSIONS : field, value.to_i ]
            end
          }
        end
        restored += 1
      end

      @config.logger.info("[IdpRails] Rehydrated #{restored} revocation(s) from the shared blocklist") if restored.positive?
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not rehydrate revocations: #{e.message}")
    end

    def each_stored_key
      return unless @store_redis

      cursor = "0"
      loop do
        cursor, keys = @store_redis.scan(cursor, match: "#{store_key_prefix}*", count: 100)
        Array(keys).each { |key| yield key }
        break if cursor.to_s == "0"
      end
    end

    def store_key(user_uuid)
      "#{store_key_prefix}#{user_uuid}"
    end

    def store_key_prefix
      @store_key_prefix ||=
        if @config.cache_redis_namespace
          "#{@config.cache_redis_namespace}:#{REVOCATION_KEY_SEGMENT}:"
        else
          "#{REVOCATION_KEY_SEGMENT}:"
        end
    end

    # A connection of its own, and only if the redis gem is actually there:
    # a RabbitMQ deployment never loads it, and losing durability is a warning
    # rather than a boot failure.
    def build_store_redis
      return nil unless @redis_config

      require "redis"
      build_redis
    rescue LoadError
      @config.logger.warn("[IdpRails] redis gem unavailable — revocations will not survive a restart")
      nil
    end

    def build_redis
      case @redis_config
      when nil
        Redis.new
      when String
        Redis.new(url: @redis_config)
      when Hash
        Redis.new(**@redis_config)
      else
        # Assume it's a Redis-compatible instance — but we need a fresh connection
        # for subscribe (blocking). Clone the config.
        Redis.new(url: @redis_config.connection[:id])
      end
    end
  end
end
