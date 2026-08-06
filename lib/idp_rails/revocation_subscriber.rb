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
    def start
      rehydrate!
      catch_up!

      synchronize do
        return if @running

        @running = true
        @thread = Thread.new { subscribe_loop }
        @thread.abort_on_exception = false
      end

      @config.logger.info("[IdpRails] Revocation subscriber started on channel: #{@channel}")
      self
    end

    # Stop the background subscriber thread.
    def stop
      synchronize { @running = false }

      if @bunny_connection
        @bunny_connection.close if @bunny_connection.open?
      else
        @subscriber_redis&.close
      end

      @thread&.join(5)
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

    def subscribe_loop
      if @rabbitmq_url
        subscribe_loop_rabbitmq
      else
        subscribe_loop_redis
      end
    end

    def subscribe_loop_redis
      require "redis"

      @subscriber_redis = build_redis
      @subscriber_redis.subscribe(@channel) do |on|
        on.message do |_channel, message|
          handle_message(message)
        end
      end
    rescue Redis::BaseConnectionError => e
      if synchronize { @running }
        @config.logger.error("[IdpRails] Revocation subscriber connection lost: #{e.message}, reconnecting in 5s...")
        sleep 5
        retry
      end
    rescue StandardError => e
      @config.logger.error("[IdpRails] Revocation subscriber error: #{e.message}")
    end

    def subscribe_loop_rabbitmq
      require "bunny"

      @bunny_connection = Bunny.new(@rabbitmq_url)
      @bunny_connection.start

      ch = @bunny_connection.create_channel
      exchange = ch.fanout(EXCHANGE_NAME, durable: true)
      queue = ch.queue("", exclusive: true, auto_delete: true)
      queue.bind(exchange)

      @config.logger.info("[IdpRails] Revocation subscriber bound to RabbitMQ exchange: #{EXCHANGE_NAME}")

      queue.subscribe(block: true) do |_delivery_info, _properties, payload|
        handle_message(payload)
      end
    rescue Bunny::TCPConnectionFailed, Bunny::ConnectionClosedError, Bunny::NetworkFailure => e
      if synchronize { @running }
        @config.logger.error("[IdpRails] RabbitMQ subscriber connection lost: #{e.message}, reconnecting in 5s...")
        sleep 5
        retry
      end
    rescue StandardError => e
      @config.logger.error("[IdpRails] RabbitMQ subscriber error: #{e.message}")
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
    # backstopping. Symbol keys are accepted because the catch-up callable
    # belongs to the app, and JSON parsers there commonly symbolize.
    #
    # idp stamps `revoked_at` off the same clock that stamps `iat`, so the two
    # compare exactly. An unreadable or absent stamp falls back to now, which
    # fails closed: the subject re-authenticates and the fresh token, issued
    # after the cutoff, is honoured.
    #
    # `sid` names the session idp actually ended. Absent, the revocation is
    # subject-wide — either one that genuinely ends everything, or an idp too
    # old to say which session, and both must fail closed.
    def apply(data)
      data = data.to_h.transform_keys(&:to_s) if data.respond_to?(:to_h)
      return false unless data.is_a?(Hash)

      user_uuid = data["sub"]
      return false unless user_uuid

      sid = data["sid"].to_s.empty? ? ALL_SESSIONS : data["sid"]
      block!(user_uuid, revoked_at: data["revoked_at"], sid: sid)
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
    # must never cost it the ability to start.
    def catch_up!
      return unless @catch_up

      since = Time.now.to_i - @config.blocklist_ttl
      applied = Array(@catch_up.call(since)).count { |entry| apply(entry) }

      @config.logger.info(
        "[IdpRails] Caught up #{applied} revocation(s) from idp since #{since}"
      )
    rescue StandardError => e
      @config.logger.warn("[IdpRails] Could not catch up on revocations: #{e.message}")
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
