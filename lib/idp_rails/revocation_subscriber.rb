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
  #   subscriber.revoked?("usr_abc123", issued_at: passport.issued_at)
  #
  #   subscriber.stop   # clean shutdown
  class RevocationSubscriber
    include MonitorMixin

    # How long to keep entries in the blocklist (seconds).
    # Should match the access token TTL.
    BLOCKLIST_TTL = 900 # 15 minutes

    # RabbitMQ fanout exchange name.
    EXCHANGE_NAME = "idp.token_revocations"

    def initialize(redis: nil, channel: nil, config: IdpRails.configuration)
      super() # MonitorMixin
      @config = config
      @redis_config = redis || config.redis
      @rabbitmq_url = config.rabbitmq_url
      @channel = channel || config.revocation_channel
      # { "usr_xxx" => { deadline: <monotonic>, cutoff: <unix seconds> } }
      @blocklist = {}
      @thread = nil
      @running = false
      @bunny_connection = nil
    end

    # Is the given token revoked? The subject names WHOSE tokens were
    # revoked; `issued_at` says whether THIS one is among them.
    #
    # A token issued after the revocation instant post-dates the event and is
    # not covered by it — that is the fresh passport a user holds after
    # signing back in. Omitting `issued_at` cannot make that distinction, so
    # it fails closed and blocks the subject outright.
    #
    # @param user_uuid [String]
    # @param issued_at [Time, Integer, nil] the token's `iat`
    # @return [Boolean]
    def revoked?(user_uuid, issued_at: nil)
      synchronize do
        entry = @blocklist[user_uuid]
        return false unless entry

        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > entry[:deadline]
          @blocklist.delete(user_uuid)
          return false
        end

        return true if issued_at.nil?

        issued_at.to_i <= entry[:cutoff]
      end
    end

    # Start the background subscriber thread.
    def start
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
    def block!(user_uuid, ttl: BLOCKLIST_TTL, revoked_at: nil)
      cutoff = to_unix(revoked_at) || Time.now.to_i

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ttl

      synchronize do
        entry = @blocklist[user_uuid]
        # Overlapping revocations: the widest window and the latest cutoff
        # win, so an earlier event can never narrow a later one.
        @blocklist[user_uuid] = {
          deadline: [ deadline, entry&.fetch(:deadline) ].compact.max,
          cutoff: [ cutoff, entry&.fetch(:cutoff) ].compact.max
        }
      end
    end

    # Remove a user from the blocklist (e.g., after a fresh login).
    def unblock!(user_uuid)
      synchronize { @blocklist.delete(user_uuid) }
    end

    # Clear the blocklist (useful for testing).
    def clear!
      synchronize { @blocklist = {} }
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
      user_uuid = data["sub"]
      return unless user_uuid

      # idp stamps `revoked_at` off the same clock that stamps `iat`, so the
      # two compare exactly. A publisher old enough not to send it falls back
      # to arrival, which delivery latency keeps within milliseconds of the
      # revocation — and never widens the window the way a skew cushion here
      # would, since that would re-refuse the fast re-login this exists to
      # let through.
      block!(user_uuid, revoked_at: data["revoked_at"])
      @config.logger.info("[IdpRails] User revoked: #{user_uuid} (reason: #{data['reason']})")
    rescue JSON::ParserError => e
      @config.logger.warn("[IdpRails] Invalid revocation message: #{e.message}")
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
