# frozen_string_literal: true

require "monitor"

module MyAccount
  module JWT
    # Subscribes to the MyAccount Redis pub/sub revocation channel and maintains
    # an in-memory blocklist of revoked user UUIDs. Entries auto-expire after
    # the access token TTL (15 minutes by default).
    #
    # Usage:
    #   subscriber = MyAccount::JWT::RevocationSubscriber.new(redis: Redis.new)
    #   subscriber.start  # spawns a background thread
    #
    #   subscriber.revoked?("usr_abc123")  # => true/false
    #
    #   subscriber.stop   # clean shutdown
    class RevocationSubscriber
      include MonitorMixin

      # How long to keep entries in the blocklist (seconds).
      # Should match the access token TTL.
      BLOCKLIST_TTL = 900 # 15 minutes

      def initialize(redis: nil, channel: nil, config: MyAccount::JWT.configuration)
        super() # MonitorMixin
        @config = config
        @redis_config = redis || config.redis
        @channel = channel || config.revocation_channel
        @blocklist = {} # { "usr_xxx" => expires_at_monotonic }
        @thread = nil
        @running = false
      end

      # Is the given user UUID currently in the revocation blocklist?
      #
      # @param user_uuid [String]
      # @return [Boolean]
      def revoked?(user_uuid)
        synchronize do
          deadline = @blocklist[user_uuid]
          return false unless deadline

          if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
            @blocklist.delete(user_uuid)
            return false
          end

          true
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

        @config.logger.info("[MyAccount::JWT] Revocation subscriber started on channel: #{@channel}")
        self
      end

      # Stop the background subscriber thread.
      def stop
        synchronize { @running = false }
        @subscriber_redis&.close
        @thread&.join(5)
        @config.logger.info("[MyAccount::JWT] Revocation subscriber stopped")
      end

      # Check if the subscriber is running.
      def running?
        synchronize { @running && @thread&.alive? }
      end

      # Manually add a user to the blocklist (useful for testing).
      def block!(user_uuid, ttl: BLOCKLIST_TTL)
        synchronize do
          @blocklist[user_uuid] = Process.clock_gettime(Process::CLOCK_MONOTONIC) + ttl
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
        require "redis"

        @subscriber_redis = build_redis
        @subscriber_redis.subscribe(@channel) do |on|
          on.message do |_channel, message|
            handle_message(message)
          end
        end
      rescue Redis::BaseConnectionError => e
        if synchronize { @running }
          @config.logger.error("[MyAccount::JWT] Revocation subscriber connection lost: #{e.message}, reconnecting in 5s...")
          sleep 5
          retry
        end
      rescue => e
        @config.logger.error("[MyAccount::JWT] Revocation subscriber error: #{e.message}")
      end

      def handle_message(message)
        data = JSON.parse(message)
        user_uuid = data["sub"]
        return unless user_uuid

        block!(user_uuid)
        @config.logger.info("[MyAccount::JWT] User revoked: #{user_uuid} (reason: #{data['reason']})")
      rescue JSON::ParserError => e
        @config.logger.warn("[MyAccount::JWT] Invalid revocation message: #{e.message}")
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
end
