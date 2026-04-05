# frozen_string_literal: true

require "monitor"

module Idp
  module JWT
    # Subscribes to token revocation events and maintains an in-memory
    # blocklist of revoked user UUIDs. Entries auto-expire after the access
    # token TTL (15 minutes by default).
    #
    # Supports two transports (exclusive-or):
    #   - RabbitMQ (preferred) — uses a fanout exchange with ephemeral queues
    #   - Redis pub/sub (fallback) — classic channel subscription
    #
    # If +rabbitmq_url+ is configured, RabbitMQ is used; otherwise Redis.
    #
    # Usage:
    #   subscriber = Idp::JWT::RevocationSubscriber.new(redis: Redis.new)
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

      # RabbitMQ fanout exchange name.
      EXCHANGE_NAME = "idp.token_revocations"

      def initialize(redis: nil, channel: nil, config: Idp::JWT.configuration)
        super() # MonitorMixin
        @config = config
        @redis_config = redis || config.redis
        @rabbitmq_url = config.rabbitmq_url
        @channel = channel || config.revocation_channel
        @blocklist = {} # { "usr_xxx" => expires_at_monotonic }
        @thread = nil
        @running = false
        @bunny_connection = nil
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

        @config.logger.info("[Idp::JWT] Revocation subscriber started on channel: #{@channel}")
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
        @config.logger.info("[Idp::JWT] Revocation subscriber stopped")
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
          @config.logger.error("[Idp::JWT] Revocation subscriber connection lost: #{e.message}, reconnecting in 5s...")
          sleep 5
          retry
        end
      rescue StandardError => e
        @config.logger.error("[Idp::JWT] Revocation subscriber error: #{e.message}")
      end

      def subscribe_loop_rabbitmq
        require "bunny"

        @bunny_connection = Bunny.new(@rabbitmq_url)
        @bunny_connection.start

        ch = @bunny_connection.create_channel
        exchange = ch.fanout(EXCHANGE_NAME, durable: true)
        queue = ch.queue("", exclusive: true, auto_delete: true)
        queue.bind(exchange)

        @config.logger.info("[Idp::JWT] Revocation subscriber bound to RabbitMQ exchange: #{EXCHANGE_NAME}")

        queue.subscribe(block: true) do |_delivery_info, _properties, payload|
          handle_message(payload)
        end
      rescue Bunny::TCPConnectionFailed, Bunny::ConnectionClosedError, Bunny::NetworkFailure => e
        if synchronize { @running }
          @config.logger.error("[Idp::JWT] RabbitMQ subscriber connection lost: #{e.message}, reconnecting in 5s...")
          sleep 5
          retry
        end
      rescue StandardError => e
        @config.logger.error("[Idp::JWT] RabbitMQ subscriber error: #{e.message}")
      end

      def handle_message(message)
        data = JSON.parse(message)
        user_uuid = data["sub"]
        return unless user_uuid

        block!(user_uuid)
        @config.logger.info("[Idp::JWT] User revoked: #{user_uuid} (reason: #{data['reason']})")
      rescue JSON::ParserError => e
        @config.logger.warn("[Idp::JWT] Invalid revocation message: #{e.message}")
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
