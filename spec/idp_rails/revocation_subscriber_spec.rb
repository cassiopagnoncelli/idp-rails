# frozen_string_literal: true

# Both drivers are development dependencies of this gem: loaded here so the
# doubles can be verified against the real transports, never by the library
# itself outside the transport that is actually configured.
require "bunny"
require "redis"
require "timeout"

RSpec.describe IdpRails::RevocationSubscriber do
  subject(:subscriber) { described_class.new }

  describe '#revoked?' do
    it 'returns false for unknown users' do
      expect(subscriber.revoked?('usr_unknown')).to be false
    end

    it 'returns true for blocked users' do
      subscriber.block!('usr_blocked')
      expect(subscriber.revoked?('usr_blocked')).to be true
    end

    it 'auto-expires entries' do
      subscriber.block!('usr_expiring', ttl: 0.01)
      sleep 0.02
      expect(subscriber.revoked?('usr_expiring')).to be false
    end

    context 'with a token issue time' do
      let(:revoked_at) { Time.now.to_i }

      it 'revokes a token issued before the revocation' do
        subscriber.block!('usr_blocked', revoked_at: revoked_at)
        expect(subscriber.revoked?('usr_blocked', issued_at: revoked_at - 60)).to be true
      end

      it 'revokes a token issued in the same second as the revocation' do
        subscriber.block!('usr_blocked', revoked_at: revoked_at)
        expect(subscriber.revoked?('usr_blocked', issued_at: revoked_at)).to be true
      end

      # The sign-out/sign-in-again case: the new passport post-dates the
      # revocation, so the event it fired never covered it.
      it 'lets through a token issued after the revocation' do
        subscriber.block!('usr_blocked', revoked_at: revoked_at)
        expect(subscriber.revoked?('usr_blocked', issued_at: revoked_at + 1)).to be false
      end

      it 'keeps the later cutoff when a second revocation lands' do
        subscriber.block!('usr_blocked', revoked_at: revoked_at)
        subscriber.block!('usr_blocked', revoked_at: revoked_at + 100)

        expect(subscriber.revoked?('usr_blocked', issued_at: revoked_at + 50)).to be true
      end

      it 'keeps the later cutoff when revocations arrive out of order' do
        subscriber.block!('usr_blocked', revoked_at: revoked_at + 100)
        subscriber.block!('usr_blocked', revoked_at: revoked_at)

        expect(subscriber.revoked?('usr_blocked', issued_at: revoked_at + 50)).to be true
      end
    end

    context 'with a session' do
      let(:revoked_at) { Time.now.to_i }

      it 'revokes the session the event named' do
        subscriber.block!('usr_multi', revoked_at: revoked_at, sid: 'sid_laptop')

        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 60, sid: 'sid_laptop')).to be true
      end

      # Signing out on a laptop is no reason to refuse the phone.
      it 'leaves the subject other sessions alone' do
        subscriber.block!('usr_multi', revoked_at: revoked_at, sid: 'sid_laptop')

        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 60, sid: 'sid_phone')).to be false
      end

      it 'still lets through a later token from the same session' do
        subscriber.block!('usr_multi', revoked_at: revoked_at, sid: 'sid_laptop')

        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at + 1, sid: 'sid_laptop')).to be false
      end

      # A subject-wide event is the whole account: password change, suspension,
      # sign out everywhere.
      it 'revokes every session when the event named none' do
        subscriber.block!('usr_multi', revoked_at: revoked_at)

        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 60, sid: 'sid_laptop')).to be true
        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 60, sid: 'sid_phone')).to be true
      end

      # Nothing to match on, so it fails closed.
      it 'refuses a token with no sid against a session-scoped entry' do
        subscriber.block!('usr_multi', revoked_at: revoked_at, sid: 'sid_laptop')

        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 60)).to be true
      end

      it 'tracks sessions independently' do
        subscriber.block!('usr_multi', revoked_at: revoked_at - 100, sid: 'sid_laptop')
        subscriber.block!('usr_multi', revoked_at: revoked_at, sid: 'sid_phone')

        # Issued between the two revocations: past the laptop's, before the phone's.
        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 50, sid: 'sid_laptop')).to be false
        expect(subscriber.revoked?('usr_multi', issued_at: revoked_at - 50, sid: 'sid_phone')).to be true
      end
    end
  end

  describe 'blocklist retention' do
    it 'defaults to the configured ttl' do
      IdpRails.configuration.blocklist_ttl = 0.01
      subscriber.block!('usr_configured')
      sleep 0.02

      expect(subscriber.revoked?('usr_configured')).to be false
    ensure
      IdpRails.configuration.blocklist_ttl = IdpRails::RevocationSubscriber::BLOCKLIST_TTL
    end

    it 'is 15 minutes out of the box, matching idp default access token ttl' do
      expect(IdpRails::Configuration.new.blocklist_ttl).to eq(900)
    end
  end

  describe 'message handling' do
    def deliver(payload)
      subscriber.send(:handle_message, JSON.generate(payload))
    end

    it 'reads the revocation instant off the event' do
      revoked_at = Time.now - 300
      deliver(sub: 'usr_evt', revoked_at: revoked_at.iso8601, reason: 'session_revoked')

      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at - 1)).to be true
      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at + 1)).to be false
    end

    it 'falls back to arrival when the event carries no instant' do
      deliver(sub: 'usr_legacy', reason: 'session_revoked')

      expect(subscriber.revoked?('usr_legacy', issued_at: Time.now.to_i - 60)).to be true
      expect(subscriber.revoked?('usr_legacy', issued_at: Time.now.to_i + 60)).to be false
    end

    it 'falls back to arrival when the instant is unreadable' do
      deliver(sub: 'usr_garbled', revoked_at: 'not-a-time', reason: 'session_revoked')

      expect(subscriber.revoked?('usr_garbled', issued_at: Time.now.to_i - 60)).to be true
    end

    it 'scopes the entry to the session the event named' do
      revoked_at = Time.now - 60
      deliver(sub: 'usr_evt', sid: 'sid_laptop', revoked_at: revoked_at.iso8601, reason: 'session_revoked')

      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at - 1, sid: 'sid_laptop')).to be true
      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at - 1, sid: 'sid_phone')).to be false
    end

    # An idp too old to say which session means the whole subject, same as one
    # that deliberately ended everything.
    it 'treats an event with no sid as subject-wide' do
      revoked_at = Time.now - 60
      deliver(sub: 'usr_evt', revoked_at: revoked_at.iso8601, reason: 'password_change')

      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at - 1, sid: 'sid_laptop')).to be true
      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at - 1, sid: 'sid_phone')).to be true
    end

    it 'treats a blank sid as subject-wide' do
      revoked_at = Time.now - 60
      deliver(sub: 'usr_evt', sid: '', revoked_at: revoked_at.iso8601, reason: 'session_revoked')

      expect(subscriber.revoked?('usr_evt', issued_at: revoked_at - 1, sid: 'sid_phone')).to be true
    end

    it 'ignores events with no subject' do
      deliver(reason: 'session_revoked')
      expect(subscriber.revoked?(nil)).to be false
    end

    # A garbled payload costs one message, never the subscribe loop it arrived
    # on — the loop's only rescue logs and RETURNS, so a raise here would stop
    # the process hearing revocations at all.
    it 'refuses a payload that is not a mapping rather than raising' do
      expect { deliver([ 1, 2 ]) }.not_to raise_error
      expect { deliver('a bare string') }.not_to raise_error
      expect { subscriber.send(:handle_message, 'not json at all') }.not_to raise_error
    end
  end

  # Consumers call #stop from at_exit, where a raise is not a message — it is
  # the exit status of a process whose actual work has already finished. A rake
  # task that dropped both databases, said so, and still exited 1 is what sent
  # someone looking.
  describe '#stop' do
    # Dies the way the subscribe loop can, and quietly: report_on_exception
    # would otherwise print the backtrace of a failure the spec is staging.
    def dead_thread(error)
      thread = Thread.new do
        Thread.current.report_on_exception = false
        raise error
      end
      sleep 0.01 while thread.alive?
      thread
    end

    it 'does not adopt the exception that killed the subscriber thread' do
      subscriber.instance_variable_set(:@thread, dead_thread(RuntimeError.new('connection reset')))

      expect { subscriber.stop }.not_to raise_error
    end

    # LoadError is a ScriptError, so `rescue StandardError` around the join
    # would not have been enough either.
    it 'survives a thread that died on something outside StandardError' do
      subscriber.instance_variable_set(:@thread, dead_thread(LoadError.new('cannot load such file -- bunny')))

      expect { subscriber.stop }.not_to raise_error
    end

    it 'is a no-op when the subscriber was never started' do
      expect { subscriber.stop }.not_to raise_error
    end

    it 'joins a thread that ended cleanly' do
      thread = Thread.new { :done }
      subscriber.instance_variable_set(:@thread, thread)

      subscriber.stop

      expect(thread).not_to be_alive
    end

    it 'closes the subscribing Redis connection' do
      redis = instance_double(Redis, close: nil)
      subscriber.instance_variable_set(:@subscriber_redis, redis)

      subscriber.stop

      expect(redis).to have_received(:close)
    end

    it 'shuts down even when the Redis connection cannot be closed' do
      redis = instance_double(Redis)
      allow(redis).to receive(:close).and_raise(Redis::CannotConnectError, 'connection refused')
      subscriber.instance_variable_set(:@subscriber_redis, redis)

      expect { subscriber.stop }.not_to raise_error
    end

    describe 'with a RabbitMQ session' do
      it 'closes a session that finished its handshake' do
        session = instance_double(Bunny::Session, connecting?: false, open?: true, close: nil)
        subscriber.instance_variable_set(:@bunny_connection, session)

        subscriber.stop

        expect(session).to have_received(:close)
      end

      # Bunny.new assigns the session; the AMQP handshake happens later, in
      # #start — and a session in that state still reports open?. Closing it
      # waits for a close-ok that will never arrive, which is how `rails
      # runner 'nil'` exited 1 with a Timeout::Error while the same code given
      # three seconds exited 0.
      it 'leaves a session that is still mid-handshake alone' do
        session = instance_double(Bunny::Session, connecting?: true, open?: true, close: nil)
        subscriber.instance_variable_set(:@bunny_connection, session)

        subscriber.stop

        expect(session).not_to have_received(:close)
      end

      it 'does not close a session that is already down' do
        session = instance_double(Bunny::Session, connecting?: false, open?: false, close: nil)
        subscriber.instance_variable_set(:@bunny_connection, session)

        subscriber.stop

        expect(session).not_to have_received(:close)
      end

      it 'shuts down even when the close itself times out' do
        session = instance_double(Bunny::Session, connecting?: false, open?: true)
        allow(session).to receive(:close).and_raise(Timeout::Error)
        subscriber.instance_variable_set(:@bunny_connection, session)

        expect { subscriber.stop }.not_to raise_error
      end
    end
  end

  # bunny and redis are the consumer's to provide: development dependencies
  # here, required at the point of use, so an app on one transport never loads
  # the other's driver. Missing, one must cost revocations and say so — not
  # take the process down, and above all not with an error naming a constant
  # instead of the gem.
  describe 'a missing driver gem' do
    let(:logger) { instance_double(Logger, info: nil, warn: nil, error: nil, debug: nil) }

    before { IdpRails.configuration.logger = logger }

    context 'over RabbitMQ' do
      before { IdpRails.configuration.rabbitmq_url = 'amqp://localhost' }

      # `Bunny` is hidden for the duration, which is the whole point: LoadError
      # escaped the StandardError rescue, and on its way out Ruby evaluated the
      # `rescue Bunny::TCPConnectionFailed, ...` clause below it — naming a
      # constant the failed require had never defined. What a consumer's users
      # actually saw was "uninitialized constant
      # IdpRails::RevocationSubscriber::Bunny (NameError)", which says nothing
      # about the gem that is missing. The clause has to come first, and this
      # example fails if it is ever moved back.
      it 'warns rather than raising, and names the gem' do
        loop_without_bunny = described_class.new
        allow(loop_without_bunny).to receive(:require).with('bunny').and_raise(LoadError)
        hide_const('Bunny')

        expect { loop_without_bunny.send(:subscribe_loop) }.not_to raise_error
        expect(logger).to have_received(:warn).with(/bunny gem unavailable/)
      end
    end

    context 'over Redis pub/sub' do
      it 'warns rather than raising' do
        loop_without_redis = described_class.new
        allow(loop_without_redis).to receive(:require).with('redis').and_raise(LoadError)
        hide_const('Redis')

        expect { loop_without_redis.send(:subscribe_loop) }.not_to raise_error
        expect(logger).to have_received(:warn).with(/redis gem unavailable/)
      end
    end
  end

  describe '#clear!' do
    it 'removes all entries' do
      subscriber.block!('usr_a')
      subscriber.block!('usr_b')
      subscriber.clear!

      expect(subscriber.revoked?('usr_a')).to be false
      expect(subscriber.revoked?('usr_b')).to be false
    end
  end

  describe 'the shared blocklist' do
    # Stands in for the handful of commands the blocklist uses — real enough to
    # catch key naming, TTL arithmetic and the rehydration round-trip, and
    # deliberately not a Redis.
    let(:store) do
      Class.new do
        attr_reader :hashes

        def initialize
          @hashes = {}
          @expiry = {}
        end

        def hset(key, field, value)
          (@hashes[key] ||= {})[field.to_s] = value.to_s
        end

        def hgetall(key)
          (@hashes[key] || {}).dup
        end

        def ttl(key)
          return -2 unless @hashes.key?(key)

          @expiry.fetch(key, -1)
        end

        def expire(key, seconds)
          @expiry[key] = seconds
        end

        def del(key)
          @hashes.delete(key)
          @expiry.delete(key)
        end

        def scan(_cursor, match:, count:) # rubocop:disable Lint/UnusedMethodArgument
          [ '0', @hashes.keys.select { |key| File.fnmatch(match, key) } ]
        end
      end.new
    end

    subject(:subscriber) { described_class.new(store: store) }

    it 'writes a session-scoped revocation through to the store' do
      subscriber.block!('usr_abc', revoked_at: 1_700_000_000, sid: 'sess_1', ttl: 900)

      expect(store.hashes['revocations:usr_abc']).to eq('sess_1' => '1700000000')
      expect(store.ttl('revocations:usr_abc')).to eq(900)
    end

    it 'files a subject-wide revocation under the all-sessions field' do
      subscriber.block!('usr_abc', revoked_at: 1_700_000_000)

      expect(store.hashes['revocations:usr_abc']).to eq('*' => '1700000000')
    end

    it 'namespaces its keys so two apps on one Redis do not collide' do
      IdpRails.configuration.cache_redis_namespace = 'idp_sessions_crm'

      described_class.new(store: store).block!('usr_abc')

      expect(store.hashes.keys).to eq([ 'idp_sessions_crm:revocations:usr_abc' ])
    end

    # The key must outlive the newest token any of its cutoffs still covers.
    it 'lets a longer window extend the key, and a shorter one leave it alone' do
      subscriber.block!('usr_abc', ttl: 900)
      subscriber.block!('usr_abc', ttl: 60)
      expect(store.ttl('revocations:usr_abc')).to eq(900)

      subscriber.block!('usr_abc', ttl: 1800)
      expect(store.ttl('revocations:usr_abc')).to eq(1800)
    end

    it 'drops the key when the subject authenticates again' do
      subscriber.block!('usr_abc')
      subscriber.unblock!('usr_abc')

      expect(store.hashes).to be_empty
    end

    # The point of the whole exercise: pub/sub replays nothing, so a process
    # that was down when the event went out used to honour the revoked token
    # for the rest of its life. #start reads the blocklist back before serving
    # its first request — which is what rehydrate! does here.
    it 'restores a revocation this process never received' do
      described_class.new(store: store)
        .block!('usr_abc', revoked_at: 1_700_000_000, sid: 'sess_1', ttl: 900)

      restarted = described_class.new(store: store)
      expect(restarted.revoked?('usr_abc', issued_at: 1_699_999_999, sid: 'sess_1')).to be false

      restarted.send(:rehydrate!)

      expect(restarted.revoked?('usr_abc', issued_at: 1_699_999_999, sid: 'sess_1')).to be true
      expect(restarted.revoked?('usr_abc', issued_at: 1_700_000_001, sid: 'sess_1')).to be false
    end

    it 'ignores a stored entry with no expiry rather than blocking forever' do
      store.hset('revocations:usr_ghost', '*', '1700000000')

      restarted = described_class.new(store: store)
      restarted.send(:rehydrate!)

      expect(restarted.revoked?('usr_ghost')).to be false
    end

    it 'keeps blocking in memory when the store cannot be written' do
      allow(store).to receive(:hset).and_raise(RuntimeError, 'connection refused')

      subscriber.block!('usr_abc')

      expect(subscriber.revoked?('usr_abc')).to be true
    end

    it 'keeps serving when the store cannot be read at startup' do
      allow(store).to receive(:scan).and_raise(RuntimeError, 'connection refused')

      expect { described_class.new(store: store).send(:rehydrate!) }.not_to raise_error
    end
  end

  # The gap the shared blocklist cannot close: it is only ever written by a
  # process that RECEIVED an event, so when every consumer process was down at
  # once, nobody wrote anything through and the revocation is gone from both
  # memory and Redis. idp still has it, so the subscriber asks.
  describe 'catching up from idp' do
    let(:asked) { [] }
    let(:revoked_at) { Time.now - 300 }
    let(:entries) do
      [ { 'sub' => 'usr_missed', 'sid' => 'sess_1', 'revoked_at' => revoked_at.utc.iso8601 } ]
    end
    let(:catch_up) { ->(since) { asked << since; entries } }

    subject(:subscriber) { described_class.new(catch_up: catch_up) }

    it 'blocks a revocation no process was up to receive' do
      subscriber.send(:catch_up!)

      expect(subscriber.revoked?('usr_missed', issued_at: revoked_at - 1, sid: 'sess_1')).to be true
    end

    # The replayed cutoff has to mean what the live one means, or a user who
    # signed straight back in is refused the passport they just collected.
    it 'honours the cutoff it was given rather than the moment it asked' do
      subscriber.send(:catch_up!)

      expect(subscriber.revoked?('usr_missed', issued_at: revoked_at + 1, sid: 'sess_1')).to be false
    end

    it 'leaves the subject other sessions alone' do
      subscriber.send(:catch_up!)

      expect(subscriber.revoked?('usr_missed', issued_at: revoked_at - 1, sid: 'sess_2')).to be false
    end

    it 'asks for the window the blocklist retains' do
      IdpRails.configuration.blocklist_ttl = 900

      subscriber.send(:catch_up!)

      expect(asked.first).to be_within(2).of(Time.now.to_i - 900)
    end

    it 'reads symbol keys, since the callable belongs to the app' do
      entries.replace([ { sub: 'usr_sym', sid: 'sess_9', revoked_at: revoked_at.utc.iso8601 } ])

      subscriber.send(:catch_up!)

      expect(subscriber.revoked?('usr_sym', issued_at: revoked_at - 1, sid: 'sess_9')).to be true
    end

    it 'treats a null sid as subject-wide' do
      entries.replace([ { 'sub' => 'usr_wide', 'sid' => nil, 'revoked_at' => revoked_at.utc.iso8601 } ])

      subscriber.send(:catch_up!)

      expect(subscriber.revoked?('usr_wide', issued_at: revoked_at - 1, sid: 'sess_any')).to be true
    end

    it 'skips entries with no subject rather than failing the whole catch-up' do
      entries.replace([
                        { 'sub' => nil, 'revoked_at' => revoked_at.utc.iso8601 },
                        { 'sub' => 'usr_good', 'sid' => 'sess_1', 'revoked_at' => revoked_at.utc.iso8601 }
                      ])

      subscriber.send(:catch_up!)

      expect(subscriber.revoked?('usr_good', issued_at: revoked_at - 1, sid: 'sess_1')).to be true
    end

    # An idp that cannot be reached costs this process the events it missed. It
    # must never cost it the ability to start.
    it 'starts anyway when idp cannot be reached' do
      failing = described_class.new(catch_up: ->(_since) { raise 'connection refused' })

      expect { failing.send(:catch_up!) }.not_to raise_error
    end

    it 'is skipped, not guessed at, when no callable is wired' do
      expect { described_class.new.send(:catch_up!) }.not_to raise_error
    end

    it 'can be wired through configuration instead of the constructor' do
      IdpRails.configuration.revocation_catch_up = catch_up

      described_class.new.send(:catch_up!)

      expect(asked.size).to eq(1)
    end

    # Ordering is the whole point: both fills happen before the subscriber
    # thread exists, and therefore before the first request can land.
    it 'runs at start, on top of the rehydrated blocklist and before serving' do
      allow(Thread).to receive(:new).and_return(instance_double(Thread, :abort_on_exception= => nil))

      rehydrated_first = nil
      started = described_class.new(
        catch_up: lambda { |_since|
          rehydrated_first = started.revoked?('usr_stored', issued_at: revoked_at - 1, sid: 'sess_0')
          entries
        }
      )
      allow(started).to receive(:rehydrate!) do
        started.block!('usr_stored', revoked_at: revoked_at.to_i, sid: 'sess_0')
      end

      started.start

      expect(rehydrated_first).to be true
      expect(started.revoked?('usr_missed', issued_at: revoked_at - 1, sid: 'sess_1')).to be true
    end
  end

  # A dropped connection used to cost every revocation published while it was
  # down — permanently. The loop reconnected and resubscribed, and stopped
  # there: neither the shared blocklist nor idp's window was ever consulted
  # again, so an event nobody was up to hear was honoured as though it had
  # never happened, for the rest of each affected token's life. The subscriber
  # reported itself perfectly healthy throughout, which is what made it cost so
  # much to notice.
  describe 'replaying what a disconnect swallowed' do
    let(:exchange) { instance_double(Bunny::Exchange) }
    let(:queue) { instance_double(Bunny::Queue, bind: nil) }
    let(:channel) { instance_double(Bunny::Channel, fanout: exchange, queue: queue) }
    let(:session) { instance_double(Bunny::Session, start: nil, create_channel: channel) }

    before do
      IdpRails.configuration.rabbitmq_url = 'amqp://guest:guest@127.0.0.1:5672'
      allow(Bunny).to receive(:new).and_return(session)
    end

    after { IdpRails.configuration.rabbitmq_url = nil }

    # The first subscribe has nothing to replay: #start rehydrated and caught
    # up before the thread existed. Replaying there would double every boot's
    # work for nothing.
    it 'does not replay on the first subscribe' do
      fresh = described_class.new
      allow(fresh).to receive(:recover_missed!)
      allow(queue).to receive(:subscribe)

      fresh.send(:subscribe_loop_rabbitmq)

      expect(fresh).not_to have_received(:recover_missed!)
    end

    it 'replays once the connection comes back' do
      reconnecting = described_class.new
      reconnecting.instance_variable_set(:@running, true)
      allow(reconnecting).to receive(:sleep)
      allow(reconnecting).to receive(:recover_missed!)

      attempts = 0
      allow(queue).to receive(:subscribe) do
        attempts += 1
        raise Bunny::NetworkFailure.new('connection reset', StandardError.new) if attempts == 1

        nil
      end

      reconnecting.send(:subscribe_loop_rabbitmq)

      expect(attempts).to eq(2)
      expect(reconnecting).to have_received(:recover_missed!).once
    end

    # After the bind and before the subscribe: from the bind onwards the broker
    # is holding everything published, so nothing more can be missed, and the
    # replay covers everything before it.
    it 'replays after binding the queue, so the gap has a far edge' do
      order = []
      reconnecting = described_class.new
      reconnecting.instance_variable_set(:@running, true)
      allow(reconnecting).to receive(:sleep)
      allow(reconnecting).to receive(:recover_missed!) { order << :replay }
      allow(queue).to receive(:bind) { order << :bind }

      attempts = 0
      allow(queue).to receive(:subscribe) do
        order << :subscribe
        attempts += 1
        raise Bunny::NetworkFailure.new('connection reset', StandardError.new) if attempts == 1

        nil
      end

      reconnecting.send(:subscribe_loop_rabbitmq)

      expect(order).to eq(%i[bind subscribe bind replay subscribe])
    end

    describe '#recover_missed!' do
      it 'reads the shared blocklist back and asks idp for the window' do
        recovered = described_class.new
        allow(recovered).to receive(:rehydrate!)
        allow(recovered).to receive(:catch_up!)
        recovered.send(:note_disconnect)

        recovered.send(:recover_missed!)

        expect(recovered).to have_received(:rehydrate!)
        expect(recovered).to have_received(:catch_up!)
      end

      # Or the next reconnect after a quiet spell replays a window it has
      # already replayed, on every single subscribe.
      it 'clears the flag once it has run' do
        recovered = described_class.new
        allow(recovered).to receive(:rehydrate!)
        allow(recovered).to receive(:catch_up!)
        recovered.send(:note_disconnect)
        expect(recovered.send(:reconnecting?)).to be true

        recovered.send(:recover_missed!)

        expect(recovered.send(:reconnecting?)).to be false
      end
    end
  end
end
