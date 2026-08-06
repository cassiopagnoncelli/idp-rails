# frozen_string_literal: true

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
end
