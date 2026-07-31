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
end
