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
end
