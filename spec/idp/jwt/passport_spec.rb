# frozen_string_literal: true

RSpec.describe Idp::JWT::Passport do
  subject(:passport) { described_class.new(claims) }

  let(:claims) do
    {
      iss: 'https://account.test',
      sub: 'usr_abc123',
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: 'tok_xyz789',
      user: {
        email: 'alice@example.com',
        name: 'Alice',
        platform_admin: false,
        platform_admin_root: false,
        mfa_verified: true,
        status: 'active'
      }
    }
  end

  describe 'standard claims' do
    it 'exposes issuer' do
      expect(passport.issuer).to eq('https://account.test')
    end

    it 'exposes subject / user_uuid' do
      expect(passport.subject).to eq('usr_abc123')
      expect(passport.user_uuid).to eq('usr_abc123')
    end

    it 'exposes jwt_id' do
      expect(passport.jwt_id).to eq('tok_xyz789')
    end

    it 'exposes issued_at and expires_at as Time' do
      expect(passport.issued_at).to be_a(Time)
      expect(passport.expires_at).to be_a(Time)
    end
  end

  describe 'user profile' do
    it 'exposes email' do
      expect(passport.email).to eq('alice@example.com')
    end

    it 'exposes name' do
      expect(passport.name).to eq('Alice')
    end

    it 'exposes mfa_verified?' do
      expect(passport.mfa_verified?).to be true
    end

    it 'exposes platform_admin?' do
      expect(passport.platform_admin?).to be false
    end

    it 'exposes platform_admin_root?' do
      expect(passport.platform_admin_root?).to be false
    end

    it 'exposes locale' do
      localized = described_class.new(claims.merge(user: claims[:user].merge(locale: 'pt-BR')))
      expect(localized.locale).to eq('pt-BR')
    end

    it 'returns nil when locale is not set' do
      expect(passport.locale).to be_nil
    end

    it 'exposes user_status' do
      expect(passport.user_status).to eq('active')
    end

    it 'returns nil when user_status is not set' do
      without_status = described_class.new(claims.merge(user: claims[:user].except(:status)))
      expect(without_status.user_status).to be_nil
    end
  end

  describe '#expired?' do
    it 'returns false for valid tokens' do
      expect(passport.expired?).to be false
    end

    it 'returns true for expired tokens' do
      expired = described_class.new(claims.merge(exp: (Time.now - 60).to_i))
      expect(expired.expired?).to be true
    end
  end
end
