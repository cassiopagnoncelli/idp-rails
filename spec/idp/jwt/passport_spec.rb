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
        email_verified: true,
        locale: nil,
        time_zone: 'UTC',
        phone_number: nil,
        created_at: 1_712_000_000,
        confirmed_at: 1_712_000_100,
        platform_role: 'none',
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

    it 'exposes email_verified?' do
      expect(passport.email_verified?).to be true
    end

    it 'returns false when email_verified is false' do
      unverified = described_class.new(claims.merge(user: claims[:user].merge(email_verified: false)))
      expect(unverified.email_verified?).to be false
    end

    it 'returns false when email_verified is not set' do
      without_email_verification = described_class.new(claims.merge(user: claims[:user].except(:email_verified)))
      expect(without_email_verification.email_verified?).to be false
    end

    it 'reads top-level email_verified when user claim is not present' do
      top_level = described_class.new(claims.merge(email_verified: true, user: claims[:user].except(:email_verified)))
      expect(top_level.email_verified?).to be true
    end

    it 'treats string email_verified values as booleans' do
      string_true = described_class.new(claims.merge(user: claims[:user].merge(email_verified: 'true')))
      string_false = described_class.new(claims.merge(user: claims[:user].merge(email_verified: 'false')))

      expect(string_true.email_verified?).to be true
      expect(string_false.email_verified?).to be false
    end

    it 'exposes mfa_verified?' do
      expect(passport.mfa_verified?).to be true
    end

    it 'exposes platform_role' do
      expect(passport.platform_role).to eq('none')
    end

    it 'exposes locale' do
      localized = described_class.new(claims.merge(user: claims[:user].merge(locale: 'pt-BR')))
      expect(localized.locale).to eq('pt-BR')
    end

    it 'returns nil when locale is not set' do
      expect(passport.locale).to be_nil
    end

    it 'exposes time_zone' do
      zoned = described_class.new(claims.merge(user: claims[:user].merge(time_zone: 'America/Sao_Paulo')))
      expect(zoned.time_zone).to eq('America/Sao_Paulo')
    end

    it 'returns nil when time_zone is not set' do
      without_time_zone = described_class.new(claims.merge(user: claims[:user].except(:time_zone)))
      expect(without_time_zone.time_zone).to be_nil
    end

    it 'exposes phone_number' do
      with_phone_number = described_class.new(claims.merge(user: claims[:user].merge(phone_number: '+5511999999999')))
      expect(with_phone_number.phone_number).to eq('+5511999999999')
    end

    it 'returns nil when phone_number is not set' do
      expect(passport.phone_number).to be_nil
    end

    it 'falls back to legacy mobile claim' do
      legacy = described_class.new(claims.merge(user: claims[:user].except(:phone_number).merge(mobile: '+5511999999999')))
      expect(legacy.phone_number).to eq('+5511999999999')
    end

    it 'exposes created_at' do
      expect(passport.created_at).to eq(1_712_000_000)
    end

    it 'returns nil when created_at is not set' do
      without_created_at = described_class.new(claims.merge(user: claims[:user].except(:created_at)))
      expect(without_created_at.created_at).to be_nil
    end

    it 'exposes confirmed_at' do
      expect(passport.confirmed_at).to eq(1_712_000_100)
    end

    it 'returns nil when confirmed_at is nil' do
      unconfirmed = described_class.new(claims.merge(user: claims[:user].merge(confirmed_at: nil)))
      expect(unconfirmed.confirmed_at).to be_nil
    end

    it 'returns nil when confirmed_at is not set' do
      without_confirmed_at = described_class.new(claims.merge(user: claims[:user].except(:confirmed_at)))
      expect(without_confirmed_at.confirmed_at).to be_nil
    end

    it 'exposes user_status' do
      expect(passport.user_status).to eq('active')
    end

    it 'returns nil when user_status is not set' do
      without_status = described_class.new(claims.merge(user: claims[:user].except(:status)))
      expect(without_status.user_status).to be_nil
    end
  end

  describe 'platform role tiers' do
    def with_role(role)
      user = role.nil? ? claims[:user].except(:platform_role) : claims[:user].merge(platform_role: role)
      described_class.new(claims.merge(user: user))
    end

    it 'owner satisfies every tier' do
      p = with_role('owner')
      expect(p.platform_owner?).to be true
      expect(p.platform_admin?).to be true
      expect(p.platform_member?).to be true
      expect(p.platform_viewer?).to be true
      expect(p.no_platform?).to be false
    end

    it 'admin satisfies admin and below, but not owner' do
      p = with_role('admin')
      expect(p.platform_owner?).to be false
      expect(p.platform_admin?).to be true
      expect(p.platform_member?).to be true
      expect(p.platform_viewer?).to be true
      expect(p.no_platform?).to be false
    end

    it 'member satisfies member and viewer, but not admin' do
      p = with_role('member')
      expect(p.platform_admin?).to be false
      expect(p.platform_member?).to be true
      expect(p.platform_viewer?).to be true
      expect(p.no_platform?).to be false
    end

    it 'viewer satisfies only viewer' do
      p = with_role('viewer')
      expect(p.platform_member?).to be false
      expect(p.platform_viewer?).to be true
      expect(p.no_platform?).to be false
    end

    it 'none satisfies nothing' do
      p = with_role('none')
      expect(p.platform_owner?).to be false
      expect(p.platform_admin?).to be false
      expect(p.platform_member?).to be false
      expect(p.platform_viewer?).to be false
      expect(p.no_platform?).to be true
    end

    it 'treats a missing platform_role claim as no platform access' do
      p = with_role(nil)
      expect(p.platform_role).to be_nil
      expect(p.platform_viewer?).to be false
      expect(p.no_platform?).to be true
    end

    it 'treats an empty platform_role claim as no platform access' do
      p = with_role('')
      expect(p.platform_viewer?).to be false
      expect(p.no_platform?).to be true
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

  describe 'service tokens (client_credentials)' do
    let(:service_claims) do
      {
        iss: 'https://account.test',
        sub: 'crm_service',
        aud: 'crm_service',
        iat: Time.now.to_i,
        exp: (Time.now + 900).to_i,
        jti: 'svc_xyz',
        client_id: 'crm_service',
        scope: 'users:lookup reports:read',
        token_use: 'client'
      }
    end
    subject(:service_passport) { described_class.new(service_claims) }

    it 'identifies the token as a service token' do
      expect(service_passport.service?).to be true
      expect(service_passport.user?).to be false
      expect(service_passport.token_use).to eq('client')
    end

    it 'exposes client_id and scopes' do
      expect(service_passport.client_id).to eq('crm_service')
      expect(service_passport.scopes).to eq(%w[users:lookup reports:read])
      expect(service_passport.has_scope?('users:lookup')).to be true
      expect(service_passport.has_scope?('admin:everything')).to be false
    end

    it 'namespaces flipper_id under Service: to avoid collisions with users' do
      expect(service_passport.flipper_id).to eq('Service:crm_service')
    end

    it 'raises NotAUserToken when user-only accessors are called' do
      expect { service_passport.email }.to raise_error(Idp::JWT::NotAUserToken, /service token/)
      expect { service_passport.platform_role }.to raise_error(Idp::JWT::NotAUserToken)
      expect { service_passport.platform_admin? }.to raise_error(Idp::JWT::NotAUserToken)
      expect { service_passport.user_uuid }.to raise_error(Idp::JWT::NotAUserToken)
    end

    it 'still exposes subject (without raising) for diagnostic logging' do
      expect(service_passport.subject).to eq('crm_service')
    end
  end

  describe 'user passports' do
    it 'reports user? true and service? false' do
      expect(passport.user?).to be true
      expect(passport.service?).to be false
    end

    it 'reports flipper_id under the Passport: namespace' do
      expect(passport.flipper_id).to eq('Passport:usr_abc123')
    end

    it 'returns an empty scope list when none are present' do
      expect(passport.scopes).to eq([])
      expect(passport.has_scope?('users:lookup')).to be false
    end
  end
end
