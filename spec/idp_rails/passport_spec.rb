# frozen_string_literal: true

RSpec.describe IdpRails::Passport do
  subject(:passport) { described_class.new(claims) }

  # The conformant access-token shape (idp ADR-0001): flat authorization
  # data, no profile fields.
  let(:claims) do
    {
      iss: 'https://account.test',
      sub: 'usr_abc123',
      aud: 'https://account.test',
      client_id: 'crm_web',
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: 'tok_xyz789',
      sid: 'sid_9f8e7d',
      scope: 'openid profile email',
      auth_time: 1_712_000_000,
      amr: %w[pwd otp mfa],
      acr: 'aal2',
      platform_role: 'none',
      status: 'active'
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

    it 'exposes the granted scope' do
      expect(passport.scopes).to eq(%w[openid profile email])
      expect(passport.has_scope?('openid')).to be true
      expect(passport.has_scope?('users:lookup')).to be false
    end
  end

  describe 'session & authentication context' do
    it 'exposes sid, amr, acr, and auth_time' do
      expect(passport.sid).to eq('sid_9f8e7d')
      expect(passport.amr).to eq(%w[pwd otp mfa])
      expect(passport.acr).to eq('aal2')
      expect(passport.auth_time).to eq(Time.at(1_712_000_000))
    end

    it 'derives mfa_verified? from amr' do
      expect(passport.mfa_verified?).to be true

      single_factor = described_class.new(claims.merge(amr: %w[pwd]))
      expect(single_factor.mfa_verified?).to be false
    end

    it 'returns empty context when the grant has none' do
      bare = described_class.new(claims.except(:amr, :acr, :auth_time, :sid))
      expect(bare.amr).to eq([])
      expect(bare.acr).to be_nil
      expect(bare.auth_time).to be_nil
      expect(bare.sid).to be_nil
      expect(bare.mfa_verified?).to be false
    end
  end

  describe 'authorization claims' do
    it 'exposes platform_role from the top level' do
      expect(passport.platform_role).to eq('none')
    end

    # ADR-0002: idp issues a passport only to an active account, so the
    # claim is gone and the accessor answers what holding one means.
    it 'answers user_status "active" whatever the token carries' do
      expect(passport.user_status).to eq('active')
      expect(described_class.new(claims.except(:status)).user_status).to eq('active')
      expect(described_class.new(claims.merge(status: 'suspended')).user_status).to eq('active')
    end
  end

  describe 'profile accessors' do
    it 'return nil on access tokens (profile left the AT — ADR-0001)' do
      expect(passport.email).to be_nil
      expect(passport.name).to be_nil
      expect(passport.locale).to be_nil
      expect(passport.time_zone).to be_nil
      expect(passport.phone_number).to be_nil
      expect(passport.email_verified?).to be false
    end

    it 'read flat OIDC claims when wrapping an ID-token/userinfo payload' do
      oidc = described_class.new(
        iss: 'https://account.test', sub: 'usr_abc123',
        exp: (Time.now + 600).to_i,
        name: 'Alice', email: 'alice@example.com', email_verified: true,
        locale: 'pt-BR', zoneinfo: 'America/Sao_Paulo', phone_number: '+5511999999999'
      )

      expect(oidc.name).to eq('Alice')
      expect(oidc.email).to eq('alice@example.com')
      expect(oidc.email_verified?).to be true
      expect(oidc.locale).to eq('pt-BR')
      expect(oidc.time_zone).to eq('America/Sao_Paulo')
      expect(oidc.phone_number).to eq('+5511999999999')
    end

    it 'treats string email_verified values as booleans' do
      expect(described_class.new(claims.merge(email_verified: 'true')).email_verified?).to be true
      expect(described_class.new(claims.merge(email_verified: 'false')).email_verified?).to be false
    end
  end

  describe 'retired legacy surface' do
    it 'created_at / confirmed_at / terms_version are always nil' do
      expect(passport.created_at).to be_nil
      expect(passport.confirmed_at).to be_nil
      expect(passport.terms_version).to be_nil
    end

    it 'ignores a legacy nested user envelope entirely' do
      legacy = described_class.new(
        iss: 'https://account.test', sub: 'usr_abc123',
        exp: (Time.now + 900).to_i,
        user: {
          email: 'alice@example.com', platform_role: 'owner',
          mfa_verified: true, status: 'active', terms_version: '1.0'
        }
      )

      expect(legacy.email).to be_nil
      expect(legacy.platform_role).to be_nil
      expect(legacy.mfa_verified?).to be false
      expect(legacy.user_status).to eq('active')
      expect(legacy.terms_version).to be_nil
      expect(legacy.no_platform?).to be true
    end
  end

  describe 'platform role tiers' do
    def with_role(role)
      described_class.new(role.nil? ? claims.except(:platform_role) : claims.merge(platform_role: role))
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
        aud: 'https://account.test',
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
      expect { service_passport.email }.to raise_error(IdpRails::NotAUserToken, /service token/)
      expect { service_passport.platform_role }.to raise_error(IdpRails::NotAUserToken)
      expect { service_passport.platform_admin? }.to raise_error(IdpRails::NotAUserToken)
      expect { service_passport.mfa_verified? }.to raise_error(IdpRails::NotAUserToken)
      expect { service_passport.user_uuid }.to raise_error(IdpRails::NotAUserToken)
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
  end
end
