# frozen_string_literal: true

RSpec.describe Idp::JWT::Verifier do
  let(:key_pair) { TestKeys.generate }

  let(:jwks_response) do
    { keys: [ key_pair.jwk ] }.to_json
  end

  let(:valid_payload) do
    {
      iss: 'https://account.test',
      sub: 'usr_abc123',
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: 'tok_xyz789',
      user: {
        email: 'alice@example.com',
        name: 'Alice',
        platform_role: 'none',
        mfa_verified: true
      }
    }
  end

  before do
    stub_request(:get, 'https://account.test/.well-known/jwks.json')
      .to_return(status: 200, body: jwks_response, headers: { 'Content-Type' => 'application/json' })
  end

  describe '#verify!' do
    it 'returns a Passport for a valid token' do
      token = TestKeys.sign_token(valid_payload, key_pair)
      passport = described_class.new.verify!(token)

      expect(passport).to be_a(Idp::JWT::Passport)
      expect(passport.user_uuid).to eq('usr_abc123')
    end

    it 'strips Bearer prefix' do
      token = TestKeys.sign_token(valid_payload, key_pair)
      passport = described_class.new.verify!("Bearer #{token}")

      expect(passport.user_uuid).to eq('usr_abc123')
    end

    it 'raises ExpiredTokenError for expired tokens' do
      payload = valid_payload.merge(exp: (Time.now - 60).to_i)
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(Idp::JWT::ExpiredTokenError)
    end

    it 'raises InvalidIssuerError for wrong issuer' do
      payload = valid_payload.merge(iss: 'https://evil.example.com')
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(Idp::JWT::InvalidIssuerError)
    end

    it 'raises InvalidSignatureError for unknown kid' do
      other_key = TestKeys.generate
      # Sign with a key that's not in the JWKS
      token = JWT.encode(valid_payload, other_key.private_key, 'ES256', { kid: 'unknown_key' })

      expect { described_class.new.verify!(token) }
        .to raise_error(Idp::JWT::InvalidSignatureError, /Unknown signing key/)
    end

    it 'raises VerificationError for tampered tokens' do
      token = TestKeys.sign_token(valid_payload, key_pair)
      parts = token.split('.')
      parts[1] = Base64.urlsafe_encode64('{"sub":"usr_hacked"}', padding: false)
      tampered = parts.join('.')

      expect { described_class.new.verify!(tampered) }
        .to raise_error(Idp::JWT::VerificationError)
    end
  end

  describe 'revocation checking' do
    let(:subscriber) { Idp::JWT::RevocationSubscriber.new }

    it 'rejects revoked users' do
      subscriber.block!('usr_abc123')

      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      expect { verifier.verify!(token) }
        .to raise_error(Idp::JWT::RevokedTokenError)
    end

    it 'passes non-revoked users' do
      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      passport = verifier.verify!(token)
      expect(passport.user_uuid).to eq('usr_abc123')
    end
  end
end
