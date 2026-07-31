# frozen_string_literal: true

RSpec.describe IdpRails::Verifier do
  let(:key_pair) { TestKeys.generate }

  let(:jwks_response) do
    { keys: [ key_pair.jwk ] }.to_json
  end

  let(:valid_payload) do
    {
      iss: 'https://account.test',
      sub: 'usr_abc123',
      aud: 'https://account.test',
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: 'tok_xyz789',
      amr: %w[pwd otp mfa],
      acr: 'aal2',
      IdpRails::Passport::PLATFORM_ROLE_CLAIM => 'none'
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

      expect(passport).to be_a(IdpRails::Passport)
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
        .to raise_error(IdpRails::ExpiredTokenError)
    end

    it 'raises InvalidIssuerError for wrong issuer' do
      payload = valid_payload.merge(iss: 'https://evil.example.com')
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(IdpRails::InvalidIssuerError)
    end

    it 'raises InvalidSignatureError for unknown kid' do
      other_key = TestKeys.generate
      # Sign with a key that's not in the JWKS
      token = JWT.encode(valid_payload, other_key.private_key, 'ES256', { kid: 'unknown_key', typ: 'at+jwt' })

      expect { described_class.new.verify!(token) }
        .to raise_error(IdpRails::InvalidSignatureError, /Unknown signing key/)
    end

    it 'rejects tokens without the at+jwt header type (e.g. ID tokens)' do
      token = TestKeys.sign_token(valid_payload, key_pair, typ: nil)

      expect { described_class.new.verify!(token) }
        .to raise_error(IdpRails::VerificationError, /Not an access token/)
    end

    it 'raises InvalidAudienceError for a foreign audience' do
      payload = valid_payload.merge(aud: 'https://other.example.com')
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(IdpRails::InvalidAudienceError)
    end

    it 'accepts an explicitly configured audience' do
      IdpRails.configuration.audience = 'urn:platform:custom'
      payload = valid_payload.merge(aud: 'urn:platform:custom')
      token = TestKeys.sign_token(payload, key_pair)

      expect(described_class.new.verify!(token).user_uuid).to eq('usr_abc123')
    end

    it 'raises VerificationError for tampered tokens' do
      token = TestKeys.sign_token(valid_payload, key_pair)
      parts = token.split('.')
      parts[1] = Base64.urlsafe_encode64('{"sub":"usr_hacked"}', padding: false)
      tampered = parts.join('.')

      expect { described_class.new.verify!(tampered) }
        .to raise_error(IdpRails::VerificationError)
    end
  end

  describe 'revocation checking' do
    let(:subscriber) { IdpRails::RevocationSubscriber.new }

    it 'rejects a token the revocation covers' do
      subscriber.block!('usr_abc123', revoked_at: Time.now + 60)

      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      expect { verifier.verify!(token) }
        .to raise_error(IdpRails::RevokedTokenError)
    end

    # Sign out, sign straight back in: the passport is minted after the
    # revocation the sign-out fired, so the event does not reach it.
    it 'passes a token issued after the revocation' do
      subscriber.block!('usr_abc123', revoked_at: Time.now - 60)

      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      passport = verifier.verify!(token)
      expect(passport.user_uuid).to eq('usr_abc123')
    end

    it 'passes non-revoked users' do
      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      passport = verifier.verify!(token)
      expect(passport.user_uuid).to eq('usr_abc123')
    end
  end
end
