# frozen_string_literal: true

RSpec.describe IdpRails do
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

  let(:token) { TestKeys.sign_token(valid_payload, key_pair) }

  before do
    stub_request(:get, 'https://account.test/.well-known/jwks.json')
      .to_return(status: 200, body: jwks_response, headers: { 'Content-Type' => 'application/json' })
  end

  # Builds a stand-in for the ::Rails module with the given application
  # config, so specs can exercise the Railtie-stash lookup without Rails.
  def stub_rails(config)
    application = config.nil? ? nil : double('application', config: config)
    stub_const('Rails', double('Rails', application: application))
  end

  describe '.default_revocation_subscriber' do
    it 'is nil outside Rails' do
      expect(defined?(::Rails)).to be_nil # the suite must not load Rails
      expect(described_class.default_revocation_subscriber).to be_nil
    end

    it 'is nil before the Rails application exists' do
      stub_rails(nil)
      expect(described_class.default_revocation_subscriber).to be_nil
    end

    it 'is nil when no subscriber was started' do
      # A real config object answers respond_to? false for keys never set.
      stub_rails(Object.new)
      expect(described_class.default_revocation_subscriber).to be_nil
    end

    it 'returns the stashed subscriber' do
      subscriber = IdpRails::RevocationSubscriber.new
      stub_rails(double('config', idp_rails_revocation_subscriber: subscriber))

      expect(described_class.default_revocation_subscriber).to be(subscriber)
    end
  end

  describe '.verify! / .verify' do
    it 'verifies without a revocation check outside Rails' do
      expect(described_class.verify!(token).user_uuid).to eq('usr_abc123')
      expect(described_class.verify(token).user_uuid).to eq('usr_abc123')
    end

    context 'inside Rails with a stashed subscriber' do
      let(:subscriber) { IdpRails::RevocationSubscriber.new }

      before do
        stub_rails(double('config', idp_rails_revocation_subscriber: subscriber))
      end

      it 'refuses a revoked token' do
        subscriber.block!('usr_abc123', revoked_at: Time.now + 60)

        expect { described_class.verify!(token) }
          .to raise_error(IdpRails::RevokedTokenError)
        expect(described_class.verify(token)).to be_nil
      end

      it 'passes a non-revoked token' do
        expect(described_class.verify!(token).user_uuid).to eq('usr_abc123')
      end

      it 'lets an explicit revocation_subscriber: override the stash' do
        subscriber.block!('usr_abc123', revoked_at: Time.now + 60)
        fresh = IdpRails::RevocationSubscriber.new

        expect(described_class.verify!(token, revocation_subscriber: fresh).user_uuid)
          .to eq('usr_abc123')
      end

      it 'lets an explicit nil skip the check' do
        subscriber.block!('usr_abc123', revoked_at: Time.now + 60)

        expect(described_class.verify!(token, revocation_subscriber: nil).user_uuid)
          .to eq('usr_abc123')
      end
    end

    it 'honors an explicit subscriber outside Rails' do
      subscriber = IdpRails::RevocationSubscriber.new
      subscriber.block!('usr_abc123', revoked_at: Time.now + 60)

      expect { described_class.verify!(token, revocation_subscriber: subscriber) }
        .to raise_error(IdpRails::RevokedTokenError)
      expect(described_class.verify(token, revocation_subscriber: subscriber)).to be_nil
    end
  end
end
