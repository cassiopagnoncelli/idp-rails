# frozen_string_literal: true

RSpec.describe Idp::JWT::JwksClient do
  subject(:client) { described_class.new }

  let(:key_pair) { TestKeys.generate }

  let(:jwks_response) do
    { keys: [ key_pair.jwk ] }.to_json
  end

  before do
    stub_request(:get, 'https://account.test/.well-known/jwks.json')
      .to_return(status: 200, body: jwks_response, headers: { 'Content-Type' => 'application/json' })
  end

  describe '#public_key' do
    it 'fetches and returns the public key for a known kid' do
      public_key = client.public_key(key_pair.kid)

      expect(public_key).to be_a(OpenSSL::PKey::EC)
    end

    it 'caches the JWKS (only one HTTP call)' do
      client.public_key(key_pair.kid)
      client.public_key(key_pair.kid)

      expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
    end

    it 'retries on unknown kid (handles key rotation)' do
      # First call loads the cache.
      client.public_key(key_pair.kid)

      # Now a new key appears.
      new_key = TestKeys.generate
      new_jwks = { keys: [ key_pair.jwk, new_key.jwk ] }.to_json

      stub_request(:get, 'https://account.test/.well-known/jwks.json')
        .to_return(status: 200, body: new_jwks)

      public_key = client.public_key(new_key.kid)
      expect(public_key).to be_a(OpenSSL::PKey::EC)
    end

    it 'raises on permanently unknown kid' do
      client.public_key(key_pair.kid) # load cache

      expect { client.public_key('nonexistent') }
        .to raise_error(Idp::JWT::InvalidSignatureError, /Unknown signing key/)
    end
  end

  describe '#clear!' do
    it 'clears the cache' do
      client.public_key(key_pair.kid)
      client.clear!

      client.public_key(key_pair.kid)
      expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').twice
    end
  end

  describe 'error handling' do
    it 'raises on HTTP failure' do
      stub_request(:get, 'https://account.test/.well-known/jwks.json')
        .to_return(status: 500, body: 'Internal Server Error')

      client.clear!
      expect { client.public_key('any') }
        .to raise_error(Idp::JWT::Error, /JWKS fetch failed/)
    end
  end
end
