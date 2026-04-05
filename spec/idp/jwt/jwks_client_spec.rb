# frozen_string_literal: true

require "redis"

RSpec.describe Idp::JWT::JwksClient do
  subject(:client) { described_class.new(config) }

  let(:key_pair) { TestKeys.generate }

  let(:jwks_response) do
    { keys: [ key_pair.jwk ] }.to_json
  end

  let(:config) { Idp::JWT.configuration }

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

  context 'with Redis cache' do
    let(:redis) { instance_double(Redis) }
    let(:config) do
      Idp::JWT.configuration.tap { |c| c.cache_redis = redis }
    end

    describe 'L2 cache hit' do
      it 'loads keys from Redis without hitting the IDP' do
        allow(redis).to receive(:get).with(described_class::REDIS_KEY).and_return(jwks_response)

        public_key = client.public_key(key_pair.kid)

        expect(public_key).to be_a(OpenSSL::PKey::EC)
        expect(WebMock).not_to have_requested(:get, 'https://account.test/.well-known/jwks.json')
      end
    end

    describe 'L2 cache miss' do
      it 'fetches from origin and writes to Redis' do
        allow(redis).to receive(:get).with(described_class::REDIS_KEY).and_return(nil)
        allow(redis).to receive(:set)

        client.public_key(key_pair.kid)

        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
        expect(redis).to have_received(:set).with(
          described_class::REDIS_KEY,
          jwks_response,
          ex: config.jwks_cache_ttl
        )
      end
    end

    describe 'Redis write-through' do
      it 'stores the raw JSON body with the configured TTL' do
        allow(redis).to receive(:get).with(described_class::REDIS_KEY).and_return(nil)
        allow(redis).to receive(:set)

        config.jwks_cache_ttl = 1800
        client.public_key(key_pair.kid)

        expect(redis).to have_received(:set).with(
          described_class::REDIS_KEY,
          jwks_response,
          ex: 1800
        )
      end
    end

    describe 'refresh! bypasses Redis read' do
      it 'always fetches from origin on refresh' do
        # First load from Redis
        allow(redis).to receive(:get).with(described_class::REDIS_KEY).and_return(jwks_response)
        allow(redis).to receive(:set)
        client.public_key(key_pair.kid)

        expect(WebMock).not_to have_requested(:get, 'https://account.test/.well-known/jwks.json')

        # Force refresh goes to origin
        client.refresh!

        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
        expect(redis).to have_received(:set).with(
          described_class::REDIS_KEY,
          jwks_response,
          ex: config.jwks_cache_ttl
        )
      end
    end

    describe 'Redis read failure' do
      it 'falls back to HTTP fetch' do
        allow(redis).to receive(:get).and_raise(Redis::CannotConnectError, 'Connection refused')
        allow(redis).to receive(:set)

        public_key = client.public_key(key_pair.kid)

        expect(public_key).to be_a(OpenSSL::PKey::EC)
        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
      end
    end

    describe 'Redis write failure' do
      it 'still succeeds and caches in-memory' do
        allow(redis).to receive(:get).with(described_class::REDIS_KEY).and_return(nil)
        allow(redis).to receive(:set).and_raise(Redis::CannotConnectError, 'Connection refused')

        public_key = client.public_key(key_pair.kid)

        expect(public_key).to be_a(OpenSSL::PKey::EC)

        # Second call uses L1 cache, no more HTTP
        client.public_key(key_pair.kid)
        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
      end
    end

    describe 'key rotation with Redis' do
      it 'fetches from origin for unknown kid and updates Redis' do
        allow(redis).to receive(:get).with(described_class::REDIS_KEY).and_return(jwks_response)
        allow(redis).to receive(:set)

        # Load initial keys from Redis
        client.public_key(key_pair.kid)

        # New key appears after rotation (with a different kid)
        new_key = TestKeys.generate
        new_kid = 'rotated_key_002'
        new_key_jwk = new_key.jwk.merge(kid: new_kid)
        new_jwks = { keys: [ key_pair.jwk, new_key_jwk ] }.to_json
        stub_request(:get, 'https://account.test/.well-known/jwks.json')
          .to_return(status: 200, body: new_jwks)

        public_key = client.public_key(new_kid)

        expect(public_key).to be_a(OpenSSL::PKey::EC)
        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
        expect(redis).to have_received(:set).with(
          described_class::REDIS_KEY,
          anything,
          ex: config.jwks_cache_ttl
        )
      end
    end
  end

  context 'without Redis configured' do
    it 'fetches from origin directly' do
      public_key = client.public_key(key_pair.kid)

      expect(public_key).to be_a(OpenSSL::PKey::EC)
      expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
    end
  end
end
