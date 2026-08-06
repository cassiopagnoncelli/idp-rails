# frozen_string_literal: true

require "redis"

RSpec.describe IdpRails::JwksClient do
  subject(:client) { described_class.new(config) }

  let(:key_pair) { TestKeys.generate }

  let(:jwks_response) do
    { keys: [ key_pair.jwk ] }.to_json
  end

  let(:config) { IdpRails.configuration }

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
        .to raise_error(IdpRails::InvalidSignatureError, /Unknown signing key/)
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
        .to raise_error(IdpRails::Error, /JWKS fetch failed/)
    end
  end

  context 'with Redis cache' do
    let(:redis) { instance_double(Redis) }
    let(:config) do
      IdpRails.configuration.tap { |c| c.cache_redis = redis }
    end

    describe 'L2 cache hit' do
      it 'loads keys from Redis without hitting the IDP' do
        allow(redis).to receive(:get).with(described_class::BASE_REDIS_KEY).and_return(jwks_response)

        public_key = client.public_key(key_pair.kid)

        expect(public_key).to be_a(OpenSSL::PKey::EC)
        expect(WebMock).not_to have_requested(:get, 'https://account.test/.well-known/jwks.json')
      end
    end

    describe 'L2 cache miss' do
      it 'fetches from origin and writes to Redis' do
        allow(redis).to receive(:get).with(described_class::BASE_REDIS_KEY).and_return(nil)
        allow(redis).to receive(:set)

        client.public_key(key_pair.kid)

        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
        expect(redis).to have_received(:set).with(
          described_class::BASE_REDIS_KEY,
          jwks_response,
          ex: config.jwks_cache_ttl
        )
      end
    end

    describe 'Redis write-through' do
      it 'stores the raw JSON body with the configured TTL' do
        allow(redis).to receive(:get).with(described_class::BASE_REDIS_KEY).and_return(nil)
        allow(redis).to receive(:set)

        config.jwks_cache_ttl = 1800
        client.public_key(key_pair.kid)

        expect(redis).to have_received(:set).with(
          described_class::BASE_REDIS_KEY,
          jwks_response,
          ex: 1800
        )
      end
    end

    describe 'refresh! bypasses Redis read' do
      it 'always fetches from origin on refresh' do
        # First load from Redis
        allow(redis).to receive(:get).with(described_class::BASE_REDIS_KEY).and_return(jwks_response)
        allow(redis).to receive(:set)
        client.public_key(key_pair.kid)

        expect(WebMock).not_to have_requested(:get, 'https://account.test/.well-known/jwks.json')

        # Force refresh goes to origin
        client.refresh!

        expect(WebMock).to have_requested(:get, 'https://account.test/.well-known/jwks.json').once
        expect(redis).to have_received(:set).with(
          described_class::BASE_REDIS_KEY,
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
        allow(redis).to receive(:get).with(described_class::BASE_REDIS_KEY).and_return(nil)
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
        allow(redis).to receive(:get).with(described_class::BASE_REDIS_KEY).and_return(jwks_response)
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
          described_class::BASE_REDIS_KEY,
          anything,
          ex: config.jwks_cache_ttl
        )
      end
    end
  end

  # The redis gem is the consumer's to provide: it is a development dependency
  # here and required at the point of use, so an app that caches JWKS in memory
  # alone never loads it. Missing, it must cost the shared cache and nothing
  # else — and `LoadError` is a `ScriptError`, so the `rescue StandardError`
  # that was the only clause here could not catch it.
  context 'without the redis gem installed' do
    let(:logger) { instance_double(Logger, info: nil, warn: nil, error: nil, debug: nil) }
    let(:config) do
      IdpRails.configuration.tap do |c|
        c.cache_redis = 'redis://localhost:6379/0'
        c.logger = logger
      end
    end

    before do
      # any_instance because the require happens in the constructor, before
      # there is an instance to stub.
      allow_any_instance_of(described_class).to receive(:require).with('redis').and_raise(LoadError)
    end

    it 'warns rather than raising' do
      expect { client }.not_to raise_error
      expect(logger).to have_received(:warn).with(/redis gem unavailable for JWKS cache/)
    end

    it 'still serves keys, from the in-memory cache alone' do
      expect(client.public_key(key_pair.kid)).to be_a(OpenSSL::PKey::EC)
    end
  end

  context 'with Redis cache and namespace' do
    let(:redis) { instance_double(Redis) }
    let(:config) do
      IdpRails.configuration.tap do |c|
        c.cache_redis = redis
        c.cache_redis_namespace = 'idp_sessions_crm'
      end
    end
    let(:namespaced_key) { "idp_sessions_crm:#{described_class::BASE_REDIS_KEY}" }

    it 'reads and writes using the namespaced key' do
      allow(redis).to receive(:get).with(namespaced_key).and_return(nil)
      allow(redis).to receive(:set)

      client.public_key(key_pair.kid)

      expect(redis).to have_received(:get).with(namespaced_key)
      expect(redis).to have_received(:set).with(
        namespaced_key,
        jwks_response,
        ex: config.jwks_cache_ttl
      )
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
