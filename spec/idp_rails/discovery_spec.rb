# frozen_string_literal: true

RSpec.describe IdpRails::Discovery do
  let(:base_url) { 'https://account.test' }
  let(:document) do
    {
      issuer: 'https://account.test',
      jwks_uri: 'https://account.test/.well-known/jwks.json',
      end_session_endpoint: 'https://account.test/oauth/end_session',
      token_endpoint: 'https://account.test/oauth/token',
      revocation_endpoint: 'https://account.test/oauth/revoke'
    }
  end

  def stub_discovery(body: document, status: 200)
    stub_request(:get, "#{base_url}/.well-known/openid-configuration")
      .to_return(status: status, body: JSON.generate(body), headers: { 'Content-Type' => 'application/json' })
  end

  describe 'reading the document' do
    it 'exposes the endpoints idp publishes' do
      stub_discovery

      discovery = described_class.new(base_url)

      expect(discovery.issuer).to eq('https://account.test')
      expect(discovery.jwks_uri).to eq('https://account.test/.well-known/jwks.json')
      expect(discovery.end_session_endpoint).to eq('https://account.test/oauth/end_session')
      expect(discovery.token_endpoint).to eq('https://account.test/oauth/token')
      expect(discovery.revocation_endpoint).to eq('https://account.test/oauth/revoke')
    end

    it 'answers nil for a key idp does not publish' do
      stub_discovery(body: { issuer: 'https://account.test' })

      expect(described_class.new(base_url).end_session_endpoint).to be_nil
    end

    it 'tolerates a base url with a trailing slash' do
      stub_discovery

      expect(described_class.new("#{base_url}/").issuer).to eq('https://account.test')
    end

    it 'fetches once and serves the rest from cache' do
      request = stub_discovery

      discovery = described_class.new(base_url)
      3.times { discovery.issuer }

      expect(request).to have_been_requested.once
    end

    it 're-fetches after the cache ttl lapses' do
      request = stub_discovery
      IdpRails.configuration.discovery_cache_ttl = 0

      discovery = described_class.new(base_url)
      discovery.issuer
      discovery.issuer

      expect(request).to have_been_requested.twice
    end

    it 'raises when idp answers with an error and nothing is cached' do
      stub_discovery(status: 500)

      expect { described_class.new(base_url).issuer }.to raise_error(IdpRails::Error, /HTTP 500/)
    end

    # These endpoints change about never. The TTL is there to pick a move up
    # eventually, not to make idp a hard dependency of every token check.
    it 'serves the document it already holds when a refresh fails' do
      stub_discovery
      IdpRails.configuration.discovery_cache_ttl = 0
      discovery = described_class.new(base_url)
      expect(discovery.issuer).to eq('https://account.test')

      stub_discovery(status: 503)

      expect(discovery.issuer).to eq('https://account.test')
      expect(discovery.jwks_uri).to eq('https://account.test/.well-known/jwks.json')
    end
  end

  describe 'configuration fallback' do
    it 'sources jwks_url, issuer and end_session_endpoint from the document' do
      stub_discovery
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url

      config = IdpRails.configuration

      expect(config.jwks_url).to eq('https://account.test/.well-known/jwks.json')
      expect(config.issuer).to eq('https://account.test')
      expect(config.end_session_endpoint).to eq('https://account.test/oauth/end_session')
    end

    # jwks_url and issuer are load-bearing: nil reaches JwksClient as URI(nil)
    # and raises an ArgumentError on the token-verification path, three frames
    # from anything naming discovery. Say it here instead.
    it 'raises a discovery-shaped error for jwks_url when the document cannot be read' do
      stub_discovery(status: 503)
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url

      expect { IdpRails.configuration.jwks_url }
        .to raise_error(IdpRails::Error, /Could not read jwks_uri from idp's discovery document/)
    end

    it 'raises for issuer rather than quietly handing back the placeholder' do
      stub_discovery(status: 503)
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url

      expect { IdpRails.configuration.issuer }
        .to raise_error(IdpRails::Error, /Could not read issuer/)
    end

    it 'raises when the document is readable but does not publish the key' do
      stub_discovery(body: { issuer: 'https://account.test' })
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url

      expect { IdpRails.configuration.jwks_url }
        .to raise_error(IdpRails::Error, /does not publish jwks_uri/)
    end

    it 'raises a self-explaining error when neither jwks_url nor discovery_url is set' do
      IdpRails.reset_configuration!

      expect { IdpRails.configuration.jwks_url }
        .to raise_error(IdpRails::Error, /no discovery_url is set/)
    end

    # Adopting discovery has to be a per-consumer decision, not a flag day.
    it 'lets an explicit setting win over the published one' do
      stub_discovery
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url
      IdpRails.configuration.jwks_url = 'https://pinned.test/jwks.json'

      expect(IdpRails.configuration.jwks_url).to eq('https://pinned.test/jwks.json')
    end

    it 'never reaches for discovery when none is configured' do
      IdpRails.reset_configuration!

      expect(IdpRails.configuration.discovery).to be_nil
      expect(IdpRails.configuration.issuer).to eq(IdpRails::Configuration::DEFAULT_ISSUER)
      expect(IdpRails.configuration.end_session_endpoint).to be_nil
    end

    # An unreachable discovery document must not take down a process whose
    # explicit settings are sitting right there.
    it 'degrades to nil when the document cannot be fetched' do
      stub_discovery(status: 503)
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url

      expect(IdpRails.configuration.end_session_endpoint).to be_nil
    end

    # validate! runs per Verifier and at boot; resolving there would put a
    # network fetch on both paths.
    it 'validates without fetching anything' do
      IdpRails.reset_configuration!
      IdpRails.configuration.discovery_url = base_url

      expect { IdpRails.configuration.validate! }.not_to raise_error
      expect(a_request(:get, %r{openid-configuration})).not_to have_been_made
    end

    it 'still refuses a configuration naming neither a jwks_url nor a discovery_url' do
      IdpRails.reset_configuration!

      expect { IdpRails.configuration.validate! }.to raise_error(IdpRails::Error, /jwks_url/)
    end
  end
end
