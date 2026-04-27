# frozen_string_literal: true

RSpec.describe Idp::JWT::ClientCredentialsClient do
  let(:token_url) { 'https://account.test/oauth/token' }
  let(:client) do
    described_class.new(
      token_url: token_url,
      client_id: 'crm_service',
      client_secret: 'sekret',
      scope: 'users:lookup'
    )
  end

  let(:success_body) do
    {
      access_token: 'svc.access.token',
      token_type: 'Bearer',
      expires_in: 900,
      scope: 'users:lookup'
    }.to_json
  end

  it 'requests a token via HTTP Basic + grant_type=client_credentials' do
    stub = stub_request(:post, token_url)
      .with(
        headers: { 'Authorization' => /^Basic /, 'Accept' => 'application/json' },
        body: { 'grant_type' => 'client_credentials', 'scope' => 'users:lookup' }
      )
      .to_return(status: 200, body: success_body, headers: { 'Content-Type' => 'application/json' })

    expect(client.token).to eq('svc.access.token')
    expect(stub).to have_been_requested
  end

  it 'caches the token across calls and refreshes only when expired' do
    stub = stub_request(:post, token_url)
      .to_return(status: 200, body: success_body, headers: { 'Content-Type' => 'application/json' })

    3.times { client.token }
    expect(stub).to have_been_requested.once

    client.reset!
    client.token
    expect(stub).to have_been_requested.times(2)
  end

  it 'considers a token expired within the skew window' do
    short_lived = {
      access_token: 'short.lived',
      token_type: 'Bearer',
      expires_in: 5,
      scope: 'users:lookup'
    }.to_json

    stub_request(:post, token_url)
      .to_return(status: 200, body: short_lived, headers: { 'Content-Type' => 'application/json' })

    expect(client.token).to eq('short.lived')
    travel_to_future(seconds: 10) do
      stub_request(:post, token_url)
        .to_return(status: 200, body: success_body, headers: { 'Content-Type' => 'application/json' })

      expect(client.token).to eq('svc.access.token')
    end
  end

  it 'raises ClientCredentialsError on a 401 response' do
    stub_request(:post, token_url)
      .to_return(
        status: 401,
        body: { error: 'unauthorized_client', error_description: 'not allowed' }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    expect { client.token }.to raise_error(Idp::JWT::ClientCredentialsError) do |err|
      expect(err.status).to eq(401)
      expect(err.code).to eq('unauthorized_client')
      expect(err.message).to include('not allowed')
    end
  end

  it 'raises ClientCredentialsError on a malformed success response' do
    stub_request(:post, token_url)
      .to_return(status: 200, body: '{}', headers: { 'Content-Type' => 'application/json' })

    expect { client.token }.to raise_error(Idp::JWT::ClientCredentialsError, /missing access_token/)
  end

  def travel_to_future(seconds:)
    original = Time.method(:now)
    target = original.call + seconds
    Time.singleton_class.define_method(:now) { target }
    yield
  ensure
    Time.singleton_class.define_method(:now, &original)
  end
end
