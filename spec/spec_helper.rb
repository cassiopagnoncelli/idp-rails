# frozen_string_literal: true

require "ostruct"
require "webmock/rspec"
require "myaccount-jwt"

# Generate a test ES256 key pair for signing tokens in specs.
module TestKeys
  def self.generate
    key = OpenSSL::PKey::EC.generate("prime256v1")
    kid = "test_key_001"

    # Build JWKS entry from the key.
    point = key.public_key
    group = point.group
    bn = point.to_bn(:uncompressed)
    coord_len = (group.degree + 7) / 8
    uncompressed = bn.to_s(2)
    x_bytes = uncompressed[1, coord_len]
    y_bytes = uncompressed[1 + coord_len, coord_len]

    jwk = {
      kty: "EC",
      crv: "P-256",
      kid: kid,
      use: "sig",
      alg: "ES256",
      x: Base64.urlsafe_encode64(x_bytes, padding: false),
      y: Base64.urlsafe_encode64(y_bytes, padding: false)
    }

    OpenStruct.new(
      private_key: key,
      public_key: OpenSSL::PKey::EC.new(key.public_to_pem),
      kid: kid,
      jwk: jwk
    )
  end

  def self.sign_token(payload, key_pair)
    JWT.encode(payload, key_pair.private_key, "ES256", { kid: key_pair.kid })
  end
end

RSpec.configure do |config|
  config.before(:each) do
    MyAccount::JWT.reset_configuration!
    MyAccount::JWT.configure do |c|
      c.jwks_url = "https://account.test/.well-known/jwks.json"
      c.issuer = "https://account.test"
    end
  end
end
