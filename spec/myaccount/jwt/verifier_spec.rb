# frozen_string_literal: true

RSpec.describe MyAccount::JWT::Verifier do
  let(:key_pair) { TestKeys.generate }

  let(:jwks_response) do
    { keys: [ key_pair.jwk ] }.to_json
  end

  let(:valid_payload) do
    {
      iss: "https://account.test",
      sub: "usr_abc123",
      iat: Time.now.to_i,
      exp: (Time.now + 900).to_i,
      jti: "tok_xyz789",
      act: {
        type: "Merchant",
        uuid: "mrc_def456",
        membership_uuid: "mbr_ghi012",
        role: "admin"
      },
      user: {
        email: "alice@example.com",
        name: "Alice",
        platform_admin: false,
        mfa_verified: true
      },
      scopes: [ "read", "write" ]
    }
  end

  before do
    stub_request(:get, "https://account.test/.well-known/jwks.json")
      .to_return(status: 200, body: jwks_response, headers: { "Content-Type" => "application/json" })
  end

  describe "#verify!" do
    it "returns a Passport for a valid token" do
      token = TestKeys.sign_token(valid_payload, key_pair)
      passport = described_class.new.verify!(token)

      expect(passport).to be_a(MyAccount::JWT::Passport)
      expect(passport.user_uuid).to eq("usr_abc123")
      expect(passport.account_type).to eq("Merchant")
      expect(passport.role).to eq("admin")
    end

    it "strips Bearer prefix" do
      token = TestKeys.sign_token(valid_payload, key_pair)
      passport = described_class.new.verify!("Bearer #{token}")

      expect(passport.user_uuid).to eq("usr_abc123")
    end

    it "raises ExpiredTokenError for expired tokens" do
      payload = valid_payload.merge(exp: (Time.now - 60).to_i)
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(MyAccount::JWT::ExpiredTokenError)
    end

    it "raises InvalidIssuerError for wrong issuer" do
      payload = valid_payload.merge(iss: "https://evil.example.com")
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(MyAccount::JWT::InvalidIssuerError)
    end

    it "raises InvalidSignatureError for unknown kid" do
      other_key = TestKeys.generate
      # Sign with a key that's not in the JWKS
      token = JWT.encode(valid_payload, other_key.private_key, "ES256", { kid: "unknown_key" })

      expect { described_class.new.verify!(token) }
        .to raise_error(MyAccount::JWT::InvalidSignatureError, /Unknown signing key/)
    end

    it "raises VerificationError for tampered tokens" do
      token = TestKeys.sign_token(valid_payload, key_pair)
      parts = token.split(".")
      parts[1] = Base64.urlsafe_encode64('{"sub":"usr_hacked"}', padding: false)
      tampered = parts.join(".")

      expect { described_class.new.verify!(tampered) }
        .to raise_error(MyAccount::JWT::VerificationError)
    end
  end

  describe "account type filtering" do
    before do
      MyAccount::JWT.configure do |c|
        c.accepted_account_types = [ "Merchant" ]
      end
    end

    it "accepts matching account types" do
      token = TestKeys.sign_token(valid_payload, key_pair)
      passport = described_class.new.verify!(token)
      expect(passport.account_type).to eq("Merchant")
    end

    it "rejects non-matching account types" do
      payload = Marshal.load(Marshal.dump(valid_payload))
      payload[:act][:type] = "Customer"
      token = TestKeys.sign_token(payload, key_pair)

      expect { described_class.new.verify!(token) }
        .to raise_error(MyAccount::JWT::InvalidAudienceError, /Customer/)
    end

    it "allows tokens without account context" do
      payload = valid_payload.merge(act: nil)
      token = TestKeys.sign_token(payload, key_pair)
      passport = described_class.new.verify!(token)

      expect(passport.account_selected?).to be false
    end
  end

  describe "revocation checking" do
    let(:subscriber) { MyAccount::JWT::RevocationSubscriber.new }

    it "rejects revoked users" do
      subscriber.block!("usr_abc123")

      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      expect { verifier.verify!(token) }
        .to raise_error(MyAccount::JWT::RevokedTokenError)
    end

    it "passes non-revoked users" do
      token = TestKeys.sign_token(valid_payload, key_pair)
      verifier = described_class.new(revocation_subscriber: subscriber)

      passport = verifier.verify!(token)
      expect(passport.user_uuid).to eq("usr_abc123")
    end
  end
end
