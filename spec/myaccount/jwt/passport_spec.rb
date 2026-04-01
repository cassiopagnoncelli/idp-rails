# frozen_string_literal: true

RSpec.describe MyAccount::JWT::Passport do
  let(:claims) do
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
      scopes: [ "read", "write", "admin", "api_keys" ]
    }
  end

  subject(:passport) { described_class.new(claims) }

  describe "standard claims" do
    it "exposes issuer" do
      expect(passport.issuer).to eq("https://account.test")
    end

    it "exposes subject / user_uuid" do
      expect(passport.subject).to eq("usr_abc123")
      expect(passport.user_uuid).to eq("usr_abc123")
    end

    it "exposes jwt_id" do
      expect(passport.jwt_id).to eq("tok_xyz789")
    end

    it "exposes issued_at and expires_at as Time" do
      expect(passport.issued_at).to be_a(Time)
      expect(passport.expires_at).to be_a(Time)
    end
  end

  describe "account context" do
    it "exposes account_type" do
      expect(passport.account_type).to eq("Merchant")
    end

    it "exposes account_uuid" do
      expect(passport.account_uuid).to eq("mrc_def456")
    end

    it "exposes membership_uuid" do
      expect(passport.membership_uuid).to eq("mbr_ghi012")
    end

    it "exposes role" do
      expect(passport.role).to eq("admin")
    end

    it "reports account_selected?" do
      expect(passport.account_selected?).to be true
    end

    context "without account context" do
      let(:claims) { super().merge(act: nil) }

      it "returns nil for account fields" do
        expect(passport.account_type).to be_nil
        expect(passport.role).to be_nil
      end

      it "reports account not selected" do
        expect(passport.account_selected?).to be false
      end
    end
  end

  describe "user profile" do
    it "exposes email" do
      expect(passport.email).to eq("alice@example.com")
    end

    it "exposes name" do
      expect(passport.name).to eq("Alice")
    end

    it "exposes mfa_verified?" do
      expect(passport.mfa_verified?).to be true
    end

    it "exposes platform_admin?" do
      expect(passport.platform_admin?).to be false
    end
  end

  describe "scopes" do
    it "returns scopes array" do
      expect(passport.scopes).to eq([ "read", "write", "admin", "api_keys" ])
    end

    it "checks scope presence" do
      expect(passport.has_scope?("write")).to be true
      expect(passport.has_scope?("billing")).to be false
    end
  end

  describe "#expired?" do
    it "returns false for valid tokens" do
      expect(passport.expired?).to be false
    end

    it "returns true for expired tokens" do
      expired = described_class.new(claims.merge(exp: (Time.now - 60).to_i))
      expect(expired.expired?).to be true
    end
  end
end
