# frozen_string_literal: true

RSpec.describe MyAccount::JWT::RevocationSubscriber do
  subject(:subscriber) { described_class.new }

  describe "#revoked?" do
    it "returns false for unknown users" do
      expect(subscriber.revoked?("usr_unknown")).to be false
    end

    it "returns true for blocked users" do
      subscriber.block!("usr_blocked")
      expect(subscriber.revoked?("usr_blocked")).to be true
    end

    it "auto-expires entries" do
      subscriber.block!("usr_expiring", ttl: 0.01)
      sleep 0.02
      expect(subscriber.revoked?("usr_expiring")).to be false
    end
  end

  describe "#clear!" do
    it "removes all entries" do
      subscriber.block!("usr_a")
      subscriber.block!("usr_b")
      subscriber.clear!

      expect(subscriber.revoked?("usr_a")).to be false
      expect(subscriber.revoked?("usr_b")).to be false
    end
  end
end
