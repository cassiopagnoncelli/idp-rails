# frozen_string_literal: true

RSpec.describe Idp::JWT::UserAgent do
  describe ".device_name" do
    it "parses Safari on macOS" do
      ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
      expect(described_class.device_name(ua)).to eq("Safari on macOS")
    end

    it "parses Chrome on Windows" do
      ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
      expect(described_class.device_name(ua)).to eq("Chrome on Windows")
    end

    it "parses Safari on iOS" do
      ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
      expect(described_class.device_name(ua)).to include("Safari").and include("iOS")
    end

    it "parses Chrome on Android" do
      ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.40 Mobile Safari/537.36"
      expect(described_class.device_name(ua)).to eq("Chrome on Android")
    end

    it "parses Firefox on Linux" do
      ua = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
      expect(described_class.device_name(ua)).to eq("Firefox on Linux")
    end

    it "parses Edge on Windows" do
      ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"
      expect(described_class.device_name(ua)).to eq("Microsoft Edge on Windows")
    end

    it "detects bots" do
      ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
      expect(described_class.device_name(ua)).to eq("Bot")
    end

    it "returns nil for unrecognized user agent" do
      expect(described_class.device_name("some-api-client/1.0")).to be_nil
    end

    it "returns nil for nil" do
      expect(described_class.device_name(nil)).to be_nil
    end

    it "returns nil for blank string" do
      expect(described_class.device_name("")).to be_nil
      expect(described_class.device_name("   ")).to be_nil
    end
  end
end
