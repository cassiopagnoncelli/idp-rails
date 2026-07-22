# frozen_string_literal: true

require "spec_helper"

RSpec.describe IdpRails::TokenRefresher do
  let(:session) { { idp_jwt: "old-jwt", idp_refresh_token: "old-refresh" } }

  it "updates the session and reports :refreshed on success" do
    outcome = described_class.call(session: session) do |refresh_token|
      expect(refresh_token).to eq("old-refresh")
      { access_token: "new-jwt", refresh_token: "new-refresh" }
    end

    expect(outcome).to be_refreshed
    expect(outcome.access_token).to eq("new-jwt")
    expect(session[:idp_jwt]).to eq("new-jwt")
    expect(session[:idp_refresh_token]).to eq("new-refresh")
  end

  it "keeps the old refresh token when rotation returns none" do
    outcome = described_class.call(session: session) { { access_token: "new-jwt" } }

    expect(outcome).to be_refreshed
    expect(session[:idp_refresh_token]).to eq("old-refresh")
  end

  it "accepts string keys from the HTTP client" do
    outcome = described_class.call(session: session) do
      { "access_token" => "new-jwt", "refresh_token" => "new-refresh" }
    end

    expect(outcome.access_token).to eq("new-jwt")
    expect(session[:idp_refresh_token]).to eq("new-refresh")
  end

  it "clears the session tokens on :invalid_grant" do
    outcome = described_class.call(session: session) { :invalid_grant }

    expect(outcome).to be_invalid_grant
    expect(session).not_to have_key(:idp_jwt)
    expect(session).not_to have_key(:idp_refresh_token)
  end

  it "keeps the session untouched on a transient failure (nil)" do
    outcome = described_class.call(session: session) { nil }

    expect(outcome).to be_transient
    expect(session[:idp_jwt]).to eq("old-jwt")
    expect(session[:idp_refresh_token]).to eq("old-refresh")
  end

  it "keeps the session on :terms_required" do
    outcome = described_class.call(session: session) { :terms_required }

    expect(outcome).to be_terms_required
    expect(session[:idp_refresh_token]).to eq("old-refresh")
  end

  it "clears tokens and reports :missing when there is nothing to refresh" do
    empty_session = { idp_jwt: "stale" }

    outcome = described_class.call(session: empty_session) { raise "must not call the block" }

    expect(outcome).to be_missing
    expect(empty_session).not_to have_key(:idp_jwt)
  end

  it "honours custom session keys" do
    custom = { jwt: "old", rt: "refresh-me" }

    outcome = described_class.call(session: custom, jwt_key: :jwt, refresh_key: :rt) do
      { access_token: "new" }
    end

    expect(outcome).to be_refreshed
    expect(custom[:jwt]).to eq("new")
  end
end
