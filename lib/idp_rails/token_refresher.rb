# frozen_string_literal: true

module IdpRails
  # Session-refresh policy for server-session Rails consumers (CRM, Trail, …)
  # that keep the idp access/refresh token pair in their Rails session.
  #
  # The HTTP exchange stays with the app's own API client; this class owns
  # what happens to the session afterwards — the part every consumer used to
  # hand-roll, and hand-roll wrong by treating a network blip like a dead
  # grant (clearing the session and forcing a fresh OAuth grant per blip).
  #
  # That API client must authenticate as THE client the refresh token was
  # issued to: idp refuses a token belonging to another client (RFC 6749 §6),
  # answering exactly as it does for a token that does not exist, so a mismatch
  # arrives here as :invalid_grant. Idp did not always check, so an app
  # refreshing another client's tokens could appear to work; it no longer can.
  #
  #   Hash from the block      → :refreshed      — session updated in place
  #   :invalid_grant           → :invalid_grant  — grant is dead; tokens
  #                                                cleared; re-login required
  #   nil                      → :transient      — idp unreachable; session
  #                                                kept untouched so the next
  #                                                request retries the refresh
  #
  # @example
  #   outcome = IdpRails::TokenRefresher.call(session: session) do |refresh_token|
  #     IdpApiClient.refresh_token(refresh_token, user_agent: request.user_agent)
  #   rescue IdpApiClient::InvalidGrantError
  #     :invalid_grant
  #   end
  #
  #   outcome.refreshed? && outcome.access_token
  class TokenRefresher
    Outcome = Struct.new(:status, :access_token, keyword_init: true) do
      def refreshed?      = status == :refreshed
      def invalid_grant?  = status == :invalid_grant
      def transient?      = status == :transient
      def missing?        = status == :missing
    end

    # @param session [#[], #[]=, #delete] the Rails session (or any hash-like)
    # @param jwt_key [Symbol] session key holding the idp access token
    # @param refresh_key [Symbol] session key holding the idp refresh token
    # @yield [refresh_token] performs the refresh-grant HTTP call
    # @yieldreturn [Hash, :invalid_grant, nil] see above
    # @return [Outcome]
    def self.call(session:, jwt_key: :idp_jwt, refresh_key: :idp_refresh_token)
      refresh_token = session[refresh_key]

      if refresh_token.to_s.empty?
        session.delete(jwt_key)
        session.delete(refresh_key)
        return Outcome.new(status: :missing)
      end

      case (result = yield(refresh_token))
      when Hash
        access_token = result[:access_token] || result["access_token"]
        new_refresh  = result[:refresh_token] || result["refresh_token"]

        session[jwt_key] = access_token
        session[refresh_key] = new_refresh if new_refresh

        Outcome.new(status: :refreshed, access_token: access_token)
      when :invalid_grant
        session.delete(jwt_key)
        session.delete(refresh_key)
        Outcome.new(status: :invalid_grant)
      else
        Outcome.new(status: :transient)
      end
    end
  end
end
