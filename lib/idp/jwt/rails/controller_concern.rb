# frozen_string_literal: true

module Idp
  module JWT
    module Rails
      # Include this concern in your ApplicationController to add JWT authentication.
      #
      # @example
      #   class ApplicationController < ActionController::API
      #     include Idp::JWT::Rails::ControllerConcern
      #
      #     before_action :authenticate!
      #   end
      #
      #   # In a specific controller:
      #   class MerchantsController < ApplicationController
      #     def index
      #       passport.user_uuid     # => "usr_a1b2c3d4"
      #     end
      #   end
      module ControllerConcern
        extend ActiveSupport::Concern if defined?(ActiveSupport::Concern)

        def self.included(base)
          if defined?(ActiveSupport::Concern)
            # Rails app — ActiveSupport::Concern handles it
          else
            # Plain Ruby — manual method injection
            base.class_eval do
              private :passport, :authenticate!, :render_auth_error, :extract_bearer_token
            end
          end
        end

        # The verified passport for the current request.
        # Only available after calling authenticate!
        #
        # @return [Passport, nil]
        def passport
          @_idp_passport
        end

        # Authenticate the current request via Bearer token.
        # Halts the request with 401 if the token is invalid.
        def authenticate!
          token = extract_bearer_token
          return render_auth_error("missing_token", status: :unauthorized) unless token

          @_idp_passport = Idp::JWT.verify!(token)
        rescue ExpiredTokenError
          render_auth_error("token_expired", status: :unauthorized)
        rescue RevokedTokenError
          render_auth_error("token_revoked", status: :unauthorized)
        rescue VerificationError => e
          render_auth_error(e.message, status: :unauthorized)
        end

        private

        def extract_bearer_token
          header = request.headers["Authorization"]
          return unless header&.match?(/\ABearer\s/i)

          header.sub(/\ABearer\s+/i, "").presence
        end

        def render_auth_error(message, status: :unauthorized)
          render json: { error: message }, status: status
        end
      end
    end
  end
end
