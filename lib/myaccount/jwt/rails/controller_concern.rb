# frozen_string_literal: true

module MyAccount
  module JWT
    module Rails
      # Include this concern in your ApplicationController to add JWT authentication.
      #
      # @example
      #   class ApplicationController < ActionController::API
      #     include MyAccount::JWT::Rails::ControllerConcern
      #
      #     before_action :authenticate!
      #   end
      #
      #   # In a specific controller:
      #   class MerchantsController < ApplicationController
      #     def index
      #       passport.account_type  # => "Merchant"
      #       passport.role          # => "admin"
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
          @_myaccount_passport
        end

        # Authenticate the current request via Bearer token.
        # Halts the request with 401 if the token is invalid.
        def authenticate!
          token = extract_bearer_token
          unless token
            return render_auth_error("missing_token", status: :unauthorized)
          end

          @_myaccount_passport = MyAccount::JWT.verify!(token)
        rescue ExpiredTokenError
          render_auth_error("token_expired", status: :unauthorized)
        rescue RevokedTokenError
          render_auth_error("token_revoked", status: :unauthorized)
        rescue InvalidAudienceError => e
          render_auth_error(e.message, status: :forbidden)
        rescue VerificationError => e
          render_auth_error(e.message, status: :unauthorized)
        end

        # Require that the passport has a specific scope.
        # Call after authenticate!
        #
        # @param scope [String]
        def require_scope!(scope)
          unless passport&.has_scope?(scope)
            render_auth_error("insufficient_scope", status: :forbidden)
          end
        end

        # Require that the passport has an account context selected.
        # Call after authenticate!
        def require_account!
          unless passport&.account_selected?
            render_auth_error("account_not_selected", status: :forbidden)
          end
        end

        private

        def extract_bearer_token
          header = request.headers["Authorization"]
          return unless header&.start_with?("Bearer ")

          header.split(" ", 2).last.presence
        end

        def render_auth_error(message, status: :unauthorized)
          render json: { error: message }, status: status
        end
      end
    end
  end
end
