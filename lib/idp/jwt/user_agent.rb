# frozen_string_literal: true

require "browser"

module Idp
  module JWT
    # Parses a User-Agent string into a human-readable device name
    # in the format "[browser] on [platform]" (e.g. "Safari on macOS").
    #
    # This mirrors the logic used by the Idp login screen so that
    # sister apps (CRM, etc.) display the same device names.
    #
    # @example
    #   Idp::JWT::UserAgent.device_name("Mozilla/5.0 (Macintosh; ...) Safari/605.1.15")
    #   # => "Safari on macOS"
    module UserAgent
      module_function

      # @param user_agent [String, nil] raw User-Agent header value
      # @return [String, nil] human-readable device name, or nil if unrecognisable
      def device_name(user_agent)
        return nil if user_agent.nil? || user_agent.strip.empty?

        b = Browser.new(user_agent)
        browser_name = b.name unless b.name == "Unknown Browser"

        platform = if b.platform.ios?
                     "iOS"
        elsif b.platform.android?
                     "Android"
        elsif b.platform.mac?
                     "macOS"
        elsif b.platform.windows?
                     "Windows"
        elsif b.platform.linux?
                     "Linux"
        elsif b.platform.chrome_os?
                     "ChromeOS"
        end

        if b.bot?
          "Bot"
        elsif browser_name && platform
          "#{browser_name} on #{platform}"
        elsif browser_name
          browser_name
        elsif platform
          platform
        end
      end
    end
  end
end
