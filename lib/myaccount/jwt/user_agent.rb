# frozen_string_literal: true

require "browser"

module MyAccount
  module JWT
    # Parses a User-Agent string into a human-readable device name
    # in the format "[browser] on [platform]" (e.g. "Safari on macOS").
    #
    # This mirrors the logic used by the MyAccount login screen so that
    # sister apps (CRM, etc.) display the same device names.
    #
    # @example
    #   MyAccount::JWT::UserAgent.device_name("Mozilla/5.0 (Macintosh; ...) Safari/605.1.15")
    #   # => "Safari on macOS"
    module UserAgent
      module_function

      # @param user_agent [String, nil] raw User-Agent header value
      # @return [String, nil] human-readable device name, or nil if unrecognisable
      def device_name(user_agent)
        return nil if user_agent.nil? || user_agent.strip.empty?

        b = Browser.new(user_agent)
        browser_name = b.name unless b.name == "Unknown Browser"

        platform = case
        when b.platform.ios?       then "iOS"
        when b.platform.android?   then "Android"
        when b.platform.mac?       then "macOS"
        when b.platform.windows?   then "Windows"
        when b.platform.linux?     then "Linux"
        when b.platform.chrome_os? then "ChromeOS"
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
