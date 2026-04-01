# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "myaccount-jwt"
  spec.version       = "0.1.0"
  spec.authors       = [ "MyAccount Team" ]
  spec.summary       = "JWT verification client for MyAccount identity provider"
  spec.description   = "Shared library for sister apps to verify JWT passports issued by MyAccount. " \
                        "Handles JWKS fetching/caching, ES256 signature verification, claim validation, " \
                        "and optional Redis pub/sub revocation listening."
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.files = Dir["lib/**/*", "LICENSE", "README.md"]
  spec.require_paths = [ "lib" ]

  spec.add_dependency "jwt", "~> 2.9"

  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "webmock", "~> 3.23"
  spec.add_development_dependency "redis", ">= 4.0"
end
