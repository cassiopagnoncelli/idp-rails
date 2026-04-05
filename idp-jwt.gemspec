# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'idp-jwt'
  spec.version       = '0.1.0'
  spec.authors       = [ 'Idp Team' ]
  spec.summary       = 'JWT verification client for Idp identity provider'
  spec.description   = 'Shared library for sister apps to verify JWT passports issued by Idp. ' \
                       'Handles JWKS fetching/caching, ES256 signature verification, claim validation, ' \
                       'and optional revocation listening via Redis pub/sub or RabbitMQ.'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.files = Dir['lib/**/*', 'LICENSE', 'README.md']
  spec.require_paths = [ 'lib' ]

  spec.add_dependency 'browser', '~> 6.2'
  spec.add_dependency 'jwt', '~> 2.9'

  spec.add_development_dependency 'bunny', '>= 2.20'
  spec.add_development_dependency 'redis', '>= 4.0'
  spec.add_development_dependency 'ostruct'
  spec.add_development_dependency 'rspec', '~> 3.13'
  spec.add_development_dependency 'rubocop', '~> 1.75'
  spec.add_development_dependency 'rubocop-rspec', '~> 3.6'
  spec.add_development_dependency 'rubocop-rails-omakase'
  spec.add_development_dependency 'webmock', '~> 3.23'
  spec.metadata['rubygems_mfa_required'] = 'true'
end
