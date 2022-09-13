lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.any? { |lp| File.expand_path(lp) == File.expand_path(lib) }
require 'oauthenticator/version'

Gem::Specification.new do |spec|
  spec.name          = 'oauthenticator'
  spec.version       = OAuthenticator::VERSION
  spec.authors       = ["Ethan"]
  spec.email         = ["ethan@unth"]
  spec.summary       = %q(OAuth 1.0 request signing and authentication)
  spec.description   = %q(OAuthenticator signs and authenticates OAuth 1.0 requests)
  spec.homepage      = %q(https://github.com/notEthan/oauthenticator)
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z lib`.split("\x0") + [
    '.yardopts',
    'LICENSE.txt',
    'CHANGELOG.md',
    'README.md',
    'Rakefile.rb',
  ]
  spec.executables   = []
  spec.test_files    = `git ls-files -z test`.split("\x0") + [
    '.simplecov',
  ]
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'rack', '>= 1.4', '< 4.0'
  spec.add_runtime_dependency 'json'
  spec.add_runtime_dependency 'faraday', '>= 0.9', '< 3.0'
  spec.add_runtime_dependency 'addressable', '~> 2.3'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'minitest-reporters'
  spec.add_development_dependency 'rack-test'
  spec.add_development_dependency 'timecop'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'api_hammer'
  spec.add_development_dependency 'yard'
end
