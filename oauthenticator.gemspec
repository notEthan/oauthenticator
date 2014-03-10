lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.any? { |lp| File.expand_path(lp) == File.expand_path(lib) }
require 'oauthenticator/version'

Gem::Specification.new do |spec|
  spec.name          = 'oauthenticator'
  spec.version       = OAuthenticator::VERSION
  spec.authors       = ["Ethan"]
  spec.email         = ["ethan@unth"]
  spec.summary       = %q(OAuth 1.0 request authentication middleware)
  spec.description   = %q(OAuthenticator authenticates OAuth 1.0 signed requests, primarily as a ) +
    %q(middleware, and forms useful error messages when authentication fails.)
  spec.homepage      = %q(https://github.com/notEthan/oauthenticator)
  spec.license       = 'MIT'

  spec.files         = [
    '.yardopts',
    'LICENSE.txt',
    'README.md',
    'lib/oauthenticator.rb',
    'lib/oauthenticator/middleware.rb',
    'lib/oauthenticator/config_methods.rb',
    'lib/oauthenticator/signed_request.rb',
    'lib/oauthenticator/version.rb'
  ]
  spec.executables   = []
  spec.test_files    = [
    'test/helper.rb',
    'test/oauthenticator_test.rb'
  ]
  spec.require_paths = ['lib']

  spec.add_runtime_dependency "rack"
  spec.add_runtime_dependency "simple_oauth"
  spec.add_runtime_dependency "json"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "minitest"
  spec.add_development_dependency "minitest-reporters"
  spec.add_development_dependency "rack-test"
  spec.add_development_dependency "timecop"
  spec.add_development_dependency "simplecov"
  begin # things for yard
    spec.add_development_dependency "yard"
    spec.add_development_dependency "rdiscount"
    spec.add_development_dependency "redcarpet"
    spec.add_development_dependency "rdoc", "~> 3.9.0"
  end
end
