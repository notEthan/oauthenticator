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

  spec.files         = ['lib/oauthenticator.rb', 'lib/oauthenticator/version.rb']
  spec.executables   = []
  spec.test_files    = []
  spec.require_paths = ['lib']
end
