proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('../lib', File.dirname(__FILE__)))

require 'simplecov'

SimpleCov.start

# NO EXPECTATIONS 
ENV["MT_NO_EXPECTATIONS"] = ''

require 'minitest/autorun'
require 'minitest/reporters'
Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

require 'rack/test'
require 'timecop'

require 'oauthenticator'

require 'test_config_methods'

class OAuthenticatorConfigSpec < Minitest::Spec
  after do
    Timecop.return
  end

  include TestHelperMethods
end

# register this to be the base class for specs instead of Minitest::Spec
Minitest::Spec.register_spec_type(//, OAuthenticatorConfigSpec)
