# simple test app using the config, consumer, and token from test/test_config_methods.rb

proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('lib', File.dirname(__FILE__)))

require 'oauthenticator'

require_relative 'test/test_config_methods'

helper = Object.new.extend(TestHelperMethods)
helper.consumer
helper.token_hash

run helper.oapp
