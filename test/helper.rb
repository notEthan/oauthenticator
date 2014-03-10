proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('../lib', File.dirname(__FILE__)))

require 'simplecov'

require 'debugger'
Debugger.start

# NO EXPECTATIONS 
ENV["MT_NO_EXPECTATIONS"]

require 'minitest/autorun'
require 'minitest/reporters'
Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

require 'rack/test'
require 'timecop'

require 'oauthenticator'
