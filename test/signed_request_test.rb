# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

# most everything about this is tested via the middlware in oauthenticator_test, so not a lot here 
describe OAuthenticator::SignedRequest do
  describe '#initialize' do
    it 'checks for unrecognized attributes' do
      assert_raises(ArgumentError) { OAuthenticator::SignedRequest.new(:foo => 'bar') }
    end
  end
end
