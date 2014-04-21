# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

describe OAuthenticator::SignedRequest do
  %w(timestamp_valid_period consumer_secret access_token_secret nonce_used? use_nonce! access_token_belongs_to_consumer?).each do |method_without_default|
    it "complains when #{method_without_default} is not implemented" do
      exc = assert_raises(NotImplementedError) do
        OAuthenticator::SignedRequest.new({}).public_send(method_without_default)
      end
      assert_match /included in a subclass of OAuthenticator::SignedRequest/, exc.message
    end
    it "uses the method #{method_without_default} when implemented" do
      called = false
      mod = Module.new { define_method(method_without_default) { called = true } }
      OAuthenticator::SignedRequest.including_config(mod).new({}).public_send(method_without_default)
      assert called
    end
  end
  it "complains when a method without a default is not implemented, using middleware" do
    exc = assert_raises(NotImplementedError) do
      OAuthenticator::Middleware.new(proc {}, {:config_methods => Module.new}).call({'HTTP_AUTHORIZATION' => %q(OAuth oauth_timestamp="1")})
    end
    assert_match /passed to OAuthenticator::Middleware using the option :config_methods./, exc.message
  end
  it "complains middleware is not given config methods" do
    assert_raises(ArgumentError) do
      OAuthenticator::Middleware.new(proc {})
    end
  end
  it 'uses timestamp_valid_period if that is implemented but timestamp_valid_past or timestamp_valid_future is not' do
    called = 0
    mod = Module.new { define_method(:timestamp_valid_period) { called +=1 } }
    OAuthenticator::SignedRequest.including_config(mod).new({}).public_send(:timestamp_valid_future)
    OAuthenticator::SignedRequest.including_config(mod).new({}).public_send(:timestamp_valid_past)
    assert_equal 2, called
  end
  it 'uses the default value for allowed signature methods' do
    assert_equal %w(RSA-SHA1 HMAC-SHA1 PLAINTEXT), OAuthenticator::SignedRequest.new({}).allowed_signature_methods
  end
  it 'uses default value for body_hash_required?' do
    assert_equal false, OAuthenticator::SignedRequest.new({}).body_hash_required?
  end
end
