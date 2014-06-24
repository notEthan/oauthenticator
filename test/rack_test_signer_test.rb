# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

require 'oauthenticator/rack_test_signer'

# not going to test a ton here, since the rack test signer mostly just calls to SignableRequest which is 
# rather well-tested 
describe OAuthenticator::RackTestSigner do
  def assert_response(expected_status, expected_body, rack_response)
    assert_equal expected_status.to_i, rack_response.status.to_i, "Expected status to be #{expected_status.inspect}" +
      "; got #{rack_response.status.inspect}. body was: #{rack_response.body}"
    assert expected_body === rack_response.body, "Expected match for #{expected_body}; got #{rack_response.body}"
  end

  def app
    oapp
  end

  # this will construct the rack test session for us
  include Rack::Test::Methods

  it 'succeeds' do
    signing_options = {
      :signature_method => 'PLAINTEXT',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => token,
      :token_secret => token_secret,
    }

    response = OAuthenticator.signing_rack_test(signing_options) { get '/' }
    assert_response 200, '☺', response
  end

  it 'succeeds with form-encoded with HMAC' do
    signing_options = {
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => token,
      :token_secret => token_secret,
    }

    response = OAuthenticator.signing_rack_test(signing_options) { put('/', :foo => {:bar => :baz}) }
    assert_response 200, '☺', response
  end

  it 'is unauthorized' do
    signing_options = {
      :signature_method => 'PLAINTEXT',
      :consumer_key => consumer_key,
      :consumer_secret => 'nope',
      :token => token,
      :token_secret => 'definitelynot',
    }

    response = OAuthenticator.signing_rack_test(signing_options) { get '/' }
    assert_response 401, /Authorization oauth_signature.*is invalid/m, response
  end
end
