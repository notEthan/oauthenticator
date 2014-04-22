# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

# not going to test a ton here, since the Faraday middleware mostly just calls to SignableRequest which is 
# rather well-tested 
describe OAuthenticator::FaradaySigner do
  def assert_response(expected_status, expected_body, faraday_response)
    assert_equal expected_status.to_i, faraday_response.status.to_i, "Expected status to be #{expected_status.inspect}" +
      "; got #{faraday_response.status.inspect}. body was: #{faraday_response.body}"
    assert expected_body === faraday_response.body, "Expected match for #{expected_body}; got #{faraday_response.body}"
  end

  it 'succeeds' do
    signing_options = {
      :signature_method => 'PLAINTEXT',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => token,
      :token_secret => token_secret,
    }

    connection = Faraday.new(:url => 'http://example.com') do |faraday|
      faraday.request :oauthenticator_signer, signing_options
      faraday.adapter :rack, oapp
    end
    response = connection.get '/'
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

    connection = Faraday.new(:url => 'http://example.com') do |faraday|
      faraday.request :url_encoded
      faraday.request :oauthenticator_signer, signing_options
      faraday.adapter :rack, oapp
    end
    response = connection.put('/', :foo => {:bar => :baz})
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

    connection = Faraday.new(:url => 'http://example.com') do |faraday|
      faraday.request :oauthenticator_signer, signing_options
      faraday.adapter :rack, oapp
    end
    response = connection.get '/'
    assert_response 401, /Authorization oauth_signature.*is invalid/m, response
  end
end
