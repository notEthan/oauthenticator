# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

describe OAuthenticator::SignableRequest do
  def example_request(attributes={})
    OAuthenticator::SignableRequest.new({
      :request_method => 'get',
      :uri => 'http://example.com',
      :media_type => 'text/plain',
      :body => 'hi there',
      :consumer_key => 'a consumer key',
      :consumer_secret => 'a consumer secret',
      :signature_method => 'PLAINTEXT'
    }.merge(attributes))
  end


  describe 'default attributes' do
    it('generates nonces') do
      assert_equal(2, 2.times.map { example_request.protocol_params['oauth_nonce'] }.uniq.compact.size)
    end
    it('defaults to version 1.0') { assert_equal('1.0', example_request.protocol_params['oauth_version']) }
    it 'lets you omit version if you really want to' do
      assert(!example_request(:version => nil).protocol_params.key?('oauth_version'))
    end
    it 'generates timestamp' do
      Timecop.freeze Time.at 1391021695
      assert_equal 1391021695.to_s, example_request.protocol_params['oauth_timestamp']
    end
  end

  describe 'required attributes' do
    it 'complains about missing required params' do
      err = assert_raises(ArgumentError) { OAuthenticator::SignableRequest.new({}) }
      %w(request_method uri media_type body consumer_key signature_method).each do |required|
        assert_match /#{required}/, err.message
      end
    end
  end

  describe 'the example in 3.1' do
    # a request with attributes from the oauth spec
    def spec_request(attributes={})
      example_request({
        :request_method => 'POST',
        :uri => 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b',
        :media_type => 'application/x-www-form-urlencoded',
        :body => 'c2&a3=2+q',
        :consumer_key => '9djdj82h48djs9d2',
        :token => 'kkk9d7dh3k39sjv7',
        :consumer_secret => 'j49sk3j29djd',
        :token_secret => 'dh893hdasih9',
        :signature_method => 'HMAC-SHA1',
        :timestamp => '137131201',
        :nonce => '7d8f3e4a',
        :version => nil,
        :realm => "Example",
      })
    end

    it 'has the same signature base string' do
      spec_signature_base = "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" +
        "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_" +
        "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m" +
        "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk" +
        "9d7dh3k39sjv7"
      assert_equal(spec_signature_base, spec_request.send(:signature_base))
    end

    it 'has the same normalized parameters' do
      spec_normalized_request_params_string = "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj" +
        "dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1" +
        "&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
      assert_equal(spec_normalized_request_params_string, spec_request.send(:normalized_request_params_string))

    end

    it 'calculates authorization the same' do
      # a keen observer may note that the signature is different than the one in the actual spec. the spec is
      # in error - see http://www.rfc-editor.org/errata_search.php?rfc=5849
      spec_authorization = OAuthenticator.parse_authorization(%q(OAuth realm="Example",
        oauth_consumer_key="9djdj82h48djs9d2",
        oauth_token="kkk9d7dh3k39sjv7",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131201",
        oauth_nonce="7d8f3e4a",
        oauth_signature="r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D"
      ))
      assert_equal(spec_authorization, spec_request.signed_protocol_params)
    end
  end

  describe '#authorization' do
    it 'has the parameter name followed by an = and a quoted encoded value' do
      many_characters = %q( !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~Ā)
      authorization = example_request(:consumer_key => many_characters).authorization
      # only alphas, numerics, and -._~ remain unencoded per 3.6
      # hexes are uppercase 
      assert authorization.include?(%q(consumer_key="%20%21%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%C4%80"))
    end
  end
end
