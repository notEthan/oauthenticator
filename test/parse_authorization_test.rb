# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

describe 'OAuthenticator.parse_authorization' do
  let :spec_authorization do
    %q(OAuth realm="Example",
      oauth_consumer_key="9djdj82h48djs9d2",
      oauth_token="kkk9d7dh3k39sjv7",
      oauth_signature_method="HMAC-SHA1",
      oauth_timestamp="137131201",
      oauth_nonce="7d8f3e4a",
      oauth_signature="r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D"
    )
  end
  let :spec_authorization_hash do
    {
      'realm' => "Example",
      'oauth_consumer_key' => "9djdj82h48djs9d2",
      'oauth_token' => "kkk9d7dh3k39sjv7",
      'oauth_signature_method' => "HMAC-SHA1",
      'oauth_timestamp' => "137131201",
      'oauth_nonce' => "7d8f3e4a",
      'oauth_signature' => "r6/TJjbCOr97/+UU0NsvSne7s5g=",
    }
  end

  it 'parses the example in the spec' do
    assert_equal(spec_authorization_hash, OAuthenticator.parse_authorization(spec_authorization))
  end
  it 'parses the authorization SignableRequest calculates' do
    request = OAuthenticator::SignableRequest.new({
      :request_method => 'POST',
      :uri => 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b',
      :media_type => 'application/x-www-form-urlencoded',
      :body => 'c2&a3=2+q',
      :authorization => spec_authorization_hash,
      :consumer_secret => 'j49sk3j29djd',
      :token_secret => 'dh893hdasih9',
    })
    assert_equal(spec_authorization_hash, OAuthenticator.parse_authorization(request.authorization))
  end

  describe 'optional linear white space' do
    { :space =>           %q(OAuth a="b", c="d", e="f"),
      :spaces =>          %q(OAuth a="b",    c="d",   e="f" ),
      :tab =>             %q(OAuth a="b",	c="d",	e="f"),
      :tabs =>            %q(OAuth a="b",		c="d",			e="f"),
      :tabs_and_spaces => %q(OAuth a="b",		 c="d",   	e="f"),
      :none =>            %q(OAuth a="b",c="d",e="f"),
    }.map do |name, authorization|
      it "parses with #{name}" do
        assert_equal({'a' => 'b', 'c' => 'd', 'e' => 'f'}, OAuthenticator.parse_authorization(authorization))
      end
    end
  end

  it "handles commas inside quoted values" do
    # note that this is invalid according to the spec; commas should be %-encoded, but this is accepted in 
    # the interests of robustness and consistency (other characters are accepted when they should really be 
    # escaped). 
    header_with_commas = 'OAuth oauth_consumer_key="a,bcd", oauth_nonce="o,LKtec51GQy", oauth_signature="efgh%2Cmnop"'
    assert_equal({'oauth_consumer_key' => "a,bcd", 'oauth_nonce' => "o,LKtec51GQy", 'oauth_signature' => "efgh,mnop"},
      OAuthenticator.parse_authorization(header_with_commas))
  end

  it "raises ParseError on input without a comma between key/value pairs" do
    assert_raises(OAuthenticator::ParseError) do
      OAuthenticator.parse_authorization(%q(OAuth oauth_consumer_key="k" oauth_nonce="n"))
    end
  end

  it "raises ParseError on malformed input" do
    assert_raises(OAuthenticator::ParseError) { OAuthenticator.parse_authorization(%q(OAuth huh=/)) }
  end

  it "raises ParseError when the header does not start with 'OAuth '" do
    assert_raises(OAuthenticator::ParseError) { OAuthenticator.parse_authorization(%q(FooAuth foo="baz")) }
  end

  it "raises DuplicatedParameter when the header contains duplicated parameters" do
    assert_raises(OAuthenticator::DuplicatedParameters) do
      OAuthenticator.parse_authorization(%q(OAuth oauth_nonce="a", oauth_nonce="b"))
    end
  end
end
