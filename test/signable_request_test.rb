# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

describe OAuthenticator::SignableRequest do
  let :base_example_initialize_attrs do
    {
      :request_method => 'get',
      :uri => 'http://example.com',
      :media_type => 'text/plain',
      :body => 'hi there',
    }
  end
  let :example_initialize_attrs do
    base_example_initialize_attrs.merge({
      :consumer_key => 'a consumer key',
      :consumer_secret => 'a consumer secret',
      :signature_method => 'PLAINTEXT'
    })
  end

  def example_request(attributes={})
    OAuthenticator::SignableRequest.new(example_initialize_attrs.reject do |k,_|
      attributes.keys.any? { |ak| ak.to_s == k.to_s }
    end.merge(attributes))
  end

  let :rsa_private_key do
    "-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----"
  end

  describe 'initialize' do
    describe 'default attributes' do
      describe 'with any signature method' do
        OAuthenticator::SignableRequest::SIGNATURE_METHODS.keys.each do |signature_method|
          it("defaults to version 1.0 with #{signature_method}") do
            request = example_request(:signature_method => signature_method)
            assert_equal('1.0', request.protocol_params['oauth_version'])
          end
          it("lets you omit version if you really want to with #{signature_method}") do
            request = example_request(:version => nil, :signature_method => signature_method)
            assert(!request.protocol_params.key?('oauth_version'))
          end
        end
      end
      describe 'not plaintext' do
        it('generates nonces') do
          nonces = 2.times.map do
            example_request(:signature_method => 'HMAC-SHA1').protocol_params['oauth_nonce']
          end
          assert_equal(2, nonces.uniq.compact.size)
        end
        it 'generates timestamp' do
          Timecop.freeze Time.at 1391021695
          request = example_request(:signature_method => 'HMAC-SHA1')
          assert_equal 1391021695.to_s, request.protocol_params['oauth_timestamp']
        end
      end
      describe 'plaintext' do
        it('does not generate nonces') do
          request = example_request(:signature_method => 'PLAINTEXT')
          assert(!request.protocol_params.key?('oauth_nonce'))
        end
        it 'does not generate timestamp' do
          request = example_request(:signature_method => 'PLAINTEXT')
          assert(!request.protocol_params.key?('oauth_timestapm'))
        end
      end
    end

    it 'accepts string and symbol' do
      initialize_attr_variants = {
        :by_string => example_initialize_attrs.map { |k,v| {k.to_s => v} }.inject({}, &:update),
        :by_symbol => example_initialize_attrs.map { |k,v| {k.to_sym => v} }.inject({}, &:update),
        :by_random_mix => example_initialize_attrs.map { |k,v| {rand(2) == 0 ? k.to_s : k.to_sym => v} }.inject({}, &:update)
      }
      authorizations = initialize_attr_variants.values.map do |attrs|
        OAuthenticator::SignableRequest.new(attrs).authorization
      end
      assert_equal(1, authorizations.uniq.size)
    end

    it 'checks type' do
      assert_raises(TypeError) { OAuthenticator::SignableRequest.new("hello!") }
    end

    it 'checks authorization type' do
      assert_raises(TypeError) { example_request(:authorization => "hello!") }
    end

    it 'does not allow protocol parameters to be specified when authorization is specified' do
      OAuthenticator::SignableRequest::PROTOCOL_PARAM_KEYS.map do |key|
        assert_raises(ArgumentError) do
          OAuthenticator::SignableRequest.new(base_example_initialize_attrs.merge(:authorization => {}, key => 'val'))
        end
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

    it 'generally looks like: OAuth key="quoted-value", anotherkey="anothervalue"' do
      assert_equal(%q(OAuth ) +
        %q(oauth_consumer_key="a%20consumer%20key", ) +
        %q(oauth_signature="a%2520consumer%2520secret%26", ) +
        %q(oauth_signature_method="PLAINTEXT", ) +
        %q(oauth_version="1.0"),
        example_request.authorization
      )
    end
  end

  describe 'signature' do
    describe 'PLAINTEXT' do
      it 'signs with the consumer and token secrets, encoded and &-joined' do
        request = example_request(:token => 'a token', :token_secret => 'a token secret', :signature_method => 'PLAINTEXT')
        assert_equal('a%20consumer%20secret&a%20token%20secret', request.signed_protocol_params['oauth_signature'])
      end
    end

    describe 'HMAC-SHA1' do
      it 'signs with a HMAC-SHA1 digest of the signature base' do
        request = example_request(
          :token => 'a token',
          :token_secret => 'a token secret',
          :signature_method => 'HMAC-SHA1',
          :nonce => 'a nonce',
          :timestamp => 1397726597
        )
        assert_equal('rVKcy4CgAih1kv4HAMGiNnjmUJk=', request.signed_protocol_params['oauth_signature'])
      end
    end

    describe 'RSA-SHA1' do
      it 'signs with a RSA private key SHA1 signature' do
        request = example_request(
          :consumer_secret => rsa_private_key,
          :token => 'a token',
          :token_secret => 'a token secret',
          :signature_method => 'RSA-SHA1',
          :nonce => 'a nonce',
          :timestamp => 1397726597
        )
        assert_equal(
          "s3/TkrCJw54tOpsKUHkoQ9PeH1r4wB2fNb70XC2G1ef7Wb/dwwNUOhtjtpGMSDhmYQHzEPt0dAJ+PgeNs1O5NZJQB5JqdsmrhLS3ZdHx2iucxYvZSuDNi0GxaEepz5VS9rg+y5Gmep60BpAKhX0KGnkMY9HIhomTPSrYidAfDOE=",
          request.signed_protocol_params['oauth_signature']
        )
      end

      it 'ignores the token secret' do
        request_attrs = {
          :consumer_secret => rsa_private_key,
          :token => 'a token',
          :signature_method => 'RSA-SHA1',
          :nonce => 'a nonce',
          :timestamp => 1397726597,
        }
        request1 = example_request(request_attrs.merge(:token_secret => 'a token secret'))
        request2 = example_request(request_attrs.merge(:token_secret => 'an entirely different token secret'))
        assert_equal(request1.signature, request2.signature)
        assert_equal(request1.authorization, request2.authorization)
      end

      describe 'with an invalid key' do
        it 'errors' do
          assert_raises(OpenSSL::PKey::RSAError) { example_request(:signature_method => 'RSA-SHA1').signature }
        end
      end
    end
  end

  describe 'protocol_params' do
    it 'includes given protocol params with an oauth_ prefix' do
      OAuthenticator::SignableRequest::PROTOCOL_PARAM_KEYS.each do |param_key|
        assert_equal(example_request(param_key => 'a value').protocol_params["oauth_#{param_key}"], 'a value')
      end
    end
    it 'does not include a calculated signature' do
      assert !example_request.protocol_params.key?('oauth_signature')
    end
    it 'does include the signature of a given authorization' do
      assert_equal('a signature', OAuthenticator::SignableRequest.new(base_example_initialize_attrs.merge(
        :authorization => {'oauth_signature' => 'a signature'}
      )).protocol_params['oauth_signature'])
    end
    it 'does include unknown parameters of a given authorization' do
      assert_equal('bar', OAuthenticator::SignableRequest.new(base_example_initialize_attrs.merge(
        :authorization => {'foo' => 'bar'}
      )).protocol_params['foo'])
    end
  end

  describe 'signed_protocol_params' do
    it 'includes a signature' do
      assert_equal 'a%20consumer%20secret&', example_request.signed_protocol_params['oauth_signature']
    end

    it 'has a different signature than the given authorization if the given authorization is wrong' do
      request = OAuthenticator::SignableRequest.new(base_example_initialize_attrs.merge(
        :authorization => {
          'oauth_consumer_key' => 'a consumer key',
          'oauth_signature' => 'wrong%20secret&',
          'oauth_signature_method' => 'PLAINTEXT',
        },
        :consumer_secret => 'a consumer secret'
      ))
      refute_equal(
        request.protocol_params['oauth_signature'],
        request.signed_protocol_params['oauth_signature']
      )
    end
  end

  describe 'uri, per section 3.4.1.2' do
    it 'lowercases scheme and host' do
      [
        'http://example.com/FooBar',
        'Http://Example.com/FooBar',
        'HTTP://EXAMPLE.cOM/FooBar',
      ].each do |uri|
        assert_equal('http://example.com/FooBar', example_request(:uri => uri).send(:base_string_uri))
      end
    end

    it 'normalizes port' do
      assert_equal('http://example.com/F', example_request(:uri => 'http://example.com/F').send(:base_string_uri))
      assert_equal('http://example.com/F', example_request(:uri => 'http://example.com:80/F').send(:base_string_uri))
      assert_equal('http://example.com:81/F', example_request(:uri => 'http://example.com:81/F').send(:base_string_uri))
      assert_equal('https://example.com/F', example_request(:uri => 'https://example.com/F').send(:base_string_uri))
      assert_equal('https://example.com/F', example_request(:uri => 'https://example.com:443/F').send(:base_string_uri))
      assert_equal('https://example.com:444/F', example_request(:uri => 'https://example.com:444/F').send(:base_string_uri))
    end

    it 'excludes query and fragment' do
      assert_equal('http://example.com/FooBar', example_request(:uri => 'http://example.com/FooBar?foo=bar#foobar').send(:base_string_uri))
    end
  end

  it 'accepts string or symbol request methods' do
    {'GET' => [:get, :Get, :GET, 'GeT', 'get'], 'OPTIONS' => [:options, 'Options']}.each do |norm, variants|
      variants.each do |request_method|
        assert_equal(norm, example_request(:request_method => request_method).send(:normalized_request_method))
      end
    end
  end

  describe 'body' do
    it 'takes a string' do
      assert_equal('abody', example_request(:body => 'abody').send(:read_body))
    end
    it 'takes an IO' do
      assert_equal('abody', example_request(:body => StringIO.new('abody')).send(:read_body))
    end
    it 'rejects something else' do
      assert_raises(TypeError) { example_request(:body => Object.new).send(:read_body) }
    end
    it 'calculates their authorization the same' do
      request_io_body = example_request(:body => StringIO.new('abody'))
      request_str_body = example_request(:body => 'abody')
      assert_equal(request_io_body.authorization, request_str_body.authorization)
    end
  end

  it 'includes unrecognized authorization params when calculating signature base' do
    authorization = %q(OAuth realm="Example",
      oauth_foo="bar",
      oauth_consumer_key="9djdj82h48djs9d2",
      oauth_signature_method="HMAC-SHA1",
      oauth_timestamp="137131201",
      oauth_nonce="7d8f3e4a"
    )
    assert OAuthenticator::SignableRequest.new(base_example_initialize_attrs.merge(
      :authorization => OAuthenticator.parse_authorization(authorization)
    )).send(:signature_base).include?("oauth_foo%3Dbar")
  end

  it 'reproduces a successful OAuth example GET (lifted from simple oauth)' do
    request = OAuthenticator::SignableRequest.new(
      :request_method => :get,
      :uri => 'http://photos.example.net/photos',
      :media_type => 'application/x-www-form-urlencoded',
      :body => 'file=vacaction.jpg&size=original',
      :consumer_key => 'dpf43f3p2l4k3l03',
      :consumer_secret => rsa_private_key,
      :nonce => '13917289812797014437',
      :signature_method => 'RSA-SHA1',
      :timestamp => '1196666512'
    )
    expected_protocol_params = {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_nonce" => "13917289812797014437",
      "oauth_signature" => "jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=",
      "oauth_signature_method" => "RSA-SHA1",
      "oauth_timestamp" => "1196666512",
      "oauth_version" => "1.0",
    }

    assert_equal(expected_protocol_params, request.signed_protocol_params)
  end

  it 'reproduces a successful OAuth example GET (lifted from simple oauth)' do
    request = OAuthenticator::SignableRequest.new(
      :request_method => :get,
      :uri => 'http://host.net/resource?name=value',
      :media_type => 'application/x-www-form-urlencoded',
      :body => 'name=value',
      :consumer_key => 'abcd',
      :consumer_secret => 'efgh',
      :token => 'ijkl',
      :token_secret => 'mnop',
      :nonce => 'oLKtec51GQy',
      :signature_method => 'PLAINTEXT',
      :timestamp => '1286977095'
    )
    expected_protocol_params = {
      "oauth_consumer_key" => "abcd",
      "oauth_nonce" => "oLKtec51GQy",
      "oauth_signature" => "efgh&mnop",
      "oauth_signature_method" => "PLAINTEXT",
      "oauth_timestamp" => "1286977095",
      "oauth_token" => "ijkl",
      "oauth_version" => "1.0"
    }

    assert_equal(expected_protocol_params, request.signed_protocol_params)
  end
end
