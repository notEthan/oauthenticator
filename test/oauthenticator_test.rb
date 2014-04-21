# encoding: utf-8
proc { |p| $:.unshift(p) unless $:.any? { |lp| File.expand_path(lp) == p } }.call(File.expand_path('.', File.dirname(__FILE__)))
require 'helper'

# config methods for testing OAuthenticator. simple 
module OAuthenticatorTestConfigMethods
  class << self
    # a set of nonces
    define_method(:nonces) { @nonces ||= Set.new }
    # a Hash keyed by consumer keys with values of consumer secrets
    define_method(:consumer_secrets) { @consumer_secrets ||= {} }
    # a Hash keyed by tokens with values of token secrets 
    define_method(:token_secrets) { @token_secrets ||= {} }
    # a Hash keyed by tokens with values of consumer keys
    define_method(:token_consumers) { @token_consumers ||= {} }
  end

  def nonce_used?
    OAuthenticatorTestConfigMethods.nonces.include?(nonce)
  end

  def use_nonce!
    OAuthenticatorTestConfigMethods.nonces << nonce
  end

  def timestamp_valid_period
    10
  end

  def allowed_signature_methods
    %w(HMAC-SHA1 RSA-SHA1 PLAINTEXT)
  end

  def consumer_secret
    OAuthenticatorTestConfigMethods.consumer_secrets[consumer_key]
  end

  def token_secret
    OAuthenticatorTestConfigMethods.token_secrets[token]
  end

  def token_belongs_to_consumer?
    OAuthenticatorTestConfigMethods.token_consumers[token] == consumer_key
  end
end

describe OAuthenticator::Middleware do
  # act like a database cleaner
  after do
    [:nonces, :consumer_secrets, :token_secrets, :token_consumers].each do |db|
      OAuthenticatorTestConfigMethods.send(db).clear
    end
  end

  let(:simpleapp) { proc { |env| [200, {}, ['☺']] } }
  let(:oapp) { OAuthenticator::Middleware.new(simpleapp, :config_methods => OAuthenticatorTestConfigMethods) }

  let(:consumer) do
    {:key => "test_client_app_key", :secret => "test_client_app_secret"}.tap do |consumer|
      OAuthenticatorTestConfigMethods.consumer_secrets[consumer[:key]] = consumer[:secret]
    end
  end
  let(:consumer_key) { consumer[:key] }
  let(:consumer_secret) { consumer[:secret] }

  let(:token_hash) do
    {:token => 'test_token', :secret => 'test_token_secret', :consumer_key => consumer_key}.tap do |hash|
      OAuthenticatorTestConfigMethods.token_secrets[hash[:token]] = hash[:secret]
      OAuthenticatorTestConfigMethods.token_consumers[hash[:token]] = hash[:consumer_key]
    end
  end
  let(:token) { token_hash[:token] }
  let(:token_secret) { token_hash[:secret] }

  def assert_response(expected_status, expected_body, actual_status, actual_headers, actual_body)
    actual_body_s = actual_body.to_enum.to_a.join
    assert_equal expected_status.to_i, actual_status.to_i, "Expected status to be #{expected_status.inspect}" +
      "; got #{actual_status.inspect}. body was: #{actual_body_s}"
    assert expected_body === actual_body_s, "Expected match for #{expected_body}; got #{actual_body_s}"
  end

  it 'makes a valid two-legged signed request (generated)' do
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))
  end

  it 'makes a valid two-legged signed request with a blank token (generated)' do
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => '',
      :token_secret => '',
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))
  end

  it 'makes a valid two-legged signed request with a form encoded body (generated)' do
    request = Rack::Request.new(Rack::MockRequest.env_for('/',
      :method => 'GET',
      :input => 'a=b&a=c',
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=UTF8',
    ))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))
  end

  it 'makes a valid three-legged signed request (generated)' do
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => token,
      :token_secret => token_secret,
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))
  end

  2.times do |i|
    # run these twice to make sure that the databas cleaner clears out the nonce since we use the same 
    # nonce across tests 
    it "makes a valid signed two-legged request (static #{i})" do
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
        %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
        %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
        %q(oauth_signature_method="HMAC-SHA1", ) +
        %q(oauth_timestamp="1391021695", ) +
        %q(oauth_version="1.0")
      assert_response(200, '☺', *oapp.call(request.env))
    end

    it "makes a valid signed three-legged request (static #{i})" do
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      token_hash # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = %q(OAuth ) +
        %q(oauth_consumer_key="test_client_app_key", ) +
        %q(oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ) +
        %q(oauth_signature="MyfcvCJfiOHCdkdwFOKtfwoOPqE%3D", ) +
        %q(oauth_signature_method="HMAC-SHA1", ) +
        %q(oauth_timestamp="1391021695", ) +
        %q(oauth_token="test_token", ) +
        %q(oauth_version="1.0")
      assert_response(200, '☺', *oapp.call(request.env))
    end
  end

  it 'complains about a missing Authorization header' do
    assert_response(401, /Authorization header is missing/, *oapp.call({}))
  end

  it 'complains about a blank Authorization header' do
    assert_response(401, /Authorization header is blank/, *oapp.call({'HTTP_AUTHORIZATION' => ' '}))
  end

  it 'complains about a non-OAuth Authentication header' do
    assert_response(401, /Authorization scheme is not OAuth/, *oapp.call({'HTTP_AUTHORIZATION' => 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='}))
  end

  describe 'invalid Authorization header' do
    it 'has duplicate params' do
      assert_response(
        401,
        /Received multiple instances of Authorization parameter oauth_version/,
        *oapp.call({'HTTP_AUTHORIZATION' => %q(OAuth oauth_version="1.0", oauth_version="1.1")})
      )
    end

    it 'has something unparseable' do
      assert_response(401, /Could not parse Authorization header/, *oapp.call({'HTTP_AUTHORIZATION' => %q(OAuth <client-app-key>test_client_app_key</client-app-key>)}))
    end
  end

  it 'omits timestamp' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      #%q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_timestamp.*is missing/m, *oapp.call(request.env))
  end
  it 'has a non-integer timestamp' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="now", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_timestamp.*is not an integer - got: now/m, *oapp.call(request.env))
  end
  it 'has a too-old timestamp' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391010893", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_timestamp.*is too old: 1391010893/m, *oapp.call(request.env))
  end
  it 'has a timestamp too far in the future' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391032497", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_timestamp.*is too far in the future: 1391032497/m, *oapp.call(request.env))
  end
  it 'omits version' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="lCVypLHYc6oKz+vOa6DKEivoyys%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695")
      #%q(oauth_version="1.0")
    assert_response(200, '☺', *oapp.call(request.env))
  end
  it 'has a wrong version' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="3.14")
    assert_response(401, /Authorization oauth_version.*must be 1\.0; got: 3\.14/m, *oapp.call(request.env))
  end
  it 'omits consumer key' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth ) + #%q(oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_consumer_key.*is missing/m, *oapp.call(request.env))
  end
  it 'has an invalid consumer key' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="nonexistent_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_consumer_key.*is invalid/m, *oapp.call(request.env))
  end
  it 'has an invalid token' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    token_hash # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth ) +
      %q(oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ) +
      %q(oauth_signature="MyfcvCJfiOHCdkdwFOKtfwoOPqE%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_token="nonexistent_token", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_token.*is invalid/m, *oapp.call(request.env))
  end
  it 'has a token belonging to a different consumer key' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    token_hash # cause this to be created

    OAuthenticatorTestConfigMethods.consumer_secrets["different_client_app_key"] = "different_client_app_secret"

    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth ) +
      %q(oauth_consumer_key="different_client_app_key", ) +
      %q(oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ) +
      %q(oauth_signature="PVscPDg%2B%2FjAXRiahIggkeBpN5zI%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_token="test_token", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_token.*does not belong to the specified consumer/m, *oapp.call(request.env))
  end
  it 'omits nonce' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      #%q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_nonce.*is missing/m, *oapp.call(request.env))
  end
  it 'has an already-used nonce' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(200, '☺', *oapp.call(request.env))
    assert_response(401, /Authorization oauth_nonce.*has already been used/m, *oapp.call(request.env))
  end
  it 'omits signature' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      #%q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_signature.*is missing/m, *oapp.call(request.env))
  end
  it 'omits signature method' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      #%q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_signature_method.*is missing/m, *oapp.call(request.env))
  end
  it 'specifies an invalid signature method' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ) +
      %q(oauth_signature_method="ROT13", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_signature_method.*must be one of HMAC-SHA1, RSA-SHA1, PLAINTEXT; got: ROT13/m, *oapp.call(request.env))
  end
  it 'has an invalid signature' do
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = %q(OAuth oauth_consumer_key="test_client_app_key", ) +
      %q(oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ) +
      %q(oauth_signature="totallylegit", ) +
      %q(oauth_signature_method="HMAC-SHA1", ) +
      %q(oauth_timestamp="1391021695", ) +
      %q(oauth_version="1.0")
    assert_response(401, /Authorization oauth_signature.*is invalid/m, *oapp.call(request.env))
  end

  describe :bypass do
    it 'bypasses with invalid request' do
      oapp = OAuthenticator::Middleware.new(simpleapp, :bypass => proc { true }, :config_methods => OAuthenticatorTestConfigMethods)
      env = Rack::MockRequest.env_for('/', :method => 'GET').merge({'HTTP_AUTHORIZATION' => 'oauth ?'})
      assert_response(200, '☺', *oapp.call(env))
    end

    it 'does not bypass with invalid request' do
      oapp = OAuthenticator::Middleware.new(simpleapp, :bypass => proc { false }, :config_methods => OAuthenticatorTestConfigMethods)
      assert_equal(401, oapp.call({}).first)
    end

    it 'bypasses with valid request' do
      was_authenticated = nil
      bapp = proc { |env| was_authenticated = env['oauth.authenticated']; [200, {}, ['☺']] }
      boapp = OAuthenticator::Middleware.new(bapp, :bypass => proc { true }, :config_methods => OAuthenticatorTestConfigMethods)
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
        :request_method => request.request_method,
        :uri => request.url,
        :media_type => request.media_type,
        :body => request.body,
        :signature_method => 'HMAC-SHA1',
        :consumer_key => consumer_key,
        :consumer_secret => consumer_secret
      }).authorization
      assert_response(200, '☺', *boapp.call(request.env))
      assert(was_authenticated == false)
    end

    it 'does not bypass with valid request' do
      was_authenticated = nil
      bapp = proc { |env| was_authenticated = env['oauth.authenticated']; [200, {}, ['☺']] }
      boapp = OAuthenticator::Middleware.new(bapp, :bypass => proc { false }, :config_methods => OAuthenticatorTestConfigMethods)
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
        :request_method => request.request_method,
        :uri => request.url,
        :media_type => request.media_type,
        :body => request.body,
        :signature_method => 'HMAC-SHA1',
        :consumer_key => consumer_key,
        :consumer_secret => consumer_secret
      }).authorization
      assert_response(200, '☺', *boapp.call(request.env))
      assert(was_authenticated == true)
    end
  end

  describe 'rack env variables' do
    let :request do
      Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET')).tap do |request|
        request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
          :request_method => request.request_method,
          :uri => request.url,
          :media_type => request.media_type,
          :body => request.body,
          :signature_method => 'HMAC-SHA1',
          :consumer_key => consumer_key,
          :consumer_secret => consumer_secret,
          :token => token,
          :token_secret => token_secret,
        }).authorization
      end
    end

    it 'sets oauth.authenticated, oauth.token, oauth.consumer_key' do
      oauth_authenticated = nil
      oauth_token = nil
      oauth_consumer_key = nil
      testapp = proc do |env|
        oauth_authenticated = env['oauth.authenticated']
        oauth_token = env['oauth.token']
        oauth_consumer_key = env['oauth.consumer_key']
        [200, {}, ['☺']]
      end
      otestapp = OAuthenticator::Middleware.new(testapp, :config_methods => OAuthenticatorTestConfigMethods)
      assert_response(200, '☺', *otestapp.call(request.env))
      assert_equal(token, oauth_token)
      assert_equal(consumer_key, oauth_consumer_key)
      assert_equal(true, oauth_authenticated)
    end
  end
end
