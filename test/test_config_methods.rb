# encoding: utf-8

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
    if OAuthenticatorTestConfigMethods.nonces.include?(nonce)
      # checking the same thing as #nonce_used? lets #nonce_used? be overridden to return false and things still work 
      raise OAuthenticator::NonceUsedError
    else
      OAuthenticatorTestConfigMethods.nonces << nonce
    end
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

module TestHelperMethods
  def self.let(name, &block)
    define_method(name) { |*args| (@lets ||= {}).key?(name) ? @lets[name] : (@lets[name] = instance_eval(*args, &block)) }
  end

  let(:simpleapp) { proc { |env| [200, {'Content-Type' => 'text/plain; charset=UTF-8'}, ['☺']] } }
  let(:oapp) { OAuthenticator::RackAuthenticator.new(simpleapp, :config_methods => OAuthenticatorTestConfigMethods) }

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
end
