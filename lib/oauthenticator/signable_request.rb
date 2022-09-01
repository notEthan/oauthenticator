# typed: strict

require 'openssl'
require 'addressable/uri'
require 'base64'
require 'cgi'
require 'strscan'
require 'oauthenticator/parse_authorization'

module OAuthenticator
  # a request which may be signed with OAuth, generally in order to apply the signature to an outgoing request 
  # in the Authorization header.
  #
  # primarily this is to be used like:
  #
  #     oauthenticator_signable_request = OAuthenticator::SignableRequest.new(
  #       :request_method => my_request_method,
  #       :uri => my_request_uri,
  #       :media_type => my_request_media_type,
  #       :body => my_request_body,
  #       :signature_method => my_oauth_signature_method,
  #       :consumer_key => my_oauth_consumer_key,
  #       :consumer_secret => my_oauth_consumer_secret,
  #       :token => my_oauth_token,
  #       :token_secret => my_oauth_token_secret,
  #       :realm => my_authorization_realm
  #     )
  #     my_http_request.headers['Authorization'] = oauthenticator_signable_request.authorization
  class SignableRequest
    extend T::Sig

    # keys of OAuth protocol parameters which form the Authorization header (with an oauth_ prefix). 
    # signature is considered separately.
    PROTOCOL_PARAM_KEYS = T.let(%w(consumer_key token signature_method timestamp nonce version).map(&:freeze).freeze, T::Array[String])

    sig { params(attributes: T::Hash[T.any(Symbol, String), T.untyped]).void }
    # initialize a signable request with the following attributes (keys may be string or symbol):
    #
    # - request_method (required) - get, post, etc. may be string or symbol.
    # - uri (required) - request URI. to_s is called so URI or Addressable::URI or whatever may be passed.
    # - media_type (required) - the request media type (may be nil if there is no body). note that this may be 
    #   different than the Content-Type header; other components of that such as encoding must not be included.
    # - body (required) - the request body. may be a String or an IO, or nil if no body is present.
    # - hash_body? - whether to add the oauth_body_hash parameter, per the OAuth Request Body Hash 
    #   specification. defaults to true. not used if the 'authorization' parameter is used.
    # - signature_method (required*) - oauth signature method (String)
    # - consumer_key (required*) - oauth consumer key (String)
    # - consumer_secret (required*) - oauth consumer secret (String)
    # - token (optional*) - oauth token; may be omitted if only using a consumer key (two-legged)
    # - token_secret (optional) - must be present if token is present. must be omitted if token is omitted.
    # - timestamp (optional*) - if omitted, defaults to the current time. 
    #   if nil is passed, no oauth_timestamp will be present in the generated authorization.
    # - nonce (optional*) - if omitted, defaults to a random string. 
    #   if nil is passed, no oauth_nonce will be present in the generated authorization.
    # - version (optional*) - must be nil or '1.0'. defaults to '1.0' if omitted. 
    #   if nil is passed, no oauth_version will be present in the generated authorization.
    # - realm (optional) - authorization realm. 
    #   if nil is passed, no realm will be present in the generated authorization.
    # - authorization - a hash of a received Authorization header, the result of a call to 
    #   OAuthenticator.parse_authorization. it is useful for calculating the signature of a received request, 
    #   but for fully authenticating a received request it is generally preferable to use 
    #   OAuthenticator::SignedRequest. specifying this precludes the requirement to specify any of 
    #   PROTOCOL_PARAM_KEYS.
    #
    # (*) attributes which are in PROTOCOL_PARAM_KEYS are unused (and not required) when the 
    # 'authorization' attribute is given for signature verification. normally, though, they are used and 
    # are required or optional as noted.
    def initialize(attributes)
      # stringify symbol keys
      @attributes = T.let(attributes.map { |k,v| {k.is_a?(Symbol) ? k.to_s : k => v} }.inject({}, &:update), T::Hash[String, T.untyped])

      # validation - presence
      required = %w(request_method uri media_type body)
      required += %w(signature_method consumer_key) unless @attributes['authorization']
      missing = required - @attributes.keys
      raise ArgumentError, "missing required attributes: #{missing.inspect}" if missing.any?
      other_recognized = PROTOCOL_PARAM_KEYS + %w(authorization consumer_secret token_secret realm hash_body?)
      extra = @attributes.keys - (required + other_recognized)
      raise ArgumentError, "received unrecognized attributes: #{extra.inspect}" if extra.any?

      if @attributes['authorization']
        # this means we are signing an existing request to validate the received signature. don't use defaults.
        unless @attributes['authorization'].is_a?(Hash)
          raise TypeError, "authorization must be a Hash"
        end

        # if authorization is specified, protocol params should not be specified in the regular attributes 
        given_protocol_params = @attributes.reject { |k,v| !(PROTOCOL_PARAM_KEYS.include?(k) && v) }
        if given_protocol_params.any?
          raise ArgumentError, "an existing authorization was given, but protocol parameters were also " +
            "given. protocol parameters should not be specified when verifying an existing authorization. " +
            "given protocol parameters were: #{given_protocol_params.inspect}"
        end
      else
        # defaults
        defaults = {
          'version' => '1.0',
        }
        if @attributes['signature_method'] != 'PLAINTEXT'
          defaults.update({
            'nonce' => OpenSSL::Random.random_bytes(16).unpack('H*')[0],
            'timestamp' => Time.now.to_i.to_s,
          })
        end
        @attributes['authorization'] = PROTOCOL_PARAM_KEYS.map do |key|
          {"oauth_#{key}" => @attributes.key?(key) ? @attributes[key] : defaults[key]}
        end.inject({}, &:update).reject {|k,v| v.nil? }
        @attributes['authorization']['realm'] = @attributes['realm'] unless @attributes['realm'].nil?

        hash_body
      end
    end

    sig { returns(String) }
    # returns the Authorization header generated for this request.
    #
    # @return [String] Authorization header
    def authorization
      "OAuth #{normalized_protocol_params_string}"
    end

    sig { returns(String) }
    # the oauth_signature calculated for this request.
    #
    # @return [String] oauth signature
    def signature
      rbmethod = SIGNATURE_METHODS[signature_method] ||
        raise(ArgumentError, "invalid signature method: #{signature_method}")
      rbmethod.bind(self).call
    end

    sig { returns(T.nilable(String)) }
    # the oauth_body_hash calculated for this request, if applicable, per the OAuth Request Body Hash 
    # specification.
    #
    # @return [String, nil] oauth body hash
    def body_hash
      BODY_HASH_METHODS[signature_method] ? T.must(BODY_HASH_METHODS[signature_method]).bind(self).call : nil
    end

    sig { returns(T::Hash[String, String]) }
    # protocol params for this request as described in section 3.4.1.3 
    #
    # signature is not calculated for this - use #signed_protocol_params to get protocol params including a 
    # signature. 
    #
    # note that if this is a previously-signed request, the oauth_signature attribute returned is the 
    # received value, NOT the value calculated by us.
    #
    # @return [Hash<String, String>] protocol params
    def protocol_params
      @attributes['authorization'].dup
    end

    sig { returns(T::Hash[String, String]) }
    # protocol params for this request as described in section 3.4.1.3, including our calculated 
    # oauth_signature.
    #
    # @return [Hash<String, String>] signed protocol params
    def signed_protocol_params
      protocol_params.merge('oauth_signature' => signature)
    end

    sig { returns(T::Boolean) }
    # is the media type application/x-www-form-urlencoded
    #
    # @return [Boolean]
    def form_encoded?
      media_type = @attributes['media_type']
      # media tye is case insensitive per http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7
      media_type = media_type.downcase if media_type.is_a?(String)
      media_type == "application/x-www-form-urlencoded"
    end

    private

    sig { returns(String) }
    # signature base string for signing. section 3.4.1
    #
    # @return [String]
    def signature_base
      parts = [normalized_request_method, base_string_uri, normalized_request_params_string]
      parts.map { |v| OAuthenticator.escape(v) }.join('&')
    end

    sig { returns(String) }
    # section 3.4.1.2
    #
    # @return [String]
    def base_string_uri
      Addressable::URI.parse(@attributes['uri'].to_s).tap do |uri|
        uri.scheme = uri.scheme.downcase if uri.scheme
        uri.host = uri.host.downcase if uri.host
        uri.normalize!
        uri.fragment = nil
        uri.query = nil
      end.to_s
    end

    sig { returns(String) }
    # section 3.4.1.1
    #
    # @return [String]
    def normalized_request_method
      @attributes['request_method'].to_s.upcase
    end

    sig { returns(String) }
    # section 3.4.1.3.2
    #
    # @return [String]
    def normalized_request_params_string
      normalized_request_params.map { |kv| kv.map { |v| OAuthenticator.escape(v.to_s) } }.sort.map { |p| p.join('=') }.join('&')
    end

    sig { returns(T::Array[T::Array[T.nilable(String)]]) }
    # section 3.4.1.3
    #
    # @return [Array<Array<String, nil> (size 2)>]
    def normalized_request_params
      query_params + protocol_params.reject { |k,v| %w(realm oauth_signature).include?(k) }.to_a + entity_params
    end

    sig { returns(T::Array[T::Array[T.nilable(String)]]) }
    # section 3.4.1.3.1
    #
    # parsed query params, extracted from the request URI. since keys may appear multiple times, represented 
    # as an array of two-element arrays and not a hash
    #
    # @return [Array<Array<String, nil> (size 2)>]
    def query_params
      parse_form_encoded(URI.parse(@attributes['uri'].to_s).query || '')
    end

    sig { returns(T::Array[T::Array[T.nilable(String)]]) }
    # section 3.4.1.3.1
    #
    # parsed entity params from the body, when the request is form encoded. since keys may appear multiple 
    # times, represented as an array of two-element arrays and not a hash
    #
    # @return [Array<Array<String, nil> (size 2)>]
    def entity_params
      if form_encoded?
        parse_form_encoded(read_body)
      else
        []
      end
    end

    sig { params(data: String).returns(T::Array[T::Array[T.nilable(String)]]) }
    # like CGI.parse but it keeps keys without any value. doesn't keep blank keys though.
    #
    # @param data [String]
    # @return [Array<Array<String, nil> (size 2)>]
    def parse_form_encoded(data)
      data.split(/[&;]/).map do |pair|
        key, value = pair.split('=', 2).map { |v| CGI::unescape(v) }
        [key, value] unless [nil, ''].include?(key)
      end.compact
    end

    sig { returns(String) }
    # string of protocol params including signature, sorted 
    #
    # @return [String]
    def normalized_protocol_params_string
      signed_protocol_params.sort.map { |(k,v)| %Q(#{OAuthenticator.escape(k)}="#{OAuthenticator.escape(v.to_s)}") }.join(', ')
    end

    sig { returns(String) }
    # reads the request body, be it String or IO 
    #
    # @return [String] request body
    def read_body
      body = @attributes['body']
      if body.nil?
        ''
      elsif body.is_a?(String)
        body
      elsif body.respond_to?(:read) && body.respond_to?(:rewind)
        body.rewind
        body.read.tap do
          body.rewind
        end
      else
        raise TypeError, "Body must be a String or something IO-like (responding to #read and #rewind). " +
          "got body = #{body.inspect}"
      end
    end

    sig { void }
    # set the oauth_body_hash to the hash of the request body 
    #
    # @return [Void]
    def hash_body
      if hash_body?
        @attributes['authorization']['oauth_body_hash'] = body_hash
      end
    end

    sig { returns(T::Boolean) }
    # whether we will hash the body, per oauth request body hash section 4.1, as well as whether the caller 
    # said to 
    #
    # @return [Boolean]
    def hash_body?
      BODY_HASH_METHODS.key?(signature_method) && !form_encoded? &&
        (@attributes.key?('hash_body?') ? @attributes['hash_body?'] : true)
    end

    sig { returns(String) }
    # signature method 
    #
    # @return [String]
    def signature_method
      @attributes['authorization']['oauth_signature_method']
    end

    sig { returns(String) }
    # signature, with method RSA-SHA1. section 3.4.3 
    #
    # @return [String]
    def rsa_sha1_signature
      private_key = OpenSSL::PKey::RSA.new(@attributes['consumer_secret'])
      Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, signature_base)).gsub(/\n/, '')
    end

    sig { returns(String) }
    # signature, with method HMAC-SHA1. section 3.4.2
    #
    # @return [String]
    def hmac_sha1_signature
      hmac_digest_signature(OpenSSL::Digest::SHA1)
    end

    sig { returns(String) }
    # signature, with method HMAC-SHA256. OAuthenticator extension, outside of spec. do not use.
    # unless you want to.
    #
    # @return [String]
    def hmac_sha256_signature
      hmac_digest_signature(OpenSSL::Digest::SHA256)
    end

    sig { returns(String) }
    # signature, with method HMAC-SHA512. OAuthenticator extension, outside of spec. do not use.
    # unless you want to.
    #
    # @return [String]
    def hmac_sha512_signature
      hmac_digest_signature(OpenSSL::Digest::SHA512)
    end

    sig { params(digest_class: T.class_of(OpenSSL::Digest)).returns(String) }
    # signature with a HMAC digest
    #
    # @param digest_class [Class] the digest class
    # @return [String]
    def hmac_digest_signature(digest_class)
      # hmac secret is same as plaintext signature 
      secret = plaintext_signature
      Base64.encode64(OpenSSL::HMAC.digest(digest_class.new, secret, signature_base)).gsub(/\n/, '')
    end

    sig { returns(String) }
    # signature, with method plaintext. section 3.4.4
    #
    # @return [String]
    def plaintext_signature
      @attributes.values_at('consumer_secret', 'token_secret').map { |v| OAuthenticator.escape(v.to_s) }.join('&')
    end

    sig { returns(String) }
    # body hash, with a signature method which uses SHA1. oauth request body hash section 3.2
    #
    # @return [String]
    def sha1_body_hash
      digest_body_hash(OpenSSL::Digest::SHA1)
    end

    sig { returns(String) }
    # body hash, with a signature method which uses SHA256. OAuthenticator extension, outside of spec. 
    # do not use. unless you want to.
    #
    # @return [String]
    def sha256_body_hash
      digest_body_hash(OpenSSL::Digest::SHA256)
    end

    sig { returns(String) }
    # body hash, with a signature method which uses SHA512. OAuthenticator extension, outside of spec. 
    # do not use. unless you want to.
    #
    # @return [String]
    def sha512_body_hash
      digest_body_hash(OpenSSL::Digest::SHA512)
    end

    sig { params(digest_class: T.untyped).returns(String) }
    # body hash with a given digest
    #
    # @param digest_class [Class] the digest class
    # @return [String]
    def digest_body_hash(digest_class)
      Base64.encode64(digest_class.digest(read_body)).gsub(/\n/, '')
    end

    # map of oauth signature methods to their signature instance methods on this class 
    SIGNATURE_METHODS = T.let({
      'RSA-SHA1'.freeze => instance_method(:rsa_sha1_signature),
      'HMAC-SHA1'.freeze => instance_method(:hmac_sha1_signature),
      'HMAC-SHA256'.freeze => instance_method(:hmac_sha256_signature),
      'HMAC-SHA512'.freeze => instance_method(:hmac_sha512_signature),
      'PLAINTEXT'.freeze => instance_method(:plaintext_signature),
    }.freeze, T::Hash[String, UnboundMethod])

    # map of oauth signature methods to their body hash instance methods on this class. oauth request body 
    # hash section 3.1
    BODY_HASH_METHODS = T.let({
      'RSA-SHA1'.freeze => instance_method(:sha1_body_hash),
      'HMAC-SHA1'.freeze => instance_method(:sha1_body_hash),
      'HMAC-SHA256'.freeze => instance_method(:sha256_body_hash),
      'HMAC-SHA512'.freeze => instance_method(:sha512_body_hash),
    }.freeze, T::Hash[String, UnboundMethod])
  end
end
