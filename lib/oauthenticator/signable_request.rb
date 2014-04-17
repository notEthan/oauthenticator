require 'openssl'
require 'uri'
require 'base64'
require 'cgi'
require 'strscan'
require 'oauthenticator/parse_authorization'

module OAuthenticator
  class SignableRequest
    PROTOCOL_PARAM_KEYS = %w(consumer_key token signature_method timestamp nonce version).map(&:freeze).freeze

    def initialize(attributes)
      raise TypeError, "attributes must be a hash" unless attributes.is_a?(Hash)
      # stringify symbol keys
      @attributes = attributes.map { |k,v| {k.is_a?(Symbol) ? k.to_s : k => v} }.inject({}, &:update)

      # validation - presence
      required = %w(request_method uri media_type body)
      required += %w(signature_method consumer_key) unless @attributes['authorization']
      missing = required - @attributes.keys
      raise ArgumentError, "missing: #{missing.inspect}" if missing.any?
      extra = @attributes.keys - (required + PROTOCOL_PARAM_KEYS + %w(authorization consumer_secret token_secret realm))
      raise ArgumentError, "received unrecognized @attributes: #{extra.inspect}" if extra.any?

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
          'nonce' => OpenSSL::Random.random_bytes(16).unpack('H*')[0],
          'timestamp' => Time.now.to_i.to_s,
          'version' => '1.0',
        }
        @attributes['authorization'] = PROTOCOL_PARAM_KEYS.map do |key|
          {"oauth_#{key}" => @attributes.key?(key) ? @attributes[key] : defaults[key]}
        end.inject({}, &:update).reject {|k,v| v.nil? }
        @attributes['authorization']['realm'] = @attributes['realm'] unless @attributes['realm'].nil?
      end
    end

    def authorization
      "OAuth #{normalized_protocol_params_string}"
    end

    def signature
      rbmethod = SIGNATURE_METHODS[signature_method] ||
        raise(ArgumentError, "invalid signature method: #{signature_method}")
      rbmethod.bind(self).call
    end

    # section 3.4.1.3 
    def protocol_params
      @attributes['authorization']
    end

    def signed_protocol_params
      protocol_params.merge('oauth_signature' => signature)
    end

    private

    # signature base string for signing. section 3.4.1
    def signature_base
      parts = [normalized_request_method, base_string_uri, normalized_request_params_string]
      parts.map { |v| OAuthenticator.escape(v) }.join('&')
    end

    # section 3.4.1.2
    def base_string_uri
      URI.parse(@attributes['uri'].to_s).tap do |uri|
        uri.scheme = uri.scheme.downcase
        uri.host = uri.host.downcase
        uri.normalize!
        uri.fragment = nil
        uri.query = nil
      end.to_s
    end

    # section 3.4.1.1
    def normalized_request_method
      @attributes['request_method'].to_s.upcase
    end

    # section 3.4.1.3.2
    def normalized_request_params_string
      normalized_request_params.map { |kv| kv.map { |v| OAuthenticator.escape(v) } }.sort.map { |p| p.join('=') }.join('&')
    end

    # section 3.4.1.3
    def normalized_request_params
      query_params + protocol_params.reject { |k,v| %w(realm oauth_signature).include?(k) }.to_a + entity_params
    end

    # section 3.4.1.3.1
    #
    # parsed query params, extracted from the request URI. since keys may appear multiple times, represented 
    # as an array of two-element arrays and not a hash
    #
    # @return [Array<Array<String>>] 
    def query_params
      parse_form_encoded(URI.parse(@attributes['uri'].to_s).query || '')
    end

    # section 3.4.1.3.1
    #
    # parsed entity params from the body, when the request is form encoded. since keys may appear multiple 
    # times, represented as an array of two-element arrays and not a hash
    #
    # @return [Array<Array<String>>] since keys may appear multiple times, represented as an array of 
    # two-element arrays and not a hash
    def entity_params
      if form_encoded?
        parse_form_encoded(read_body)
      else
        []
      end
    end

    # like CGI.parse but it keeps keys without any value. doesn't keep blank keys though.
    def parse_form_encoded(data)
      data.split(/[&;]/).map do |pair|
        key, value = pair.split('=', 2).map { |v| CGI::unescape(v) }
        [key, value] unless [nil, ''].include?(key)
      end.compact
    end

    # string of protocol params including signature, sorted 
    def normalized_protocol_params_string
      signed_protocol_params.sort.map { |(k,v)| %Q(#{OAuthenticator.escape(k)}="#{OAuthenticator.escape(v)}") }.join(', ')
    end

    # reads the request body, be it String or IO 
    def read_body
      body = @attributes['body']
      if body.is_a?(String)
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

    def signature_method
      @attributes['authorization']['oauth_signature_method']
    end

    def form_encoded?
      @attributes['media_type'] == "application/x-www-form-urlencoded"
    end

    def rsa_sha1_signature
      private_key = OpenSSL::PKey::RSA.new(@attributes['consumer_secret'])
      Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, signature_base)).chomp.gsub(/\n/, '')
    end

    def hmac_sha1_signature
      # hmac secret is same as plaintext signature 
      secret = plaintext_signature
      Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret, signature_base)).chomp.gsub(/\n/, '')
    end

    def plaintext_signature
      @attributes.values_at('consumer_secret', 'token_secret').map { |v| OAuthenticator.escape(v) }.join('&')
    end

    SIGNATURE_METHODS = {
      'RSA-SHA1'.freeze => instance_method(:rsa_sha1_signature),
      'HMAC-SHA1'.freeze => instance_method(:hmac_sha1_signature),
      'PLAINTEXT'.freeze => instance_method(:plaintext_signature),
    }.freeze
  end
end
