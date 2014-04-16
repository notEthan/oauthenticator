require 'openssl'
require 'uri'
require 'base64'
require 'cgi'
require 'strscan'

module OAuthenticator
  # OAuthenticator::Error represents some problem with authenticating. it has an #errors attribute with error 
  # messages in the form we use.
  class Error < StandardError
    def initialize(message, errors=nil)
      super(message)
      @errors = errors
    end

    def errors
      @errors ||= Hash.new { |h,k| h[k] = [] }
    end
  end

  class ParseError < Error; end
  class DuplicatedParameters < Error; end

  class << self
    def parse_authorization(header)
      header = header.to_s
      scanner = StringScanner.new(header)
      auth_parse_error = proc { |message| raise ParseError.new(message, {'Authorization' => [message]}) }
      scanner.scan(/OAuth\s*/) || auth_parse_error.call("Authorization scheme is not OAuth - recieved: #{header}")
      attributes = Hash.new { |h,k| h[k] = [] }
      while match = scanner.scan(/(\w+)="([^"]*)"\s*(,?)\s*/)
        key = scanner[1]
        value = scanner[2]
        comma_follows = !scanner[3].empty?
        if !comma_follows && !scanner.eos?
          auth_parse_error.call("Could not parse Authorization header: #{header}\naround or after character #{scanner.pos}: #{scanner.rest}")
        end
        attributes[unescape(key)] << unescape(value)
      end
      unless scanner.eos?
        auth_parse_error.call("Could not parse Authorization header: #{header}\naround or after character #{scanner.pos}: #{scanner.rest}")
      end
      duplicates = attributes.select { |k,v| v.size > 1 }
      if duplicates.any?
        errors = duplicates.map do |k,vs|
          {k => "Received multiple instances of Authorization parameter #{k}. Received values were: #{vs.inspect}"}
        end.inject({}, &:update)
        raise DuplicatedParameters.new("Received duplicate parameters: #{duplicates.keys.inspect}", errors)
      end
      return attributes.map { |k,v| {k => v.first} }.inject({}, &:update)
    end

    def escape(value)
      uri_parser.escape(value.to_s, /[^a-z0-9\-\.\_\~]/i)
    end

    def unescape(value)
      uri_parser.unescape(value.to_s)
    end

    private
    def uri_parser
      @uri_parser ||= URI.const_defined?(:Parser) ? URI::Parser.new : URI
    end
  end

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
        if @attributes['authorization'].is_a?(String)
          @attributes['authorization'] = OAuthenticator.parse_authorization(@attributes['authorization'])
        end
        unless @attributes['authorization'].is_a?(Hash)
          raise TypeError, "authorization must be a String or Hash"
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
      signature_method = @attributes['authorization']['oauth_signature_method']
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
      parts = [@attributes['request_method'].to_s.upcase, base_string_uri, normalized_request_params_string]
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

    # section 3.4.1.3.2
    def normalized_request_params_string
      normalized_request_params.map { |kv| kv.map { |v| OAuthenticator.escape(v) } }.sort.map { |p| p.join('=') }.join('&')
    end

    # section 3.4.1.3
    def normalized_request_params
      query_params + protocol_params.reject { |k,v| %w(realm oauth_signature).include?(k) }.to_a + entity_params
    end

    # section 3.4.1.3.1
    def query_params
      CGI.parse(URI.parse(@attributes['uri'].to_s).query || '').map{|k,vs| vs.map{|v| [k,v] } }.inject([], &:+)
    end

    # section 3.4.1.3.1
    def entity_params
      if @attributes['media_type'] == "application/x-www-form-urlencoded"
        CGI.parse(read_body).map{|k,vs| vs.map{|v| [k,v] } }.inject([], &:+)
      else
        []
      end
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
