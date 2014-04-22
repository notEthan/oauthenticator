module OAuthenticator
  # OAuthenticator::Error represents some problem with authenticating. it has an #errors attribute with error 
  # messages in the form we use.
  class Error < StandardError
    # @param message [String]
    # @param errors [Hash<String, Array<String>>]
    def initialize(message, errors=nil)
      super(message)
      @errors = errors
    end

    # @return [Hash<String, Array<String>>]
    def errors
      @errors ||= Hash.new { |h,k| h[k] = [] }
    end
  end

  # an error parsing an authorization header in .parse_authorization
  class ParseError < Error; end

  # an error indicating duplicated paramaters present in an authorization header, in violation of section 3.1 
  # ("Each parameter MUST NOT appear more than once per request.") and 3.2 ("The server SHOULD return a 400 
  # (Bad Request) status code when receiving a request with unsupported parameters, an unsupported signature 
  # method, missing parameters, or duplicated protocol parameters.")
  class DuplicatedParameters < Error; end

  class << self
    # @param header [String] an Authorization header
    # @return [Hash<String, String>] parsed authorization parameters
    # @raise [OAuthenticator::ParseError] if the header is not well-formed and cannot be parsed
    # @raise [OAuthenticator::DuplicatedParameters] if the header contains multiple instances of the same param
    def parse_authorization(header)
      header = header.to_s
      scanner = StringScanner.new(header)
      auth_parse_error = proc { |message| raise ParseError.new(message, {'Authorization' => [message]}) }
      scanner.scan(/OAuth\s*/i) || auth_parse_error.call("Authorization scheme is not OAuth - recieved: #{header}")
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
      duplicates = attributes.reject { |k,v| v.size <= 1 }
      if duplicates.any?
        errors = duplicates.map do |k,vs|
          {k => "Received multiple instances of Authorization parameter #{k}. Received values were: #{vs.inspect}"}
        end.inject({}, &:update)
        raise DuplicatedParameters.new("Received duplicate parameters: #{duplicates.keys.inspect}", errors)
      end
      return attributes.map { |k,v| {k => v.first} }.inject({}, &:update)
    end

    # escape a value
    # @param value [String] value
    # @return [String] escaped value
    def escape(value)
      uri_parser.escape(value.to_s, /[^a-z0-9\-\.\_\~]/i)
    end

    # unescape a value
    # @param value [String] escaped value
    # @return [String] unescaped value
    def unescape(value)
      uri_parser.unescape(value.to_s)
    end

    private

    # @return [Object] a parser that responds to #escape and #unescape
    def uri_parser
      @uri_parser ||= URI.const_defined?(:Parser) ? URI::Parser.new : URI
    end
  end
end
