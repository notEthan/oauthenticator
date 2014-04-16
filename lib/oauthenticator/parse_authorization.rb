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
end
