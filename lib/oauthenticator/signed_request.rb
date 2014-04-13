require 'simple_oauth'

module OAuthenticator
  # this class represents an OAuth signed request. its primary user-facing method is {#errors}, which returns 
  # nil if the request is valid and authentic, or a helpful object of error messages describing what was 
  # invalid if not. 
  #
  # this class is not useful on its own, as various methods must be implemented on a module to be included 
  # before the implementation is complete enough to use. see the README and the documentation for the module 
  # {OAuthenticator::ConfigMethods} for details. to pass such a module to 
  # {OAuthenticator::SignedRequest}, use {.including_config}, like 
  # `OAuthenticator::SignedRequest.including_config(config_module)`.
  class SignedRequest
    class << self
      # returns a subclass of OAuthenticator::SignedRequest which includes the given config module 
      #
      # @param config_methods_module [Module] a module which implements the methods described in the 
      # documentation for {OAuthenticator::ConfigMethods} and the README
      #
      # @return [Class] subclass of SignedRequest with the given module included 
      def including_config(config_methods_module)
        @extended_classes ||= Hash.new do |h, confmodule|
          h[confmodule] = Class.new(::OAuthenticator::SignedRequest).send(:include, confmodule)
        end
        @extended_classes[config_methods_module]
      end
    end

    ATTRIBUTE_KEYS = %w(request_method url body media_type authorization).map(&:freeze).freeze
    OAUTH_ATTRIBUTE_KEYS = %w(consumer_key token timestamp nonce version signature_method signature).map(&:to_sym).freeze

    # readers 
    ATTRIBUTE_KEYS.each { |attribute_key| define_method(attribute_key) { @attributes[attribute_key] } }

    # readers for oauth header parameters 
    OAUTH_ATTRIBUTE_KEYS.each { |key| define_method(key) { oauth_header_params[key] } }

    # question methods to indicate whether oauth header parameters were included with a non-blank value in 
    # the Authorization header
    OAUTH_ATTRIBUTE_KEYS.each do |key|
      define_method("#{key}?") do
        value = oauth_header_params[key]
        value.is_a?(String) ? !value.empty? : !!value
      end
    end

    VALID_SIGNATURE_METHODS = %w(HMAC-SHA1 RSA-SHA1 PLAINTEXT).map(&:freeze).freeze

    class << self
      # instantiates a `OAuthenticator::SignedRequest` (subclass thereof, more precisely) representing a 
      # request given as a Rack::Request.
      #
      # like {#initialize}, this should be called on a subclass of SignedRequest created with {.including_config}
      #
      # @param request [Rack::Request]
      # @return [subclass of OAuthenticator::SignedRequest]
      def from_rack_request(request)
        new({
          :request_method => request.request_method,
          :url => request.url,
          :body => request.body,
          :media_type => request.media_type,
          :authorization => request.env['HTTP_AUTHORIZATION'],
        })
      end
    end

    # initialize a {SignedRequest}. this should not be called on OAuthenticator::SignedRequest directly, but 
    # a subclass made with {.including_config} - see {SignedRequest}'s documentation.
    def initialize(attributes)
      @attributes = attributes.inject({}){|acc, (k,v)| acc.update((k.is_a?(Symbol) ? k.to_s : k) => v) }
      extra_attributes = @attributes.keys - ATTRIBUTE_KEYS
      if extra_attributes.any?
        raise ArgumentError, "received unrecognized attribute keys: #{extra_attributes.inspect}"
      end
    end

    # inspects the request represented by this instance of SignedRequest. if the request is authentically 
    # signed with OAuth, returns nil to indicate that there are no errors. if the request is inauthentic or 
    # invalid for any reason, this returns a hash containing the reason(s) why the request is invalid.
    #
    # The error object's structure is a hash with string keys indicating attributes with errors, and values 
    # being arrays of strings indicating error messages on the attribute key. this structure takes after 
    # structured rails / ActiveResource, and looks like:
    #
    #     {'attribute1': ['messageA', 'messageB'], 'attribute2': ['messageC']}
    #
    # @return [nil, Hash<String, Array<String>>] either nil or a hash of errors
    def errors
      @errors ||= begin
        if authorization.nil?
          {'Authorization' => ["Authorization header is missing"]}
        elsif authorization !~ /\S/
          {'Authorization' => ["Authorization header is blank"]}
        elsif authorization !~ /\Aoauth\s/i
          {'Authorization' => ["Authorization scheme is not OAuth; received Authorization: #{authorization}"]}
        else
          to_rescue = SimpleOAuth.const_defined?(:ParseError) ? SimpleOAuth::ParseError : StandardError
          begin
            oauth_header_params
          rescue to_rescue
            parse_exception = $!
          end
          if parse_exception
            if parse_exception.class.name == 'SimpleOAuth::ParseError'
              message = parse_exception.message
            else
              message = "Authorization header is not a properly-formed OAuth 1.0 header."
            end
            {'Authorization' => [message]}
          else
            errors = Hash.new { |h,k| h[k] = [] }

            # timestamp
            if !timestamp?
              errors['Authorization oauth_timestamp'] << "is missing"
            elsif timestamp !~ /\A\s*\d+\s*\z/
              errors['Authorization oauth_timestamp'] << "is not an integer - got: #{timestamp}"
            else
              timestamp_i = timestamp.to_i
              if timestamp_i < Time.now.to_i - timestamp_valid_past
                errors['Authorization oauth_timestamp'] << "is too old: #{timestamp}"
              elsif timestamp_i > Time.now.to_i + timestamp_valid_future
                errors['Authorization oauth_timestamp'] << "is too far in the future: #{timestamp}"
              end
            end

            # oauth version
            if version? && version != '1.0'
              errors['Authorization oauth_version'] << "must be 1.0; got: #{version}"
            end

            # she's filled with secrets
            secrets = {}

            # consumer / client application
            if !consumer_key?
              errors['Authorization oauth_consumer_key'] << "is missing"
            else
              secrets[:consumer_secret] = consumer_secret
              if !secrets[:consumer_secret]
                errors['Authorization oauth_consumer_key'] << 'is invalid'
              end
            end

            # access token
            if token?
              secrets[:token_secret] = access_token_secret
              if !secrets[:token_secret]
                errors['Authorization oauth_token'] << 'is invalid'
              elsif !access_token_belongs_to_consumer?
                errors['Authorization oauth_token'] << 'does not belong to the specified consumer'
              end
            end

            # nonce
            if !nonce?
              errors['Authorization oauth_nonce'] << "is missing"
            elsif nonce_used?
              errors['Authorization oauth_nonce'] << "has already been used"
            end

            # signature method
            if !signature_method?
              errors['Authorization oauth_signature_method'] << "is missing"
            elsif !allowed_signature_methods.any? { |sm| signature_method.downcase == sm.downcase }
              errors['Authorization oauth_signature_method'] << "must be one of " +
                "#{allowed_signature_methods.join(', ')}; got: #{signature_method}"
            end

            # signature
            if !signature?
              errors['Authorization oauth_signature'] << "is missing"
            end

            if errors.any?
              errors
            else
              # proceed to check signature
              if !simple_oauth_header.valid?(secrets)
                {'Authorization oauth_signature' => ['is invalid']}
              else
                use_nonce!
                nil
              end
            end
          end
        end
      end
    end

    require 'oauthenticator/config_methods'
    include ConfigMethods

    private

    # hash of header params. keys should be a subset of OAUTH_ATTRIBUTE_KEYS.
    def oauth_header_params
      @oauth_header_params ||= SimpleOAuth::Header.parse(authorization)
    end

    # reads the request body, be it String or IO 
    def read_body
      if body.is_a?(String)
        body
      elsif body.respond_to?(:read) && body.respond_to?(:rewind)
        body.rewind
        body.read.tap do
          body.rewind
        end
      else
        raise ArgumentError, "Body must be a String or something IO-like (responding to #read and #rewind). " +
          "got body = #{body.inspect}"
      end
    end

    # SimpleOAuth::Header for this request
    def simple_oauth_header
      params = media_type == "application/x-www-form-urlencoded" ? CGI.parse(read_body).map{|k,vs| vs.map{|v| [k,v] } }.inject([], &:+) : nil
      simple_oauth_header = SimpleOAuth::Header.new(request_method, url, params, authorization)
    end

    # raise a nice error message for a method that needs to be implemented on a module of config methods 
    def config_method_not_implemented
      caller_name = caller[0].match(%r(in `(.*?)'))[1]
      using_middleware = caller.any? { |l| l =~ %r(oauthenticator/middleware.rb:.*`call') }
      message = "method \##{caller_name} must be implemented on a module of oauth config methods, which is " + begin
        if using_middleware
          "passed to OAuthenticator::Middleware using the option :config_methods."
        else
          "included in a subclass of OAuthenticator::SignedRequest, typically by passing it to OAuthenticator::SignedRequest.including_config(your_module)."
        end
      end + " Please consult the documentation."
      raise NotImplementedError, message
    end
  end
end
