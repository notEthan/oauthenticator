# typed: strict

require 'oauthenticator/signable_request'
require 'oauthenticator/parse_authorization'

module OAuthenticator
  # an error which is to be raised when an attempt is made to use a nonce which has already been used.
  class NonceUsedError < Error
  end

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

    # attributes of a SignedRequest
    ATTRIBUTE_KEYS = %w(request_method uri body media_type authorization).map(&:freeze).freeze

    # oauth attributes parsed from the request authorization
    OAUTH_ATTRIBUTE_KEYS = (SignableRequest::PROTOCOL_PARAM_KEYS + %w(signature body_hash)).freeze

    def request_method
      @attributes['request_method']
    end

    def uri
      @attributes['uri']
    end

    def body
      @attributes['body']
    end

    def media_type
      @attributes['media_type']
    end

    def authorization
      @attributes['authorization']
    end

    def consumer_key
      oauth_header_params["oauth_consumer_key"]
    end

    def token
      oauth_header_params["oauth_token"]
    end

    def signature_method
      oauth_header_params["oauth_signature_method"]
    end

    def timestamp
      oauth_header_params["oauth_timestamp"]
    end

    def nonce
      oauth_header_params["oauth_nonce"]
    end

    def version
      oauth_header_params["oauth_version"]
    end

    def signature
      oauth_header_params["oauth_signature"]
    end

    def body_hash
      oauth_header_params["oauth_body_hash"]
    end

    def oauth_header_param?(key)
      value = oauth_header_params["oauth_#{key}"]
      value.is_a?(String) ? !value.empty? : !!value
    end

    def consumer_key?
      oauth_header_param?('consumer_key')
    end

    def token?
      oauth_header_param?('token')
    end

    def signature_method?
      oauth_header_param?('signature_method')
    end

    def timestamp?
      oauth_header_param?('timestamp')
    end

    def nonce?
      oauth_header_param?('nonce')
    end

    def version?
      oauth_header_param?('version')
    end

    def signature?
      oauth_header_param?('signature')
    end

    def body_hash?
      oauth_header_param?('body_hash')
    end

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
          :uri => request.url,
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
      return @errors if instance_variable_defined?('@errors')
      @errors = catch(:errors) do
        if authorization.nil?
          throw(:errors, {'Authorization' => ["Authorization header is missing"]})
        elsif authorization !~ /\S/
          throw(:errors, {'Authorization' => ["Authorization header is blank"]})
        end

        begin
          oauth_header_params
        rescue OAuthenticator::Error => parse_exception
          throw(:errors, parse_exception.errors)
        end

        errors = Hash.new { |h,k| h[k] = [] }

        # timestamp
        if !timestamp?
          unless signature_method == 'PLAINTEXT'
            errors['Authorization oauth_timestamp'] << "Authorization oauth_timestamp is missing"
          end
        elsif timestamp !~ /\A\s*\d+\s*\z/
          errors['Authorization oauth_timestamp'] << "Authorization oauth_timestamp is not an integer - got: #{timestamp}"
        else
          timestamp_i = timestamp.to_i
          if timestamp_i < Time.now.to_i - timestamp_valid_past
            errors['Authorization oauth_timestamp'] << "Authorization oauth_timestamp is too old: #{timestamp}"
          elsif timestamp_i > Time.now.to_i + timestamp_valid_future
            errors['Authorization oauth_timestamp'] << "Authorization oauth_timestamp is too far in the future: #{timestamp}"
          end
        end

        # oauth version
        if version? && version != '1.0'
          errors['Authorization oauth_version'] << "Authorization oauth_version must be 1.0; got: #{version}"
        end

        # she's filled with secrets
        secrets = {}

        # consumer / client application
        if !consumer_key?
          errors['Authorization oauth_consumer_key'] << "Authorization oauth_consumer_key is missing"
        else
          secrets[:consumer_secret] = consumer_secret
          if !secrets[:consumer_secret]
            errors['Authorization oauth_consumer_key'] << 'Authorization oauth_consumer_key is invalid'
          end
        end

        # token
        if token?
          secrets[:token_secret] = token_secret
          if !secrets[:token_secret]
            errors['Authorization oauth_token'] << 'Authorization oauth_token is invalid'
          elsif !token_belongs_to_consumer?
            errors['Authorization oauth_token'] << 'Authorization oauth_token does not belong to the specified consumer'
          end
        end

        # nonce
        if !nonce?
          unless signature_method == 'PLAINTEXT'
            errors['Authorization oauth_nonce'] << "Authorization oauth_nonce is missing"
          end
        elsif nonce_used?
          errors['Authorization oauth_nonce'] << "Authorization oauth_nonce has already been used"
        end

        # signature method
        if !signature_method?
          errors['Authorization oauth_signature_method'] << "Authorization oauth_signature_method is missing"
        elsif !allowed_signature_methods.any? { |sm| signature_method.downcase == sm.downcase }
          errors['Authorization oauth_signature_method'] << "Authorization oauth_signature_method must be one of " +
            "#{allowed_signature_methods.join(', ')}; got: #{signature_method}"
        end

        # signature
        if !signature?
          errors['Authorization oauth_signature'] << "Authorization oauth_signature is missing"
        end

        signable_request = SignableRequest.new(@attributes.merge(secrets).merge('authorization' => oauth_header_params))

        # body hash

        # present?
        if body_hash?
          # allowed?
          if !signable_request.form_encoded?
            # applicable?
            if SignableRequest::BODY_HASH_METHODS.key?(signature_method)
              # correct?
              if body_hash == signable_request.body_hash
                # all good
              else
                errors['Authorization oauth_body_hash'] << "Authorization oauth_body_hash is invalid"
              end
            else
              # received a body hash with plaintext. weird situation - we will ignore it; signature will not 
              # be verified but it will be a part of the signature. 
            end
          else
            errors['Authorization oauth_body_hash'] << "Authorization oauth_body_hash must not be included with form-encoded requests"
          end
        else
          # allowed?
          if !signable_request.form_encoded?
            # required?
            if body_hash_required?
              errors['Authorization oauth_body_hash'] << "Authorization oauth_body_hash is required (on non-form-encoded requests)"
            else
              # okay - not supported by client, but allowed
            end
          else
            # all good
          end
        end

        throw(:errors, errors) if errors.any?

        # proceed to check signature
        unless self.signature == signable_request.signature
          throw(:errors, {'Authorization oauth_signature' => ['Authorization oauth_signature is invalid']})
        end

        if nonce?
          begin
            use_nonce!
          rescue NonceUsedError
            throw(:errors, {'Authorization oauth_nonce' => ['Authorization oauth_nonce has already been used']})
          end
        end

        nil
      end
    end

    require 'oauthenticator/config_methods'
    include ConfigMethods

    # hash of header params. keys should be a subset of OAUTH_ATTRIBUTE_KEYS.
    def oauth_header_params
      @oauth_header_params ||= OAuthenticator.parse_authorization(authorization)
    end

    private

    # raise a nice error message for a method that needs to be implemented on a module of config methods 
    def config_method_not_implemented
      caller_name = caller[0].match(%r(in `(.*?)'))[1]
      using_middleware = caller.any? { |l| l =~ %r(oauthenticator/rack_authenticator.rb:.*`call') }
      message = "method \##{caller_name} must be implemented on a module of oauth config methods, which is " + begin
        if using_middleware
          "passed to OAuthenticator::RackAuthenticator using the option :config_methods."
        else
          "included in a subclass of OAuthenticator::SignedRequest, typically by passing it to OAuthenticator::SignedRequest.including_config(your_module)."
        end
      end + " Please consult the documentation."
      raise NotImplementedError, message
    end
  end
end
