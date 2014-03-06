require 'simple_oauth'

module OAuthenticator
  class SignedRequest
    class << self
      # returns a subclass of OAuthenticator::SignedRequest which includes the given config module 
      def including_config(config_methods_module)
        @extended_classes ||= Hash.new do |h, confmodule|
          h[confmodule] = Class.new(::OAuthenticator::SignedRequest).send(:include, confmodule)
        end
        @extended_classes[config_methods_module]
      end
    end

    ATTRIBUTE_KEYS = %w(request_method url body media_type authorization)

    # readers 
    ATTRIBUTE_KEYS.each { |attribute_key| define_method(attribute_key) { @attributes[attribute_key] } }

    class << self
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

    def initialize(attributes)
      @attributes = attributes.inject({}){|acc, (k,v)| acc.update((k.is_a?(Symbol) ? k.to_s : k) => v) }
      extra_attributes = @attributes.keys - ATTRIBUTE_KEYS
      if extra_attributes.any?
        raise ArgumentError, "received unrecognized attribute keys: #{extra_attributes.inspect}"
      end
    end

    def errors
      @errors ||= begin
        if authorization.nil?
          {'Authorization' => ["Authorization header is missing"]}
        elsif authorization !~ /\S/
          {'Authorization' => ["Authorization header is blank"]}
        elsif authorization !~ /\Aoauth\s/i
          {'Authorization' => ["Authorization scheme is not OAuth; received Authorization: #{authorization}"]}
        else
          errors = Hash.new { |h,k| h[k] = [] }

          # timestamp
          if !oauth_header_params.key?(:timestamp)
            errors['Authorization oauth_timestamp'] << "is missing"
          elsif oauth_header_params[:timestamp] !~ /\A\s*\d+\s*\z/
            errors['Authorization oauth_timestamp'] << "is not an integer - got: #{oauth_header_params[:timestamp]}"
          else
            timestamp_i = oauth_header_params[:timestamp].to_i
            if timestamp_i < Time.now.to_i - timestamp_valid_past
              errors['Authorization oauth_timestamp'] << "is too old: #{oauth_header_params[:timestamp]}"
            elsif timestamp_i > Time.now.to_i + timestamp_valid_future
              errors['Authorization oauth_timestamp'] << "is too far in the future: #{oauth_header_params[:timestamp]}"
            end
          end

          # oauth version
          if oauth_header_params.key?(:version) && oauth_header_params[:version] != '1.0'
            errors['Authorization oauth_version'] << "must be 1.0; got: #{oauth_header_params[:version]}"
          end

          # consumer / client application
          if !oauth_header_params.key?(:consumer_key)
            errors['Authorization oauth_consumer_key'] << "is missing"
          elsif !consumer_secret
            errors['Authorization oauth_consumer_key'] << 'is invalid'
          end

          # access token
          if oauth_header_params.key?(:token)
            if !access_token_secret
              errors['Authorization oauth_token'] << 'is invalid'
            elsif !access_token_belongs_to_consumer?
              errors['Authorization oauth_token'] << 'does not belong to the specified consumer'
            end
          end

          # nonce
          if !oauth_header_params.key?(:nonce)
            errors['Authorization oauth_nonce'] << "is missing"
          elsif nonce_used?
            errors['Authorization oauth_nonce'] << "has already been used"
          end

          # signature method
          if !oauth_header_params.key?(:signature_method)
            errors['Authorization oauth_signature_method'] << "is missing"
          elsif !allowed_signature_methods.any? { |sm| oauth_header_params[:signature_method].downcase == sm.downcase }
            errors['Authorization oauth_signature_method'] << "must be one of " +
              "#{allowed_signature_methods.join(', ')}; got: #{oauth_header_params[:signature_method]}"
          end

          # signature
          if !oauth_header_params.key?(:signature)
            errors['Authorization oauth_signature'] << "is missing"
          end

          if errors.any?
            errors
          else
            # proceed to check signature
            secrets = {}
            secrets[:consumer_secret] = consumer_secret
            secrets[:token_secret] = access_token_secret if access_token_secret
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

    def oauth_header_params
      @oauth_header_params ||= SimpleOAuth::Header.parse(authorization)
    end

    def read_body
      if body.is_a?(String)
        body
      elsif body.respond_to?(:read) && body.respond_to?(:rewind)
        body.rewind
        body.read.tap do
          body.rewind
        end
      else
        raise NotImplementedError, "body = #{body.inspect}"
      end
    end

    def simple_oauth_header
      params = media_type == "application/x-www-form-urlencoded" ? CGI.parse(read_body).map{|k,vs| vs.map{|v| [k,v] } }.inject([], &:+) : nil
      simple_oauth_header = SimpleOAuth::Header.new(request_method, url, params, authorization)
    end

    def timestamp_valid_past
      timestamp_valid_period
    end

    def timestamp_valid_future
      timestamp_valid_period
    end
  end
end
