# typed: strict

require 'rack'
require 'json'
require 'oauthenticator/signed_request'

module OAuthenticator
  # Rack middleware to determine if the incoming request is signed authentically with OAuth 1.0.
  #
  # If the request is not authentically signed, then the middleware responds with 401 Unauthorized, with the 
  # body a JSON object indicating errors encountered authenticating the request. The error object is 
  # structured like rails / ActiveResource:
  #
  #     {'errors' => {'attribute1' => ['messageA', 'messageB'], 'attribute2' => ['messageC']}}
  class RackAuthenticator
    extend T::Sig

    sig { params(app: T.untyped, options: T::Hash[Symbol, T.untyped]).void }
    # options:
    #
    # - `:bypass` - a proc which will be called with a Rack::Request, which must have a boolean result. 
    #   if the result is true, authentication checking is bypassed. if false, the request is authenticated 
    #   and responds 401 if not authenticated.
    #
    # - `:config_methods` - a Module which defines necessary methods for an {OAuthenticator::SignedRequest} to 
    #   determine if it is validly signed. See documentation for {OAuthenticator::ConfigMethods} 
    #   for details of what this module must implement.
    #
    # - `:logger` - a Logger instance to which OAuthenticator::RackAuthenticator will log informative messages 
    #
    # - `:realm` - 401 responses include a `WWW-Authenticate` with the realm set to the given value. default 
    #   is an empty string.
    def initialize(app, options = {})
      @app = T.let(app, T.untyped)
      @options = T.let(options, T.untyped)
      unless @options[:config_methods].is_a?(Module)
        raise ArgumentError, "options[:config_methods] must be a Module"
      end
    end

    sig { params(env: T::Hash[String, T.untyped]).returns(T::Array[T.any(Integer, T::Hash[String, String], T::Array[String])]) }
    # call the middleware!
    def call(env)
      request = Rack::Request.new(env)

      if @options[:bypass] && @options[:bypass].call(request)
        env["oauth.authenticated"] = false
        @app.call(env)
      else
        oauth_signed_request_class = OAuthenticator::SignedRequest.including_config(@options[:config_methods])
        oauth_request = oauth_signed_request_class.from_rack_request(request)
        oauth_request_errors = oauth_request.errors
        if oauth_request_errors
          log_unauthenticated(env, oauth_request)
          unauthenticated_response(oauth_request_errors)
        else
          log_success(env, oauth_request)
          env["oauth.signed_request"] = oauth_request
          env["oauth.consumer_key"] = oauth_request.consumer_key
          env["oauth.token"] = oauth_request.token
          env["oauth.authenticated"] = true
          @app.call(env)
        end
      end
    end

    private

    sig { params(errors: T::Hash[String, T::Array[String]]).returns(T::Array[T.any(Integer, T::Hash[String, String], T::Array[String])]) }
    # the response for an unauthenticated request. the argument will be a hash with the key 'errors', whose 
    # value is a hash with string keys indicating attributes with errors, and values being arrays of strings 
    # indicating error messages on the attribute key. 
    def unauthenticated_response(errors)
      # default to a blank realm, I suppose
      realm = @options[:realm] || ''
      response_headers = {"WWW-Authenticate" => %Q(OAuth realm="#{realm}"), 'Content-Type' => 'application/json'}

      body = {'errors' => errors}
      error_message = begin
        error_values = errors.values.inject([], &:+)
        if error_values.size <= 1
          error_values.first
        else
          # sentencify with periods 
          error_values.map { |v| v =~ /\.\s*\z/ ? v : v + '.' }.join(' ')
        end
      end
      body['error_message'] = error_message if error_message

      [401, response_headers, [JSON.pretty_generate(body)]]
    end

    sig { params(env: T::Hash[String, T.untyped], oauth_request: SignedRequest).void }
    # write a log entry regarding an unauthenticated request
    def log_unauthenticated(env, oauth_request)
      log :warn, "OAuthenticator rejected a request:\n" +
        "\tAuthorization: #{env['HTTP_AUTHORIZATION']}\n" +
        "\tErrors: #{JSON.generate(oauth_request.errors)}"
    end

    sig { params(env: T::Hash[String, T.untyped], oauth_request: SignedRequest).void }
    # write a log entry for a successfully authenticated request
    def log_success(env, oauth_request)
      log :info, "OAuthenticator authenticated an authentic request with Authorization: #{env['HTTP_AUTHORIZATION']}"
    end

    sig { params(level: Symbol, message: String).void }
    def log(level, message)
      if @options[:logger]
        @options[:logger].send(level, message)
      end
    end
  end
end
