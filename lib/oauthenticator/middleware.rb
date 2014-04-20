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
  #     {'errors': {'attribute1': ['messageA', 'messageB'], 'attribute2': ['messageC']}}
  class Middleware
    # options:
    #
    # - `:bypass` - a proc which will be called with a Rack::Request, which must have a boolean result. 
    #   if the result is true, authorization checking is bypassed. if false, the request is authenticated 
    #   and responds 401 if not authenticated.
    #
    # - `:config_methods` - a Module which defines necessary methods for an {OAuthenticator::SignedRequest} to 
    #   determine if it is validly signed. See documentation for {OAuthenticator::ConfigMethods} 
    #   for details of what this module must implement.
    #
    # - `:realm` - 401 responses include a `WWW-Authenticate` with the realm set to the given value. default 
    #   is an empty string.
    def initialize(app, options={})
      @app=app
      @options = options
      unless @options[:config_methods].is_a?(Module)
        raise ArgumentError, "options[:config_methods] must be a Module"
      end
    end

    # call the middleware!
    def call(env)
      request = Rack::Request.new(env)

      if @options[:bypass] && @options[:bypass].call(request)
        env["oauth.authenticated"] = false
        @app.call(env)
      else
        oauth_signed_request_class = OAuthenticator::SignedRequest.including_config(@options[:config_methods])
        oauth_request = oauth_signed_request_class.from_rack_request(request)
        if oauth_request.errors
          unauthorized_response({'errors' => oauth_request.errors})
        else
          env["oauth.consumer_key"] = oauth_request.consumer_key
          env["oauth.access_token"] = oauth_request.token
          env["oauth.authenticated"] = true
          @app.call(env)
        end
      end
    end

    # the response for an unauthorized request. the argument will be a hash with the key 'errors', whose value 
    # is a hash with string keys indicating attributes with errors, and values being arrays of strings 
    # indicating error messages on the attribute key.. 
    def unauthorized_response(error_object)
      # default to a blank realm, I suppose
      realm = @options[:realm] || ''
      response_headers = {"WWW-Authenticate" => %Q(OAuth realm="#{realm}"), 'Content-Type' => 'application/json'}
      [401, response_headers, [JSON.pretty_generate(error_object)]]
    end
  end
end
