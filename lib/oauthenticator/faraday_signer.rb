require 'faraday'

if Faraday.respond_to?(:register_middleware)
  Faraday.register_middleware(:request, :oauthenticator_signer => proc { OAuthenticator::FaradaySigner })
end
if Faraday::Request.respond_to?(:register_middleware)
  Faraday::Request.register_middleware(:oauthenticator_signer => proc { OAuthenticator::FaradaySigner })
end

module OAuthenticator
  # OAuthenticator Faraday middleware to sign outgoing requests.
  #
  # The middleware should be in the stack immediately before the adapter. Any other middleware that modifies 
  # the request between OAuthenticator signing it and the request actually being made may render the signature 
  # invalid. 
  #
  # This request middleware is registered as `:oauthenticator_signer`. It should be used like
  #
  #     connection = Faraday.new('http://example.com/') do |faraday|
  #       faraday.request :url_encoded
  #       faraday.request :oauthenticator_signer, signing_options
  #       faraday.adapter Faraday.default_adapter
  #     end
  #
  # Note that `:url_encoded` is only included to illustrate that other middleware should all go before 
  # `:oauthenticator_signer`; the use of `:url_encoded` is not related to OAuthenticator. 
  #
  # See {#initialize} for details of what the `signing_options` hash should include. 
  class FaradaySigner
    # options are passed to {OAuthenticator::SignableRequest}. 
    #
    # attributes of the request are added by the middleware, so you should not provide those as optiosn 
    # (it would not make sense to do so on the connection level). 
    #
    # These are the options you should or may provide (see {OAuthenticator::SignableRequest} for details of 
    # what options are required, what options have default or generated values, and what may be omitted):
    #
    # - signature_method
    # - consumer_key
    # - consumer_secret
    # - token
    # - token_secret
    # - version
    # - realm
    # - hash_body?
    def initialize(app, options)
      @app = app
      @options = options
    end

    # do the thing
    def call(request_env)
      request_attributes = {
        :request_method => request_env[:method],
        :uri => request_env[:url],
        :media_type => request_env[:request_headers]['Content-Type'],
        :body => request_env[:body]
      }
      oauthenticator_signable_request = OAuthenticator::SignableRequest.new(@options.merge(request_attributes))
      request_env[:request_headers]['Authorization'] = oauthenticator_signable_request.authorization
      @app.call(request_env)
    end
  end
end
