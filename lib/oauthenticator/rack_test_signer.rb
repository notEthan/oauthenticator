module OAuthenticator
  module RackTestSigner
    # takes a block. for the duration of the block, requests made with Rack::Test will be signed
    # with the given oauth_attrs. oauth_attrs are passed to {OAuthenticator::SignableRequest}. 
    #
    # attributes of the request are set from the Rack::Test request, so you should not provide those in 
    # the outh_attrs.
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
    def signing_rack_test(oauth_attrs, &block)
      begin
        Thread.current[:oauthenticator_rack_test_attributes] = oauth_attrs
        return yield
      ensure
        Thread.current[:oauthenticator_rack_test_attributes] = nil
      end
    end
  end

  # you can run OAuthenticator.signing_rack_test(attrs) { stuff }
  extend RackTestSigner
end

class Rack::Test::Session
  actual_process_request = instance_method(:process_request)
  remove_method(:process_request)
  define_method(:process_request) do |uri, env, &block|
    oauth_attrs = Thread.current[:oauthenticator_rack_test_attributes]
    if oauth_attrs
      request = Rack::Request.new(env)

      env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new(oauth_attrs.merge({
        :request_method => request.request_method,
        :uri => request.url,
        :media_type => request.media_type,
        :body => request.body,
      })).authorization
    end

    actual_process_request.bind(self).call(uri, env, &block)
  end
end
