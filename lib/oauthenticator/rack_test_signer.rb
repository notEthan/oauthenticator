# typed: strict

module OAuthenticator
  module RackTestSigner
    extend T::Sig

    sig { params(oauth_attrs: T::Hash[String, String], _block: T.proc.returns(T.untyped)).returns(T.untyped) }
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
    def signing_rack_test(oauth_attrs, &_block)
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
  extend T::Sig

  alias actual_process_request process_request
  remove_method(:process_request)

  sig { params(uri: T.untyped, env: T::Hash[String, T.untyped], block: T.nilable(T.proc.returns(T.untyped))).returns(T.untyped) }
  def process_request(uri, env, &block)
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

    actual_process_request(uri, env, &block)
  end
end
