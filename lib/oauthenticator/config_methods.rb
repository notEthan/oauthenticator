module OAuthenticator
  # This module contains stubs, or in some cases default values, for implementations of particulars of the 
  # OAuth protocol. Applications must implement some of these, and are likely to want to override the default 
  # values of others. certain methods will need to use methods of the {OAuthenticator::SignedRequest} class.
  #
  # the methods your implementation will need to be used are primarily those from the parsed OAuth 
  # Authorization header. these are methods your implementation WILL need to use to implement the required 
  # functionality:
  #
  # - `#consumer_key`
  # - `#token`
  # - `#nonce`
  # - `#timestamp`
  #
  # the following are the other parts of the Authorization, but your implementation will probably NOT need to 
  # use these (OAuthenticator does everything that is needed to validate these parts):
  #
  # - `#version`
  # - `#signature_method`
  # - `#signature`
  module ConfigMethods
    # the number of seconds (integer) in both the past and future for which the request is considered valid. 
    #
    # if it is desired to have a different period considered valid in the past than in the future, then the 
    # methods {#timestamp_valid_past} and {#timestamp_valid_future} may be implemented instead, and this 
    # method may remain unimplemented. 
    #
    # see the documentation for {#timestamp_valid_past} and {#timestamp_valid_future} for other considerations 
    # of the valid period. 
    #
    # @return [Integer] period in seconds
    def timestamp_valid_period
      config_method_not_implemented
    end

    # the number of seconds (integer) in the past for which the request is considered valid. 
    #
    # if the timestamp is more than this number of seconds less than the current clock time, then the request 
    # is considered invalid and the response is an error. 
    #
    # this should be large enough to allow for clock skew between your application's server and the 
    # requester's clock. 
    #
    # nonces older than Time.now - timestamp_valid_past may be discarded.
    #
    # this method may remain unimplemented if {#timestamp_valid_period} is implemented. 
    #
    # @return [Integer] period in seconds
    def timestamp_valid_past
      timestamp_valid_period
    end

    # the number of seconds (integer) in the future for which the request is considered valid. 
    #
    # if the timestamp is more than this number of seconds greater than the current clock time, then the 
    # request is considered invalid and the response is an error. 
    #
    # this should be large enough to allow for clock skew between your application's server and the 
    # requester's clock. 
    #
    # this method may remain unimplemented if {#timestamp_valid_period} is implemented. 
    #
    # @return [Integer] period in seconds
    def timestamp_valid_future
      timestamp_valid_period
    end

    # the signature methods which the application will accept. this MUST be a subset of the signature methods 
    # defined in the OAuth 1.0 protocol plus OAuthenticator-defined extensions:
    # `%w(HMAC-SHA1 RSA-SHA1 PLAINTEXT HMAC-SHA512 HMAC-SHA256)`.
    # the default value for this is all allowed signature methods, and may remain unimplemented if you wish
    # to allow all defined signature methods.
    #
    # @return [Array<String>]
    def allowed_signature_methods
      SignableRequest::SIGNATURE_METHODS.keys
    end

    # this should look up the consumer secret in your application's storage corresponding to the request's 
    # consumer key, which is available via the `#consumer_key` method. see the README for an example 
    # implementation.
    #
    # @return [String] the consumer secret for the request's consumer key
    def consumer_secret
      config_method_not_implemented
    end

    # this should look up the token secret in your application's storage corresponding to the request's 
    # token, which is available via the `#token` method. see the README for an example implementation.
    #
    # @return [String] the token secret for the request's token
    def token_secret
      config_method_not_implemented
    end

    # whether the nonce, available via the `#nonce` method, has already been used. you may wish to use this in 
    # conjunction with the timestamp (`#timestamp`), per the OAuth 1.0 spec.
    #
    # it's worth noting that if this ever returns true, it may indicate a replay attack under way against your 
    # application. the replay attack will fail due to OAuth, but you may wish to log the event.
    #
    # this method MAY simply return false IF the method #use_nonce! is implemented to raise 
    # OAuthenticator::NonceUsedError when it encounters an already-used nonce. this may be preferable - see 
    # the #use_nonce! documentation. 
    #
    # @return [Boolean] whether the request's nonce has already been used.
    def nonce_used?
      config_method_not_implemented
    end

    # cause the nonce, available via the `#nonce` method, to be marked as used. you may wish to use this in 
    # conjunction with the timestamp (`#timestamp`).
    #
    # although this will only be called when #nonce_used? has returned false, since a nonzero amount of time 
    # does elapse between that being called and this, a race condition may occur. therefore, if the 
    # implementation is able to perform an atomic test-and-set (e.g. with SETNX in redis, or with a 
    # uniqueness-ensuring index in SQL) when it is using the nonce, then it SHOULD do so in this method, 
    # and if the test-and-set indicates the nonce has been used, SHOULD raise OAuthenticator::NonceUsedError.
    #
    # if it is more performant for the implementation to only check whether the nonce is used once, when 
    # setting, then the method #nonce_used? MAY simply return false, and raising 
    # OAuthenticator::NonceUsedError from this method may be the only method of indicating a used nonce.
    #
    # @return [Void] (return value is ignored / unused)
    # @raise [OAuthenticator::NonceUsedError] if the nonce (with the timestamp, optionally) has already been used
    def use_nonce!
      config_method_not_implemented
    end

    # whether the token indicated by the request (via `#token`) belongs to the consumer indicated by 
    # the request (via `#consumer_key`). 
    #
    # this method may simply return true if the implementation does not care to restrict tokens by 
    # consumer. 
    #
    # @return [Boolean] whether the request's token belongs to the request's consumer 
    def token_belongs_to_consumer?
      config_method_not_implemented
    end

    # whether the request will be considered valid if it is missing the oauth_body_hash parameter, when that 
    # parameter is allowed. if you require requests to include the oauth_body_hash parameter, return true 
    # here. 
    #
    # the default for this method is false, since the oauth body hash is not widely implemented. 
    #
    # this only applies to requests which are NOT form encoded - requests which are form-encoded must never 
    # have the oauth_body_hash parameter regardless of this setting and will be rejected as inauthentic, per 
    # the OAuth Request Body Hash spec. this also does not apply to requests with a signature method which 
    # does not have a corresponding body hash method - i.e., the PLAINTEXT signature method.
    #
    # @return [Boolean] whether body hash is required
    def body_hash_required?
      false
    end
  end
end
