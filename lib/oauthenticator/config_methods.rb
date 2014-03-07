module OAuthenticator
  module ConfigMethods
    def timestamp_valid_period
      config_method_not_implemented
    end

    def timestamp_valid_past
      timestamp_valid_period
    end

    def timestamp_valid_future
      timestamp_valid_period
    end

    def allowed_signature_methods
      OAuthenticator::SignedRequest::VALID_SIGNATURE_METHODS
    end

    def consumer_secret
      config_method_not_implemented
    end

    def access_token_secret
      config_method_not_implemented
    end

    def nonce_used?
      config_method_not_implemented
    end

    def use_nonce!
      config_method_not_implemented
    end

    def access_token_belongs_to_consumer?
      config_method_not_implemented
    end
  end
end
