require "oauthenticator/version"

module OAuthenticator
  autoload :Middleware, 'oauthenticator/middleware'
  autoload :SignedRequest, 'oauthenticator/signed_request'
end
