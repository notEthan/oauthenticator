# OAuthenticator

[![Build Status](https://travis-ci.org/notEthan/oauthenticator.svg?branch=master)](https://travis-ci.org/notEthan/oauthenticator)

OAuthenticator signs outgoing requests with OAuth 1.0. 

OAuthenticator authenticates incoming OAuth 1.0 signed requests, primarily as a middleware, and forms useful 
error messages when authentication fails. 

Note: The canonical location of this README is on [RubyDoc](http://rubydoc.info/gems/oauthenticator/). When 
viewed on [Github](https://github.com/notEthan/oauthenticator/), it may be inconsistent with the latest 
released gem, and Yardoc links will not work.

## Signing outgoing requests

### Faraday

OAuthenticator provides Faraday middleware for easy signing of outgoing requests. This request middleware is 
registered with faraday named `:oauthenticator_signer`.

The middleware should be in the stack immediately before the adapter. Any other middleware that modifies the 
request between OAuthenticator signing it and the request actually being made may render the signature 
invalid. 

See the documentation for {OAuthenticator::FaradaySigner} for more detailed information.

An example:

```ruby
require 'oauthenticator'

signing_options = {
  :signature_method => 'HMAC-SHA1',
  :consumer_key => 'a consumer',
  :consumer_secret => 'a consumer secret',
  :token => 'a token',
  :token_secret => 'a token secret',
  :realm => 'The Realm',
}

connection = Faraday.new('http://example.com/') do |faraday|
  faraday.request :url_encoded
  faraday.request :oauthenticator_signer, signing_options
  faraday.adapter Faraday.default_adapter
end

connection.get '/path'
```

Note that `:url_encoded` is only included to illustrate that other middleware should all go before 
`:oauthenticator_signer`; the use of `:url_encoded` is not related to OAuthenticator.

Note that for the RSA-SHA1 signature method, the token secret is the contents of the RSA certificate
used for signing the requests.

### Any other HTTP library

Generating an Authorization header to apply to an outgoing request is a relatively straightforward affair:

```ruby
oauthenticator_signable_request = OAuthenticator::SignableRequest.new(
  :request_method => my_request_method,
  :uri => my_request_uri,
  :media_type => my_request_media_type,
  :body => my_request_body,
  :signature_method => my_oauth_signature_method,
  :consumer_key => my_oauth_consumer_key,
  :consumer_secret => my_oauth_consumer_secret,
  :token => my_oauth_token,
  :token_secret => my_oauth_token_secret,
  :realm => my_authorization_realm,
  :hash_body? => my_body_hashing_requirement
)
my_http_request.headers['Authorization'] = oauthenticator_signable_request.authorization
```

See the documentation for {OAuthenticator::SignableRequest} for more detailed information.

### OAuth Request Body Hash

The [OAuth Request Body Hash](https://tools.ietf.org/html/draft-eaton-oauth-bodyhash-00)
specification is supported. By default all signing of outgoing does include the body hash. This can be 
disabled by setting the `:hash_body?` / `'hash_body?'` attribute to false when instantiating an 
OAuthenticator::SignableRequest. 

For info on when to include the body hash, see 
[When to Include the Body Hash](https://tools.ietf.org/html/draft-eaton-oauth-bodyhash-00#section-4.1.1). 

## Authenticating incoming requests

### Config Methods module

There are many ways (infinite, really) in which certain parts of the OAuth spec may be implemented. In order 
to flexibly accomodate the general case of OAuth authentication, OAuthenticator leaves certain parts of the 
implementation up to the user. The user configures this by creating a module implementing what is needed, 
which will be passed to OAuthenticator.

For more information on the details of the methods which must or may be implemented, please see the 
documentation for the module {OAuthenticator::ConfigMethods}, which defines stub methods for 
each recognized method, with method documentation relating to your implementation.

A simple, contrived example follows, which approximately resembles what you might implement. It is not useful 
on its own but will be used in following examples for usage of RackAuthenticator and SignedRequest. 

```ruby
require 'oauthenticator'

# we'll suppose that there exist the following ActiveRecord classes with the named 
# attributes (all of which are strings), for this example:
#
# - OAuthNonce:
#   - nonce
#   - timestamp
# - OAuthConsumer
#   - key
#   - secret
# - OAuthToken
#   - token
#   - secret
#   - consumer_key

module AwesomeOAuthConfig
  # check for an existing nonce, coupled with the timestamp 
  def nonce_used?
    OAuthNonce.where(:nonce => nonce, :timestamp => timestamp).any?
  end

  # nonce is used, store it so that in the future #nonce_used? will return true 
  # correctly 
  def use_nonce!
    OAuthNonce.create!(:nonce => nonce, :timestamp => timestamp)
  end

  # number seconds in the past and the future for which we'll consider a request 
  # authentic 
  def timestamp_valid_period
    25
  end

  # no plaintext for us! 
  def allowed_signature_methods
    %w(HMAC-SHA1 RSA-SHA1)
  end

  # consumer secret, looked up by consumer key from ActiveRecord storage
  def consumer_secret
    OAuthConsumer.where(:key => consumer_key).first.try(:secret)
  end

  # token secret, looked up by token 
  def token_secret
    OAuthToken.where(:token => token).first.try(:secret)
  end

  # whether the token belongs to the consumer 
  def token_belongs_to_consumer?
    OAuthToken.where(:token => token).first.try(:consumer_key) == consumer_key
    # alternately:
    # OAuthToken.where(:token => token, :consumer_key => consumer_key).any?
  end

  # whether oauth_body_hash is required (this method defaults to false and may be omitted)
  def body_hash_required?
    false
  end
end
```

You may also find it enlightening to peruse `test/test_config_methods.rb`, which sets up some very simple 
storage in memory, and defines a module of config methods which are used through the tests. 

### OAuthenticator::RackAuthenticator

The RackAuthenticator middleware is used by passing the above-mentioned module on the `:config_methods` key to 
initialize the middleware:

```ruby
# config.ru

use OAuthenticator::RackAuthenticator, :config_methods => AwesomeOAuthConfig
run proc { |env| [200, {'Content-Type' => 'text/plain'}, ['access granted!']] }
```

The authentication can also be bypassed with a proc on the `:bypass` key; see the documentation for 
{OAuthenticator::RackAuthenticator} for the details of that. 

### OAuthenticator::SignedRequest

The OAuthenticator::SignedRequest class may be used independently of the RackAuthenticator middleware, though 
it must also be passed your module of config methods to include. It is used like:

```ruby
OAuthenticator::SignedRequest.including_config(AwesomeOAuthConfig).new(request_attrs)
```

See the documentation of {OAuthenticator::SignedRequest} for how the class is used, once it includes the 
methods it needs to function. 

### OAuth Request Body Hash

The [OAuth Request Body Hash](https://tools.ietf.org/html/draft-eaton-oauth-bodyhash-00)
specification is supported. Requests which include the oauth_body_hash parameter are authenticated according 
to the spec. 

Requests which may include the oauth_body_hash parameter but do not are accepted or rejected based on the 
config method `#body_hash_required?` - if the implementation indicates that oauth_body_hash is required, then 
the request is rejected as inauthentic; if it is not required then the request is allowed (assuming all other 
aspects of the OAuth signature are authentic.) 

