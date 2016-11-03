# 1.3.3

- env["oauth.signed_request"] contains the signed request. this makes any helper methods from the implemented 
config methods module available and helps avoid code duplication (and sometimes duplicated db queries - 
depending on implementation)
- fix irrelevant warning with Hash#reject called on hash with a default proc

# 1.3.2

- loosen dependency to allow rack 2.0

# 1.3.1

- set media type to the default that the adapter will use if it's not specified on a request that is expected to have a body

# 1.3.0

- Make error messages fully-human readable on their own (not requiring context of the error key)
- Add error_message key to error response, with a sentence of error messages.
- clarify argument errors

# 1.2.0

- OAuthenticator::RackTestSigner / OAuthenticator.signing_rack_test
- don't try to use a nonce when not required and specified

# 1.1.0

- added OAuthenticator::NonceUsedError to address race condition between `#nonce_used?` and `#use_nonce!`
- minor fixes for ruby 1.8.7 compatibility

# 1.0.0

- initial stable release
