# 1.2.0

- OAuthenticator::RackTestSigner / OAuthenticator.signing_rack_test
- don't try to use a nonce when not required and specified

# 1.1.0

- added OAuthenticator::NonceUsedError to address race condition between `#nonce_used?` and `#use_nonce!`
- minor fixes for ruby 1.8.7 compatibility

# 1.0.0

- initial stable release
