# SSH GPG tool

My command line utility for ED25519, X25519 fiddling. Supports creating GPG keys with custom private keys, extracting raw private keys from SSH, etc.

## Background

Currently GPG does not allow to reuse ed25519 private key in cv25519, but it's possible:

1. Filippo Valsorda has article about this: ["Using Ed25519 signing keys for encryption"](https://words.filippo.io/using-ed25519-keys-for-encryption/)
2. Key to implementation in here is dryoc (libsodium-like-library) function `crypto_sign_ed25519_sk_to_curve25519`.

None of this is advisiable, but I'm trying to see can I have just one single key
and live with it. That's how [`age`](https://github.com/FiloSottile/age) by
Filippo Valsorda also works, it allows signing and encrypting with single
ed25519 key. However I can't use `age` as it doesn't allow decrypting files if
it's stored in YubiKey.

## License

I consider my code MIT licensed, but as I consulted sequoia-pgp code, parts maybe considered also LGPL2.

## TODO

-   Error handling to Rust enums

## Notes & bookmaks

-   [Nice diagram of ed25519](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/)
-   ED25519 private key is not scalar, but rather a seed
    -   You can however obtain the scalar value by hashing (see the diagram above)
-   X25519 private key is scalar
-   `Private scalar * G` (montgomery basepoint of ed25519) is the public key for both X25519 and ED25519
-   Public key for both algorithms is Montgomery point not a scalar
-   [ECDH X25519 test vectors](https://www.rfc-editor.org/rfc/rfc7748#section-6.1)
-   [EdDSA Ed25519 test vectors](https://www.rfc-editor.org/rfc/rfc8032#page-24)
