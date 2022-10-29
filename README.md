# Convert GPG ed25519 key to cv25519 encryption key

This program appends cv25519 encryption key to GPG private key, it derives the private key from existing ed25519 key.

```
Usage: gpg-ed25519-to-cv25519 [INPUT_FILE] [OUTPUT_FILE]

  INPUT_FILE: Armored PGP private key with ed25519 key, and no encryption key
  OUTPUT_FILE: Armored PGP private key with cv25519 encryption key

  Note: INPUT_FILE must not have passphrase.
```

## Background

Currently GPG does not allow to reuse ed25519 private key in cv25519, but it's possible:

1. Filippo Valsorda has article about this: ["Using Ed25519 signing keys for encryption"](https://words.filippo.io/using-ed25519-keys-for-encryption/)
2. Key to implementation in here is dryoc (libsodium-like-library) function `crypto_sign_ed25519_sk_to_curve25519`.

None of this of course advisiable, but I'm trying to see can I have just one
single key and live with it. That's how
[`age`](https://github.com/FiloSottile/age) by Filippo Valsorda also works, it
allows signing and encrypting with single ed25519 key. However I can't use `age`
as it doesn't allow decrypting files if it's stored in YubiKey.

## License

I consider my code MIT licensed, but as I consulted sequoia-pgp code, parts maybe considered also LGPL2.
