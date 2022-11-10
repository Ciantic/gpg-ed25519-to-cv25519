#!/bin/bash

set -e
export GNUPGHOME="/tmp/tmp.gpgtests.gpg.modify/"
rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

gpg --quiet --batch --passphrase '' --default-new-key-algo "ed25519/cert" --quick-generate-key "John Doe <john@example.com>"
gpg --export-secret-keys --armor > test_gpg_modify.key


ED25519KEY=$(echo "0102030405060708091011121314151617181920212223242526272829303132" | xxd -r -p | base64)
X25519KEY=$(cargo run ed25519 $ED25519KEY --convert-to-x25519-private-key)

# Export 
cargo run gpg modify test_gpg_modify.key \
    -e "$ED25519KEY" \
    -x "$X25519KEY" \
    -c S
gpg --list-packets --verbose test_gpg_modify.key

rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME
gpg --import test_gpg_modify.key


echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign --encrypt | gpg --quiet --trust-model always --decrypt
echo "✅ Swordfish signed, encrypted and decrypted"

