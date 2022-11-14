#!/bin/bash


set -e
export GNUPGHOME="/tmp/tmp.gpgtests.gpg.create/"
rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

# Export 
ED25519KEY=$(echo "0102030405060708091011121314151617181920212223242526272829303132" | xxd -r -p | base64)
X25519KEY=$(cargo run ed25519 private-key $ED25519KEY --convert-to-x25519-private-key)
rm test_gpg_create.key || true
cargo run gpg create test_gpg_create.key -u "John O Cron <john@example.com>" \
    -e "$ED25519KEY" \
    -x "$X25519KEY" \
    -c CSA \
    -t 10

rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME
gpg --import test_gpg_create.key

echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign --encrypt | gpg --quiet --trust-model always --decrypt
echo "✅ Swordfish signed, encrypted and decrypted"

