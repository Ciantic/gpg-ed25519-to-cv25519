#!/bin/bash

set -e
export GNUPGHOME="/tmp/tmp.gpgtests.gpg.modify/"
rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

gpg --quiet --batch --passphrase '' --default-new-key-algo "ed25519/cert" --quick-generate-key "John Doe <john@example.com>"
gpg --export-secret-keys --armor > test_gpg_modify.key

# Export 
cargo run gpg modify test_gpg_modify.key -e 0102030405060708091011121314151617181920212223242526272829303132 -c S
gpg --list-packets --verbose test_gpg_modify.key

rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME
gpg --import test_gpg_modify.key


echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign 
echo "✅ Swordfish signed"