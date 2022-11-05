#!/bin/bash
set -e

# This is not a test, but a helper script to find the shortest key

export GNUPGHOME="/tmp/tmp.gpgtests.gpg.temp/"
rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME
gpg --quiet --batch --passphrase '' --default-new-key-algo "ed25519/cert,sign,auth+cv25519/encr" --quick-generate-key "John Doe <john@example.com>"
gpg --export-secret-keys --armor > shortest-key-gpg.key