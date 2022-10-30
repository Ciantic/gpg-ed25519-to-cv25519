#!/bin/bash
set -e
mkdir -p /tmp/tmp.gpgtests/
export GNUPGHOME="/tmp/tmp.gpgtests/"
chmod 700 $GNUPGHOME
rm -rf /tmp/tmp.gpgtests/*

# Create key and export it
gpg --quiet --batch --passphrase '' --default-new-key-algo "ed25519/cert,auth,sign" --quick-generate-key "John Doe <john@example.com>"
gpg --quiet --export-secret-keys --armor -o test.key

# Generate a new key with encryption
cargo run test.key test2.key

# Test the new key
rm -rf /tmp/tmp.gpgtests/*
gpg --quiet --import test2.key
echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign --encrypt | gpg --quiet --trust-model always --decrypt