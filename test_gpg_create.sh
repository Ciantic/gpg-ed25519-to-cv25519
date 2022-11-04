#!/bin/bash

set -e
export GNUPGHOME="/tmp/tmp.gpgtests.gpg.create/"
rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

# Export 
rm test_gpg_create.key || true
cargo run gpg create test_gpg_create.key -u "John O Cron <john@example.com>" -e 0102030405060708091011121314151617181920212223242526272829303132 -c CSA

rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME
gpg --import test_gpg_create.key


echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign 
echo "✅ Swordfish signed"