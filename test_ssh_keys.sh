#!/bin/bash

set -e

# if file does not exist
if [ ! -f "shortest-key-gpg.key" ]; then
    ssh-keygen -t ed25519 -f test_ssh_keys.key -N '' -C "" -q
fi

ED25519KEY=$(cargo run ssh test_ssh_keys.key --get-private-key)
ED25519PUBLICKEY=$(cargo run ssh test_ssh_keys.key --get-ssh-public-key)
# echo "$ED25519PUBLICKEY_B64"
# echo "$ED25519PUBLICKEY"
# exit 0
X25519KEY=$(cargo run ed25519 private-key $ED25519KEY --convert-to-x25519-private-key)
cargo run gpg create test_ssh_keys_pgp.key -u "John O Cron <john@example.com>" \
    -e "$ED25519KEY" \
    -x "$X25519KEY" \
    -c CSA \
    -t 10

export GNUPGHOME="/tmp/tmp.gpgtests.gpg.sshtest/"
rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME
gpg --import test_ssh_keys_pgp.key

echo "$ED25519KEY"
echo "$ED25519PUBLICKEY"
ENC=$(echo "swordfish" | age --encrypt --identity test_ssh_keys.key --output - -)

HEADER=$(echo $ENC | cut -d' ' -f1)
STANZA=$(echo $ENC | cut -d' ' -f3)
TAG=$(echo $ENC | cut -d' ' -f4)
X25519=$(echo $ENC | cut -d' ' -f5)

if [ "$HEADER" != "age-encryption.org/v1" ]; then
    echo "❌ Age header not found"
    exit 1
fi
if [ "$STANZA" != "ssh-ed25519" ]; then
    echo "❌ SSH-ed25519 not found"
    exit 1
fi


MY_TAG=$(echo "$ED25519PUBLICKEY" | cut -d' ' -f2 | base64 -d | openssl dgst -sha256 -binary | cut -b 1-4 | base64 | cut -c 1-6) 

if [ "$TAG" != "$MY_TAG" ]; then
    echo "❌ Tags are not matching"
    exit 1
fi


echo "X25519"
echo $X25519


# hex to binary
ED25519PUBLICKEY_BIN=$(echo $ED25519PUBLICKEY | xxd -r -p)

# echo $ED25519PUBLICKEY_BIN

# Sha256
# echo -n $ED25519PUBLICKEY_BIN | openssl dgst -sha256 -binary 

# convert to hex
# TAG=$(echo $TAG | xxd -p)
# echo $TAG