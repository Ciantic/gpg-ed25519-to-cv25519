#!/bin/bash

# https://www.gnupg.org/documentation/manuals/gnupg/Agent-Protocol.html#Agent-Protocol
# https://www.gnupg.org/documentation/manuals/gnupg/Agent-PKDECRYPT.html
# https://www.gnupg.org/documentation/manuals/gnupg/Agent-PKSIGN.html#Agent-PKSIGN

(return 0 2>/dev/null) && sourced=1 || sourced=0

if [ $sourced -eq 0 ]; then
    set -e
fi


GNUPGHOME="/tmp/tmp.gpgtests.gpgagent/"
GPG_TTY=$(tty)
export GNUPGHOME
export GPG_TTY

rm -r $GNUPGHOME || true
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

killall gpg-agent || true

gpg --quiet --batch --passphrase '' --default-new-key-algo "ed25519/cert,auth,sign+cv25519/encr" --quick-generate-key "John Doe <john@example.com>"

# Test encrypt and decrypt
# echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign --encrypt | gpg --quiet --trust-model always --decrypt

KEYGRIPS=$(gpg --list-keys --with-keygrip | grep -Po '(?<=Keygrip = )(.*)')

# Get first line
PRIMARY_KEYGRIP=$(echo "$KEYGRIPS" | head -n 1)

# Get second line
ENCRYPT_KEYGRIP=$(echo "$KEYGRIPS" | tail -n 1)

echo "Primary keygrip: $PRIMARY_KEYGRIP"
echo "Encrypt keygrip: $ENCRYPT_KEYGRIP"

# Trust a primary key
echo "$PRIMARY_KEYGRIP S" > $GNUPGHOME/trustlist.txt

# GPG Agent conf
echo "
enable-ssh-support
debug-all
allow-mark-trusted
log-file gpg-agent.log
" > $GNUPGHOME/gpg-agent.conf


# Do encryption on ephemeral and s values
echo ""
echo "⌛ Try PKDECRYPT ..."

echo "(7:enc-val (4:ecdh (1:e:12341234)(1:s:12341234)))" > $GNUPGHOME/ciphertext.txt

echo "
/definqfile CIPHERTEXT $GNUPGHOME/ciphertext.txt
SETKEY $ENCRYPT_KEYGRIP
PKDECRYPT
" > $GNUPGHOME/decrypt_example.txt

gpg-connect-agent --run $GNUPGHOME/decrypt_example.txt --homedir $GNUPGHOME --verbose /bye

echo "✅ PKDECRYPT, If you see above  D (5:value33:...)"
echo ""
echo "⌛ Try PKSIGN ..."

echo "
SIGKEY $PRIMARY_KEYGRIP
SETHASH --hash=sha512 12345678901234567890123456789014
PKSIGN
" > $GNUPGHOME/sign_example.txt

gpg-connect-agent --run $GNUPGHOME/sign_example.txt --homedir $GNUPGHOME --verbose /bye

echo "✅ PKSIGN, If you see above  D (7:sig-val(5:eddsa(1:r32:...)(1:s32:...)))"