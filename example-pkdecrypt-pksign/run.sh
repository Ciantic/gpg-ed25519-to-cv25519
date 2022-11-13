#!/bin/bash

# https://www.gnupg.org/documentation/manuals/gnupg/Agent-Protocol.html#Agent-Protocol
# https://www.gnupg.org/documentation/manuals/gnupg/Agent-PKDECRYPT.html
# https://www.gnupg.org/documentation/manuals/gnupg/Agent-PKSIGN.html#Agent-PKSIGN

(return 0 2>/dev/null) && sourced=1 || sourced=0

if [ $sourced -eq 0 ]; then
    echo "⤴ Stop on fail"
    set -e
fi


GNUPGHOME="/tmp/tmp.gpgtests.gpgagent"
GPG_TTY=$(tty)
export GNUPGHOME
export GPG_TTY

# if first argument is "delete"
if [ "$1" = "delete" ]; then
    echo "🗑 Deleting $GNUPGHOME..."
    rm -r $GNUPGHOME
fi

if [ ! -d "$GNUPGHOME" ]; then
    mkdir -p $GNUPGHOME
    chmod 700 $GNUPGHOME
    gpg --quiet --batch --passphrase '' --default-new-key-algo "ed25519/cert,auth,sign+cv25519/encr" --quick-generate-key "John Doe <john@example.com>"
    gpg --export --armor > gpg.key
fi

# It's important to close gpg agents after `gpg` command, otherwise some of the
# instances might cause race conditions for the tests below
killall gpg-agent || true

# Test encrypt and decrypt
# echo "swordfish" | gpg --quiet --trust-model always --recipient John --armor --sign --encrypt | gpg --quiet --trust-model always --decrypt

KEYGRIPS=$(gpg --list-keys --with-keygrip | grep -Po '(?<=Keygrip = )(.*)')
PRIMARY_KEYGRIP=$(echo "$KEYGRIPS" | head -n 1)
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

# Decrypting example
echo "
/hex
/let MYCIPHER (7:enc-val (4:ecdh (1:e:12341234)))
/definq CIPHERTEXT MYCIPHER
# Or using file
# /definqfile CIPHERTEXT ciphertext.txt
SETKEY $ENCRYPT_KEYGRIP
PKDECRYPT
" > $GNUPGHOME/example_decrypt.txt

# Signing example
echo "
/hex
SIGKEY $PRIMARY_KEYGRIP
SETHASH --hash=sha512 12345678901234567890123456789014
PKSIGN
" > $GNUPGHOME/example_signing.txt

# Run examples
gpg-connect-agent --run $GNUPGHOME/example_decrypt.txt --homedir $GNUPGHOME --verbose /bye
gpg-connect-agent --run $GNUPGHOME/example_signing.txt --homedir $GNUPGHOME --verbose /bye

echo "✅ PKDECRYPT, If you see above hex (5:value33:...)"
echo "✅ PKSIGN, If you see above hex (7:sig-val(5:eddsa(1:r32:...)(1:s32:...)))"

if [ "$1" = "bash" ]; then
    echo "🐚 Entering bash..."

    # Start bash with short prompt
    bash --rcfile <(echo "PS1='\033[0;32mexample\$\033[0m '")
fi    
