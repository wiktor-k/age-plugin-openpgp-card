#!/bin/bash

set -Eeuxo pipefail

/etc/init.d/pcscd start

# start a virtual smartcard
vpicc &
sleep 2

export PINENTRY_PROGRAM=/app/scripts/fake-pinentry.sh
echo 12345678 > admin-pin
echo 123456 > user-pin
oct admin --card 0000:00000000 --admin-pin admin-pin generate --user-pin user-pin --output /tmp/no-need-for-this --userid 'No need for that' curve25519

function roundtrip {
  age-plugin-openpgp-card | tee identity.txt
  grep -oh "age1.*" identity.txt > recipients.txt
  echo I like strawberries > message.txt
  < message.txt rage -R recipients.txt -a | tee encrypted.age
  rage -d -i identity.txt < encrypted.age > decrypted.txt
  cmp --silent message.txt decrypted.txt
}

# test encryption/decryption without KDF
roundtrip

# test encryption/decryption with KDF
oct system kdf-setup --card 0000:00000000
roundtrip
