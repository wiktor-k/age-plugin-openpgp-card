#!/bin/bash

set -euxo pipefail

/etc/init.d/pcscd start

# start a virtual smartcard
vpicc &
sleep 2

export PINENTRY_PROGRAM=/app/scripts/fake-pinentry.sh
echo 12345678 > admin-pin
echo 123456 > user-pin
oct admin --card 0000:00000000 --admin-pin admin-pin generate --user-pin user-pin --output /tmp/no-need-for-this cv25519

age-plugin-openpgp-card | tee identity.txt
grep -oh "age1.*" identity.txt > recipients.txt
echo I like strawberries | rage -R recipients.txt -a | tee encrypted.age
rage -d -i identity.txt < encrypted.age
