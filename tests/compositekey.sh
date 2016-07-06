#!/bin/bash

srcdir=$(dirname $0)
sslkey="c18b4f04dc8ad2b57202e40f4389dfea96fc82535ffa1e326a2561c96857e34f"
sslparams="enc -aes-256-ecb -nopad -K $sslkey -iv 00000000000000000000000000000000 -bufsize 32"

function keyFromFile {
    base64Key=`xmlstarlet sel -T -t -v /KeyFile/Key/Data "$1"`
    echo "$base64Key" | openssl enc -d -base64
}

function keyFromPass {
    echo -n "$1" | openssl dgst -sha256 -binary
}

function composeKey {

    echo -n "$1" | openssl dgst -sha256 -binary > composite.data
    
    bash -c "tail --pid \$\$ -f composite.data | openssl $sslparams | (dd bs=32 obs=32 seek=1 count=$(($2-1)) conv=notrunc of=composite.data; head -c 32 | openssl dgst -sha256 -binary | xxd -p | tr -d '\n'; kill \$\$)"
    rm -f composite.data
}

echo -n "Test #1: Password only... "
joinedKey="`keyFromPass  qwerty1234`"
key=`composeKey "$joinedKey" 6000 2> /dev/null `
testkey=`./compositekey -p qwerty1234 -t $sslkey`
if [ "$key" != "$testkey" ]; then
    echo "Failed: $key != $testkey"
    exit 1;
fi
echo "Passed!!!"


echo -n "Test #2: Key file only... "
joinedKey="`keyFromFile  "$srcdir/../tests/TestDatabase.key"`"
key=`composeKey "$joinedKey" 6000 2> /dev/null `
testkey=`./compositekey -f "$srcdir/../tests/TestDatabase.key" -t $sslkey`
if [ "$key" != "$testkey" ]; then
    echo "Failed: $key != $testkey"
    exit 1;
fi
echo "Passed!!!"

echo -n "Test #3: Both... "
joinedKey="`keyFromPass  qwerty1234``keyFromFile  "$srcdir/../tests/TestDatabase.key"`"
key=`composeKey "$joinedKey" 6000 2> /dev/null `
testkey=`./compositekey -p qwerty1234 -f "$srcdir/../tests/TestDatabase.key" -t $sslkey`
if [ "$key" != "$testkey" ]; then
    echo "Failed: $key != $testkey"
    exit 1;
fi
echo "Passed!!!"

exit 0




