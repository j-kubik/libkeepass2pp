#!/bin/bash

# As wide-available and reliable implementation for those algorythms is not avaialable, this
# test is not designed as correctness test, but only as invariance test. Should there be any
# bugs fixed in relevant code, following data will need updating!!!
#

#key 1 68ac5bdd2f1aa4e932c6c08af09f
# Arc four output: (stdin)= f23c930b6c81eee4c4470b692004cbd1b85931c3b0cb20a1d5841ac8c89e0e2a
# Salsa output:    (stdin)= 221865291d54672650ee406768e5ed44fd22ef93d3b8cc830f369327562c23ad
#key 2 b060272ff3841c08dd046539b350
# Arc four output: (stdin)= 5f9bf23bba61ae7f9ef8a37b98f98e64512e365fc0a53a91d8b5676a90c3dd57
# Salsa output:    (stdin)= 3bde20fc9ee08b1ff657385c2f5af892542474069846dc2f031b06c3dd9eb020

echo "Test #1: Key 68ac5bdd2f1aa4e932c6c08af09f, Arc Four algorythm"
output=`./cryptorandom a 68ac5bdd2f1aa4e932c6c08af09f | openssl dgst -sha256`
if [ "$output" != "(stdin)= f23c930b6c81eee4c4470b692004cbd1b85931c3b0cb20a1d5841ac8c89e0e2a" ]; then
    exit 1;
fi

echo "Test #2: Key b060272ff3841c08dd046539b350, Arc Four algorythm"
output=`./cryptorandom a b060272ff3841c08dd046539b350 | openssl dgst -sha256`
if [ "$output" != "(stdin)= 5f9bf23bba61ae7f9ef8a37b98f98e64512e365fc0a53a91d8b5676a90c3dd57" ]; then
    exit 1;
fi


echo "Test #3: Key 68ac5bdd2f1aa4e932c6c08af09f, Salsa20 algorythm"
output=`./cryptorandom s 68ac5bdd2f1aa4e932c6c08af09f | openssl dgst -sha256`
if [ "$output" != "(stdin)= 221865291d54672650ee406768e5ed44fd22ef93d3b8cc830f369327562c23ad" ]; then
    exit 1;
fi

echo "Test #4: Key b060272ff3841c08dd046539b350, Salsa20 algorythm"
output=`./cryptorandom s b060272ff3841c08dd046539b350 | openssl dgst -sha256`
if [ "$output" != "(stdin)= 3bde20fc9ee08b1ff657385c2f5af892542474069846dc2f031b06c3dd9eb020" ]; then
    exit 1;
fi