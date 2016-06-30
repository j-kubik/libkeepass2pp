#!/bin/bash

srcdir=$(dirname $0)

sslkey="-aes-256-cbc -K c18b4f04dc8ad2b57202e40f4389dfea96fc82535ffa1e326a2561c96857e34f -iv d01f71601189889b5aab63a5ea2b6bdb"


function runPipeline {
    echo -n ./pipeline "$1" "$2" pipeline.output ... =
    ./pipeline "$1" "$2" pipeline.output
    result=$?
    echo $result
    if [ $result -ne 0 ]; then
        exit $result
    fi
}

function compareFiles {
    echo -n diff "$1" "$2" ... =
    diff "$1" "$2"
    result=$?
    echo $result
    if [ $result -ne 0 ]; then
        exit $result
    fi
}

function runTests {

    echo "Test #1: passthrough."
    runPipeline "" $1
    compareFiles $1 pipeline.output
    rm -f pipeline.output
    echo ""

    echo "Test #2: inflate."
    gzip -c $1 > pipeline.input.gz
    runPipeline "i" pipeline.input.gz
    compareFiles $1 pipeline.output
    rm -f pipeline.output
    rm -f pipeline.input.gz
    echo ""

    echo "Test #3: encrypt."
    runPipeline "e" $1
    openssl enc -d $sslkey -in pipeline.output -out pipeline.decrypted
    compareFiles $1 pipeline.decrypted
    rm -f pipeline.output
    rm -f pipeline.decrypted
    echo ""

    echo "Test #4: deflate, encrypt, hash, unhash."
    runPipeline "dehu" $1
    openssl enc -d $sslkey -in pipeline.output -out pipeline.output.gz
    rm pipeline.output
    gzip -d pipeline.output.gz
    compareFiles $1 pipeline.output
    rm -f pipeline.output
    rm -f pipeline.output.gz
    echo ""

    echo "Test #5: deflate, encrypt, hash, unhash, decrypt, inflate."
    runPipeline "dehuxi" $1
    compareFiles $1 pipeline.output
    rm -f pipeline.output
    rm -f pipeline.output.gz
    echo ""

}

echo "Pass #1: 512kB file"
runTests $srcdir/pipeline.input

echo "Pass #2: Empty file"
touch pipeline.empty
runTests pipeline.empty
rm pipeline.empty

echo "Pass #3: Small file"
echo "12345" > pipeline.small
runTests pipeline.small
rm pipeline.small

echo "Pass #4: This script file"
runTests $0


