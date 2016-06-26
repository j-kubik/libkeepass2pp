#!/bin/bash

srcdir=$(dirname $0)

./pipeline both $srcdir/pipeline.input pipeline.output
result=$?
if [ $result -ne 0 ]; then
    exit $result;
fi

diff $srcdir/pipeline.input pipeline.output
#
exit $?
