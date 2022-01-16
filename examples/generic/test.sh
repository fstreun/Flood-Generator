#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration>

# cd to directory of script
scriptDir=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
cd "$scriptDir"

libmoonBuild=../../../libmoon/build



echo $scriptDir/../../lua