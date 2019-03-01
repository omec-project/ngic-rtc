#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

# Move to script directory
cd $(dirname ${BASH_SOURCE[0]})

# Load iface parameters
source config/dp_config.cfg

calc_cidrmask() {
    local CIDR_MASK=0
    local DOTTED_MASK=$1
    for octet in $(echo $DOTTED_MASK | sed 's/\./ /g'); do
	binbits=$(echo "obase=2; ibase=10; ${octet}"| bc | sed 's/0//g')
	let CIDR_MASK+=${#binbits}
    done

    echo $CIDR_MASK
}

SUDO=''
[[ $EUID -ne 0 ]] && SUDO=sudo

$SUDO ip link add $UL_IFACE type veth peer name l_$UL_IFACE
$SUDO ip link add $DL_IFACE type veth peer name l_$DL_IFACE
$SUDO ip link set $UL_IFACE up
$SUDO ip link set $DL_IFACE up
$SUDO ip link set l_$UL_IFACE up
$SUDO ip link set l_$DL_IFACE up
$SUDO ip link set dev $UL_IFACE address $S1U_MAC
$SUDO ip link set dev $DL_IFACE address $SGI_MAC

CIDR_MASK=$(calc_cidrmask $S1U_MASK)
$SUDO ip addr add $S1U_IP/$CIDR_MASK dev $UL_IFACE

CIDR_MASK=$(calc_cidrmask $SGI_MASK)
$SUDO ip addr add $SGI_IP/$CIDR_MASK dev $DL_IFACE

ip route
