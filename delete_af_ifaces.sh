#!/usr/bin/env bash

set -o pipefail
set -o nounset

# Move to script directory
cd $(dirname ${BASH_SOURCE[0]})

# Load iface parameters
source config/dp_config.cfg

SUDO=''
[[ $EUID -ne 0 ]] && SUDO=sudo

# delete ul interface
$SUDO ip link delete $UL_IFACE || true

# delete dl interface
$SUDO ip link delete $DL_IFACE || true
