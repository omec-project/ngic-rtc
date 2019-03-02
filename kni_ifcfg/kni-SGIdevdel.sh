#! /bin/bash

# Move to script directory
cd $(dirname ${BASH_SOURCE[0]})

source ../config/dp_config.cfg
ifconfig $DL_IFACE
ip addr del $SGI_IP/24 dev $DL_IFACE
ifconfig $DL_IFACE

