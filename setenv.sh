#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

NG_CORE=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
RTE_SDK=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/dpdk
HYPERSCAN_DIR="$(pwd)/hyperscan-4.1.0"

export NG_CORE=$NG_CORE
export RTE_SDK=$RTE_SDK
export RTE_TARGET=x86_64-native-linuxapp-gcc

if [[ -d "$HYPERSCAN_DIR" ]]; then
  export HYPERSCANDIR=$HYPERSCAN_DIR
fi

export HYPERSCANDIR=/home/ngic-rtc-tmopl/hyperscan-4.1.0
#export HYPERSCANDIR=/home/dp-crash-sgx-fix/ngic-rtc-tmopl/hyperscan-4.1.0
