#! /bin/bash
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

NG_CORE=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
RTE_SDK=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/dpdk-1802
HYPERSCAN_DIR="$(pwd)/hyperscan-4.1.0"

export NG_CORE=$NG_CORE
export RTE_SDK=$RTE_SDK
export RTE_TARGET=x86_64-native-linuxapp-gcc

if [[ -d "$HYPERSCAN_DIR" ]]; then
  export HYPERSCANDIR=$HYPERSCAN_DIR
fi

export HYPERSCANDIR=/home/intel-lab/temp/ngic-rtc/hyperscan-4.1.0
