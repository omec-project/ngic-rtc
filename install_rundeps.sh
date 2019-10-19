#!/bin/bash
#
# Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
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
#
export NGIC_DIR=$PWD
MODPROBE="/sbin/modprobe"
INSMOD="/sbin/insmod"

DPDK_DIR=$NGIC_DIR/third_party/dpdk

build_dpdk()
{
        echo "Build DPDK"
        export RTE_TARGET=x86_64-native-linuxapp-gcc
        cp -f dpdk-18.02_common_linuxapp "$DPDK_DIR"/config/common_linuxapp

        pushd "$DPDK_DIR"
        make -j 10 install T="$RTE_TARGET"
        if [ $? -ne 0 ] ; then
                echo "Failed to build dpdk, please check the errors."
                exit 1
        fi
        popd
}
build_dpdk
