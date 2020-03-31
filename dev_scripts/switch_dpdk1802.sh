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

S1UDEV=0000:af:00.0
SGIDEV=0000:af:00.1

echo -e "Switching to DPDK 18.02...\n"
echo "Path to dpdk18.02 @/home/intel-lab/ngic-rtc-dbg/dpdk-1802..."
source setenv_dpdk1802.sh
echo -e "insmod DPDK 18.02 igb_uio @$RTE_SDK/$RTE_TARGET...\n"
rmmod igb_uio
insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
lsmod | grep uio*
echo -e "...\n"
pushd dp
echo  "Building dp..."
make clean; make
echo -e "\nBind $S1UDEV & $SGIDEV to DPDK 18.02 igb_uio..."
$RTE_SDK/usertools/dpdk-devbind.py -b igb_uio $S1UDEV $SGIDEV
$RTE_SDK/usertools/dpdk-devbind.py -s | grep '$S1UDEV\|$S1UDEV'
popd
echo -e "...\n"
pushd cp
echo  "Building cp..."
make clean; make
echo -e "\n**** System switched to dpdk-1802. RTE_SDK=$RTE_SDK ****\n"

