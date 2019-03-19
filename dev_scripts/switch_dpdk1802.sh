#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

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

