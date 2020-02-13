#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

SUDO=''
[[ $EUID -ne 0 ]] && SUDO=sudo

CUR_DIR=$PWD
function finish() {
	cd $CUR_DIR
}
trap finish EXIT

install_pkg_deps() {
	$SUDO apt-get update && $SUDO apt-get -y install \
		build-essential \
		libcurl4-openssl-dev \
		libhyperscan-dev \
		libjson-c-dev \
		libnuma-dev \
		libpcap0.8-dev \
		libssl-dev \
                libmnl-dev \
		libzmq3-dev \
		wget
}

DEPS_DIR=${DEPS_DIR:-"$PWD/third_party"}
CPUS=${CPUS:-''}

# Install DPDK
DPDK_VER=${DPDK_VER:-'18.02.2'}
export RTE_SDK=${RTE_SDK:-$DEPS_DIR/dpdk}
export RTE_TARGET=${RTE_TARGET:-'x86_64-native-linuxapp-gcc'}
export RTE_MACHINE=${RTE_MACHINE:-'native'}
install_dpdk() {
	[ -d $RTE_SDK ] && echo "DPDK already exists at $RTE_SDK" && return

	mkdir -p ${RTE_SDK} && cd ${RTE_SDK}/../
	wget http://fast.dpdk.org/rel/dpdk-${DPDK_VER}.tar.xz
	tar -xvf dpdk-${DPDK_VER}.tar.xz -C ${RTE_SDK} --strip-components 1
	cd ${RTE_SDK}
	sed -ri 's,(IGB_UIO=).*,\1n,' config/common_linuxapp
	sed -ri 's,(KNI_KMOD=).*,\1n,' config/common_linuxapp
	make -j $CPUS install T=${RTE_TARGET} RTE_MACHINE=${RTE_MACHINE}
	echo "Installed DPDK at $RTE_SDK"
}

install_build_deps() {
	install_pkg_deps
	install_dpdk
}

(return 2>/dev/null) && echo "Sourced" && return

set -o errexit
set -o pipefail
set -o nounset

install_build_deps
echo "Dependency install complete"
