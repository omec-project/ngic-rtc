#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

source ./git_url.cfg
THIRD_PARTY_SW_PATH="third_party"

SERVICES="$1"
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
		libjson-c-dev \
		libnuma-dev \
		libpcap0.8-dev \
		libssl-dev \
		libzmq3-dev \
    libjson0-dev \
	  libc6-dev \
	  libcurl4-openssl-dev \
		libc6 \
    g++ cmake ragel libboost-all-dev \
		automake libgcrypt-dev flex bison gnutls-dev \
		libidn11-dev libtool libsctp-dev \
		wget


}
DEPS_DIR=${DEPS_DIR:-"$PWD/$THIRD_PARTY_SW_PATH"}
CPUS=${CPUS:-'5'}

# Install DPDK
DPDK_VER=${DPDK_VER:-'18.02.2'}
export RTE_SDK=${RTE_SDK:-$DEPS_DIR/dpdk}
export RTE_TARGET=${RTE_TARGET:-'x86_64-native-linuxapp-gcc'}

install_dpdk() {

	[ -d $RTE_SDK ] && echo "DPDK already exists at $RTE_SDK" && return

	mkdir -p ${RTE_SDK} && cd ${RTE_SDK}/../
	wget http://fast.dpdk.org/rel/dpdk-${DPDK_VER}.tar.xz
	tar -xvf dpdk-${DPDK_VER}.tar.xz -C ${RTE_SDK} --strip-components 1

	echo "Applying AVX not supported patch for resolved dpdk-18.02 i40e driver issue.."
	patch $RTE_SDK/drivers/net/i40e/i40e_rxtx.c $RTE_SDK/../../patches/avx_not_suported.patch
	if [ $? -ne 0 ] ; then
		echo "Failed to apply AVX patch, please check the errors."
		return
	fi

	cd ${RTE_SDK}
	cp $CUR_DIR/dpdk-18.02_common_linuxapp config/common_linuxapp
#	sed -ri 's,(KNI_KMOD=).*,\1n,' config/common_linuxapp
	make -j $CPUS install T=${RTE_TARGET}
	echo "Installed DPDK at $RTE_SDK"

}

download_hyperscan()
{
        [ -d $DEPS_DIR/hyperscan-4.1.0 ] && echo "Hyperscan already exists at $DEPS_DIR/hyperscan-4.1.0" && return

        cd $DEPS_DIR

        echo "Downloading HS and dependent libraries"
        wget $HYPERSCAN_GIT_LINK
        tar -xvf v4.1.0.tar.gz
        pushd hyperscan-4.1.0
        mkdir build; pushd build
        cmake -DCMAKE_CXX_COMPILER=c++ ..
        cmake --build .
        export LD_LIBRARY_PATH=${LD_LIBRARY_PATH-}:$PWD/lib
        popd
        export HYPERSCANDIR=$PWD
        echo "export HYPERSCANDIR=$PWD" >> ../setenv.sh
        popd
}

download_freediameter()
{
        cd $CUR_DIR
        [ -d $DEPS_DIR/freeDiameter ] && echo "FreeDiameter already exists at $DEPS_DIR/freeDiameter" && return
        echo "Download FreeDiameter from sprint-repos....."
        if [ ! -d $THIRD_PARTY_SW_PATH ]; then
             mkdir $THIRD_PARTY_SW_PATH
        fi
        pushd $THIRD_PARTY_SW_PATH
        git clone $FREEDIAMETER
        if [ $? -ne 0 ] ; then
                        echo "Failed to clone FreeDiameter, please check the errors."
                        return
        fi
        popd

}

download_hiredis()
{
	echo "Download Highredis from git....."
	[ -d $CUR_DIR/$THIRD_PARTY_SW_PATH/hiredis ] && echo "hiredis already exists" && return
    pushd $CUR_DIR/$THIRD_PARTY_SW_PATH
	git clone $HIREDIS
	if [ $? -ne 0 ] ; then
	                echo "Failed to clone hiredis, please check the errors."
	                return
	fi
        popd

}

build_fd_lib()
{
	pushd $CUR_DIR/$THIRD_PARTY_SW_PATH/freeDiameter
	if [ ! -e "build" ]; then
		mkdir build
	fi
	pushd build
	cmake ../
	make || { echo -e "\nFD: Make lib failed\n"; }
	make install || { echo -e "\nFD: Make install failed\n"; }

	libfdproto="/usr/local/lib/libfdproto.so"
	libfdcore="/usr/local/lib/libfdcore.so"

	if [ ! -e "$libfdproto" ]  && [ ! -e "$libfdcore" ]; then
     	        echo "LibFdproto and LibfdCore.so does not exist at /usr/local/lib"
		return
	fi
	popd
	popd
}

build_gxapp()
{
	pushd $CUR_DIR/cp/gx_app
	make clean
	make || { echo -e "\nGxApp: Make GxApp failed\n"; }
	popd
}

build_fd_gxapp()
{
	echo "Building FreeDiameter ..."
	build_fd_lib

	echo "Building GxAPP ..."
	build_gxapp
}

build_hiredis()
{
	pushd $CUR_DIR/$THIRD_PARTY_SW_PATH/hiredis
	git checkout $HIREDIS_COMMIT_ID
	make clean
	make USE_SSL=1
	if [ $? -ne 0 ] ; then
		echo "Failed to build Hiredis, please check the errors."
		exit 1
	fi
	make install
	if [ $? -ne 0 ] ; then
		echo "Make install Failed in Hiredis, please check the errors."
		exit 1
	fi

	libhrso="/usr/local/lib/libhiredis.so"
	libhra="/usr/local/lib/libhiredis.a"

	if [ ! -e "$libhrso" ] && ! [ -e "$libhra" ]; then
		echo "libhiredis.so and libhiredis.a does not exist at /usr/local/lib"
		return
	fi
	sudo ldconfig
	popd
}

install_epc_tools()
{
	mkdir -p third_party
	pushd $CUR_DIR/third_party
	if [ ! -d "$CUR_DIR/third_party/epctools/" ]; then
		git clone $EPC_TOOLS_GIT_LINK epctools
	fi
	pushd epctools
	git checkout $EPC_TOOLS_COMMIT_ID
	./configure
	make; make install
	popd
	popd
	pushd oss_adapter/libepcadapter
	make
	popd
}

install_pfcp_and_gtpv2_library()
{
	pushd $CUR_DIR/third_party
	if [ ! -d "$CUR_DIR/third_party/libpfcp/" ]; then
		git clone $LIBPFCP_GIT_LINK libpfcp
	fi
	pushd libpfcp/
	git checkout $LIBPFCP_COMMIT_ID
	make clean
	make
	popd
	popd
	if [[ $SERVICES != "DP" ]] && [[ $SERVICES != "dp" ]]; then
		if [ ! -d "$CUR_DIR/third_party/libgtpv2c/" ]; then
			pushd $CUR_DIR/third_party
			git clone $LIBGTPV2_GIT_LINK libgtpv2c
			pushd libgtpv2c/
			git checkout $LIBGTPV2_COMMIT_ID
		else
			pushd $CUR_DIR/third_party
			pushd libgtpv2c/
			git checkout $LIBGTPV2_COMMIT_ID
		fi
			make clean
			make
			popd
			popd
	fi
}

install_build_deps() {
       install_pkg_deps
       install_dpdk
	   install_pfcp_and_gtpv2_library
       if [[ $SERVICES == "CP" ]] || [[ $SERVICES == "cp" ]]; then
	     install_epc_tools
	     download_freediameter
         build_fd_gxapp
         download_hiredis
         build_hiredis
       elif [[ $SERVICES == "DP" ]] || [[ $SERVICES == "dp" ]]; then
	     install_epc_tools
         download_hyperscan
       else
         download_hyperscan
         download_freediameter
         install_epc_tools
         build_fd_gxapp
	     download_hiredis
         build_hiredis
       fi
}


(return 2>/dev/null) && echo "Sourced" && return

set -o errexit
set -o pipefail
set -o nounset

install_build_deps
echo "Dependency install complete"

