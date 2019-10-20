#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

THIRD_PARTY_SW_PATH="third_party"
OSS_UTIL_DIR="oss-util"
C3PO_OSS_DIR="oss_adapter/c3po_oss"
OSS_UTIL_GIT_LINK="http://10.155.205.206/C3PO-NGIC/oss-util.git"
FREEDIAMETER="http://10.155.205.206/C3PO-NGIC/freeDiameter.git"

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
	sed -ri 's,(KNI_KMOD=).*,\1n,' config/common_linuxapp
	make -j $CPUS install T=${RTE_TARGET}
	echo "Installed DPDK at $RTE_SDK"
        
}

download_hyperscan()
{
        [ -d $DEPS_DIR/hyperscan-4.1.0 ] && echo "Hyperscan already exists at $DEPS_DIR/hyperscan-4.1.0" && return

        cd $DEPS_DIR
	
        echo "Downloading HS and dependent libraries"
        wget https://github.com/01org/hyperscan/archive/v4.1.0.tar.gz
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
        [ -d $DEPS_DIR/freediameter ] && echo "FreeDiameter already exists at $DEPS_DIR/freediameter" && return
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

build_fd_lib()
{
	pushd $CUR_DIR/$THIRD_PARTY_SW_PATH/freediameter
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

build_pfcp_lib()
{
        echo "Building libpfcp..."
        pushd $CUR_DIR/libpfcp
        make clean
        make || { echo -e "\nLibPfcp: Make lib failed\n"; }
        popd
}

build_libgtpcv2c(){

        echo "Building libgtpv2c..."
        pushd $CUR_DIR/libgtpv2c
        make clean
        make || { echo -e "\nlibgtpv2c: Make failed\n"; }
        popd

}

build_fd_gxapp()
{
	echo "Building FreeDiameter ..."
	build_fd_lib
        ldconfig 
	echo "Building GxAPP ..."
	build_gxapp
}

install_oss_util()
{
        T_DIR=$CUR_DIR/$C3PO_OSS_DIR
        cd $T_DIR

        OSS_DIR=$CUR_DIR/$C3PO_OSS_DIR/$OSS_UTIL_DIR

        echo "Checking OSS-UTIL-DIR $OSS_DIR"
     
        if [ ! -d $OSS_DIR ]; then
       	     echo "Cloning OSS-UTIL repo ...$OSS_UTIL_GIT_LINK"
             git clone $OSS_UTIL_GIT_LINK
#      	     mv oss_util_gslab oss-util     
        fi

        cp $CUR_DIR/oss-util.sh $OSS_DIR/
       
	pushd $OSS_DIR
	./oss-util.sh | tee /var/log/oss-util.log
	popd


}

install_build_deps() {
       install_pkg_deps
       install_dpdk
       if [[ $SERVICES == "CP" ]] || [[ $SERVICES == "cp" ]]; then
	    install_oss_util
#	    download_freediameter
            build_libgtpcv2c 
            build_fd_gxapp
       elif [[ $SERVICES == "DP" ]] || [[ $SERVICES == "dp" ]]; then
            download_hyperscan  
       else
            download_hyperscan
#            download_freediameter
            install_oss_util
            build_libgtpcv2c 
            build_fd_gxapp
       fi 
       build_pfcp_lib  
}


(return 2>/dev/null) && echo "Sourced" && return

set -o errexit
set -o pipefail
set -o nounset

install_build_deps
echo "Dependency install complete"

