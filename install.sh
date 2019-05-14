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

cd $(dirname ${BASH_SOURCE[0]})
SERVICE=3
SGX_SERVICE=0
SERVICE_NAME="Collocated CP and DP"
source ./services.cfg
export NGIC_DIR=$PWD
echo "------------------------------------------------------------------------------"
echo " NGIC_DIR exported as $NGIC_DIR"
echo "------------------------------------------------------------------------------"

HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`
MODPROBE="/sbin/modprobe"
INSMOD="/sbin/insmod"
DPDK_DOWNLOAD="https://fast.dpdk.org/rel/dpdk-18.02.tar.gz"
DPDK_DIR=$NGIC_DIR/dpdk
LINUX_SGX_SDK="https://github.com/intel/linux-sgx.git"
LINUX_SGX_SDK_BRANCH_TAG="sgx_1.9"
CP_NUMA_NODE=0
DP_NUMA_NODE=0


OSS_UTIL_GIT_LINK="http://gsgit.gslab.com/nilesh/oss_util_gslab.git"
OSS_UTIL_DIR="oss_adapter/c3po_oss/"

#
# Sets QUIT variable so script will finish.
#
quit()
{
	QUIT=$1
}

# Shortcut for quit.
q()
{
	quit
}

setup_http_proxy()
{
	while true; do
		echo
		read -p "Enter Proxy : " proxy
		export http_proxy=$proxy
		export https_proxy=$proxy
		echo "Acquire::http::proxy \"$http_proxy\";" | sudo tee -a /etc/apt/apt.conf > /dev/null
		echo "Acquire::https::proxy \"$http_proxy\";" | sudo tee -a /etc/apt/apt.conf > /dev/null

		wget -T 20 -t 3 --spider http://www.google.com
		if [ "$?" != 0 ]; then
		  echo -e "No Internet connection. Proxy incorrect? Try again"
		  echo -e "eg: http://<proxy>:<port>"
		  exit 1
		fi
	return
	done
}

step_1()
{
        TITLE="Environment setup."
        CONFIG_NUM=1
        TEXT[1]="Check OS and network connection"
        FUNC[1]="setup_env"
        TEXT[2]="Configured Service - $SERVICE_NAME"
        FUNC[2]="configure_services"

}

setup_env()
{
	# a. Check for OS dependencies
	source /etc/os-release
	if [[ $VERSION_ID != "16.04" ]] ; then
		echo "WARNING: It is recommended to use Ubuntu 16.04..Your version is "$VERSION_ID
		echo "The libboost 1.58 dependency is not met by official Ubuntu PPA. Either attempt"
		echo "to find/compile boost 1.58 or upgrade your distribution by performing 'sudo do-release-upgrade'"
	else
		echo "Ubuntu 16.04 OS requirement met..."
	fi
	echo
	echo "Checking network connectivity..."
	# b. Check for internet connections
	wget -T 20 -t 3 --spider http://www.google.com
	if [ "$?" != 0 ]; then
		while true; do
			read -p "No Internet connection. Are you behind a proxy (y/n)? " yn
			case $yn in
				[Yy]* ) $SETUP_PROXY ; return;;
				[Nn]* ) echo "Please check your internet connection..." ; exit;;
				* ) "Please answer yes or no.";;
			esac
		done
	fi
}

step_2()
{
	TITLE="Download and Install"
	CONFIG_NUM=1
	TEXT[1]="Agree to download"
	FUNC[1]="get_agreement_download"
	TEXT[2]="Download packages"
	FUNC[2]="install_libs"
	TEXT[3]="Download DPDK zip"
	FUNC[3]="download_dpdk_zip"
	TEXT[4]="Install DPDK"
	FUNC[4]="install_dpdk"
	if [ "$SERVICE" -ne 1 ] ; then
	TEXT[5]="Download hyperscan"
	FUNC[5]="download_hyperscan"
	if [ "$SGX_SERVICE" -eq 1 ] ; then
	TEXT[6]="Download Intel(R) SGX SDK"
	FUNC[6]="download_linux_sgx"
	fi
	fi
	if [ "$SERVICE" -ne 2 ] ; then
	TEXT[5]="Download and install oss-util for DNS and cli"
    FUNC[5]="install_oss_util"
	fi
}

get_agreement_download()
{
	echo
	echo "List of packages needed for NGIC build and installation:"
	echo "-------------------------------------------------------"
	echo "1.  DPDK version 16.11.4"
	echo "2.  build-essential"
	echo "3.  linux-headers-generic"
	echo "4.  git"
	echo "5.  unzip"
	echo "6.  libpcap-dev"
	echo "7.  make"
	echo "8.  hyperscan"
	echo "9.  curl"
	echo "10. openssl-dev"
	echo "11. and other library dependencies"
	while true; do
		read -p "We need download above mentioned package. Press (y/n) to continue? " yn
		case $yn in
			[Yy]* )
				touch .agree
				return;;
			[Nn]* ) exit;;
			* ) "Please answer yes or no.";;
		esac
	done
}

install_libs()
{
	echo "Install libs needed to build and run NGIC..."
	file_name=".agree"
	if [ ! -e "$file_name" ]; then
		echo "Please choose option '3. Agree to download' first"
		return
	fi
	file_name=".download"
	if [ -e "$file_name" ]; then
		clear
		return
	fi
	sudo apt-get update
	sudo apt-get -y install curl build-essential linux-headers-$(uname -r) \
		git unzip libpcap0.8-dev gcc libjson0-dev make libc6 libc6-dev \
		g++-multilib libzmq3-dev libcurl4-openssl-dev libssl-dev python-pip

	pip install zmq

	touch .download
}

download_dpdk_zip()
{
	echo "Download DPDK zip"
	file_name=".agree"
	if [ ! -e "$file_name" ]; then
		echo "Please choose option '3. Agree to download' first"
		return
	fi
	wget --no-check-certificate "${DPDK_DOWNLOAD}"

	if [ $? -ne 0 ] ; then
		echo "Failed to download dpdk submodule."
		return
	fi

	tar -xzvf "${DPDK_DOWNLOAD##*/}"
	rm -rf "$NGIC_DIR"/dpdk/
	rm -f "${DPDK_DOWNLOAD##*/}"
	mv "$NGIC_DIR"/dpdk-*/ "$NGIC_DIR"/dpdk

	echo ""
	echo "Applying AVX not supported patch for resolved dpdk-18.02 i40e driver issue.."
	patch $DPDK_DIR/drivers/net/i40e/i40e_rxtx.c $NGIC_DIR/patches/avx_not_suported.patch

	if [ $? -ne 0 ] ; then
		echo "Failed to apply AVX patch, please check the errors."
		return
	fi

	echo "AVX patch successfully applied to dpdk."

}

install_dpdk()
{
	echo "Build DPDK"
	export RTE_TARGET=x86_64-native-linuxapp-gcc
	cp -f dpdk-18.02_common_linuxapp "$DPDK_DIR"/config/common_linuxapp

	pushd "$DPDK_DIR"
	make -j 20 install T="$RTE_TARGET"
	if [ $? -ne 0 ] ; then
		echo "Failed to build dpdk, please check the errors."
		return
	fi

	if lsmod | grep rte_kni >&/dev/null; then
		echo -e "\n*************************************"
		echo "rte_kni.ko module already loaded..!!!"
		echo -e "*************************************\n"
	else
		sudo $INSMOD "$RTE_TARGET"/kmod/rte_kni.ko

		if lsmod | grep rte_kni >&/dev/null; then
			echo -e "\n*********************************"
			echo "Inserted 'rte_kni.ko' module..!!!"
			echo -e "*********************************\n"
		else
			echo -e "\n**********************************************"
			echo "ERROR: 'rte_kni.ko' module failed to load..!!!"
			echo -e "**********************************************\n"
		fi

	fi

	sudo modinfo igb_uio
	if [ $? -ne 0 ] ; then
		sudo $MODPROBE -v uio
		sudo $INSMOD "$RTE_TARGET"/kmod/igb_uio.ko
		sudo cp -f "$RTE_TARGET"/kmod/igb_uio.ko /lib/modules/"$(uname -r)"
		echo "uio" | sudo tee -a /etc/modules
		echo "igb_uio" | sudo tee -a /etc/modules
		sudo depmod
	fi
	popd
}

setup_dp_type()
{
	while true; do
		read -p "Do you want data-plane with Intel(R) SGX based CDR? " yn
		case $yn in
			[Yy]* )	SGX_SERVICE=1; return;;
			[Nn]* ) SGX_SERVICE=0; return;;
			* ) "Please answer yes or no.";;
		esac
	done

}

configure_services()
{
	clear
	echo "------------------"
	echo "Service Selection."
	echo "------------------"
	echo "1. Configure CP only"
	echo "2. Configure DP only"
	echo "3. Configure Collocated CP and DP "
	echo ""
	while true;do
		read -p "Please choose option : " opt
		case $opt in
			[1])	echo "Control Plane Settings"
				SERVICE=1
				SERVICE_NAME="CP"
				recom_memory=1024
				memory=`cat cp/run.sh  | grep "MEMORY=" | head -n 1 | cut -d '=' -f 2`
				setup_memory
				setup_numa_node
				setup_hugepages
				return;;

			[2])	echo "Data Plane Setting"
				setup_dp_type
				SERVICE=2
				SERVICE_NAME="DP"
				recom_memory=4096
				memory=`cat config/dp_config.cfg  | grep "MEMORY=" | head -n 1 | cut -d '=' -f 2`
				setup_memory
				setup_numa_node
				setup_hugepages
				return;;

			[3])	echo "Control and Data Plane Setting"
				SERVICE=3
				SERVICE_NAME="Collocated CP and DP"
				recom_memory=5120
				setup_dp_type
				setup_collocated_memory
				setup_memory
				setup_numa_node
				setup_hugepages
				return;;

			*)	echo
				echo "Please select appropriate option."
				echo ;;
		esac

	done
}

setup_numa_node()
{
	if [ `cat cp/run.sh  | grep "NUMA0_MEMORY=0" | wc -l` != 0 ]; then
		CP_NUMA_NODE=1
	fi
	if [ `cat config/dp_config.cfg  | grep "NUMA0_MEMORY=0" | wc -l` != 0 ]; then
		DP_NUMA_NODE=1
	fi
}

setup_memory()
{
	echo
	echo "Current $SERVICE_NAME memory size : $memory (MB)"
		while true; do
			read -p "Do you want change the $SERVICE_NAME memory size[Recommended = $recom_memory](y/n)? " yn
			case $yn in
				[Yy]* )	if [ $SERVICE == 1 ] || [ $SERVICE == 3 ] ; then
							set_size CP
							sed -i '/^MEMORY=/s/=.*/='$memory'/' cp/run.sh
						fi

						if [ $SERVICE == 2 ] || [ $SERVICE == 3 ] ; then
							set_size DP
							sed -i '/^MEMORY=/s/=.*/='$memory'/' config/dp_config.cfg
						fi

						if [ $SERVICE == 3 ] ; then
							setup_collocated_memory
						echo "Total memory size allocated for Collocated CP and DP : $memory "
                                fi
						return;;

				[Nn]* ) return;;

				* ) "Please answer yes or no.";;
			esac
		done

}

set_size()
{
	while true;do
	read -p "Enter $1 memory size[MB] : " memory
		if [[ ! ${memory} =~ ^[0-9]+$ ]] ; then
			echo
			echo "Please enter valid input."
			echo
		else
			return
		fi
	done
}

setup_collocated_memory()
{
	dp_memory=`cat config/dp_config.cfg  | grep "MEMORY=" | head -n 1 | cut -d '=' -f 2`
	cp_memory=`cat cp/run.sh  | grep "MEMORY=" | head -n 1 | cut -d '=' -f 2`
	memory=$(($cp_memory + $dp_memory))
}

setup_hugepages()
{
	Pages=16
	cp_pages=8
	dp_pages=8
	echo "SERVICE_NAME=\"$SERVICE_NAME\" " > ./services.cfg
	echo "SERVICE=$SERVICE" >> ./services.cfg
	echo "SGX_SERVICE=$SGX_SERVICE" >> ./services.cfg
	echo "CP_NUMA_NODE=$CP_NUMA_NODE" >> ./services.cfg
	echo "DP_NUMA_NODE=$DP_NUMA_NODE" >> ./services.cfg

	if [[ "$HUGEPGSZ" = "2048kB" ]] ; then
		#---- Calculate number of pages base on configure MEMORY and page size
		Hugepgsz=`echo $HUGEPGSZ | tr -d 'kB'`
		Pages=$((($memory*1024) / $Hugepgsz))
		if [ $SERVICE == 3 ] ; then
			cp_pages=$((($cp_memory*1024) / $Hugepgsz))
			dp_pages=$((($dp_memory*1024) / $Hugepgsz))
		fi
		echo "MEMORY (MB) : " $memory
		echo "Number of pages : " $Pages
	fi

	case $SERVICE in
		[1])	echo "Control Plane NUMA memory Settings"
			echo "$Pages" > /sys/devices/system/node/node$CP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
			echo "CP_NUMA_PAGES=$Pages" >> ./services.cfg
			echo "DP_NUMA_PAGES=0" >> ./services.cfg
			return;;

		[2])	echo "Data Plane NUMA memory Settings"
			echo "$Pages" > /sys/devices/system/node/node$DP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
			echo "DP_NUMA_PAGES=$Pages" >> ./services.cfg
			echo "CP_NUMA_PAGES=0" >> ./services.cfg
			return;;

		[3])	echo "Control and Data Plane NUMA memory Settings"
			if [ $CP_NUMA_NODE == $DP_NUMA_NODE ] ; then
				echo "$Pages" > /sys/devices/system/node/node$CP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
				echo "CP_NUMA_PAGES=$Pages" >> ./services.cfg
				echo "DP_NUMA_PAGES=$Pages" >> ./services.cfg
			else
				echo "$cp_pages" > /sys/devices/system/node/node$CP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
				echo "$dp_pages" > /sys/devices/system/node/node$DP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
				echo "CP_NUMA_PAGES=$cp_pages" >> ./services.cfg
				echo "DP_NUMA_PAGES=$dp_pages" >> ./services.cfg
			fi
			return;;

		*)	echo
			echo "Invalid service configuration."
			echo ;;
	esac

	sudo service procps start

	grep -s '/dev/hugepages' /proc/mounts
	if [ $? -ne 0 ] ; then
		echo "Creating /mnt/huge and mounting as hugetlbfs"
		sudo mkdir -p /mnt/huge
		sudo mount -t hugetlbfs nodev /mnt/huge
		echo "nodev /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab > /dev/null
        fi
}

download_hyperscan()
{
	source /etc/os-release
	if [[ $VERSION_ID != "16.04" ]] ; then
		echo "Download boost manually "$VERSION_ID
		wget http://sourceforge.net/projects/boost/files/boost/1.58.0/boost_1_58_0.tar.gz
		tar -xf boost_1_58_0.tar.gz
		pushd boost_1_58_0
		sudo apt-get install g++
		./bootstrap.sh --prefix=/usr/local
		./b2
		./b2 install
		popd
	else
		sudo apt-get install libboost-all-dev
	fi
	echo "Downloading HS and dependent libraries"
	sudo apt-get install cmake ragel
	wget https://github.com/01org/hyperscan/archive/v4.1.0.tar.gz
	tar -xvf v4.1.0.tar.gz
	pushd hyperscan-4.1.0
	mkdir build; pushd build
	cmake -DCMAKE_CXX_COMPILER=c++ ..
	cmake --build .
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/lib
	popd
	export HYPERSCANDIR=$PWD
	echo "export HYPERSCANDIR=$PWD" >> ../setenv.sh
	popd
}


download_linux_sgx()
{
	echo "Download Linux SGX SDK....."
	git clone --branch $LINUX_SGX_SDK_BRANCH_TAG $LINUX_SGX_SDK
	if [ $? -ne 0 ] ; then
	                echo "Failed to clone Linux SGX SDK, please check the errors."
	                return
	fi
}

build_pfcp_lib()
{
	pushd $NGIC_DIR/libpfcp
	make clean
	make || { echo -e "\nLibPfcp: Make lib failed\n"; }
	popd
}

step_3()
{
        TITLE="Build NGIC"
        CONFIG_NUM=1
		TEXT[1]="Build NGIC"
        FUNC[1]="build_ngic"
        sed -i '/SGX_BUILD/d' setenv.sh
		if [ "$SGX_SERVICE" -eq 1 ] ; then
			echo "export SGX_BUILD=1" >> setenv.sh
			TEXT[1]="Build NGIC With SGX"
			FUNC[1]="build_ngic"
		fi
}

install_oss_util()
{
   pushd $NGIC_DIR/$OSS_UTIL_DIR
   git clone $OSS_UTIL_GIT_LINK
   mv oss_util_gslab oss-util
   pushd oss-util
   ./install.sh
   popd
   popd
}



build_ngic()
{
	pushd $NGIC_DIR
	source setenv.sh

	echo "Building PFCP Libs ..."
	build_pfcp_lib

	if [ $SERVICE == 2 ] || [ $SERVICE == 3 ] ; then
		make clean-lib
		make clean-dp
		echo "Building Libs..."
		make build-lib || { echo -e "\nNG-CORE: Make lib failed\n"; }
		echo "Building DP..."
		make build-dp || { echo -e "\nDP: Make failed\n"; }
	fi
	if [ $SERVICE == 1 ] || [ $SERVICE == 3 ] ; then
		echo "Building libgtpv2c..."
		pushd $NGIC_DIR/libgtpv2c
			make clean
			make || { echo -e "\nlibgtpv2c: Make failed\n"; }
		popd

		echo "Building CP..."
		make clean-cp
		make build-cp || { echo -e "\nCP: Make failed\n"; }
	fi
	popd
}

SETUP_PROXY="setup_http_proxy"
STEPS[1]="step_1"
STEPS[2]="step_2"
STEPS[3]="step_3"

QUIT=0

clear

echo -n "Checking for user permission.. "
sudo -n true
if [ $? -ne 0 ]; then
   echo "Password-less sudo user must run this script" 1>&2
   exit 1
fi
echo "Done"
clear

while [ "$QUIT" == "0" ]; do
        OPTION_NUM=1
        for s in $(seq ${#STEPS[@]}) ; do
                ${STEPS[s]}

                echo "----------------------------------------------------------"
                echo " Step $s: ${TITLE}"
                echo "----------------------------------------------------------"

                for i in $(seq ${#TEXT[@]}) ; do
                        echo "[$OPTION_NUM] ${TEXT[i]}"
                        OPTIONS[$OPTION_NUM]=${FUNC[i]}
                        let "OPTION_NUM+=1"
                done

                # Clear TEXT and FUNC arrays before next step
                unset TEXT
                unset FUNC

                echo ""
        done

        echo "[$OPTION_NUM] Exit Script"
        OPTIONS[$OPTION_NUM]="quit"
        echo ""
        echo -n "Option: "
        read our_entry
        echo ""
        ${OPTIONS[our_entry]} ${our_entry}

        if [ "$QUIT" == "0" ] ; then
                echo
                echo -n "Press enter to continue ..."; read
                clear
                continue
                exit
        fi
        echo "Installation complete. Please refer to README.MD for more information"
done

