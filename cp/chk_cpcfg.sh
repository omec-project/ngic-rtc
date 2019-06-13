#! /bin/bash

#Script to perform mandatory checks while executing run.sh.
#Input: CFLAG values of CP Makefile which denotes whether CP runs in an optimized manner or on debug mode.
#This script also verifies for sufficient MEMORY set in config/cp_config.cfg to be 4096 and prompts for user action

#CFLAG values of CP set in Makefile - Denotes either Optimized or debug mode
cp_opt_flag="CFLAGS += -O3"
cp_debug_flag="CFLAGS += -g -O0"

#Recommended MEMORY value for CP
NUMA_MEMORY="1024"

#Reading the MEMORY set in config/cp_config
source ../services.cfg

MEMORY=`cat run.sh  | grep "MEMORY=" | head -n 1 | cut -d '=' -f 2`
CP_MEMORY=$MEMORY
HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

#Code to check whether CP runs in Optimized or Debug mode
if grep -q -e "^$cp_opt_flag" -e "^#$cp_debug_flag" Makefile; then
       echo "CP Optimization level-3 for performance is set:";
   elif grep -q -e "^$cp_debug_flag" -e "^#$cp_opt_flag" Makefile; then
       echo "Debug mode is set: CP Performance will be poor";
fi

#Code to check for MEMORY requirement for CP
if (($CP_MEMORY < $NUMA_MEMORY)); then
        while true; do
                read -p "Memory is not sufficient. Do you wish to continue?" response
                case $response in
                        [Yy]* ) break;;
                        [Nn]* ) exit;;
                        * ) echo "Please answer yes(y) or no(n)";;
                esac
        done
fi

#Setup number of NUMA pages
setup_hugepages()
{
	case $SERVICE in
		[1])	echo "Setting up Control Plane NUMA memory"
			echo "$CP_NUMA_PAGES" > /sys/devices/system/node/node$CP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
			return;;

		[2])	echo "Setting up Data Plane NUMA memory"
			echo "$DP_NUMA_PAGES" > /sys/devices/system/node/node$DP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
			return;;

		[3])	echo "Setting up Control and Data Plane NUMA memory"
			if [ $CP_NUMA_NODE == $DP_NUMA_NODE ] ; then
				echo "$CP_NUMA_PAGES" > /sys/devices/system/node/node$CP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
			else
				echo "$CP_NUMA_PAGES" > /sys/devices/system/node/node$CP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
				echo "$DP_NUMA_PAGES" > /sys/devices/system/node/node$DP_NUMA_NODE/hugepages/hugepages-$HUGEPGSZ/nr_hugepages
			fi
			return;;

		*)	echo
			echo "Invalid service configuration."
			echo ;;
	esac
}
setup_hugepages
