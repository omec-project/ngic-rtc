#! /bin/bash

#Script to perform mandatory checks while executing run.sh.
#Input: CFLAG values of DP Makefile which denotes whether DP runs in an optimized manner or on debug mode.
#This script also verifies for sufficient MEMORY set in config/dp_config.cfg to be 4096 and prompts for user action

#CFLAG values of DP set in dp/Makefile - Denotes either Optimized or debug mode
dp_opt_flag="CFLAGS += -O3"
dp_debug_flag="CFLAGS += -g -O0"
dp_perf_flag="CFLAGS += -DPERF_TEST"

#Recommended MEMORY value for DP
NUMA_MEMORY="4096"

#Reading the MEMORY set in config/dp_config
source ../config/dp_config.cfg
source ../services.cfg
DP_MEMORY=$MEMORY
HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

#Code to check whether DP runs in Optimized or Debug mode
if grep -q -e "^$dp_opt_flag" -e "^#$dp_debug_flag" Makefile; then
       echo -e "\nDP Optimization level-3 for performance is set:";
elif grep -q -e "^$dp_debug_flag" -e "^#$dp_opt_flag" Makefile; then
       echo -e "\nDebug mode is set: DP Performance will be poor";
fi

#Code to check Log Level and if PERF_TEST is enabled or disabled in DP Makefile
if [ $LOG_LEVEL -eq 2 ]; then
if grep -q -e "^$dp_perf_flag" Makefile; then
	   echo -e "Log level is $LOG_LEVEL. Please disable PERF_TEST in DP Makefile for log messages"
	   while true; do
			   read -p "Do you wish to continue? (Y=NO Log msgs; N= recompile w/ PERF_TEST DISABLD):" response
			   case $response in
			           [Yy]* ) break;;
			           [Nn]* ) exit;;
			           * ) echo "Please answer yes(y) or no(n)";;
			   esac
	   done
fi
fi

#Code to check for MEMORY requirement for DP
if (($DP_MEMORY < $NUMA_MEMORY)); then
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
