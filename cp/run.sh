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

#Checking cp system configuration's
source chk_cpcfg.sh

source ../config/cp_config.cfg

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../libgtpv2c/lib

APP_PATH="./build"
APP="ngic_controlplane"
LOG_LEVEL=1

if [ "${SPGW_CFG}" == "01" ]; then
	ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
      -d $SPGW_CFG            \
	  -m $S11_MME_IP          \
	  -s $S11_SGW_IP          \
	  -w $S1U_SGW_IP          \
	  -r $S5S8_SGWC_IP        \
	  -g $S5S8_PGWC_IP        \
	  -v $S5S8_SGWU_IP        \
	  -u $S5S8_PGWU_IP        \
	  -i $IP_POOL_IP          \
	  -p $IP_POOL_MASK        \
	  -l $LOG_LEVEL"
elif [ "${SPGW_CFG}" == "02" ]; then
	ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
      -d $SPGW_CFG            \
	  -m $S11_MME_IP          \
	  -s $S11_SGW_IP          \
	  -w $S1U_SGW_IP          \
	  -r $S5S8_SGWC_IP        \
	  -g $S5S8_PGWC_IP        \
	  -v $S5S8_SGWU_IP        \
	  -u $S5S8_PGWU_IP        \
	  -i $IP_POOL_IP          \
	  -p $IP_POOL_MASK        \
	  -l $LOG_LEVEL"
elif [ "${SPGW_CFG}" == "03" ]; then
	ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
      -d $SPGW_CFG            \
	  -m $S11_MME_IP          \
	  -s $S11_SGW_IP          \
	  -w $S1U_SGW_IP          \
	  -i $IP_POOL_IP          \
	  -p $IP_POOL_MASK        \
	  -l $LOG_LEVEL"
fi

IFS=',' read -a APNS <<< "${APN}"
for _apn in "${APNS[@]}"
do
   ARGS="$ARGS -a $_apn"
done
echo $ARGS

USAGE=$"Usage: run.sh [ debug | log ]
	debug:	executes $APP under gdb
	log:	executes $APP with logging enabled to date named file under
		$APP_PATH/logs. Requires Control-C to exit even if $APP exits"

if [ -z "$1" ]; then

	$APP_PATH/$APP $ARGS

elif [ "$1" == "pcap" ]; then
    $APP_PATH/$APP $ARGS -x ../pcap/cp_in.pcap -y ../pcap/cp_out.pcap

elif [ "$1" == "log" ]; then

	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE

elif [ "$1" == "debug" ];then

	GDB_EX="-ex 'set print pretty on'"
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS

#elif [ "$1" == "zmq" ];then
#	pgrep -fa python | grep req_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "Starting req_streamer_dev.py"
#		$NG_CORE/test/zmq_device/req_streamer_dev.py &
#	else
#		echo "req_streamer_dev.py already Running"
#	fi

#	pgrep -fa python | grep resp_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "Starting resp_streamer_dev.py"
#		$NG_CORE/test/zmq_device/resp_streamer_dev.py &
#	else
#		echo "resp_streamer_dev.py already Running"
#	fi
#	sleep 2

	$APP_PATH/$APP $ARGS

#elif [ "$1" == "kill" ];then
#	pgrep -fa python | grep req_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "req_streamer_dev.py no longer running.."
#	else
#		echo "Stopping req_streamer_dev.py"
#		killall -9 req_streamer_dev.py
#	fi

#	pgrep -fa python | grep resp_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "resp_streamer_dev.py no longer running.."
#	else
#		echo "Stopping resp_streamer_dev.py"
#		killall -9 resp_streamer_dev.py
#	fi

else
	echo "$USAGE"
fi
