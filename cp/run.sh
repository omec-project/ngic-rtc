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

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../libgtpv2c/lib:../libpfcp/lib

APP_PATH="./build"
APP="ngic_controlplane"
LOG_LEVEL=0

#Set NUMA memory
MEMORY=2048
NUMA0_MEMORY=$MEMORY
NUMA1_MEMORY=0

#Set corelist here
CORELIST="0-1"

NOW=$(date +"%Y-%m-%d_%H-%M")
FILE="logs/cp_$NOW.log"

ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
		-z $LOG_LEVEL"

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

else
	echo "$USAGE"
fi
