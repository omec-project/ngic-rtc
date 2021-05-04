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

#Set the Log Level
LOG_LEVEL=0

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../third_party/libpfcp/lib

APP_PATH="./build"
APP="ngic_dataplane"
KNI_PORTMASK=03
NOW=$(date +"%Y-%m-%d_%H-%M")
FILE="logs/dp_$NOW.log"

#WB_PORT: S1U/S5S8 Interface PCI Address
WB_PORT=0000:00:04.0
#EB_PORT: S5S8/SGI Interface PCI Address
EB_PORT=0000:00:05.0

#MEMORY in (MB) which used for hugepages calculation
#MEMORY=5120
MEMORY=4096
#Give numa memory according to numa1 or numa0 socket
NUMA0_MEMORY=$MEMORY
NUMA1_MEMORY=0

#set coremask here
CORELIST=0-3

ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY	\
			--file-prefix dp	\
			-w $WB_PORT -w $EB_PORT --	\
			--LOG $LOG_LEVEL	\
			--KNI_PORTMASK $KNI_PORTMASK"

echo $ARGS | sed -e $'s/--/\\\n\\t--/g'

#set pending signals limit
ulimit -i unlimited

USAGE=$"Usage: run.sh [ debug | log ]
	debug:	executes $APP under gdb
	log:	executes $APP with logging enabled to date named file under
		$APP_PATH/logs. Requires Control-C to exit even if $APP exits"

if [ -z "$1" ]; then

	$APP_PATH/$APP $ARGS

elif [ "$1" == "core" ]; then
	/bin/rm -f ./core
	ulimit -c unlimited
	$APP_PATH/$APP $ARGS

elif [ "$1" == "log" ]; then

	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE

elif [ "$1" == "debug" ]; then

	GDB_EX="-ex 'set print pretty on' "
	echo $GDB_EX
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS

elif [ "$1" == "valgrind" ]; then

	echo "Valgrind started on data-plane....."
	valgrind --tool=memcheck --leak-check=full --log-file="data_plane.logs" $APP_PATH/$APP $ARGS
else
	echo "$USAGE"
fi
