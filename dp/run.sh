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

#Checking dp system configuration's
source chk_dpcfg.sh
source ../config/dp_config.cfg
source ../config/cdr.cfg

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../libpfcp/lib

APP_PATH="./build"
APP="ngic_dataplane"
KNI_PORTMASK=03

if [ -z $GTPU_SEQNB_IN ]; then GTPU_SEQNB_IN=0; fi
if [ -z $GTPU_SEQNB_OUT ]; then GTPU_SEQNB_OUT=0; fi

if [ "${SPGW_CFG}" == "01" ]; then
	ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY	\
				--file-prefix dp	\
				-w $S1U_PORT -w $S5S8_SGWU_PORT --	\
				--s1u_ip $S1U_IP	\
				--s1u_mac $S1U_MAC	\
				--s5s8_sgwu_ip $S5S8_SGWU_IP	\
				--s5s8_sgwu_mac $S5S8_SGWU_MAC	\
				--num_workers $NUM_WORKER 	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $UL_IFACE	\
				--dl_iface $S5S8_IFACE	\
				--kni_portmask $KNI_PORTMASK \
				--teidri $TEIDRI \
				--transmit_timer $TRANSMIT_TIMER	\
				--periodic_timer $PERIODIC_TIMER \
				--transmit_count $TRANSMIT_COUNT \
				--dp_logger $DP_LOGGER"
elif [ "${SPGW_CFG}" == "02" ]; then
	ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY 	\
				--file-prefix dp	\
				-w $S5S8_PGWU_PORT -w $SGI_PORT	--	\
				--s5s8_pgwu_ip $S5S8_PGWU_IP	\
				--s5s8_pgwu_mac $S5S8_PGWU_MAC	\
				--sgi_ip $SGI_IP	\
				--sgi_mac $SGI_MAC	\
				--num_workers $NUM_WORKER	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $S5S8_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK \
				--teidri $TEIDRI \
				--transmit_timer $TRANSMIT_TIMER	\
				--periodic_timer $PERIODIC_TIMER \
				--transmit_count $TRANSMIT_COUNT \
				--dp_logger $DP_LOGGER"
elif [ "${SPGW_CFG}" == "03" ]; then
	ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY 	\
				--file-prefix dp	\
				-w $S1U_PORT -w $SGI_PORT --	\
				--s1u_ip $S1U_IP	\
				--s1u_mask $S1U_MASK \
				--s1u_mac $S1U_MAC	\
				--sgi_ip $SGI_IP	\
				--sgi_mask $SGI_MASK \
				--sgi_mac $SGI_MAC	\
				--num_workers $NUM_WORKER	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $UL_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK \
				--teidri $TEIDRI \
				--transmit_timer $TRANSMIT_TIMER	\
				--periodic_timer $PERIODIC_TIMER \
				--transmit_count $TRANSMIT_COUNT \
				--dp_logger $DP_LOGGER"
fi


if [ -n "${S1U_GW_IP}" ]; then
	ARGS="$ARGS --s1u_gw_ip $S1U_GW_IP"
fi

if [ -n "${SGI_GW_IP}" ]; then
	ARGS="$ARGS --sgi_gw_ip $SGI_GW_IP"
fi

if [ -n "${CDR_PATH}" ]; then
	ARGS="$ARGS --cdr_path $CDR_PATH"
fi

if [ -n "${MASTER_CDR}" ]; then
	ARGS="$ARGS --master_cdr $MASTER_CDR"
fi

echo $ARGS | sed -e $'s/--/\\\n\\t--/g'

USAGE=$"Usage: run.sh [ debug | log ]
	debug:	executes $APP under gdb
	log:	executes $APP with logging enabled to date named file under
		$APP_PATH/logs. Requires Control-C to exit even if $APP exits"

if [ -z "$1" ]; then

	$APP_PATH/$APP $ARGS

elif [ "$1" == "log" ]; then

	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE
	#valgrind --tool=memcheck --leak-check=full --log-file="sgwu_dp1.logs" $APP_PATH/$APP $ARGS

elif [ "$1" == "debug" ]; then

	GDB_EX="-ex 'set print pretty on' "
	echo $GDB_EX
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS
	#valgrind --tool=memcheck --leak-check=full --log-file="sgwu_dp1.logs" $APP_PATH/$APP $ARGS

else
	echo "$USAGE"
fi
