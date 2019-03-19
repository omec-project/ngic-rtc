#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

#Set the Log Level
LOG_LEVEL=0

#Checking dp system configuration's
source chk_dpcfg.sh
source ../config/dp_config.cfg
source ../config/cdr.cfg

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
				--sgw_s5s8gw_ip $SGW_S5S8GW_IP	\
				--sgw_s5s8gw_mask $SGW_S5S8GW_MASK	\
				--num_workers $NUM_WORKER 	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $UL_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK"
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
				--ul_iface $UL_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK"
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
				--kni_portmask $KNI_PORTMASK"
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
