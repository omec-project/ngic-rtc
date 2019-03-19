#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

#
# The start-ZMQ_Streamer.sh script starts the ZMQ Steamer. This script
# needs to be run before starting CP and DP in an NGIC setup
#

source ../setenv.sh
IF_FILE="../config/interface.cfg"

echo "Starting ZMQ streamer processes"

zmq_cp_ip=$(cat $IF_FILE | grep -v "^[#|;]" | grep -iw "zmq_cp_ip" | cut -d '=' -f 2 | awk '{print $0}')
zmq_cp_push_port=$(cat $IF_FILE | grep -v "^[#|;]" | grep -iw "zmq_cp_push_port" | cut -d '=' -f 2 | awk '{print $0}')
zmq_cp_pull_port=$(cat $IF_FILE | grep -v "^[#|;]" | grep -iw "zmq_cp_pull_port" | cut -d '=' -f 2 | awk '{print $0}')
zmq_dp_ip=$(cat $IF_FILE | grep -v "^[#|;]" | grep -iw "zmq_dp_ip" | cut -d '=' -f 2 | awk '{print $0}')
zmq_dp_push_port=$(cat $IF_FILE | grep -v "^[#|;]" | grep -iw "zmq_dp_push_port" | cut -d '=' -f 2 | awk '{print $0}')
zmq_dp_pull_port=$(cat $IF_FILE | grep -v "^[#|;]" | grep -iw "zmq_dp_pull_port" | cut -d '=' -f 2 | awk '{print $0}')

pgrep -fa python | grep req_streamer_dev.py  &> /dev/null
if [ $? -eq 1 ]; then
	echo "Starting req_streamer_dev.py"
	$NG_CORE/test/zmq_device/req_streamer_dev.py $zmq_cp_ip $zmq_cp_push_port $zmq_dp_pull_port &
	#./req_streamer_dev.py $zmq_cp_ip $zmq_cp_push_port $zmq_dp_pull_port &
else
	echo "req_streamer_dev.py already Running"
fi

pgrep -fa python | grep resp_streamer_dev.py  &> /dev/null
if [ $? -eq 1 ]; then
	echo "Starting resp_streamer_dev.py"
	$NG_CORE/test/zmq_device/resp_streamer_dev.py $zmq_dp_ip $zmq_dp_push_port $zmq_cp_pull_port&
	#./resp_streamer_dev.py $zmq_dp_ip $zmq_dp_push_port $zmq_cp_pull_port&
else
	echo "resp_streamer_dev.py already Running"
fi
sleep 2

