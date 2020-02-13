#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation


#
# The stop-ZMQ_Streamer.sh script stops the ZMQ Steamer. This script
# needs to be run after stopping CP and DP in an NGIC setup
#

pgrep -fa python | grep req_streamer_dev.py  &> /dev/null
if [ $? -eq 1 ]; then
	echo "req_streamer_dev.py no longer running.."
else
	echo "Stopping req_streamer_dev.py"
	killall -9 req_streamer_dev.py
fi

pgrep -fa python | grep resp_streamer_dev.py  &> /dev/null
if [ $? -eq 1 ]; then
	echo "resp_streamer_dev.py no longer running.."
else
	echo "Stopping resp_streamer_dev.py"
	killall -9 resp_streamer_dev.py
fi
