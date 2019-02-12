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
