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

GX_APP_PATH="$PWD"
GX_APP="gx_app"
LOG_LEVEL=0

NOW=$(date +"%Y-%m-%d_%H-%M")
GX_FILE="$PWD/logs/gx_$NOW.log"

USAGE=$"Usage: run.sh"

if [ -z "$1" ]; then
	$GX_APP_PATH/$GX_APP

else
	echo "$USAGE"
fi
