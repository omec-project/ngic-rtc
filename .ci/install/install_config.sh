#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation

set -o nounset

export DP_PROCESS="ngic_dataplane"
export CP_PROCESS="ngic_controlplane"

BASE_LOG_DIR="/var/log/cicd/install"

export ACTION_INST="_install"

export STDOUT_EXT=".stdout.log"
export STDERR_EXT=".stderr.log"

export LOG_DIR=${BASE_LOG_DIR}
