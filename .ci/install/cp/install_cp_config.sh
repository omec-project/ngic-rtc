#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation

set -o nounset

# shellcheck disable=SC1091
source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/install/install_config.sh


# Log file names.

export CP_STDOUT_LOG="${LOG_DIR}/cicd_cp1${ACTION_INST}${STDOUT_EXT}"
export CP_STDERR_LOG="${LOG_DIR}/cicd_cp1${ACTION_INST}${STDERR_EXT}"
