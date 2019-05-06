#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation

set -o nounset
set -o errexit

INSTALL_CI_PATH=$1

cd "$(dirname "${BASH_SOURCE[0]}")"
source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/install/install_config.sh

echo "${LOG_DIR}"
