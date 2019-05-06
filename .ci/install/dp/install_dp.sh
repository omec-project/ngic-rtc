#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation

set -o nounset
set -o errexit

export INSTALL_CI_PATH=$1
export SGX_INSTALL_CI_PATH=${2:-/home/jenkins}

cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck disable=SC1091
# source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/common/install_config.sh
# shellcheck disable=SC1091
source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/install/dp/install_dp_config.sh
# shellcheck disable=SC1091
source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/common/utils.sh


# Main

# Clean log dir or create it, if needed
log_step "Clean log directory ${LOG_DIR} ..."
clean_all_logs "${LOG_DIR}"

log_step "Check/kill processes, if any ..."
check_process "${DP_PROCESS}"

log_step "Copy config/*.mk files ..."
# Compilation at install time is done for TC1 test config
cp -f "${INSTALL_CI_PATH}"/ngic-rtc/.ci/tc1/config/dp_config.cfg "${INSTALL_CI_PATH}"/ngic-rtc/config/dp_config.cfg
cp -f "${INSTALL_CI_PATH}"/ngic-rtc/.ci/tc1/config/interface.cfg "${INSTALL_CI_PATH}"/ngic-rtc/config/interface.cfg
cp -f "${INSTALL_CI_PATH}"/ngic-rtc/.ci/tc1/dp/custom-dp.mk "${INSTALL_CI_PATH}"/ngic-rtc/dp/custom-dp.mk

log_step "Install DP ..."
cd "${INSTALL_CI_PATH}"/ngic-rtc && ./install.sh < "${INSTALL_CI_PATH}"/ngic-rtc/.ci/install/dp/dp-auto-install-options.txt 1>"${DP_STDOUT_LOG}" 2>"${DP_STDERR_LOG}"

# Update MRENCLAVE / MRSIGNER in ngic-rtc/config/interface.cfg if SGX-dealer is available.
# If no path is provided, default path is used.
# This setting will be overwritten in each test case.
log_step "update MRENCLAVE / MRSIGNER in ngic-rtc/config/interface.cfg"
update_interface_keys "${INSTALL_CI_PATH}" "${SGX_INSTALL_CI_PATH}"

log_step "Make ..."
cd "${INSTALL_CI_PATH}"/ngic-rtc/dp && source ../setenv.sh && make clean && make -j"$(nproc)" 1>>"${DP_STDOUT_LOG}" 2>>"${DP_STDERR_LOG}"
