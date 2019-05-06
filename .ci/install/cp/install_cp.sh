#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation

set -o nounset
set -o errexit

export INSTALL_CI_PATH=$1

cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck disable=SC1091
# source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/common/install_config.sh
# shellcheck disable=SC1091
source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/install/cp/install_cp_config.sh
# shellcheck disable=SC1091
source "${INSTALL_CI_PATH}"/ngic-rtc/.ci/common/utils.sh


# Main

# Clean log dir or create it, if needed
log_step "Clean log directory ${LOG_DIR} ..."
clean_all_logs "${LOG_DIR}"

log_step "Check/kill processes, if any ..."
check_process "${CP_PROCESS}"

log_step "Copy config/*.mk files ..."
# Compilation at install time is done for TC1 test config
cp -f "${INSTALL_CI_PATH}"/ngic-rtc/.ci/tc1/config/cp_config.cfg "${INSTALL_CI_PATH}"/ngic-rtc/config/cp_config.cfg
cp -f "${INSTALL_CI_PATH}"/ngic-rtc/.ci/tc1/config/interface.cfg "${INSTALL_CI_PATH}"/ngic-rtc/config/interface.cfg
cp -f "${INSTALL_CI_PATH}"/ngic-rtc/.ci/tc1/cp/custom-cp.mk "${INSTALL_CI_PATH}"/ngic-rtc/cp/custom-cp.mk

log_step "Install CP ..."
cd "${INSTALL_CI_PATH}"/ngic-rtc && ./install.sh < "${INSTALL_CI_PATH}"/ngic-rtc/.ci/install/cp/cp-auto-install-options.txt 1>"${CP_STDOUT_LOG}" 2>"${CP_STDERR_LOG}"

log_step "Make ..."
# shellcheck disable=SC1091
cd "${INSTALL_CI_PATH}"/ngic-rtc/cp && source ../setenv.sh && make clean && make -j"$(nproc)" 1>>"${CP_STDOUT_LOG}" 2>>"${CP_STDERR_LOG}"
