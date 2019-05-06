#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation

set -o nounset
set -o errexit

clean_all_logs()
{
    # Clean all logs
    local LOG_DIR=$1

    if [ ! -d "${LOG_DIR}" ]; then mkdir -p "${LOG_DIR}"; fi
    rm -fr "${LOG_DIR:?}"/*
}


check_process()
{
    # Kill any running process
    local PROCESS_NAME=$1

    if pgrep -f "${PROCESS_NAME}"; then pkill -f "${PROCESS_NAME}"; fi
}


log_step()
{
    local ARG=$1
    local LENGTH=${#ARG}
    printf "\n%s\n" "${ARG}"
    # shellcheck disable=SC2046
    printf "%.s-" $(seq 1 "${LENGTH}")
    printf "\n"
}


modify_interface_cfg()
{
    local INSTALL_PATH=$1
    local MRENCLAVE=$2
    local MRSIGNER=$3

    cd "${INSTALL_PATH}"/ngic-rtc/config

    sed -i "s/dealer_in_mrenclave *= *.*/dealer_in_mrenclave = ${MRENCLAVE}/" interface.cfg
    sed -i "s/dealer_in_mrsigner *= *.*/dealer_in_mrsigner = ${MRSIGNER}/" interface.cfg

    grep -P "dealer_in_mrenclave" interface.cfg
    grep -P "dealer_in_mrsigner" interface.cfg
}


get_sgx_dealer_keys()
{
    # Fetch keys from SGX-dealer.

    local INSTALL_PATH=$1
    local KEYS=
    # shellcheck disable=SC2029
    KEYS=$(ssh sgx-kms-cdr "source ${INSTALL_PATH}/c3po/.ci/scripts/utils.sh; get_sgx_dealer_keys ${INSTALL_PATH}")

    echo "${KEYS}"
}


update_interface_keys()
{
    # Fetch keys from SGX-dealer and update interface.cfg file accordingly.

    local INSTALL_PATH=$1
    local SGX_INSTALL_PATH=$2
    local MRENCLAVE=
    local MRSIGNER=
    local SGX_DEALER_KEYS=

    mapfile -t SGX_DEALER_KEYS < <(get_sgx_dealer_keys "${SGX_INSTALL_PATH}")

    if [[ ${#SGX_DEALER_KEYS[@]} -eq 2 ]]; then
        MRENCLAVE=${SGX_DEALER_KEYS[0]}
        MRSIGNER=${SGX_DEALER_KEYS[1]}
        echo "MRENCLAVE = ${MRENCLAVE}"
        echo "MRSIGNER = ${MRSIGNER}"
        modify_interface_cfg "${INSTALL_PATH}" "${MRENCLAVE}" "${MRSIGNER}"
    else
        echo "MRENCLAVE / MRSIGNER not available."
        echo "SGX-dealer not available at ${SGX_INSTALL_PATH}"
    fi
}
