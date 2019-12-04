#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

SUDO=''
[[ $EUID -ne 0 ]] && SUDO=sudo

install_run_cp_deps() {
	$SUDO apt-get update && $SUDO apt-get -y install \
		libnuma1 \
		libpcap0.8 \
		libzmq5
}

install_run_dp_deps() {
	$SUDO apt-get update && $SUDO apt-get -y install \
		libhyperscan4 \
		libmnl0 \
		libnuma1 \
		libssl1.1 \
		libzmq5
}

install_run_utils() {
	$SUDO apt-get update && $SUDO apt-get -y install \
		dnsutils \
		iproute2 \
		iputils-ping \
		tcpdump
}

cleanup_image() {
	$SUDO rm -rf /var/lib/apt/lists/*
}

(return 2>/dev/null) && echo "Sourced" && return
