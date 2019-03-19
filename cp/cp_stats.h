/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef CP_STATS_H
#define CP_STATS_H

#include <stdint.h>

#include <rte_common.h>

/**
 * @file
 *
 * Control Plane statistic declarations
 */

/**
 * @brief counters used to display statistics on the control plane
 */
struct cp_stats_t {
	uint64_t time;

	uint64_t create_session;
	uint64_t delete_session;
	uint64_t modify_bearer;
	uint64_t rel_access_bearer;
	uint64_t bearer_resource;
	uint64_t create_bearer;
	uint64_t delete_bearer;
	uint64_t ddn;
	uint64_t ddn_ack;
	uint64_t echo;
	uint64_t rx;
	uint64_t tx;
	uint64_t rx_last;
	uint64_t tx_last;
#ifdef SDN_ODL_BUILD
	uint64_t nb_sent;
	uint64_t nb_ok;
	uint64_t nb_cnr;
#endif
};

extern struct cp_stats_t cp_stats;

/**
 * Prints control plane signaling message statistics
 *
 * @return
 *   Never returns/value ignored
 */
int
do_stats(__rte_unused void *ptr);

/**
 * @brief clears the control plane statistic counters
 */
void
reset_cp_stats(void);

#endif
