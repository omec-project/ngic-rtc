/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
