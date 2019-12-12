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
#include <time.h>
#include <rte_common.h>
#define LAST_TIMER_SIZE 80
#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
/**
 * @file
 *
 * Control Plane statistic declarations
 */

/**
 * @brief  : counters used to display statistics on the control plane
 */
struct cp_stats_t {

	uint64_t time;
	clock_t  execution_time;
	clock_t  reset_time;

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

	char stat_timestamp[LAST_TIMER_SIZE];

#ifdef SDN_ODL_BUILD
	uint64_t nb_sent;
	uint64_t nb_ok;
	uint64_t nb_cnr;
#endif
};

extern struct cp_stats_t cp_stats;

extern int s11logger;
extern int s5s8logger;
extern int sxlogger;
extern int gxlogger;
extern int apilogger;
extern int epclogger;

/**
 * @brief  : Prints control plane signaling message statistics
 * @param  : Currently not being used
 * @return : Never returns/value ignored
 */
int
do_stats(__rte_unused void *ptr);

/**
 * @brief  : clears the control plane statistic counters
 * @param  : No param
 * @return : Returns nothing
 */
void
reset_cp_stats(void);

#endif
