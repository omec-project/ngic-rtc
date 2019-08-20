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

/**
 * @file
 *
 * Control Plane statistic declarations
 */

/**
 * @brief counters used to display statistics on the control plane
 */
struct cp_stats_t {

	// MME --> SGWC
	uint64_t nbr_of_mme_to_sgwc_echo_req_rcvd;  // request  : received
	uint64_t nbr_of_mme_to_sgwc_echo_resp_rcvd; // response : received

	uint64_t nbr_of_sgwc_to_mme_echo_req_sent;  // request  : sent
	uint64_t nbr_of_sgwc_to_mme_echo_resp_sent; // response : sent

	// PGWC --> SGWC
	uint64_t nbr_of_pgwc_to_sgwc_echo_req_rcvd;
	uint64_t nbr_of_pgwc_to_sgwc_echo_resp_rcvd;

	uint64_t nbr_of_sgwc_to_pgwc_echo_req_sent;
	uint64_t nbr_of_sgwc_to_pgwc_echo_resp_sent;

	// SGWU --> SGWC
	uint64_t nbr_of_sgwu_to_sgwc_echo_req_rcvd;
	uint64_t nbr_of_sgwu_to_sgwc_echo_resp_rcvd;

	uint64_t nbr_of_sgwc_to_sgwu_echo_req_sent;
	uint64_t nbr_of_sgwc_to_sgwu_echo_resp_sent;

	// SGWC --> PGWC
	uint64_t nbr_of_sgwc_to_pgwc_echo_req_rcvd;
	uint64_t nbr_of_sgwc_to_pgwc_echo_resp_rcvd;

	uint64_t nbr_of_pgwc_to_sgwc_echo_req_sent;
	uint64_t nbr_of_pgwc_to_sgwc_echo_resp_sent;

	// PGWU --> PGWC
	uint64_t nbr_of_pgwu_to_pgwc_echo_req_rcvd;
	uint64_t nbr_of_pgwu_to_pgwc_echo_resp_rcvd;

	uint64_t nbr_of_pgwc_to_pgwu_echo_req_sent;
	uint64_t nbr_of_pgwc_to_pgwu_echo_resp_sent;

	uint64_t nbr_of_timeouts;

	uint64_t nbr_of_mme_to_sgwc_timeouts;
	uint64_t nbr_of_sgwu_to_sgwc_timeouts;
	uint64_t nbr_of_pgwc_to_sgwc_timeouts;

	uint64_t nbr_of_sgwc_to_pgwc_timeouts;
	uint64_t nbr_of_pgwu_to_pgwc_timeouts;

	int mme_status;
	int sgwc_status;
	int pgwc_status;
	int sgwu_status;
	int pgwu_status;
	int spgwc_status;
	int spgwu_status;



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

        //const char *create_session_time;
	//const char *delete_session_time;


	uint64_t number_of_ues;
	uint64_t number_of_connected_ues;
	uint64_t number_of_suspended_ues;
	uint64_t sgw_nbr_of_pdn_connections;
	uint64_t sgw_nbr_of_bearers;
	uint64_t sgw_nbr_of_active_bearers;
	uint64_t sgw_nbr_of_idle_bearers;
	uint64_t sm_create_session_req_sent;
	uint64_t sm_create_session_req_rcvd;
	uint64_t create_session_resp_acc_rcvd;
	uint64_t create_session_resp_rej_rcvd;
	uint64_t sm_delete_session_req_sent;
	uint64_t sm_delete_session_req_rcvd;
	uint64_t sm_delete_session_resp_acc_rcvd;
	uint64_t sm_delete_session_resp_rej_rcvd;

    uint64_t session_establishment_req_sent;
	uint64_t session_establishment_resp_acc_rcvd;
	uint64_t session_establishment_resp_rej_rcvd;
	uint64_t session_modification_req_sent;
	uint64_t session_modification_resp_acc_rcvd;
	uint64_t session_modification_resp_rej_rcvd;
	uint64_t session_deletion_req_sent;
	uint64_t session_deletion_resp_acc_rcvd;
	uint64_t session_deletion_resp_rej_rcvd;
	uint64_t association_setup_req_sent;
	uint64_t association_setup_resp_acc_rcvd;
	uint64_t association_setup_resp_rej_rcvd;

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
