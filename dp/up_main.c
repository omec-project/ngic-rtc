/*
 * Copyright (c) 2019 Sprint
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

#include <unistd.h>
#include <locale.h>
#include <signal.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>

#include "up_main.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"

#include "gw_adapter.h"
#include "clogger.h"
#include "cstats.h"
#include "predef_rule_init.h"
#include "tcp_client.h"

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */

uint32_t start_time;

extern struct in_addr cp_comm_ip;
extern struct in_addr dp_comm_ip;

#ifdef USE_CSID
uint16_t local_csid = 0;
#endif /* USE_CSID */

/* List of allocated teid ranges*/
teidri_info *upf_teidri_allocated_list = NULL;
/* List of free teid ranges*/
teidri_info *upf_teidri_free_list = NULL;
/* List of blocked teid ranges, needs to release after timer expires*/
teidri_info *upf_teidri_blocked_list = NULL;

void dp_sig_handler(int signo)
{
	if (signo == SIGINT) {

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
			print_perf_statistics();
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
		rte_exit(EXIT_SUCCESS, "received SIGINT\n");
	}
}

/**
 * Main function.
 */
int main(int argc, char **argv)
{
	int ret;
	bool ret_val;

	start_time = current_ntp_timestamp();

#ifdef USE_REST
	/* Write User-plane start time on Disk */
	recovery_time_into_file(start_time);
#endif

	/* Initialize the Environment Abstraction Layer */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	if (signal(SIGINT, dp_sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");
	argc -= ret;
	argv += ret;

	/* DP restart conter info */
	dp_restart_cntr = get_dp_restart_cntr();

	/* DP Init */
	dp_init(argc, argv);

	/* TODO: CLI Changes, CLI modules need to refactore and remove dp mode dependancy */
	init_cli_module(app.dp_logger);

	/* TODO: Need to validate LI*/
	/* Create TCP connection between data-plane and d-df2 */
	ddf2_fd = create_ddf_tunnel(app.ddf2_ip, app.ddf2_port,
			app.ddf2_intfc);
	if (ddf2_fd < 0) {
		/* Error Handling */
	}

	/* Create TCP connection between data-plane and d-df3 */
	ddf3_fd = create_ddf_tunnel(app.ddf3_ip, app.ddf3_port,
			app.ddf3_intfc);
	if (ddf3_fd < 0) {
		/* Error Handling */
	}

	number_of_transmit_count = app.transmit_cnt;
	periodic_timer_value = app.periodic_timer;
	transmit_timer_value = app.transmit_timer;

	create_node_id_hash();
	create_heartbeat_hash_table();

	/* Initialize DP PORTS and membufs */
	dp_port_init();

	/* Initiliazed the predefined rules tables */
	init_predef_rule_hash_tables();

	/**
	 * SGWU: UE <--S1U/WB-->[SGW]<--EB/S5/S8/WB-->[PGW]<--SGi/EB-->
	 * PGWU: UE <--S1U/WB-->[SGW]<--EB/S5/S8/WB-->[PGW]<--SGi/EB-->
	 * SAEGWU: UE <--S1U/WB--> [SAEGW] <--SGi/EB-->
	 */

	/* Pipeline Init */
	epc_init_packet_framework(app.eb_port,
			app.wb_port);

	/* West Bound port handler*/
	register_ul_worker(wb_pkt_handler, app.wb_port);

	/* East Bound port handler*/
	register_dl_worker(eb_pkt_handler, app.eb_port);

	/* Initialization of the PFCP interface */
	iface_module_constructor();

	/* Create the session, pdr,far,qer and urr tables */
	init_up_hash_tables();

	/* Initialized/Start Pcaps on User-Plane */
	if (app.generate_pcap) {
		up_pcap_init();
	}

	/* Init Downlink data notification ring, container and mempool  */
	dp_ddn_init();

#ifdef USE_REST
	/* Create thread for handling for sending echo req to its peer node */
	rest_thread_init();

	/* DP TEIDRI Timer */
	if(app.teidri_val != 0){
		ret_val = start_dp_teidri_timer();
		if(ret_val == false){
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Unable to start timer for TEIDRI\n", LOG_VALUE);
		}
	}
#endif  /* USE_REST */

#ifdef USE_CSID
	init_fqcsid_hash_tables();
#endif /* USE_CSID */

	packet_framework_launch();

	rte_eal_mp_wait_lcore();

	return 0;
}
