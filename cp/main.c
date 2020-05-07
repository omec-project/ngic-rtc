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
#include <stdio.h>
#include <getopt.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cfgfile.h>

#include "cp.h"
#include "main.h"
#include "cp_app.h"
#include "cp_stats.h"
#include "pfcp_util.h"
#include "sm_struct.h"
#include "cp_config.h"
#include "debug_str.h"
#include "dp_ipc_api.h"
#include "pfcp_set_ie.h"
#include "../pfcp_messages/pfcp.h"


#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

#ifdef USE_DNS_QUERY
#include "cdnshelper.h"
#endif /* USE_DNS_QUERY */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */

#define LOG_LEVEL_SET      (0x0001)

#define REQ_ARGS           (LOG_LEVEL_SET)

//#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

uint32_t start_time;
extern pfcp_config_t pfcp_config;

enum cp_config spgw_cfg;

#ifdef USE_REST
uint32_t up_time = 0;
uint8_t rstCnt = 0;
#endif /* USE_REST*/

#ifdef USE_CSID
uint16_t local_csid = 0;
#endif /* USE_CSID */

struct cp_params cp_params;
extern struct cp_stats_t cp_stats;

int apnidx = 0;
clock_t cp_stats_execution_time;
_timer_t st_time;

/**
 * @brief  : Setting/enable CP RTE LOG_LEVEL.
 * @param  : log_level, log level to be set
 * @return : Returns nothing
 */
static void
set_log_level(uint8_t log_level)
{

/** Note :In dpdk set max log level is INFO, here override the
 *  max value of RTE_LOG_INFO for enable DEBUG logs (dpdk-16.11.4
 *  and dpdk-18.02).
 */
	if (log_level == NGIC_DEBUG)
		rte_log_set_level(RTE_LOGTYPE_CP, RTE_LOG_DEBUG);
	else if (log_level == NOTICE)
		rte_log_set_global_level(RTE_LOG_NOTICE);
	else rte_log_set_global_level(RTE_LOG_INFO);

}

/**
 * @brief  : This function is used to set signal mask
 *           for main thread.This maks will be inherited
 *           by all other threads as default
 * @param  : No param
 * @return : Returns nothing
 */
/*static void
set_signal_mask(void)
{
	sigset_t mask;
	sigset_t orig_mask;

	sigemptyset(&mask);
	sigaddset(&mask,(SIGRTMIN + 1));

	sigprocmask(SIG_BLOCK, &mask, &orig_mask);
}*/

/**
 * @brief  : Parses c-string containing dotted decimal ipv4 and stores the
 *           value within the in_addr type
 * @param  : optarg, c-string containing dotted decimal ipv4 address
 * @param  : addr, destination of parsed IP string
 * @return : Returns nothing
 */
/*
static void
parse_arg_ip(const char *optarg, struct in_addr *addr)
{
	if (!inet_aton(optarg, addr))
		rte_panic("Invalid argument - %s - Exiting.\n", optarg);
}
*/

/**
 *
 * @brief  : Parses non-dpdk command line program arguments for control plane
 * @param  : argc, number of arguments
 * @param  : argv, array of c-string arguments
 * @return : Returns nothing
 */
static void
parse_arg(int argc, char **argv)
{
	char errbuff[PCAP_ERRBUF_SIZE];
	int args_set = 0;
	int c = 0;
	pcap_t *pcap;

	const struct option long_options[] = {
	  {"pcap_file_in", required_argument, NULL, 'x'},
	  {"pcap_file_out", required_argument, NULL, 'y'},
	  {"log_level",   required_argument, NULL, 'z'},
	  {0, 0, 0, 0}
	};

	do {
		int option_index = 0;

		c = getopt_long(argc, argv, "x:y:z:", long_options,
		    &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'x':
			pcap_reader = pcap_open_offline(optarg, errbuff);
			break;
		case 'y':
			pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);
			pcap_dumper = pcap_dump_open(pcap, optarg);
			s11_pcap_fd = pcap_fileno(pcap);
			break;
		case 'z':
			set_log_level((uint8_t)atoi(optarg));
			args_set |= LOG_LEVEL_SET;
			break;
		default:
			rte_panic("Unknown argument - %s.", argv[optind]);
			break;
		}
	} while (c != -1);

	if ((args_set & REQ_ARGS) != REQ_ARGS) {
		clLog(clSystemLog, eCLSeverityCritical, "Usage: %s\n", argv[0]);
		for (c = 0; long_options[c].name; ++c) {
			clLog(clSystemLog, eCLSeverityCritical, "\t[ -%s | -%c ] %s\n",
					long_options[c].name,
					long_options[c].val,
					long_options[c].name);
		}
		rte_panic("\n");
	}
}

#ifndef SDN_ODL_BUILD
/**
 * @brief  : callback initated by nb listener thread
 * @param  : arg, unused
 * @return : never returns
 */
static int
control_plane(void)
{
	iface_init_ipc_node();

	iface_ipc_register_msg_cb(MSG_DDN, cb_ddn);

	while (1) {
		iface_process_ipc_msgs();
	}

	return 0;
}

#endif /* SDN_ODL_BUILD */

/**
 * @brief  : initializes the core assignments for various control plane threads
 * @param  : No param
 * @return : Returns nothing
 */
static void
init_cp_params(void) {
	unsigned last_lcore = rte_get_master_lcore();

	cp_params.stats_core_id = rte_get_next_lcore(last_lcore, 1, 0);
	if (cp_params.stats_core_id == RTE_MAX_LCORE)
		clLog(clSystemLog, eCLSeverityCritical, "Insufficient cores in coremask to "
				"spawn stats thread\n");
	last_lcore = cp_params.stats_core_id;

#ifdef SIMU_CP
	cp_params.simu_core_id = rte_get_next_lcore(last_lcore, 1, 0);
	if (cp_params.simu_core_id == RTE_MAX_LCORE)
		clLog(clSystemLog, eCLSeverityCritical, "Insufficient cores in coremask to "
				"spawn stats thread\n");
	last_lcore = cp_params.simu_core_id;
#endif
}


/**
 * @brief  : Main function - initializes dpdk environment, parses command line arguments,
 *           calls initialization function, and spawns stats and control plane function
 * @param  : argc, number of arguments
 * @param  : argv, array of c-string arguments
 * @return : returns 0
 */
int
main(int argc, char **argv)
{
	int ret;

	//set_signal_mask();

	start_time = current_ntp_timestamp();

#ifdef USE_REST
	/* VS: Set current component start/up time */
	up_time = current_ntp_timestamp();

	/* VS: Increment the restart counter value after starting control plane */
	rstCnt = update_rstCnt();

	TIMER_GET_CURRENT_TP(st_time);
	printf("CP: Control-Plane rstCnt: %u\n", rstCnt);
	recovery_time_into_file(start_time);

#endif /* USE_REST */

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	parse_arg(argc - ret, argv + ret);

	config_cp_ip_port(&pfcp_config);
	/* TODO: REMOVE spgw_cfg */
	spgw_cfg = pfcp_config.cp_type;

	init_cp();
	init_cp_params();

	init_cli_module(pfcp_config.cp_logger);

	/* TODO: Need to Re-arrange the hash initialize */
	create_heartbeat_hash_table();
	create_associated_upf_hash();

	/* Make a connection between control-plane and gx_app */
#ifdef GX_BUILD
	if(pfcp_config.cp_type != SGWC)
		start_cp_app();
#endif

#ifdef SYNC_STATS
	stats_init();
	init_stats_hash();
#endif /* SYNC_STATS */

	if (cp_params.stats_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(do_stats, NULL, cp_params.stats_core_id);

#ifdef SIMU_CP
	if (cp_params.simu_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(simu_cp, NULL, cp_params.simu_core_id);
#endif

#ifdef SDN_ODL_BUILD
	init_nb();
	server();
#endif

#ifdef USE_REST

	/* Create thread for handling for sending echo req to its peer node */
	rest_thread_init();

#endif  /* USE_REST */

	init_pfcp_tables();
	init_sm_hash();

#ifdef USE_CSID
	init_fqcsid_hash_tables();
#endif /* USE_CSID */

	control_plane();

	/* TODO: Move this call in appropriate place */
	/* clear_heartbeat_hash_table(); */
	return 0;
}
