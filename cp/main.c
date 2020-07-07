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
#include "gw_adapter.h"
#include "li_config.h"
#include "tcp_client.h"
#include "cdnshelper.h"
#include "ipc_api.h"
#include "predef_rule_init.h"

#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */


//#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

extern int ddf2_fd;
uint32_t li_seq_no;
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

extern int gx_app_sock_read;
extern int route_sock;
int route_sock = -1;
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Usage: %s\n", LOG_VALUE, argv[0]);
		for (c = 0; long_options[c].name; ++c) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"\t[ -%s | -%c ] %s\n", LOG_VALUE,
					long_options[c].name,
					long_options[c].val,
					long_options[c].name);
		}
		rte_panic("\n");
	}
}

/**
 * @brief  : change the byte order of control plane ip addresses
 * @param  : arg, unused
 * @return : never returns
 */
static void change_byte_order(void)
{
	cp_configuration.ip_byte_order_changed = PRESENT;
	pfcp_config.s11_ip.s_addr = ntohl(pfcp_config.s11_ip.s_addr);
	pfcp_config.s5s8_ip.s_addr = ntohl(pfcp_config.s5s8_ip.s_addr);
	pfcp_config.pfcp_ip.s_addr = ntohl(pfcp_config.pfcp_ip.s_addr);
}

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
		process_cp_msgs();
	}

	return 0;
}

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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Insufficient cores in coremask to "
				"spawn stats thread\n", LOG_VALUE);
	last_lcore = cp_params.stats_core_id;

#ifdef SIMU_CP
	cp_params.simu_core_id = rte_get_next_lcore(last_lcore, 1, 0);
	if (cp_params.simu_core_id == RTE_MAX_LCORE)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Insufficient cores in coremask to "
				"spawn stats thread\n", LOG_VALUE);
	last_lcore = cp_params.simu_core_id;
#endif
}

void cp_sig_handler(int signo)
{
		if (signo == SIGINT) {

			if ((pfcp_config.use_gx) && gx_app_sock_read > 0)
				close_ipc_channel(gx_app_sock_read);

#ifdef SYNC_STATS
			retrive_stats_entry();
			close_stats();
#endif /* SYNC_STATS */

#ifdef USE_REST
			gst_deinit();
#endif /* USE_REST */

		close(route_sock);
		rte_exit(EXIT_SUCCESS, "received SIGINT\n");
		}
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
	uint16_t uiLiCntr = 0;
	struct li_df_config_t li_df_config[LI_MAX_SIZE];

	//set_signal_mask();

	start_time = current_ntp_timestamp();

#ifdef USE_REST
	/* Set current component start/up time */
	up_time = current_ntp_timestamp();

	/* Increment the restart counter value after starting control plane */
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

	init_cp();
	init_cp_params();

	number_of_transmit_count = pfcp_config.transmit_cnt;
	number_of_request_tries = pfcp_config.request_tries;
	transmit_timer_value = pfcp_config.transmit_timer;
	periodic_timer_value = pfcp_config.periodic_timer;
	request_timeout_value = pfcp_config.request_timeout;

	init_cli_module(pfcp_config.cp_logger);

	if (pfcp_config.cp_type != SGWC) {
		/* Create and initialize the tables to maintain the predefined rules info*/
		init_predef_rule_hash_tables();
		/* Init rule tables of user-plane */
		init_dp_rule_tables();
	}

	if (pfcp_config.cp_type == SGWC &&
			pfcp_config.generate_sgw_cdr) {
		init_redis();
	} else if(pfcp_config.cp_type != SGWC &&
					pfcp_config.generate_cdr){
		init_redis();
	}

	ret = registerCpOnDadmf(pfcp_config.dadmf_ip,
			pfcp_config.dadmf_port, pfcp_config.pfcp_ip,
			li_df_config, &uiLiCntr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Failed to register Control Plane on D-ADMF");
	}

	ret = fillup_li_df_hash(li_df_config, uiLiCntr);
	if (ret != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Failed to fillup LI hash");
	}

	/* Create TCP connection between control-plane and d-df2 */
	ddf2_fd = create_ddf_tunnel(pfcp_config.ddf2_ip.s_addr,
			pfcp_config.ddf2_port, pfcp_config.ddf2_intfc);
	if (ddf2_fd < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Failed to create tcp connection between Control Plane and D-DF2");
	}

	/* TODO: Need to Re-arrange the hash initialize */
	create_heartbeat_hash_table();
	create_associated_upf_hash();

	/* Make a connection between control-plane and gx_app */
	if((pfcp_config.use_gx) && pfcp_config.cp_type != SGWC)
		start_cp_app();

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

#ifdef USE_REST

	/* Create thread for handling for sending echo req to its peer node */
	rest_thread_init();

#endif  /* USE_REST */

	init_pfcp_tables();
	init_sm_hash();

#ifdef USE_CSID
	init_fqcsid_hash_tables();
#endif /* USE_CSID */

	recovery_flag = 0;

	change_byte_order();

	control_plane();

	/* TODO: Move this call in appropriate place */
	/* clear_heartbeat_hash_table(); */
	return 0;
}
