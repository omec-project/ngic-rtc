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
#include "li_interface.h"
#include "gw_adapter.h"
#include "li_config.h"
#include "cdnshelper.h"
#include "ipc_api.h"
#include "predef_rule_init.h"
#include "redis_client.h"
#include "config_validater.h"
#ifdef USE_REST
#include "ngic_timer.h"
#endif /* USE_REST */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */


//#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4
#define CP "CONTROL PLANE"
#define CP_LOG_PATH "logs/cp.log"
#define LOGGER_JSON_PATH "../config/log.json"
#define DDF2    "DDF2"

extern void *ddf2_fd;
uint32_t li_seq_no;
uint32_t start_time;
extern pfcp_config_t config;
extern uint8_t gw_type;
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

int clSystemLog = STANDARD_LOGID;
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
 * @brief  : callback
 * @param  : signal
 * @return : never returns
 */
static void
sig_handler(int signo)
{
	RTE_SET_USED(signo);
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"signal_handler \n");
}

/**
 * @brief  : init signals
 * @param  : void
 * @return : never returns
 */
static void
init_signal_handler(void)
{
	{
		sigset_t sigset;
		/* mask SIGALRM in all threads by default */
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGRTMIN);
		sigaddset(&sigset, SIGRTMIN + 2);
		sigaddset(&sigset, SIGRTMIN + 3);
		sigaddset(&sigset, SIGUSR1);
		sigprocmask(SIG_BLOCK, &sigset, NULL);
	}

	struct sigaction sa;

	/* Setup the signal handler */
	sa.sa_handler = sig_handler;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) == -1) {}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {}
	if (sigaction(SIGRTMIN+1, &sa, NULL) == -1) {}


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

		/*Close connection to redis server*/
		if ( ctx != NULL)
			redis_disconnect(ctx);

		if ((config.use_gx) && gx_app_sock_read > 0)
			close_ipc_channel(gx_app_sock_read);

		deinit_ddf();

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

static void
init_cli_framework(void) {
	set_gw_type(OSS_CONTROL_PLANE);
	cli_node.upsecs = &cli_node.cli_config.oss_reset_time;
	cli_init(&cli_node, &cli_node.cli_config.cnt_peer);

	cli_node.cli_config.gw_adapter_callback_list.update_request_tries = &post_request_tries;
	cli_node.cli_config.gw_adapter_callback_list.update_request_timeout = &post_request_timeout;
	cli_node.cli_config.gw_adapter_callback_list.update_periodic_timer = &post_periodic_timer;
	cli_node.cli_config.gw_adapter_callback_list.update_transmit_timer = &post_transmit_timer;
	cli_node.cli_config.gw_adapter_callback_list.update_transmit_count = &post_transmit_count;
	cli_node.cli_config.gw_adapter_callback_list.get_request_tries = &get_request_tries;
	cli_node.cli_config.gw_adapter_callback_list.get_request_timeout = &get_request_timeout;
	cli_node.cli_config.gw_adapter_callback_list.get_periodic_timer = &get_periodic_timer;
	cli_node.cli_config.gw_adapter_callback_list.get_transmit_timer = &get_transmit_timer;
	cli_node.cli_config.gw_adapter_callback_list.get_transmit_count = get_transmit_count;
	cli_node.cli_config.gw_adapter_callback_list.get_cp_config = &fill_cp_configuration;
	cli_node.cli_config.gw_adapter_callback_list.add_ue_entry = &fillup_li_df_hash;
	cli_node.cli_config.gw_adapter_callback_list.update_ue_entry = &fillup_li_df_hash;
	cli_node.cli_config.gw_adapter_callback_list.delete_ue_entry = &del_li_entry;

	/* Init rest framework */
	init_rest_framework(config.cli_rest_ip_buff, config.cli_rest_port);

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

	/* Precondition for configuration file */
	read_cfg_file(CP_CFG_PATH);

	init_log_module(LOGGER_JSON_PATH);
	init_signal_handler();

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

	config_cp_ip_port(&config);
	init_cli_framework();

	init_cp();
	init_cp_params();

	if (config.cp_type != SGWC) {
		/* Create and initialize the tables to maintain the predefined rules info*/
		init_predef_rule_hash_tables();
		/* Init rule tables of user-plane */
		init_dp_rule_tables();
	}

	if (config.cp_type == SGWC &&
			config.generate_sgw_cdr) {
		init_redis();
	} else if(config.cp_type != SGWC &&
					config.generate_cdr){
		init_redis();
	}

	ret = registerCpOnDadmf(config.dadmf_ip,
			config.dadmf_port, config.dadmf_local_addr,
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
	init_ddf();

	ddf2_fd = create_ddf_tunnel(config.ddf2_ip,
			config.ddf2_port, config.ddf2_local_ip, (const uint8_t *)DDF2);
	if (ddf2_fd == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Failed to create tcp connection between Control Plane and D-DF2");
	}

	/* TODO: Need to Re-arrange the hash initialize */
	create_heartbeat_hash_table();
	create_associated_upf_hash();

	/* Make a connection between control-plane and gx_app */
	if((config.use_gx) && config.cp_type != SGWC) {
		start_cp_app();
		fill_gx_iface_ip();
	}

#ifdef SYNC_STATS
	stats_init();
	init_stats_hash();
#endif /* SYNC_STATS */

	init_stats_timer();

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

	control_plane();

	/* TODO: Move this call in appropriate place */
	/* clear_heartbeat_hash_table(); */
	return 0;
}
