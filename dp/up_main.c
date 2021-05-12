/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

#include "li_interface.h"
#include "gw_adapter.h"

#include "up_main.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"

#include "cstats.h"
#include "predef_rule_init.h"
#include "config_validater.h"
#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */

#define UP "USER PLANE"
#define DP_LOG_PATH "logs/dp.log"
#define LOGGER_JSON_PATH "../config/log.json"

#define DDF2    "DDF2"
#define DDF3    "DDF3"

#define EXIT 0

extern int fd_array_v4[2];
extern int fd_array_v6[2];

uint32_t start_time;
extern struct in_addr cp_comm_ip;
extern struct in_addr dp_comm_ip;
int clSystemLog = STANDARD_LOGID;

#ifdef USE_CSID
uint16_t local_csid = 0;
#endif /* USE_CSID */

/* List of allocated teid ranges*/
teidri_info *upf_teidri_allocated_list = NULL;
/* List of free teid ranges*/
teidri_info *upf_teidri_free_list = NULL;
/* List of blocked teid ranges, needs to release after timer expires*/
teidri_info *upf_teidri_blocked_list = NULL;

/**
 * @brief  : callback
 * @param  : signal
 * @return : never returns
 */
static void
sig_handler(int signo)
{
	deinit_ddf();

	RTE_SET_USED(signo);
	clLog(clSystemLog, eCLSeverityDebug, "UP: Called Signal_handler..\n");

	/* Close the KNI Sockets */
	for (uint8_t inx = 0; inx < 2; inx++) {
		if (fd_array_v4[inx] > 0)
			close(fd_array_v4[inx]);
		if (fd_array_v6[inx] > 0)
			close(fd_array_v6[inx]);
	}
	/* TODO: Cleanup the stored data, and closed the sockets */
	rte_exit(EXIT, "\nExit Gracefully User-plane service...\n");
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

static void
init_cli_framework(void) {
	set_gw_type(OSS_USER_PLANE);
	cli_node.upsecs = &cli_node.cli_config.oss_reset_time;
	cli_init(&cli_node, &cli_node.cli_config.cnt_peer);
	cli_node.cli_config.perf_flag = app.perf_flag;

	cli_node.cli_config.gw_adapter_callback_list.update_periodic_timer = &post_periodic_timer;
	cli_node.cli_config.gw_adapter_callback_list.update_transmit_timer = &post_transmit_timer;
	cli_node.cli_config.gw_adapter_callback_list.update_transmit_count = &post_transmit_count;
	cli_node.cli_config.gw_adapter_callback_list.get_periodic_timer = &get_periodic_timer;
	cli_node.cli_config.gw_adapter_callback_list.get_transmit_timer = &get_transmit_timer;
	cli_node.cli_config.gw_adapter_callback_list.get_transmit_count = get_transmit_count;
	cli_node.cli_config.gw_adapter_callback_list.get_generate_pcap = &get_pcap_status;
	cli_node.cli_config.gw_adapter_callback_list.update_pcap_status = &post_pcap_status;
	cli_node.cli_config.gw_adapter_callback_list.get_dp_config = &fill_dp_configuration;
	cli_node.cli_config.gw_adapter_callback_list.get_perf_flag = &get_perf_flag;
	cli_node.cli_config.gw_adapter_callback_list.update_perf_flag = &update_perf_flag;

	/* Init rest framework */
	init_rest_framework(app.cli_rest_ip_buff, app.cli_rest_port);
}

/**
 * Main function.
 */
int main(int argc, char **argv)
{
	int ret;
	bool ret_val;
	start_time = current_ntp_timestamp();

	/* Precondition for configuration file */
	read_cfg_file(DP_CFG_PATH);

	init_log_module(LOGGER_JSON_PATH);
	init_signal_handler();

#ifdef USE_REST
	/* Write User-plane start time on Disk */
	recovery_time_into_file(start_time);
#endif

	/* Initialize the Environment Abstraction Layer */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* DP restart conter info */
	dp_restart_cntr = get_dp_restart_cntr();

	/* DP Init */
	dp_init(argc, argv);

	init_cli_framework();

	/* TODO: Need to validate LI*/
	/* Create TCP connection between data-plane and d-df2 */
	init_ddf();

	ddf2_fd = create_ddf_tunnel(app.ddf2_ip, app.ddf2_port, app.ddf2_local_ip,
			(const uint8_t *)DDF2);
	if (ddf2_fd == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Unable to connect to DDF2\n", LOG_VALUE);
	}

	/* Create TCP connection between data-plane and d-df3 */
	ddf3_fd = create_ddf_tunnel(app.ddf3_ip, app.ddf3_port, app.ddf3_local_ip,
			(const uint8_t *)DDF3);
	if (ddf3_fd == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Unable to connect to DDF3\n", LOG_VALUE);
	}

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

	init_stats_timer();

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
