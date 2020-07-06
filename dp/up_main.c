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
#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */
/**
 * Main function.
 */

uint32_t start_time;
extern struct in_addr cp_comm_ip;

#ifdef USE_CSID
uint16_t local_csid = 0;
#endif /* USE_CSID */

/**
 * Main function.
 */
int main(int argc, char **argv)
{
	int ret;

	start_time = current_ntp_timestamp();

#ifdef USE_REST
	recovery_time_into_file(start_time);
#endif
	/* Initialize the Environment Abstraction Layer */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");
	argc -= ret;
	argv += ret;

	/* DP Init */
	dp_init(argc, argv);

	init_cli_module(app.dp_logger);

#ifndef PERF_TEST
	/* Add support for dpdk-18.02 */
	/* enable DP log level */
	if (app.log_level == NGIC_DEBUG) {
		/*Enable DEBUG log level*/
		rte_log_set_level(RTE_LOGTYPE_DP, RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_KNI, RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_API, RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_EPC, RTE_LOG_DEBUG);
		clLog(clSystemLog, eCLSeverityDebug, "LOG_LEVEL=LOG_DEBUG::"
				"\n\trte_log_get_global_level()= %u\n\n",
				rte_log_get_global_level());
	} else if (app.log_level == NOTICE) {
		/*Enable NOTICE log level*/
		rte_log_set_global_level(RTE_LOG_NOTICE);
		clLog(clSystemLog, eCLSeverityDebug,"LOG_LEVEL=LOG_NOTICE::"
				"\n\trte_log_get_global_level()= %u\n\n",
				rte_log_get_global_level());
	} else {
		/*Enable INFO log level*/
		rte_log_set_global_level(RTE_LOG_INFO);
		clLog(clSystemLog, eCLSeverityDebug,"LOG_LEVEL=LOG_INFO::"
				"\n\trte_log_get_global_level()= %u\n\n",
				rte_log_get_global_level());
	}
#endif

	create_node_id_hash();
	create_heartbeat_hash_table();
	/* Initialize DP PORTS and membufs */
	dp_port_init();

	switch (app.spgw_cfg) {
		case SGWU:
			/**
			 *UE <--S1U-->[SGW]<--S5/8-->[PGW]<--SGi-->
			 */
			clLog(clSystemLog, eCLSeverityInfo, "SPGW_CFG=SGWU::"
					"\n\tWEST_PORT=S1U <> EAST_PORT=S5/S8\n");
			/* Pipeline Init */
			epc_init_packet_framework(app.s5s8_sgwu_port,
					app.s1u_port);
#ifdef NGCORE_SHRINK
			/*S1U port handler*/
			register_ul_worker(s1u_pkt_handler, app.s1u_port);
			/*S5/8 port handler*/
			register_dl_worker(sgw_s5_s8_pkt_handler, app.s5s8_sgwu_port);
#else
			/*S1U port handler*/
			register_worker(s1u_pkt_handler, app.s1u_port);

			/*S5/8 port handler*/
			register_worker(sgw_s5_s8_pkt_handler, app.s5s8_sgwu_port);
#endif	/* NGCORE_SHRINK */
			break;

		case PGWU:
			/**
			 *UE <--S1U-->[SGW]<--S5/8-->[PGW]<--SGi-->
			 */
			clLog(clSystemLog, eCLSeverityInfo, "SPGW_CFG=PGWU::"
					"\n\tWEST_PORT=S5/S8 <> EAST_PORT=SGi\n");
			/* Pipeline Init */
			epc_init_packet_framework(app.sgi_port, app.s5s8_pgwu_port);
#ifdef NGCORE_SHRINK
			/*S5/8 port handler*/
			register_ul_worker(pgw_s5_s8_pkt_handler, app.s5s8_pgwu_port);
			/*SGi port handler*/
			register_dl_worker(sgi_pkt_handler, app.sgi_port);
#else
			/*S5/8 port handler*/
			register_worker(pgw_s5_s8_pkt_handler, app.s5s8_pgwu_port);

			/*SGi port handler*/
			register_worker(sgi_pkt_handler, app.sgi_port);
#endif	/* NGCORE_SHRINK */
			break;

		case SAEGWU:
			/**
			 * UE <--S1U--> [SPGW] <--SGi-->
			 */
			clLog(clSystemLog, eCLSeverityInfo, "SPGW_CFG=SAEGWU::"
					"\n\tWEST_PORT=S1U <> EAST_PORT=SGi\n");
			/* Pipeline Init */
			epc_init_packet_framework(app.sgi_port, app.s1u_port);
#ifdef NGCORE_SHRINK
			/*S1U port handler*/
			register_ul_worker(s1u_pkt_handler, app.s1u_port);
			/*SGi port handler*/
			register_dl_worker(sgi_pkt_handler, app.sgi_port);
#else
			/*S1U port handler*/
			register_worker(s1u_pkt_handler, app.s1u_port);

			/*SGi port handler*/
			register_worker(sgi_pkt_handler, app.sgi_port);
#endif	/* NGCORE_SHRINK */
			break;

		default:
			rte_exit(EXIT_FAILURE, "Invalid DP type(SPGW_CFG).\n");
	}

	iface_module_constructor();

	/* Create the session, pdr,far,qer and urr tables */
	init_up_hash_tables();

#ifdef PCAP_GEN
	up_pcap_init();
#endif /* PCAP_GEN */

	/* VS: Init Downlink data notification ring, container and mempool  */
	dp_ddn_init();

#ifdef USE_REST

	/* VS: Set current component start/up time */
	//up_time = current_ntp_timestamp();

	/* VS: Create thread for handling for sending echo req to its peer node */
	rest_thread_init();

#endif  /* USE_REST */

#ifdef USE_CSID
	init_fqcsid_hash_tables();
#endif /* USE_CSID */

	packet_framework_launch();

	rte_eal_mp_wait_lcore();

	//free_kni_ports();

	return 0;
}
