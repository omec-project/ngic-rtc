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

#include <string.h>
#include <sched.h>
#include <unistd.h>

#include <rte_ring.h>
#include <rte_pipeline.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_port_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "stats.h"
#include "up_main.h"
#include "commands.h"
#include "interface.h"
#include "dp_ipc_api.h"
#include "epc_packet_framework.h"
#include "gw_adapter.h"
struct rte_ring *epc_mct_spns_dns_rx;
struct rte_ring *li_dl_ring;
struct rte_ring *li_ul_ring;
struct rte_ring *cdr_pfcp_rpt_req;
extern int clSystemLog;
/**
 * @brief  : Maintains epc parameters
 */
struct epc_app_params epc_app = {
	/* Ports */
	.n_ports = NUM_SPGW_PORTS,

	/* Rings */
	.ring_rx_size = EPC_DEFAULT_RING_SZ,
	.ring_tx_size = EPC_DEFAULT_RING_SZ,

	/* Burst sizes */
	.burst_size_rx_read = EPC_DEFAULT_BURST_SZ,
	.burst_size_rx_write = EPC_BURST_SZ_64,
	.burst_size_worker_read = EPC_DEFAULT_BURST_SZ,
	.burst_size_worker_write = EPC_BURST_SZ_64,
	.burst_size_tx_read = EPC_DEFAULT_BURST_SZ,
	.burst_size_tx_write = EPC_BURST_SZ_64,

	.core_mct = -1,
	.core_iface = -1,
	.core_stats = -1,
	.core_spns_dns = -1,
	.core_ul[S1U_PORT_ID] = -1,
	.core_dl[SGI_PORT_ID] = -1,
#ifdef STATS
	.ul_params[S1U_PORT_ID].pkts_in = 0,
	.ul_params[S1U_PORT_ID].pkts_out = 0,
	.dl_params[SGI_PORT_ID].pkts_in = 0,
	.dl_params[SGI_PORT_ID].pkts_out = 0,
	.dl_params[SGI_PORT_ID].ddn = 0,
	.dl_params[SGI_PORT_ID].ddn_buf_pkts = 0,
#endif
};

/**
 * @brief  : Creats ZMQ read thread , Polls message queue
 *           Populates hash table from que
 * @param  : arg, unused parameter
 * @return : Returns nothing
 */
static void epc_iface_core(__rte_unused void *args)
{
#ifdef SIMU_CP
	static int simu_call;

	if (simu_call == 0) {
		simu_cp();
		simu_call = 1;
	}
#else
	uint32_t lcore;

	lcore = rte_lcore_id();
	clLog(clSystemLog, eCLSeverityMajor,
		LOG_FORMAT"RTE NOTICE enabled on lcore %d\n", LOG_VALUE, lcore);
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"RTE INFO enabled on lcore %d\n", LOG_VALUE, lcore);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"RTE DEBUG enabled on lcore %d\n", LOG_VALUE, lcore);

	/*
	 * Poll message que. Populate hash table from que.
	 */
	while (1) {
		process_dp_msgs();
#ifdef NGCORE_SHRINK
		scan_dns_ring();
#endif
	}
#endif
}

/**
 * @brief  : Initialize epc core
 * @param  : No param
 * @return : Returns nothing
 */
static void epc_init_lcores(void)
{
	epc_alloc_lcore(epc_arp, NULL, epc_app.core_mct);
	epc_alloc_lcore(epc_iface_core, NULL, epc_app.core_iface);

	epc_alloc_lcore(epc_ul, &epc_app.ul_params[S1U_PORT_ID],
						epc_app.core_ul[S1U_PORT_ID]);
	epc_alloc_lcore(epc_dl, &epc_app.dl_params[SGI_PORT_ID],
						epc_app.core_dl[SGI_PORT_ID]);
}

#define for_each_port(port) for (port = 0; port < epc_app.n_ports; port++)
#define for_each_core(core) for (core = 0; core < DP_MAX_LCORE; core++)

/**
 * @brief  : Initialize rings common to all pipelines
 * @param  : No param
 * @return : Returns nothing
 */
static void epc_init_rings(void)
{
	uint32_t port;

	/* Ring for Process Slow Path packets like ICMP, ARP, GTPU-ECHO */
	/* create communication rings between RX-core and mct core */
	for_each_port(port) {
		char name[32];

		snprintf(name, sizeof(name), "rx_to_mct_%u", port);
		epc_app.epc_mct_rx[port] = rte_ring_create(name,
		                epc_app.ring_rx_size,
		                rte_socket_id(),
		                RING_F_SP_ENQ |
		                RING_F_SC_DEQ);
		if (epc_app.epc_mct_rx[port] == NULL)
		        rte_exit(EXIT_FAILURE, LOG_FORMAT"Cannot create RX ring %u\n", LOG_VALUE, port);

		snprintf(name, sizeof(name), "tx_from_mct_%u", port);
	}

	/* Creating UL and DL rings for LI*/
	li_dl_ring = rte_ring_create("LI_DL_RING",
			DL_PKTS_RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (li_dl_ring == NULL)
		rte_panic("Cannot create LI DL ring \n");

	li_ul_ring = rte_ring_create("LI_UL_RING",
			UL_PKTS_RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (li_ul_ring == NULL)
		rte_panic("Cannot create LI UL ring \n");

	/* Creating rings for CDR Report Request*/
	cdr_pfcp_rpt_req = rte_ring_create("CDR_RPT_REQ_RING",
								DL_PKTS_RING_SIZE,
								rte_socket_id(),
								RING_F_SP_ENQ
								|
								RING_F_SC_DEQ);

	if (cdr_pfcp_rpt_req == NULL)
		rte_panic("Cannot create DR_RPT_REQ_RING \n");


}

/**
 * @brief  : Launch epc pipeline
 * @param  : No param
 * @return : Returns nothing
 */
static inline void epc_run_pipeline(void)
{
	struct epc_lcore_config *config;
	int i;
	unsigned lcore;

	lcore = rte_lcore_id();
	config = &epc_app.lcores[lcore];

#ifdef INSTMNT
	uint64_t start_tsc, end_tsc;

	if (lcore == epc_app.worker_cores[0]) {
		for (i = 0; i < config->allocated; i++) {
			start_tsc = rte_rdtsc();
			config->launch[i].func(config->launch[i].arg);
			if (flag_wrkr_update_diff) {
				end_tsc = rte_rdtsc();
				diff_tsc_wrkr += end_tsc - start_tsc;
				flag_wrkr_update_diff = 0;
			}
		}
	} else
#endif
		for (i = 0; i < config->allocated; i++) {
			config->launch[i].func(config->launch[i].arg);
		}
}

/**
 * @brief  : Start epc core
 * @param  : arg, unused parameter
 * @return : Returns 0 in case of success
 */
static int epc_lcore_main_loop(__attribute__ ((unused))
		void *arg)
{
	struct epc_lcore_config *config;
	uint32_t lcore;

	lcore = rte_lcore_id();
	config = &epc_app.lcores[lcore];

	if (config->allocated == 0)
		return 0;

	clLog(clSystemLog, eCLSeverityMajor,
		LOG_FORMAT"RTE NOTICE enabled on lcore %d\n", LOG_VALUE, lcore);
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"RTE INFO enabled on lcore %d\n", LOG_VALUE, lcore);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"RTE DEBUG enabled on lcore %d\n", LOG_VALUE, lcore);

	while (1)
		epc_run_pipeline();

	return 0;
}

void epc_init_packet_framework(uint8_t east_port_id, uint8_t west_port_id)
{
	if (epc_app.n_ports > NUM_SPGW_PORTS) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Number of ports exceeds a configured number %u\n",
			LOG_VALUE, epc_app.n_ports);
		exit(1);
	}
	epc_app.ports[WEST_PORT_ID] = west_port_id;
	epc_app.ports[EAST_PORT_ID] = east_port_id;
	printf("ARP-ICMP Core on:\t\t%d\n", epc_app.core_mct);
	printf("CP-DP IFACE Core on:\t\t%d\n", epc_app.core_iface);
#ifdef NGCORE_SHRINK
	epc_app.core_spns_dns = epc_app.core_iface;
#endif
	printf("SPNS DNS Core on:\t\t%d\n", epc_app.core_spns_dns);
#ifdef STATS
#ifdef NGCORE_SHRINK
	epc_app.core_stats = epc_app.core_mct;
#endif
	printf("STATS-Timer Core on:\t\t%d\n", epc_app.core_stats);
#endif
	/*
	 * Initialize rings
	 */
	epc_init_rings();

	/*
	 * Initialize arp & spns_dns cores
	 */
	epc_arp_init();
	epc_spns_dns_init();

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Uplink Core on:\t\t\t%d\n", LOG_VALUE, epc_app.core_ul[WEST_PORT_ID]);
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"VS- ng-core_shrink:\n\t"
		"epc_ul_init::epc_app.core_ul[WEST_PORT_ID]= %d\n\t"
		"WEST_PORT_ID= %d; EAST_PORT_ID= %d\n",
		LOG_VALUE, epc_app.core_ul[WEST_PORT_ID],
		WEST_PORT_ID, EAST_PORT_ID);

	epc_ul_init(&epc_app.ul_params[WEST_PORT_ID],
				epc_app.core_ul[WEST_PORT_ID],
				WEST_PORT_ID, EAST_PORT_ID);

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Downlink Core on:\t\t%d\n", LOG_VALUE, epc_app.core_dl[EAST_PORT_ID]);
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"VS- ng-core_shrink:\n\t"
		"epc_dl_init::epc_app.core_dl[EAST_PORT_ID]= %d\n\t"
		"EAST_PORT_ID= %d; WEST_PORT_ID= %d\n",
		LOG_VALUE, epc_app.core_dl[EAST_PORT_ID],
		EAST_PORT_ID, WEST_PORT_ID);

	epc_dl_init(&epc_app.dl_params[EAST_PORT_ID],
				epc_app.core_dl[EAST_PORT_ID],
				EAST_PORT_ID, WEST_PORT_ID);

	/*
	 * Assign pipelines to cores
	 */
	epc_init_lcores();

	/* Init IPC msgs */
	iface_init_ipc_node();
}

void packet_framework_launch(void)
{
	if (rte_eal_mp_remote_launch(epc_lcore_main_loop, NULL, CALL_MASTER) < 0)
		rte_exit(EXIT_FAILURE, LOG_FORMAT"MP remote lauch fail !!!\n", LOG_VALUE);
}

void epc_alloc_lcore(pipeline_func_t func, void *arg, int core)
{
	struct epc_lcore_config *lcore;

	if (core >= DP_MAX_LCORE)
		rte_exit(EXIT_FAILURE, LOG_FORMAT" Core %d exceed Max core %d\n", LOG_VALUE, core,
				DP_MAX_LCORE);

	lcore = &epc_app.lcores[core];
	lcore->launch[lcore->allocated].func = func;
	lcore->launch[lcore->allocated].arg = arg;

	lcore->allocated++;
}
