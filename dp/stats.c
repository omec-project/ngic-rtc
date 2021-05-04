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
#include "gw_adapter.h"
#include "epc_packet_framework.h"


/**
 * @brief  : Maintains uplink packet data
 */
struct ul_pkt_struct {
	uint64_t IfPKTS;
	uint64_t IfMisPKTS;
	uint64_t ULRX;
	uint64_t iLBRNG;
	uint64_t oLBRNG;
	uint64_t iWKRNG;
	uint64_t iTXRNG;
	uint64_t ULTX;
	uint64_t GTP_ECHO;
	uint64_t RS_RX;
	uint64_t RS_TX;
};

/**
 * @brief  : Maintains downlink packet data
 */
struct dl_pkt_struct {
	uint64_t IfPKTS;
	uint64_t IfMisPKTS;
	uint64_t DLRX;
	uint64_t iLBRNG;
	uint64_t oLBRNG;
	uint64_t iWKRNG;
	uint64_t iTXRNG;
	uint64_t DLTX;
	uint64_t ddn_req;
	uint64_t ddn_pkts;
};

struct ul_pkt_struct ul_param = { 0 };
struct dl_pkt_struct dl_param = { 0 };
uint8_t cnt = 0;
extern int clSystemLog;
#ifdef STATS

void
print_headers(void)
{
	printf("\n\n");
	printf("%s\n", "##NGCORE_SHRINK(RTC)");

#ifdef EXSTATS
	printf("%30s %32s %24s\n", "UPLINK", "||", "DOWNLINK");
	printf("%9s %9s %9s %9s %9s %9s %4s %9s %9s %9s %9s %9s \n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "GTP-ECHO", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF");
#else
#if DEBUG_DDN
	printf("%24s %29s %24s\n", "UPLINK", "||", "DOWNLINK");
	printf("%9s %9s %9s %9s %9s %4s %9s %9s %9s %9s %9s %9s  %9s\n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF", "DDN", "DDN_BUF_PKTS");
#else
#ifdef DEBUG_RS_MSG
	printf("%30s %33s %30s\n", "UPLINK", "||", "DOWNLINK");
	printf("%9s %9s %9s %9s %9s %9s %4s %9s %9s %9s %9s %9s %9s \n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "RS-RX", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF", "RS-TX");
#else
	printf("%24s %29s %24s\n", "UPLINK", "||", "DOWNLINK");
	printf("%9s %9s %9s %9s %9s %4s %9s %9s %9s %9s %9s \n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF");
#endif /* DEBUG_RS_MSG */
#endif /* DEBUG_DDN */
#endif /* EXSTATS */
}

void
display_stats(void)
{
#ifdef EXSTATS
	printf("%9lu %9lu %9lu %9lu %9lu %9lu %4s %9lu %9lu %9lu %9lu %9lu \n",
			ul_param.IfMisPKTS, ul_param.IfPKTS, ul_param.ULRX, ul_param.ULTX,
			(ul_param.ULRX - ul_param.ULTX), ul_param.GTP_ECHO,  "||",
			dl_param.IfMisPKTS, dl_param.IfPKTS, dl_param.DLRX, dl_param.DLTX,
			(dl_param.DLRX - dl_param.DLTX));
#else
#if DEBUG_DDN
	printf("%9lu %9lu %9lu %9lu %9lu %4s %9lu %9lu %9lu %9lu %9lu %9lu %9lu\n",
			ul_param.IfMisPKTS, ul_param.IfPKTS, ul_param.ULRX, ul_param.ULTX,
			(ul_param.ULRX - ul_param.ULTX), "||",
			dl_param.IfMisPKTS, dl_param.IfPKTS, dl_param.DLRX, dl_param.DLTX,
			(dl_param.DLRX - dl_param.DLTX), dl_param.ddn_req, dl_param.ddn_pkts);
#else
#ifdef DEBUG_RS_MSG
	printf("%9lu %9lu %9lu %9lu %9lu %9lu %4s %9lu %9lu %9lu %9lu %9lu %9lu\n",
			ul_param.IfMisPKTS, ul_param.IfPKTS, ul_param.ULRX, ul_param.ULTX,
			(ul_param.ULRX - ul_param.ULTX), ul_param.RS_RX, "||",
			dl_param.IfMisPKTS, dl_param.IfPKTS, dl_param.DLRX, dl_param.DLTX,
			(dl_param.DLRX - dl_param.DLTX), ul_param.RS_TX);
#else
	printf("%9lu %9lu %9lu %9lu %9lu %4s %9lu %9lu %9lu %9lu %9lu \n",
			ul_param.IfMisPKTS, ul_param.IfPKTS, ul_param.ULRX, ul_param.ULTX,
			(ul_param.ULRX - ul_param.ULTX), "||",
			dl_param.IfMisPKTS, dl_param.IfPKTS, dl_param.DLRX, dl_param.DLTX,
			(dl_param.DLRX - dl_param.DLTX));
#endif /* DEBUG_RS_MSG */
#endif /* DEBUG_DDN */
#endif /* EXSTATS */
}

void
pip_istats(struct rte_pipeline *p, char *name, uint8_t port_id, struct rte_pipeline_port_in_stats *istats)
{
	int status;
#ifdef STATS_CLR
	/* set clear bit */
	status = rte_pipeline_port_in_stats_read(p, port_id, istats, 1);
#else
	status = rte_pipeline_port_in_stats_read(p, port_id, istats, 0);
#endif /* STATS_CLR*/
	if (status != 0)
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT" Stats Read Error\n", LOG_VALUE);

}

void
pipeline_in_stats(void)
{
	ul_param.ULRX = epc_app.ul_params[S1U_PORT_ID].pkts_in;
	ul_param.RS_RX = epc_app.ul_params[S1U_PORT_ID].pkts_rs_in;
	dl_param.DLRX = epc_app.dl_params[SGI_PORT_ID].pkts_in;
	dl_param.ddn_req = epc_app.dl_params[SGI_PORT_ID].ddn;
	dl_param.ddn_pkts = epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#ifdef EXSTATS
	ul_param.GTP_ECHO = epc_app.ul_params[S1U_PORT_ID].pkts_echo;
#endif /* EXSTATS */
}

void
pip_ostats(struct rte_pipeline *p, char *name, uint8_t port_id, struct rte_pipeline_port_out_stats *ostats)
{
	int status;

	status = rte_pipeline_port_out_stats_read(p, port_id, ostats, 0);
	if (status != 0)
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT" Stats Read Error\n",LOG_VALUE);
}

void
pipeline_out_stats(void)
{
	ul_param.ULTX = epc_app.ul_params[S1U_PORT_ID].pkts_out;
	ul_param.RS_TX = epc_app.ul_params[S1U_PORT_ID].pkts_rs_out;
	dl_param.DLTX = epc_app.dl_params[SGI_PORT_ID].pkts_out;

}

void
nic_in_stats(void)
{
	int ret = 0;
	struct rte_eth_stats stats0 = {0};
	struct rte_eth_stats stats1 = {0};

	/* UPLINK: Get/Read the NIC/Iface stats */
	ret = rte_eth_stats_get(app.wb_port, &stats0);
	if (ret != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"UPLINK: Packets are not read from UL PORT\n", LOG_VALUE);
	}

	/* DOWNLINK: Get/Read the NIC/Iface stats */
	ret = rte_eth_stats_get(app.eb_port, &stats1);
	if (ret != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"DOWNLINK: Packets are not read from DL PORT\n", LOG_VALUE);
	}

	{
		ul_param.IfPKTS = stats0.ipackets;
		ul_param.IfMisPKTS = stats0.imissed;

	}
	{
		dl_param.IfPKTS = stats1.ipackets;
		dl_param.IfMisPKTS = stats1.imissed;

	}

#ifdef STATS_CLR
	rte_eth_stats_reset(app.wb_port);
	rte_eth_stats_reset(app.eb_port);
#endif /* STATS_CLR */
}

#endif /*STATS*/

#ifndef CMDLINE_STATS
/**
 * @brief  : Timer callback
 * @param  : time, timer value, unused param
 * @param  : arg, unused param
 * @return : Returns nothing
 */
static void timer_cb(__attribute__ ((unused))
		struct rte_timer *tim, __attribute__ ((unused))void *arg)
{
	static unsigned counter;

#ifdef STATS
	nic_in_stats();

	pipeline_in_stats();

	pipeline_out_stats();

	if(cnt == 0 || cnt == 20) {
		print_headers();
		if(cnt == 20)
			cnt=1;
	}
	display_stats();
	cnt++;

#endif /* STATS */
	/* this timer is automatically reloaded until we decide to
	 * stop it, when counter reaches 500. */
	if ((counter++) == 500) {
		/* rte_timer_stop(tim); */
	}

	/* CLI counter */
	cli_node.cli_config.oss_reset_time++;

}
#endif


#define TIMER_RESOLUTION_CYCLES 20000000ULL	/* around 10ms at 2 Ghz */
#define TIMER_INTERVAL 1 /* sec */

#ifndef CMDLINE_STATS
static struct rte_timer timer0;
uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
#endif

void epc_stats_core(void)
{

#ifdef CMDLINE_STATS
	struct cmdline *cl = NULL;
	int status;
	static int cmd_ready;

	if (cmd_ready == 0) {
		cl = cmdline_stdin_new(main_ctx, "vepc>");
		if (cl == NULL)
			rte_panic("Cannot create cmdline instance\n");
		cmdline_interact(cl);
		cmd_ready = 1;
	}

	status = cmdline_poll(cl);
	if (status < 0)
		rte_panic("CLI poll error (%" PRId32 ")\n", status);
	else if (status == RDLINE_EXITED) {
		cmdline_stdin_exit(cl);
		rte_exit(0, NULL);
	}

#else
	/* init timer structures */
	static uint8_t start_timer = 1;
	/* For NGCORE_SHRINK version, this function would be invoked in an
	 * infinite loop. Initialize timer parameters only once */
	if (start_timer == 1) {
		rte_timer_init(&timer0);

		/* load timer0, every second, on master lcore, reloaded automatically */
		uint64_t hz = rte_get_timer_hz();
		unsigned lcore_id = rte_lcore_id();
		rte_timer_reset(&timer0, hz * TIMER_INTERVAL, PERIODICAL, lcore_id,
				timer_cb, NULL);
		start_timer = 0;
	}
	cur_tsc = rte_rdtsc();
	diff_tsc = cur_tsc - prev_tsc;
	if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
		rte_timer_manage();
		prev_tsc = cur_tsc;
	}
#endif
}
