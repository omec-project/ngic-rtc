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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include <sponsdn.h>

#include "up_main.h"
#include "clogger.h"

#define NB_CORE_MSGBUF 10000
#define MAX_NAME_LEN    32
static struct rte_mempool *message_pool;
extern struct rte_ring *epc_mct_spns_dns_rx;
uint64_t num_dns_processed;

void epc_spns_dns_init(void)
{
	 message_pool = rte_pktmbuf_pool_create("ms_msg_pool",
						NB_CORE_MSGBUF, 32, 0,
						RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());
	if (message_pool == NULL)
		rte_exit(EXIT_FAILURE, "Create msg mempool failed\n");
}

int push_dns_ring(struct rte_mbuf *pkts)
{
	void *msg;
	int ret;

	if (epc_mct_spns_dns_rx == NULL)
		return -1;

	msg = (void *)rte_pktmbuf_clone(pkts, message_pool);
	if (msg == NULL) {
		clLog(clSystemLog, eCLSeverityDebug, "Error to get message buffer\n");
		return -1;
	}

	ret = rte_ring_mp_enqueue(epc_mct_spns_dns_rx, (void *)msg);
	if (ret != 0) {
		clLog(clSystemLog, eCLSeverityDebug, "DNS ring: error enqueuing\n");
		rte_pktmbuf_free(msg);
		return -1;
	}
	return 0;
}

#ifdef NGCORE_SHRINK
void scan_dns_ring(void)
#else
void scan_dns_ring(__rte_unused void *args)
#endif
{
	void *msg;
	int ret;
	int i;

	if (epc_mct_spns_dns_rx == NULL)
		return;
	ret = rte_ring_sc_dequeue(epc_mct_spns_dns_rx, &msg);
	if (ret == 0) {
		/* DNSTODO: IP header with options */
		unsigned dns_payload_off =
			sizeof(struct ether_hdr) +
			sizeof(struct ipv4_hdr) +
			sizeof(struct udp_hdr);
		int addr4_cnt;
		struct in_addr addr4[100];
		unsigned match_id;
		struct rte_mbuf *pkts = (struct rte_mbuf *)msg;

		epc_sponsdn_scan(rte_pktmbuf_mtod(pkts, char *) + dns_payload_off,
				rte_pktmbuf_data_len(pkts) - dns_payload_off,
				NULL,
				&match_id,
				addr4,
				&addr4_cnt,
				NULL,
				NULL,
				NULL);
		++num_dns_processed;

		for (i = 0; i < addr4_cnt; ++i) {
			//struct msg_adc msg = { .ipv4 = addr4[i].s_addr, .rule_id = match_id };

			clLog(clSystemLog, eCLSeverityDebug, "adding a rule with IP: %s, rule id %d\n",
					inet_ntoa(addr4[i]), match_id);
			//adc_dns_entry_add(&msg);
		}
		rte_pktmbuf_free(msg);
	}
}
