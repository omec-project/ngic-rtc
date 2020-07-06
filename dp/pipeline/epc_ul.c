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
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#include <rte_string_fns.h>
#include <rte_ring.h>
#include <rte_pipeline.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>
#include <rte_port_ring.h>
#include <rte_kni.h>
#include <rte_arp.h>
#include <unistd.h>

#include "gtpu.h"
#include "up_main.h"
#include "epc_packet_framework.h"
#include "clogger.h"
#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

/* Borrowed from dpdk ip_frag_internal.c */
#define PRIME_VALUE	0xeaad8405

/* Generate new pcap for s1u port */
#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_west;
extern pcap_dumper_t *pcap_dumper_east;
#endif /* PCAP_GEN */

extern struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

#ifdef TIMER_STATS
#include "perf_timer.h"
extern _timer_t _init_time;
#endif /* TIMER_STATS */
uint32_t ul_nkni_pkts = 0;

#ifdef USE_REST
/**
 * @brief  : Perform lookup for src ip, and set activity flag if connection
 *           is active for uplink
 * @param  : srcIp, Ip address
 * @return : Returns nothing
 */
static inline void check_activity(uint32_t srcIp)
{
	/* VS: TODO */
	int ret = 0;
	peerData *conn_data = NULL;

	ret = rte_hash_lookup_data(conn_hash_handle,
				&srcIp, (void **)&conn_data);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "Entry not found for NODE :%s\n",
							inet_ntoa(*(struct in_addr *)&srcIp));
		return;
	} else {
		clLog(clSystemLog, eCLSeverityDebug, "Recv pkts from NODE :%s\n",
						inet_ntoa(*(struct in_addr *)&srcIp));
		conn_data->activityFlag = 1;
	}
}
#endif /* USE_REST */

/**
 * @brief  : set port id value for uplink
 * @param  : m, rte mbuf pointer
 * @return : Returns nothing
 */
static inline void epc_ul_set_port_id(struct rte_mbuf *m)
{
	uint8_t *m_data = rte_pktmbuf_mtod(m, uint8_t *);
	struct epc_meta_data *meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m,
				META_DATA_OFFSET);
	uint32_t *port_id_offset = &meta_data->port_id;
	uint32_t *ue_ipv4_hash_offset = &meta_data->ue_ipv4_hash;
	struct ipv4_hdr *ipv4_hdr =
		(struct ipv4_hdr *)&m_data[sizeof(struct ether_hdr)];
	struct udp_hdr *udph;
	uint32_t ip_len;
	struct ether_hdr *eh = (struct ether_hdr *)&m_data[0];
	uint32_t ipv4_packet;
	/* Host Order ipv4_hdr->dst_addr */
	uint32_t ho_addr;

	ipv4_packet = (eh->ether_type == htons(ETHER_TYPE_IPv4));


	if (unlikely(
		     (m->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD ||
		     (m->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD)) {
		//clLog(clSystemLog, eCLSeverityCritical, "UL Bad checksum: %lu\n", m->ol_flags);
		//ipv4_packet = 0;
	}
	*port_id_offset = 1;

	/* Flag ARP pkt for linux handling */
	if (eh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP) ||
			ipv4_hdr->next_proto_id == IPPROTO_ICMP)
	{
		clLog(clSystemLog, eCLSeverityDebug, "epc_ul.c:%s::"
				"\n\t@S1U:eh->ether_type==ETHER_TYPE_ARP= 0x%X\n",
				__func__, eh->ether_type);
		ul_arp_pkt = 1;
		return;
	}
	ho_addr = ntohl(ipv4_hdr->dst_addr);
	/* Flag pkt destined to S1U_IP for linux handling */
	if (app.s1u_ip == ho_addr)
	{
		clLog(clSystemLog, eCLSeverityDebug, "epc_ul.c:%s::"
				"\n\t@S1U:app.s1u_ip==ipv4_hdr->dst_addr= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&ho_addr));
		ul_arp_pkt = 1;
		return;
	}
	/* Flag MCAST pkt for linux handling */
	if (IS_IPV4_MCAST(ho_addr))
	{
		clLog(clSystemLog, eCLSeverityDebug, "epc_ul.c:%s::"
				"\n\t@S1U:IPV$_MCAST==ipv4_hdr->dst_addr= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&ho_addr));
		ul_arp_pkt = 1;
		return;
	}
	/* Flag BCAST pkt for linux handling */
	if (app.s1u_bcast_addr == ho_addr)
	{
		clLog(clSystemLog, eCLSeverityDebug, "epc_ul.c:%s::"
				"\n\t@S1U:app.s1u_bcast_addr==ipv4_hdr->dst_addr= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&ho_addr));
		ul_arp_pkt = 1;
		return;
	}

	/* Flag all other pkts for epc_ul proc handling */
	if (likely(ipv4_packet && ipv4_hdr->next_proto_id == IPPROTO_UDP)) {
		ip_len = (ipv4_hdr->version_ihl & 0xf) << 2;
		udph =
			(struct udp_hdr *)&m_data[sizeof(struct ether_hdr) +
			ip_len];
		if (likely(udph->dst_port == UDP_PORT_GTPU_NW_ORDER)) {
#ifdef USE_REST
			/* VS: TODO Set activity flag if data receive from peer node */
			check_activity(ipv4_hdr->src_addr);
#endif /* USE_REST */
			struct gtpu_hdr *gtpuhdr = get_mtogtpu(m);
			if ((gtpuhdr->msgtype == GTPU_ECHO_REQUEST && gtpuhdr->teid == 0) ||
					gtpuhdr->msgtype == GTPU_ECHO_RESPONSE) {
					return;
			} else {
				/* TODO: Inner could be ipv6 ? */
				struct ipv4_hdr *inner_ipv4_hdr =
					(struct ipv4_hdr *)RTE_PTR_ADD(udph,
							UDP_HDR_SIZE +
							sizeof(struct
								gtpu_hdr));
				const uint32_t *p =
					(const uint32_t *)&inner_ipv4_hdr->src_addr;
				clLog(clSystemLog, eCLSeverityDebug, "UL: gtpu packet\n");
				*port_id_offset = 0;
				ul_gtpu_pkt = 1;
				ul_arp_pkt = 0;

#ifdef SKIP_LB_HASH_CRC
				*ue_ipv4_hash_offset = p[0] >> 24;
#else
				*ue_ipv4_hash_offset =
					rte_hash_crc_4byte(p[0], PRIME_VALUE);
#endif
			}
		}
	}
}

/**
 * @brief  : Capture uplink packets
 * @param  : p, rte pipeline pointer
 * @param  : pkts, rte mbuf
 * @param  : n, number of packets
 * @param  : arg, unused parameter
 * @return : Returns nothing
 */
static int epc_ul_port_in_ah(struct rte_pipeline *p,
		struct rte_mbuf **pkts, uint32_t n,
		void *arg)
{
#ifdef TIMER_STATS
	TIMER_GET_CURRENT_TP(_init_time);
#endif /* TIMER_STATS*/

	static uint32_t i;
	RTE_SET_USED(arg);
	RTE_SET_USED(p);
	struct rte_mbuf *kni_pkts_burst[n];

	ul_ndata_pkts = 0;
	ul_nkni_pkts = 0;
	ul_arp_pkt = 0;
	ul_gtpu_pkt = 0;
	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		epc_ul_set_port_id(m);
		if (ul_gtpu_pkt) {
			ul_gtpu_pkt = 0;
			ul_ndata_pkts++;
		} else if(ul_arp_pkt) {
			ul_arp_pkt = 0;
			kni_pkts_burst[ul_nkni_pkts++] = pkts[i];
		}
	}

	if (ul_nkni_pkts) {
		RTE_LOG(DEBUG, DP, "KNI: UL send pkts to kni\n");
		kni_ingress(kni_port_params_array[S1U_PORT_ID],
				kni_pkts_burst, ul_nkni_pkts);
	}

#ifdef STATS
	epc_app.ul_params[S1U_PORT_ID].pkts_in += ul_ndata_pkts;
#endif /* STATS */
	ul_pkts_nbrst++;

/* Capture packets on s1u_port.*/
#ifdef PCAP_GEN
	    dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */
	return 0;
}

static epc_ul_handler epc_ul_worker_func[NUM_SPGW_PORTS];

/**
 * @brief  : Uplink packet handler
 * @param  : p, rte pipeline pointer
 * @param  : pkts, rte mbuf
 * @param  : pkts_mask, packet mask
 * @param  : arg, port number
 * @return : Returns nothing
 */
static inline int epc_ul_port_out_ah(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint64_t pkts_mask, void *arg)
{
	int worker_index = 0, ret = 0;
	RTE_SET_USED(p);
	int portno = (uintptr_t) arg;
	if (ul_pkts_nbrst == ul_pkts_nbrst_prv)	{
		return 0;
	} else if (ul_ndata_pkts)	{
		ul_pkts_nbrst_prv = ul_pkts_nbrst;
		epc_ul_handler f = epc_ul_worker_func[portno];
		/* ASR- NGCORE_SHRINK: worker_index-TBC */
		ret = f(p, pkts, ul_ndata_pkts, worker_index);
	}
#ifdef TIMER_STATS
#ifndef AUTO_ANALYSIS
	ul_stat_info.port_in_out_delta = TIMER_GET_ELAPSED_NS(_init_time);
	/* Export stats into file. */
	ul_timer_stats(ul_ndata_pkts, &ul_stat_info);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * perf_stats.op_time[12] = port_in_out_time */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[12], _init_time, ul_ndata_pkts, 0);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS*/

	return ret;
}

void epc_ul_init(struct epc_ul_params *param, int core, uint8_t in_port_id, uint8_t out_port_id)
{
	struct rte_pipeline *p;
	unsigned i;

	ul_pkts_nbrst = 0;
	ul_pkts_nbrst_prv = 0;

	switch (app.spgw_cfg) {
	    case SGWU:
	        if (in_port_id != app.s5s8_sgwu_port && in_port_id != app.s1u_port)
				rte_exit(EXIT_FAILURE, "Wrong MAC configured for S1U/S5S8_SGWU interface\n");
	        break;

	    case PGWU:
	        if (in_port_id != app.sgi_port && in_port_id != app.s5s8_pgwu_port)
				rte_exit(EXIT_FAILURE, "Wrong MAC configured for S5S8_PGWU/SGI interface\n");
		break;

	    case SAEGWU:
		if (in_port_id != app.sgi_port && in_port_id != app.s1u_port)
				rte_exit(EXIT_FAILURE, "Wrong MAC configured for S1U/SGI interface\n");
		break;

	    default:
	        rte_exit(EXIT_FAILURE, "Invalid DP type(SPGW_CFG).\n");
	}

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "epc_ul_%d", in_port_id);
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;
	param->pipeline_params.offset_port_id = META_DATA_OFFSET;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("%s: Unable to configure the pipeline\n", __func__);

	/* Input port configuration */
	if (rte_eth_dev_socket_id(in_port_id)
			!= (int)lcore_config[core].socket_id) {
		clLog(clSystemLog, eCLSeverityMinor,
				"location of the RX core for port=%d is not optimal\n",
				in_port_id);
		clLog(clSystemLog, eCLSeverityMinor,
				"***** performance may be degradated !!!!! *******\n");
	}

	struct rte_port_ethdev_reader_params port_ethdev_params = {
		.port_id = epc_app.ports[in_port_id],
		.queue_id = 0,
	};

	struct rte_pipeline_port_in_params in_port_params = {
		.ops = &rte_port_ethdev_reader_ops,
		.arg_create = (void *)&port_ethdev_params,
		.burst_size = epc_app.burst_size_rx_read,
	};
	if (in_port_id == S1U_PORT_ID)	{
		in_port_params.f_action = epc_ul_port_in_ah;
		in_port_params.arg_ah = NULL;
	}
	if (rte_pipeline_port_in_create
			(p, &in_port_params, &param->port_in_id))
	{
		rte_panic("%s: Unable to configure input port for port %d\n",
				__func__, in_port_id);
	}

	/* Output port configuration */
	for (i = 0; i < epc_app.n_ports; i++) {
		if (i == 0){
			/* Pipeline driving decapped fast path pkts out the epc_ul core */
			struct rte_port_ethdev_writer_nodrop_params port_ethdev_params =
			{
				.port_id = epc_app.ports[out_port_id],
				.queue_id = 0,
				.tx_burst_sz = epc_app.burst_size_tx_write,
				.n_retries = 0,
			};
			struct rte_pipeline_port_out_params out_port_params =
			{
				.ops = &rte_port_ethdev_writer_nodrop_ops,
				.arg_create = (void *)&port_ethdev_params,
				.f_action = epc_ul_port_out_ah,
				.arg_ah = (void *)(uintptr_t) i,
			};
			if (rte_pipeline_port_out_create
					(p, &out_port_params, &param->port_out_id[i])) {
				rte_panic
					("%s: Unable to configure output port\n"
					 "for ring RX %i\n", __func__, i);
			}
		}
		else {
			/* Pipeline equeueing arp request pkts to epc_mct core ring */
			struct rte_port_ring_writer_params port_ring_params = {
				.tx_burst_sz = epc_app.burst_size_rx_write,
			};

			struct rte_pipeline_port_out_params out_port_params = {
				.ops = &rte_port_ring_writer_ops,
				.arg_create = (void *)&port_ring_params
			};
			port_ring_params.ring = epc_app.epc_mct_rx[in_port_id];
			if (rte_pipeline_port_out_create
					(p, &out_port_params, &param->port_out_id[i])) {
				rte_panic
					("%s: Unable to configure output port\n"
					 "for ring RX %i\n", __func__, i);
			}
		}
	}

	/* table configuration */
	/* Tables */
	{
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops
		};

		if (rte_pipeline_table_create
				(p, &table_params, &param->table_id)) {
			rte_panic("%s: Unable to configure table %u\n",
					__func__, param->table_id);
		}
	}

	if (rte_pipeline_port_in_connect_to_table
			(p, param->port_in_id, param->table_id)) {
		rte_panic("%s: Unable to connect input port %u to table %u\n",
				__func__, param->port_in_id, param->table_id);
	}

	/* Add entries to tables */
	{
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT_META,
		};
		struct rte_pipeline_table_entry *default_entry_ptr;

		int status = rte_pipeline_table_default_entry_add(p,
				param->table_id,
				&default_entry,
				&default_entry_ptr);

		if (status) {
			rte_panic(
					"%s: failed to add table default entry\n",
					__func__);
			rte_pipeline_free(p);
			return;
		}
	}

	/* Enable input ports */
	if (rte_pipeline_port_in_enable(p, param->port_in_id)) {
		rte_panic("%s: unable to enable input port %d\n", __func__,
				param->port_in_id);
	}

	/* set flush option */
	param->flush_max = EPC_PIPELINE_FLUSH_MAX;

	/* Check pipeline consistency */
	if (rte_pipeline_check(p) < 0)
		rte_panic("%s: Pipeline consistency check failed\n", __func__);

	param->pipeline = p;
}

void epc_ul(void *args)
{
	struct epc_ul_params *param = (struct epc_ul_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}

	/** Handle the request mbufs sent from kernel space,
	 *  Then analyzes it and calls the specific actions for the specific requests.
	 *  Finally constructs the response mbuf and puts it back to the resp_q.
	 */
	rte_kni_handle_request(kni_port_params_array[S1U_PORT_ID]->kni[0]);

	uint32_t queued_cnt = rte_ring_count(shared_ring[SGI_PORT_ID]);
	if (queued_cnt) {
		struct rte_mbuf *pkts[queued_cnt];
		uint32_t rx_cnt = rte_ring_dequeue_bulk(shared_ring[SGI_PORT_ID],
				(void**)pkts, queued_cnt, NULL);
		uint32_t pkt_indx = 0;
/* Capture the echo packets.*/
#ifdef PCAP_GEN
		dump_pcap(pkts, rx_cnt, pcap_dumper_east);
#endif /* PCAP_GEN */
		while (rx_cnt) {
			uint16_t pkt_cnt = PKT_BURST_SZ;
			if (rx_cnt < PKT_BURST_SZ)
				pkt_cnt = rx_cnt;
			/* ARP_REQ on SGI direct driven by epc_ul core */
			uint16_t tx_cnt = rte_eth_tx_burst(SGI_PORT_ID,
					0, &pkts[pkt_indx], pkt_cnt);
			rx_cnt -= tx_cnt;
			pkt_indx += tx_cnt;
		}
	}

}

void register_ul_worker(epc_ul_handler f, int port)
{
	epc_ul_worker_func[port] = f;
}

