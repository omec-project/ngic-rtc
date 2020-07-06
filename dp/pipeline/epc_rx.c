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
#include <rte_port_ring.h>

#include "epc_packet_framework.h"
#include "main.h"
#include "gtpu.h"

/**
 * @brief  : Set s1u port id
 * @param  : m, rte mbuf pointer
 * @return : Returns nothing
 */
static inline void epc_s1u_rx_set_port_id(struct rte_mbuf *m)
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

	ipv4_packet = (eh->ether_type == htons(ETHER_TYPE_IPv4));

	if (unlikely(m->ol_flags
		& (PKT_RX_L4_CKSUM_BAD
		| PKT_RX_IP_CKSUM_BAD))) {
		clLog(epclogger, eCLSeverityCritical, "Bad checksum\n");
		ipv4_packet = 0;
	}

	*port_id_offset = 1;

	if (likely(ipv4_packet && ipv4_hdr->next_proto_id == IPPROTO_UDP)) {
		ip_len = (ipv4_hdr->version_ihl & 0xf) << 2;
		udph =
		    (struct udp_hdr *)&m_data[sizeof(struct ether_hdr) +
					      ip_len];
		if (likely(udph->dst_port == htons(2152))) {
			/* TODO: Inner could be ipv6 ? */

			clLog(epclogger, eCLSeverityDebug, "Function:%s::\n\t"
					 "gtpu_hdrsz= %lu\n",
					 __func__, sizeof(struct gtpu_hdr));

			struct ipv4_hdr *inner_ipv4_hdr =
			    (struct ipv4_hdr *)RTE_PTR_ADD(udph,
							   UDP_HDR_SIZE +
							   sizeof(struct
								  gtpu_hdr));

			const uint32_t *p =
			    (const uint32_t *)&inner_ipv4_hdr->src_addr;

			clLog(epclogger, eCLSeverityDebug, "gtpu packet\n");
			*port_id_offset = 0;

			set_ue_ipv4_hash(ue_ipv4_hash_offset, p);
		}
	}
}

/**
 * @brief  : Set s1u port id in action handler
 * @param  : p, rte pipeline pointer
 * @param  : pkts, rte mbuf pointer
 * @param  : n, number of packets
 * @param  : arg, unused parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int epc_s1u_rx_port_in_action_handler(struct rte_pipeline *p,
					struct rte_mbuf **pkts, uint32_t n,
					void *arg)
{
	uint32_t i;

	RTE_SET_USED(arg);
	RTE_SET_USED(p);

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		epc_s1u_rx_set_port_id(m);
	}
	return 0;
}

/**
 * @brief  : Set sgi port id in action handler
 * @param  : m, rte mbuf pointer
 * @return : Returns nothing
 */
static inline void epc_sgi_rx_set_port_id(struct rte_mbuf *m)
{
	uint8_t *m_data = rte_pktmbuf_mtod(m, uint8_t *);
	struct epc_meta_data *meta_data =
	    (struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m,
							META_DATA_OFFSET);
	uint32_t *port_id_offset = &meta_data->port_id;
	uint32_t *ue_ipv4_hash_offset = &meta_data->ue_ipv4_hash;
	struct ipv4_hdr *ipv4_hdr =
	    (struct ipv4_hdr *)&m_data[sizeof(struct ether_hdr)];

	struct ether_hdr *eh = (struct ether_hdr *)&m_data[0];
	uint32_t ipv4_packet;
	int bcast;

	ipv4_packet = (eh->ether_type == htons(ETHER_TYPE_IPv4));
	bcast = is_broadcast_ether_addr(&eh->d_addr);

	if (unlikely(m->ol_flags
		& (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD))) {
		clLog(epclogger, eCLSeverityDebug, "Bad checksum\n");
		/* put packets with bad checksum to kernel */
		ipv4_packet = 0;
	}

	if (app.spgw_cfg == SGWU) {
		*port_id_offset = ipv4_packet &&
				((ipv4_hdr->dst_addr == app.s5s8_sgwu_ip) &&
				 !bcast) ? 0 : 1;
	} else {
		*port_id_offset = ipv4_packet &&
				((ipv4_hdr->dst_addr != app.sgi_ip) &&
				 !bcast) ? 0 : 1;
	}

	if (likely(!*port_id_offset)) {
		const uint32_t *p = (const uint32_t *)&ipv4_hdr->dst_addr;

		clLog(epclogger, eCLSeverityDebug, "SGI packet\n");

		set_ue_ipv4_hash(ue_ipv4_hash_offset, p);
	}
}

/**
 * @brief  : Set sgi port id in action handler
 * @param  : p, rte pipeline pointer
 * @param  : pkts, rte mbuf pointer
 * @param  : n, number of packets
 * @param  : arg, unused parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
epc_sgi_rx_port_in_action_handler(struct rte_pipeline *p,
					struct rte_mbuf **pkts,
					  uint32_t n, void *arg)
{
	uint32_t i;

	RTE_SET_USED(arg);
	RTE_SET_USED(p);
	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		epc_sgi_rx_set_port_id(m);
	}
	return 0;
}

void epc_rx_init(struct epc_rx_params *param, int core, uint8_t port_id)
{
	struct rte_pipeline *p;
	unsigned i;
	uint32_t east_port, west_port;

	switch (app.spgw_cfg) {
		case SGWU:
			if (port_id != app.s5s8_sgwu_port && port_id != app.s1u_port)
				rte_panic("%s: Unknown port no %d", __func__, port_id);
			east_port = app.s5s8_sgwu_port;
			west_port = app.s1u_port;
			break;

		case PGWU:
			if (port_id != app.sgi_port && port_id != app.s5s8_pgwu_port)
				rte_panic("%s: Unknown port no %d", __func__, port_id);
			east_port = app.sgi_port;
			west_port = app.s5s8_pgwu_port;
			break;

		case SAEGWU:
			if (port_id != app.sgi_port && port_id != app.s1u_port)
				rte_panic("%s: Unknown port no %d", __func__, port_id);
			east_port = app.sgi_port;
			west_port = app.s1u_port;
			break;

		default:
			rte_exit(EXIT_FAILURE, "Invalid DP type(SPGW_CFG).\n");
	}

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "epc_rx_%d", port_id);
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;
	param->pipeline_params.offset_port_id = META_DATA_OFFSET;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("%s: Unable to configure the pipeline\n", __func__);

	 /* Input port configuration */
	if (rte_eth_dev_socket_id(port_id)
		!= (int)lcore_config[core].socket_id) {
		clLog(epclogger, eCLSeverityMinor,
			"location of the RX core for port=%d is not optimal\n",
			port_id);
		clLog(epclogger, eCLSeverityMinor,
			"***** performance may be degradated !!!!! *******\n");
	}

	struct rte_port_ethdev_reader_params port_ethdev_params = {
		.port_id = epc_app.ports[port_id],
		.queue_id = 0,
	};

	struct rte_pipeline_port_in_params port_params = {
		.ops = &rte_port_ethdev_reader_ops,
		.arg_create = (void *)&port_ethdev_params,
		.burst_size = epc_app.burst_size_rx_read,
	};

	if (port_id == west_port)
		port_params.f_action = epc_s1u_rx_port_in_action_handler;
	else if (port_id == east_port)
		port_params.f_action = epc_sgi_rx_port_in_action_handler;

	if (rte_pipeline_port_in_create(p, &port_params, &param->port_in_id)) {
		rte_panic("%s: Unable to configure input port for port %d\n",
			  __func__, port_id);
	}

	/* Output port configuration */
	for (i = 0; i < NUM_SPGW_PORTS; i++) {
		struct rte_port_ring_writer_params port_ring_params = {
			.tx_burst_sz = epc_app.burst_size_rx_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *)&port_ring_params
		};

		if (i == 0)
			port_ring_params.ring = epc_app.epc_lb_rx[port_id];
		else
			port_ring_params.ring = epc_app.epc_mct_rx[port_id];

		if (rte_pipeline_port_out_create
		    (p, &port_params, &param->port_out_id[i])) {
			rte_panic
			    ("%s: Unable to configure output port\n"
				"for ring RX %i\n", __func__, i);
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

	if (rte_pipeline_port_in_enable(p, param->port_in_id)) {
		rte_panic("%s: unable to enable input port %d\n", __func__,
			  param->port_in_id);
	}

	param->flush_max = EPC_PIPELINE_FLUSH_MAX;

	if (rte_pipeline_check(p) < 0)
		rte_panic("%s: Pipeline consistency check failed\n", __func__);

	param->pipeline = p;
}

void epc_rx(void *args)
{
	struct epc_rx_params *param = (struct epc_rx_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}
}
