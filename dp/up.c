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

#include <arpa/inet.h>
#include <pcap.h>
#include <rte_ip.h>
#include <sponsdn.h>
#include <stdbool.h>
#include <rte_errno.h>
#include <rte_cycles.h>
#include <rte_ip_frag.h>

#include "up_main.h"
#include "gtpu.h"
#include "ipv4.h"
#include "util.h"
#include "up_acl.h"
#include "clogger.h"
#include "up_ether.h"
#include "pfcp_util.h"
#include "interface.h"
#include "gw_adapter.h"
#include "epc_packet_framework.h"

pcap_dumper_t *pcap_dumper_east;
pcap_dumper_t *pcap_dumper_west;

void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *decap_pkts_mask)
{
	uint32_t i;
	int ret = 0;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct gtpu_hdr *gtpu_hdr;
	struct epc_meta_data *meta_data;

	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*decap_pkts_mask, i))
			continue;

		/* reject if not with s1u/logical intf ip */
		ipv4_hdr = get_mtoip(pkts[i]);
		uint32_t ip = 0; //GCC_Security flag
		uint32_t ip_li = 0; //GCC_Security flag

		/* Uplink IP Address */
		ip = ntohl(app.wb_ip);
		ip_li = ntohl(app.wb_li_ip);

		if ((ipv4_hdr->dst_addr != ip) && (ipv4_hdr->dst_addr != ip_li)) {
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		/* reject un-tunneled packet */
		udp_hdr = get_mtoudp(pkts[i]);
		if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		gtpu_hdr = get_mtogtpu(pkts[i]);
		if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
#ifdef STATS
			--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#ifdef EXSTATS
			++epc_app.ul_params[S1U_PORT_ID].pkts_echo;
#endif /* EXSTATS */
#endif /* STATS */
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[i],
						META_DATA_OFFSET);
		meta_data->teid = ntohl(gtpu_hdr->teid);
		meta_data->enb_ipv4 = ntohl(ipv4_hdr->src_addr);
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Received tunneled packet with teid 0x%X\n",
			LOG_VALUE, ntohl(meta_data->teid));
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"From UE IP " IPV4_ADDR "\n",
				LOG_VALUE, IPV4_ADDR_FORMAT(GTPU_INNER_SRC_IP(pkts[i])));

		ret = DECAP_GTPU_HDR(pkts[i]);

		if (ret < 0){
			RESET_BIT(*pkts_mask, i);
#ifdef STATS
			--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#endif /* STATS */
		}
	}
}

void
gtpu_encap(pdr_info_t **pdrs, pfcp_session_datat_t **sess_data, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, uint64_t *fd_pkts_mask, uint64_t *pkts_queue_mask)
{
	uint16_t len = 0;
	uint32_t i = 0;
	uint32_t src_addr = 0;
	uint32_t dst_addr = 0;
	pdr_info_t *pdr = NULL;
	far_info_t *far = NULL;
	struct rte_mbuf *m = NULL;
	pfcp_session_datat_t *si = NULL;

	for (i = 0; i < n; i++) {
		si = sess_data[i];
		pdr = pdrs[i];
		m = pkts[i];

		if (!ISSET_BIT(*fd_pkts_mask, i)) {
			continue;
		}

		if (!ISSET_BIT(*pkts_mask, i)) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			continue;
		}

		if (si == NULL) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Session Data is NULL\n", LOG_VALUE);
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		if (pdr == NULL) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"PDR INFO IS NULL\n", LOG_VALUE);
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		/* If Pdr value is not NULL */
		far = pdr->far;

		if (far == NULL) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"FAR INFO IS NULL\n", LOG_VALUE);
			RESET_BIT(*pkts_mask, i);
			continue;
		}
/** Check downlink bearer is ACTIVE or IDLE */
		if (si->sess_state != CONNECTED) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Session State is NOT CONNECTED\n", LOG_VALUE);
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}

		if (!far->actions.forw) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Action is NOT set to FORW,"
				" PDR_ID:%u, FAR_ID:%u\n",
				LOG_VALUE, pdr->rule_id, far->far_id_value);
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}

		if (!far->frwdng_parms.outer_hdr_creation.teid) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Next hop teid is NULL: "
				" PDR_ID:%u, FAR_ID:%u\n",
				LOG_VALUE, pdr->rule_id, far->far_id_value);
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}

		if (ENCAP_GTPU_HDR(m, (pdr->far)->frwdng_parms.outer_hdr_creation.teid) < 0) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to ENCAP GTPU HEADER \n", LOG_VALUE);
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		len = rte_pktmbuf_data_len(m);
		len = len - ETH_HDR_SIZE;

		/* construct iphdr with destination IP Address */
		dst_addr = (pdr->far)->frwdng_parms.outer_hdr_creation.ipv4_address;

		/* Validate the Destination IP Address subnet */
		if (validate_Subnet(dst_addr, app.wb_net, app.wb_bcast_addr)) {
			/* construct iphdr with local IP Address */
			src_addr = app.wb_ip;
		} else if (validate_Subnet(dst_addr, app.wb_li_net, app.wb_li_bcast_addr)) {
			/* construct iphdr with local IP Address */
			src_addr = app.wb_li_ip;
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Destination IPv4 Addr "IPV4_ADDR" is NOT in local intf subnet\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dst_addr));
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		/* Check SRC or DST Address are not Zero */
		if ((!src_addr) || (!dst_addr)) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Not Found Src or Dest IPv4 Addr, SrcAddr: "IPV4_ADDR", DstAddr: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(src_addr), IPV4_ADDR_HOST_FORMAT(dst_addr));
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"IPv4 hdr: SRC ADDR:"IPV4_ADDR", DST ADDR:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(src_addr), IPV4_ADDR_HOST_FORMAT(dst_addr));

		construct_ipv4_hdr(m, len, IP_PROTO_UDP, src_addr, dst_addr);

		len = len - IPv4_HDR_SIZE;
		/* construct udphdr */
		construct_udp_hdr(m, len, UDP_PORT_GTPU, UDP_PORT_GTPU);
	}
}

void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask,
		pfcp_session_datat_t **sess_data)
{
	uint32_t j = 0;
	uint64_t hit_mask = 0;
	void *key_ptr[MAX_BURST_SZ] = {NULL};
	struct ul_bm_key key[MAX_BURST_SZ] = {0};

	/* TODO: uplink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		key[j].teid = 0;
		key_ptr[j] = &key[j];

		struct ipv4_hdr *ipv4_hdr = NULL;
		struct udp_hdr *udp_hdr = NULL;
		struct gtpu_hdr *gtpu_hdr = NULL;

		/* reject if not with Wstbnd ip */
		ipv4_hdr = get_mtoip(pkts[j]);
		if ((ntohl(ipv4_hdr->dst_addr) != app.wb_ip) &&
				(ntohl(ipv4_hdr->dst_addr) != app.wb_li_ip)) {
			RESET_BIT(*pkts_mask, j);
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"WB_IP or WB_LI_IP is not valid dst ip address:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ipv4_hdr->dst_addr));
			continue;
		}

		/* reject un-tunneled packet */
		udp_hdr = get_mtoudp(pkts[j]);
		if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
			RESET_BIT(*pkts_mask, j);
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"GTPU UDP PORT is not valid\n", LOG_VALUE);
			continue;
		}

		gtpu_hdr = get_mtogtpu(pkts[j]);
		if (gtpu_hdr->teid == 0 || ((gtpu_hdr->msgtype != GTP_GPDU) && (gtpu_hdr->msgtype != GTPU_END_MARKER_REQUEST))) {
			RESET_BIT(*pkts_mask, j);
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"GTPU TEID and MSG TYPE is not valid\n", LOG_VALUE);
			continue;
		}

		key[j].teid = gtpu_hdr->teid;
	}

	if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr[0], n,
			&hit_mask, (void **)sess_data)) < 0) {
		hit_mask = 0;
	}

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":Session Data LKUP:FAIL!! ULKEY "
				"TEID: %u\n", LOG_VALUE, key[j].teid);
			sess_data[j] = NULL;
		} else {

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SESSION INFO:"
				"TEID:%u, Session State:%u\n",
				LOG_VALUE, key[j].teid, (sess_data[j])->sess_state);
		//TODO:Handle condition properly
//			if (app.spgw_cfg == SGWU) {
//				if (sess_data[j]->action == ACTION_DROP) {
//#ifdef STATS
//					--epc_app.ul_params[S1U_PORT_ID].pkts_in;
//#endif /* STATS */
//					RESET_BIT(*pkts_mask, j);
//					continue;
//			}
		}
	}
}

/* TODO: Optimized this function */
void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, pfcp_session_datat_t **si,
		uint64_t *pkts_queue_mask)
{
	uint32_t j = 0;
	void *key_ptr[MAX_BURST_SZ] = {NULL};
	void *key_ptr_t[MAX_BURST_SZ] = {NULL};
	struct ipv4_hdr *ipv4_hdr = NULL;
	uint32_t dst_addr = 0;
	uint64_t hit_mask = 0;
	struct dl_bm_key key[MAX_BURST_SZ] = {0};
	struct ul_bm_key key_t[MAX_BURST_SZ] = {0};


	/* TODO: downlink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		struct udp_hdr *udp_hdr = NULL;
		struct gtpu_hdr *gtpu_hdr = NULL;

		udp_hdr = get_mtoudp(pkts[j]);
		if ((ntohs(udp_hdr->dst_port) == UDP_PORT_GTPU)
				|| (udp_hdr->dst_port == UDP_PORT_GTPU_NW_ORDER)) {

			key_t[j].teid = 0;
			key_ptr_t[j] = &key_t[j];

			/* tunnel packets */
			/* reject if not with wb ip */
			ipv4_hdr = get_mtoip(pkts[j]);
			if ((ntohl(ipv4_hdr->dst_addr) != app.eb_ip)
					&& (ntohl(ipv4_hdr->dst_addr) != app.eb_li_ip)) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"EB IP is not valid, Exp IP:"IPV4_ADDR" or "IPV4_ADDR","
						"Rcvd_IP:"IPV4_ADDR"\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(app.eb_ip),
						IPV4_ADDR_HOST_FORMAT(app.eb_li_ip),
						IPV4_ADDR_HOST_FORMAT(ntohl(ipv4_hdr->dst_addr)));
				continue;
			}

			gtpu_hdr = get_mtogtpu(pkts[j]);
			if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GEMR) {
					RESET_BIT(*pkts_mask, j);
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"GTPU TEID:%u and MSG_TYPE:%x is not valid\n",
						LOG_VALUE, gtpu_hdr->teid, gtpu_hdr->msgtype);
					continue;
				}
			}

			key_t[j].teid = gtpu_hdr->teid;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DL_KEY: TEID:%u\n", LOG_VALUE, key_t[j].teid);

		} else {
			key[j].ue_ipv4 = 0;
			key_ptr[j] = &key[j];

			ipv4_hdr = get_mtoip(pkts[j]);
			dst_addr = ipv4_hdr->dst_addr;

			key[j].ue_ipv4 = htonl(dst_addr);
			struct epc_meta_data *meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
								META_DATA_OFFSET);
			meta_data->key.ue_ipv4 = key[j].ue_ipv4;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"BEAR SESS LKUP:DL_KEY UE IP:"IPV4_ADDR "\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(meta_data->key.ue_ipv4));

			key_ptr[j] = &key[j];
		}

	}

	if (key_ptr_t[0] != NULL) {
		if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr_t[0], n,
						&hit_mask, (void **)si)) < 0) {
			    hit_mask = 0;
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"SDF BEAR Bulk LKUP:FAIL\n", LOG_VALUE);
		}

		for (j = 0; j < n; j++) {
			if (!ISSET_BIT(hit_mask, j)) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SDF BEAR LKUP FAIL!! DL KEY "
						"TEID:%u\n", LOG_VALUE, key_t[j].teid);
				si[j] = NULL;
			} else {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SESSION INFO:"
						"TEID:%u, Session State:%u\n", LOG_VALUE, key_t[j].teid,
						(si[j])->sess_state);

				/** Check downlink bearer is ACTIVE or IDLE */
				if (si[j]->sess_state != CONNECTED) {
#ifdef STATS
					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
					++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
					RESET_BIT(*pkts_mask, j);
					SET_BIT(*pkts_queue_mask, j);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Enqueue Pkts Set the Pkt Mask:%u\n",
							LOG_VALUE, pkts_queue_mask);
				}

			}
		}
	}

	if (key_ptr[0] != NULL) {
		if ((iface_lookup_downlink_bulk_data((const void **)&key_ptr[0], n,
				&hit_mask, (void **)si)) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"SDF BEAR Bulk LKUP:FAIL\n", LOG_VALUE);
		}
		for (j = 0; j < n; j++) {
			if (!ISSET_BIT(hit_mask, j)) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SDF BEAR LKUP FAIL!! DL KEY "
					"UE IP:"IPV4_ADDR"\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT((key[j]).ue_ipv4));
				si[j] = NULL;
			} else {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SESSION INFO:"
						"UE IP:"IPV4_ADDR", ACL TABLE Index: %u "
						"Session State:%u\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT((si[j])->ue_ip_addr),
					(si[j])->acl_table_indx, (si[j])->sess_state);
			}
		}
	}
}

void
qer_gating(pdr_info_t **pdr, uint32_t n, uint64_t *pkts_mask,
		uint64_t *fd_pkts_mask, uint64_t *pkts_queue_mask, uint8_t direction)
{
	uint32_t i = 0;

	/* Uplink Gate Status Check */
	if (direction == UPLINK) {
		for (i = 0; i < n; i++) {
			if ((ISSET_BIT(*pkts_mask, i)) && (ISSET_BIT(*fd_pkts_mask, i))) {
				/* Currently we apply 1st qer */
				if (pdr[i]->qer_count) {
					if ((pdr[i]->quer[0]).gate_status.ul_gate == CLOSE) {
						RESET_BIT(*pkts_mask, i);
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Matched PDR_ID:%u, FAR_ID:%u, QER_ID:%u\n",
							LOG_VALUE, pdr[i]->rule_id, (pdr[i]->far)->far_id_value,
								(pdr[i]->quer[0]).qer_id);
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Packets DROPPED UL_GATE : CLOSED\n", LOG_VALUE);
					}
				}
			}
		}
	} else if (direction == DOWNLINK) {
		/* DownLink Gate Status Check */
		for (i = 0; i < n; i++) {
			if ((ISSET_BIT(*pkts_mask, i)) && (ISSET_BIT(*fd_pkts_mask, i))) {
				/* Currently we apply 1st qer */
				if (pdr[i]->qer_count) {
					if ((pdr[i]->quer[0]).gate_status.dl_gate == CLOSE) {
						RESET_BIT(*pkts_mask, i);
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Matched PDR_ID:%u, FAR_ID:%u, QER_ID:%u\n",
								LOG_VALUE, pdr[i]->rule_id, (pdr[i]->far)->far_id_value,
								(pdr[i]->quer[0]).qer_id);
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Packets DROPPED DL_GATE : CLOSED\n", LOG_VALUE);
					}
				}
			}
		}
	}
}

/**
 * @brief  : Check if packet contains dns data
 * @param  : m, buffer containing  packet data
 * @param  : rid, dns rule id
 * @return : Returns true for dns packet, false otherwise
 */
static inline bool is_dns_pkt(struct rte_mbuf *m, uint32_t rid)
{
	struct ipv4_hdr *ip_hdr;
	struct ether_hdr *eth_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr))
		return false;

	if (rid != DNS_RULE_ID)
		return false;

	return true;
}

void
update_dns_meta(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid)
{
	uint32_t i;
	struct epc_meta_data *meta_data;
	for (i = 0; i < n; i++) {

		meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(
					pkts[i], META_DATA_OFFSET);

		if (likely(!is_dns_pkt(pkts[i], rid[i]))) {
			meta_data->dns = 0;
			continue;
		}

		meta_data->dns = 1;
	}
}

#ifdef HYPERSCAN_DPI
/**
 * @brief  : Get worker index
 * @param  : lcore_id
 * @return : Returns epc app worker index
 */
static int
get_worker_index(unsigned lcore_id)
{
	return epc_app.worker_core_mapping[lcore_id];
}

void
clone_dns_pkts(struct rte_mbuf **pkts, uint32_t n, uint64_t pkts_mask)
{
	uint32_t i;
	struct epc_meta_data *meta_data;
	unsigned lcore_id = rte_lcore_id();
	int worker_index = get_worker_index(lcore_id);

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(pkts_mask, i)) {
			meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(
						pkts[i], META_DATA_OFFSET);
			if (meta_data->dns) {
				push_dns_ring(pkts[i]);
				/* NGCORE_SHRINK HYPERSCAN clone_dns_pkt to be tested */
				++(epc_app.dl_params[worker_index].
						num_dns_packets);
			}
		}
	}
}
#endif /* HYPERSCAN_DPI */

void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid,
		pdr_info_t **pdr)
{
	uint32_t i;
	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			if (construct_ether_hdr(pkts[i], portid, &pdr[i]) < 0)
				RESET_BIT(*pkts_mask, i);
		}
		/* TODO: Set checksum offload.*/
	}
}

void
update_nexts5s8_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *fwd_pkts_mask, pfcp_session_datat_t **sess_data,
		pdr_info_t **pdr)
{
	uint32_t i;
	uint16_t len;

	for (i = 0; i < n; i++) {
		if ((ISSET_BIT(*pkts_mask, i)) && (ISSET_BIT(*fwd_pkts_mask, i))) {
			len = rte_pktmbuf_data_len(pkts[i]);
			len = len - ETH_HDR_SIZE;

			if (sess_data[i]->pdrs != NULL) {
				/* Retrieve Next Hop Destination Address */
				uint32_t next_hop_addr =
					((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.ipv4_address;

				uint32_t src_addr = 0;
				/* Validate the Destination IP Address subnet */
				if (validate_Subnet(next_hop_addr, app.eb_net, app.eb_bcast_addr)) {
					/* Source interface IP address */
					src_addr = app.eb_ip;
				} else if (validate_Subnet(next_hop_addr, app.eb_li_net, app.eb_li_bcast_addr)) {
					/* Source interface IP address */
					src_addr = app.eb_li_ip;
				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Destination S5S8 intf IPv4 Addr "IPV4_ADDR" is NOT in local intf subnet\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(next_hop_addr));
					RESET_BIT(*pkts_mask, i);
					continue;
				}


				/* Fill the Source and Destination IP address in the IPv4 Header */
				/* RCVD: CORE --> SEND: ACCESS */
				/* RCVD: ACCESS --> SEND: CORE */
				construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP, src_addr, next_hop_addr);

				/* Update the GTP-U header teid of S5S8 PGWU*/
				((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
						ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.teid);

			} else {
				RESET_BIT(*pkts_mask, i);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Session Data don't have PDR info\n", LOG_VALUE);
				sess_data[i]->pdrs = NULL;
			}
		}
		/* Fill the PDR info form the session data */
		if (sess_data[i] != NULL) {
			pdr[i] = sess_data[i]->pdrs;
		}
	}
}

void
update_enb_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *fd_pkts_mask,
		pfcp_session_datat_t **sess_data, pdr_info_t **pdr)
{
	uint16_t len = 0;
	uint32_t i = 0;

	for (i = 0; i < n; i++) {
		if ((ISSET_BIT(*pkts_mask, i)) &&
				(ISSET_BIT(*fd_pkts_mask, i))) {
			len = rte_pktmbuf_data_len(pkts[i]);
			len = len - ETH_HDR_SIZE;

			if (sess_data[i]->pdrs != NULL) {
				/* Next hop or destination IP Address */
				uint32_t enb_addr =
					sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.ipv4_address;

				uint32_t src_addr = 0;
				/* Validate the Destination IP Address subnet */
				if (validate_Subnet(enb_addr, app.wb_net, app.wb_bcast_addr)) {
					/* Source interface IP address */
					src_addr = app.wb_ip;
				} else if (validate_Subnet(enb_addr, app.wb_li_net, app.wb_li_bcast_addr)) {
					/* Source interface IP address */
					src_addr = app.wb_li_ip;
				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Destination eNB IPv4 Addr "IPV4_ADDR" is NOT in local intf subnet\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(enb_addr));
					RESET_BIT(*pkts_mask, i);
					continue;
				}

				/* Fill the Source and Destination IP address in the IPv4 Header */
				construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP, src_addr, enb_addr);

				/* Update tied in GTP U header*/
				((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
						ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.teid);

				/* Fill the PDR info form the session data */
				pdr[i] = sess_data[i]->pdrs;
			} else {
				RESET_BIT(*pkts_mask, i);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Session Data don't have PDR info\n", LOG_VALUE);
				sess_data[i]->pdrs = NULL;
				pdr[i] = NULL;
			}
		}
	}
}

void
update_adc_rid_from_domain_lookup(uint32_t *rb, uint32_t *rc, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (rc[i] != 0)
			rb[i] = rc[i];
}

/**
 * @brief  : create hash table.
 * @param  : name, hash name
 * @param  : rte_hash, pointer to  store created hash
 * @param  : entrie, entries to add in table
 * @param  : key_len, key length
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
hash_create(const char *name, struct rte_hash **rte_hash,
		uint32_t entries, uint32_t key_len)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = name,
		.entries = entries,
		.key_len = key_len,
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	*rte_hash = rte_hash_create(&rte_hash_params);
	if (*rte_hash == NULL)
		rte_exit(EXIT_FAILURE, "%s hash create failed: %s (%u)\n",
			rte_hash_params.name,
			rte_strerror(rte_errno), rte_errno);
	return 0;
}

/**
 * @brief  : Get the system current timestamp.
 * @param  : timestamp is used for storing system current timestamp
 * @return : Returns 0 in case of success
 */
static uint8_t
get_timestamp(char *timestamp)
{

	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);

	strftime(timestamp, MAX_LEN, "%Y%m%d%H%M%S", tmp);
	return 0;
}

/**
 * @brief  : Get pcap file name .
 * @param  : east_file, store east interface pcap file name.
 * @param  : west_file, store west interface pcap filw name.
 * @param  : east_iface_name, file name.
 * @param  : west_iface_name, file name.
 * @return : Returns 0 in case of success
 */
static void
get_pcap_file_name(char *east_file, char *west_file,
		char *east_iface_name, char *west_iface_name)
{
	char timestamp[MAX_LEN] = {0};

	get_timestamp(timestamp);

	snprintf(east_file, MAX_LEN, "%s%s%s", east_iface_name,
			timestamp, PCAP_EXTENTION);
	snprintf(west_file, MAX_LEN, "%s%s%s", west_iface_name,
			timestamp, PCAP_EXTENTION);
}

void up_pcap_init(void)
{

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Pcap files will be Created\n", LOG_VALUE);

	char east_file[PCAP_FILENAME_LEN] = {0};
	char west_file[PCAP_FILENAME_LEN] = {0};

	/* Fill the PCAP File Names */
	get_pcap_file_name(east_file, west_file,
			DOWNLINK_PCAP_FILE, UPLINK_PCAP_FILE);

	pcap_dumper_east = init_pcap(east_file);
	pcap_dumper_west = init_pcap(west_file);

}

pcap_dumper_t *
init_pcap(char* pcap_filename)
{
	pcap_dumper_t *pcap_dumper = NULL;
	pcap_t *pcap = NULL;
	pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);

	if ((pcap_dumper = pcap_dump_open(pcap, pcap_filename)) == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error in opening Pcap file\n", LOG_VALUE);
		return NULL;
	}
	return pcap_dumper;
}

void dump_pcap(struct rte_mbuf **pkts, uint32_t n,
pcap_dumper_t *pcap_dumper)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		struct pcap_pkthdr pcap_hdr;
		uint8_t *pkt = rte_pktmbuf_mtod(pkts[i], uint8_t *);

		pcap_hdr.len = pkts[i]->pkt_len;
		pcap_hdr.caplen = pcap_hdr.len;
		gettimeofday(&(pcap_hdr.ts), NULL);

		pcap_dump((u_char *)pcap_dumper, &pcap_hdr, pkt);
		pcap_dump_flush((pcap_dumper_t *)pcap_dumper);
	}
	return;
}

/**
 * @brief  : Close pcap file.
 * @param  : void.
 * @return : Returns nothing
 */
static void
close_up_pcap_dump(void)
{

	if (pcap_dumper_west != NULL) {
		pcap_dump_close(pcap_dumper_west);
		pcap_dumper_west = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"PCAP : West Pcap Generaion Stop\n", LOG_VALUE);
	}
	if (pcap_dumper_east != NULL) {
		pcap_dump_close(pcap_dumper_east);
		pcap_dumper_east = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"PCAP : East Pcap Generaion Stop\n", LOG_VALUE);
	}
}

void
up_pcap_dumper(pcap_dumper_t *pcap_dumper,
		struct rte_mbuf **pkts, uint32_t n)
{

	switch (app.generate_pcap) {
		case START_PCAP_GEN:
			{
				if (pcap_dumper != NULL) {
					dump_pcap(pkts, n, pcap_dumper);
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"PCAP : Packet dumped into pcap\n", LOG_VALUE);
				} else {
					up_pcap_init();
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"PCAP : Open file for store Packet\n", LOG_VALUE);
					if (pcap_dumper != NULL)
						dump_pcap(pkts, n, pcap_dumper);
				}
				break;
			}
		case STOP_PCAP_GEN:
			{
				close_up_pcap_dump();
				break;
			}
		case RESTART_PCAP_GEN:
			{
				close_up_pcap_dump();
				up_pcap_init();
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"PCAP : Restarted Pcap generation\n", LOG_VALUE);
				if (pcap_dumper != NULL)
					dump_pcap(pkts, n, pcap_dumper);

				app.generate_pcap = START_PCAP_GEN;
				break;
			}
		default :
			app.generate_pcap = STOP_PCAP_GEN;
			break;
	}
}
