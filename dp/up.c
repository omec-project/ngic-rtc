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

#ifdef PCAP_GEN
#include <pcap.h>
#endif /* PCAP_GEN */

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
#include "up_ether.h"
#include "interface.h"
#include "epc_packet_framework.h"


#ifdef PCAP_GEN
pcap_dumper_t *pcap_dumper_east;
pcap_dumper_t *pcap_dumper_west;
#endif /* PCAP_GEN */

void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask)
{
	uint32_t i;
	int ret = 0;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct gtpu_hdr *gtpu_hdr;
	struct epc_meta_data *meta_data;

	for (i = 0; i < n; i++) {
		/* reject if not with s1u ip */
		ipv4_hdr = get_mtoip(pkts[i]);
		uint32_t ip = 0; //GCC_Security flag

		switch(app.spgw_cfg) {
			case SAEGWU:
				ip = app.s1u_ip;
				break;

			case PGWU:
				ip = app.s5s8_pgwu_ip;
				break;

			default:
				break;
		}

		if (ipv4_hdr->dst_addr != ip) {
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
		RTE_LOG_DP(DEBUG, DP, "Received tunneled packet with teid 0x%X\n",
				ntohl(meta_data->teid));
		RTE_LOG_DP(DEBUG, DP, "From Ue IP " IPV4_ADDR "\n",
				IPV4_ADDR_FORMAT(GTPU_INNER_SRC_IP(pkts[i])));

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
		uint32_t n, uint64_t *pkts_mask, uint64_t *pkts_queue_mask)
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
			RTE_LOG_DP(DEBUG, DP, FORMAT":Session Data is NULL\n", ERR_MSG);
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		if (pdr == NULL) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			RTE_LOG_DP(DEBUG, DP, FORMAT":PDR INFO IS NULL\n", ERR_MSG);
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		/* If Pdr value is not NULL */
		far = pdr->far;

		if (far == NULL) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			RTE_LOG_DP(DEBUG, DP, FORMAT":FAR INFO IS NULL\n", ERR_MSG);
			RESET_BIT(*pkts_mask, i);
			continue;
		}
/** VS: Check downlink bearer is ACTIVE or IDLE */
		if (app.spgw_cfg == SAEGWU){
			if (si->sess_state != CONNECTED) {
#ifdef STATS
				--epc_app.dl_params[SGI_PORT_ID].pkts_in;
				++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
				RTE_LOG_DP(DEBUG, DP, FORMAT"Session State is NOT CONNECTED\n",
					ERR_MSG);
				RESET_BIT(*pkts_mask, i);
				SET_BIT(*pkts_queue_mask, i);
				continue;
			}
		}

		if (!far->actions.forw) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
			RTE_LOG_DP(DEBUG, DP, "ERROR:"FORMAT"Action is NOT set to FORW,"
				" PDR_ID:%u, FAR_ID:%u\n",
				ERR_MSG, pdr->rule_id, far->far_id_value);
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}

		if (!far->frwdng_parms.outer_hdr_creation.teid) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			RTE_LOG_DP(DEBUG, DP, "ERROR:"FORMAT"Next hop teid is NULL: "
				" PDR_ID:%u, FAR_ID:%u\n",
				ERR_MSG, pdr->rule_id, far->far_id_value);
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}

		if (ENCAP_GTPU_HDR(m, (pdr->far)->frwdng_parms.outer_hdr_creation.teid) < 0) {
#ifdef STATS
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
			RTE_LOG_DP(DEBUG, DP, "ERROR:"FORMAT":Failed to ENCAP GTPU HEADER \n", ERR_MSG);
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		len = rte_pktmbuf_data_len(m);
		len = len - ETH_HDR_SIZE;

		dst_addr = (pdr->far)->frwdng_parms.outer_hdr_creation.ipv4_address;
		RTE_LOG_DP(DEBUG, DP, "DST ADDR:"IPV4_ADDR"\n", IPV4_ADDR_HOST_FORMAT(dst_addr));

		/* construct iphdr */
		switch(app.spgw_cfg) {
			case SAEGWU:
				src_addr = app.s1u_ip;
				break;

			case PGWU:
				src_addr = app.s5s8_pgwu_ip;
				break;

			default:
				break;
		}

		construct_ipv4_hdr(m, len, IP_PROTO_UDP, ntohl(src_addr),
					dst_addr);

		len = len - IPv4_HDR_SIZE;
		/* construct udphdr */
		construct_udp_hdr(m, len, UDP_PORT_GTPU, UDP_PORT_GTPU);
	}
}

//VS
void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask,
		pfcp_session_datat_t **sess_data)
{
	uint32_t j = 0;
	uint64_t hit_mask = 0;
	void *key_ptr[MAX_BURST_SZ] = {NULL};
	struct epc_meta_data *meta_data = NULL;
	struct ul_bm_key key[MAX_BURST_SZ] = {0};

	/* TODO: uplink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		key[j].teid = 0;
		key_ptr[j] = &key[j];

		switch (app.spgw_cfg) {
			case SAEGWU: {
				meta_data =
					(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
					META_DATA_OFFSET);
				key[j].teid = ntohl(meta_data->teid);
				//key[j].teid = meta_data->teid;
				break;
			}

			case SGWU: {
				struct ipv4_hdr *ipv4_hdr = NULL;
				struct udp_hdr *udp_hdr = NULL;
				struct gtpu_hdr *gtpu_hdr = NULL;

				/* reject if not with s1u ip */
				ipv4_hdr = get_mtoip(pkts[j]);
				if (ipv4_hdr->dst_addr != app.s1u_ip) {
					RESET_BIT(*pkts_mask, j);
					RTE_LOG_DP(DEBUG, DP, FORMAT":S1U IP is not valid\n",
						ERR_MSG);
					continue;
				}

				/* reject un-tunneled packet */
				udp_hdr = get_mtoudp(pkts[j]);
				if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
					RESET_BIT(*pkts_mask, j);
					RTE_LOG_DP(DEBUG, DP, FORMAT":GTPU UDP PORT is not valid\n",
						ERR_MSG);
					continue;
				}

				gtpu_hdr = get_mtogtpu(pkts[j]);
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
					RESET_BIT(*pkts_mask, j);
					RTE_LOG_DP(DEBUG, DP, FORMAT":GTPU TEID and MSG_TYPE is not valid\n",
						ERR_MSG);
					continue;
				}

			//	key[j].teid = ntohl(gtpu_hdr->teid);
				key[j].teid = gtpu_hdr->teid;
				break;
			}

			case PGWU: {
				meta_data =
					(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
					META_DATA_OFFSET);
				key[j].teid = ntohl(meta_data->teid);
				//key[j].teid = meta_data->teid;
				break;
			}

			default:
				break;
		}
	}

	if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr[0], n,
			&hit_mask, (void **)sess_data)) < 0) {
		hit_mask = 0;
	}

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG_DP(DEBUG, DP, FORMAT":Session Data LKUP:FAIL!! UL_KEY "
				"TEID:%u\n", ERR_MSG,
				key[j].teid);
			sess_data[j] = NULL;
		} else {

			RTE_LOG_DP(DEBUG, DP, "SESSION INFO:"
					"TEID:%u, "
					"Session State:%u\n", key[j].teid,
					(sess_data[j])->sess_state);
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

//
void
dl_get_sess_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask,
		pfcp_session_datat_t **sess_data, uint64_t *pkts_queue_mask)
{
	uint32_t j = 0;
	uint64_t hit_mask = 0;
	void *key_ptr[MAX_BURST_SZ] = {NULL};
	struct ul_bm_key key[MAX_BURST_SZ] = {0};

	for (j = 0; j < n; j++) {
		key[j].teid = 0;
		key_ptr[j] = &key[j];

		struct ipv4_hdr *ipv4_hdr = NULL;
		struct udp_hdr *udp_hdr = NULL;
		struct gtpu_hdr *gtpu_hdr = NULL;

		/* reject if not with s5s8 sgwu ip */
		ipv4_hdr = get_mtoip(pkts[j]);
		if (ipv4_hdr->dst_addr != app.s5s8_sgwu_ip) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG_DP(DEBUG, DP, FORMAT":S5S8 SGWU IP is not valid\n",
				ERR_MSG);
			continue;
		}

		/* reject un-tunneled packet */
		udp_hdr = get_mtoudp(pkts[j]);
		if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG_DP(DEBUG, DP, FORMAT":GTPU UDP PORT is not valid\n",
				ERR_MSG);
			continue;
		}

		gtpu_hdr = get_mtogtpu(pkts[j]);
		if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG_DP(DEBUG, DP, FORMAT":GTPU TEID and MSG_TYPE is not valid\n",
				ERR_MSG);
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
			RTE_LOG_DP(DEBUG, DP, FORMAT":Session Data LKUP:FAIL!! UL_KEY "
				"TEID:%u\n", ERR_MSG,
				key[j].teid);
			sess_data[j] = NULL;
		} else {

			RTE_LOG_DP(DEBUG, DP, "SESSION INFO:"
					"TEID:%u, "
					"Session State:%u\n", key[j].teid,
					(sess_data[j])->sess_state);
			/** VS: Check downlink bearer is ACTIVE or IDLE */
			if (app.spgw_cfg == SGWU) {
				if (sess_data[j]->sess_state != CONNECTED) {
#ifdef STATS
					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
					++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
					RESET_BIT(*pkts_mask, j);
					SET_BIT(*pkts_queue_mask, j);
				}
			}
//			/** VS: Check downlink bearer is ACTIVE or IDLE */
//			if (app.spgw_cfg == SGWU) {
//				if (si[j]->action == ACTION_DROP) {
//#ifdef STATS
//					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
//#endif /* STATS */
//					RESET_BIT(*pkts_mask, j);
//					continue;
//				}else if (si[j]->sess_state != CONNECTED) {
//#ifdef STATS
//					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
//					++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
//#endif /* STATS */
//					RESET_BIT(*pkts_mask, j);
//					SET_BIT(*pkts_queue_mask, j);
//				}
//			}
		}
	}
}

//VS
void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, pfcp_session_datat_t **si,
		uint64_t *pkts_queue_mask)
{
	uint32_t j = 0;
	struct dl_bm_key key[MAX_BURST_SZ];
	void *key_ptr[MAX_BURST_SZ];
	struct ipv4_hdr *ipv4_hdr = NULL;
	uint32_t dst_addr = 0;
	uint64_t hit_mask = 0;

	/* TODO: downlink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		key[j].ue_ipv4 = 0;
		key_ptr[j] = &key[j];

		switch (app.spgw_cfg) {
			case SGWU: {
				struct udp_hdr *udp_hdr = NULL;
				struct gtpu_hdr *gtpu_hdr = NULL;

				/* reject if not with s1u ip */
				ipv4_hdr = get_mtoip(pkts[j]);
				if (ipv4_hdr->dst_addr != app.s5s8_sgwu_ip) {
					RESET_BIT(*pkts_mask, j);
					RTE_LOG_DP(DEBUG, DP, FORMAT":S5S8 IP is not valid\n",
						ERR_MSG);
					continue;
				}

				/* reject un-tunneled packet */
				udp_hdr = get_mtoudp(pkts[j]);
				if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
					RESET_BIT(*pkts_mask, j);
					RTE_LOG_DP(DEBUG, DP, FORMAT":GTPU UDP PORT is not valid\n",
						ERR_MSG);
					continue;
				}

				gtpu_hdr = get_mtogtpu(pkts[j]);
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
					RESET_BIT(*pkts_mask, j);
					RTE_LOG_DP(DEBUG, DP, FORMAT":GTPU TEID and MSG_TYPE is not valid\n",
						ERR_MSG);
					continue;
				}

				uint8_t *pkt_ptr = (uint8_t *) gtpu_hdr;
				pkt_ptr += GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr);
				ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;
				dst_addr = ntohl(ipv4_hdr->dst_addr);
				break;
			}

			case PGWU: {
				/* Values are same as SAEGWU.*/
				ipv4_hdr = get_mtoip(pkts[j]);
				dst_addr = ipv4_hdr->dst_addr;
				break;
			}

			case SAEGWU: {
				ipv4_hdr = get_mtoip(pkts[j]);
				dst_addr = ipv4_hdr->dst_addr;
				break;
			}

			default:
				break;
		}

		key[j].ue_ipv4 = dst_addr;
		struct epc_meta_data *meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
							META_DATA_OFFSET);
		meta_data->key.ue_ipv4 = key[j].ue_ipv4;
		RTE_LOG_DP(DEBUG, DP, "BEAR_SESS LKUP:DL_KEY ue_addr:"IPV4_ADDR
				"\n",
				IPV4_ADDR_HOST_FORMAT(ntohl(meta_data->key.ue_ipv4)));

		key_ptr[j] = &key[j];
	}

	if ((iface_lookup_downlink_bulk_data((const void **)&key_ptr[0], n,
			&hit_mask, (void **)si)) < 0) {
		RTE_LOG_DP(ERR, DP, "SDF BEAR Bulk LKUP:FAIL!!\n");
	}

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG_DP(DEBUG, DP, "SDF BEAR LKUP FAIL!! DL_KEY "
					"UE_Addr:"IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(ntohl((key[j]).ue_ipv4)));
			si[j] = NULL;
		} else {
			RTE_LOG_DP(DEBUG, DP, "SESSION INFO:"
					"UE_Addr:"IPV4_ADDR", ACL_TABLE_Index-%u "
					"Session State:%u\n",
				IPV4_ADDR_HOST_FORMAT((si[j])->ue_ip_addr),
				(si[j])->acl_table_indx, (si[j])->sess_state);
			/** VS: Check downlink bearer is ACTIVE or IDLE */
			if (app.spgw_cfg == SGWU) {
				if (si[j]->sess_state != CONNECTED) {
#ifdef STATS
					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
					++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
					RESET_BIT(*pkts_mask, j);
					SET_BIT(*pkts_queue_mask, j);
				}
			}
		}
	}
}

void
qer_gating(pdr_info_t **pdr, uint32_t n, uint64_t *pkts_mask,
		uint64_t *pkts_queue_mask, uint8_t direction)
{
	uint32_t i = 0;

	/* Uplink Gate Status Check */
	if (direction == UPLINK) {
		for (i = 0; i < n; i++) {
			if (ISSET_BIT(*pkts_mask, i)) {
				/* Currently we apply 1st qer */
				if (pdr[i]->qer_count) {
					if ((pdr[i]->quer[0]).gate_status.ul_gate == CLOSE) {
						RESET_BIT(*pkts_mask, i);
						RTE_LOG_DP(DEBUG, DP, "Matched PDR_ID:%u, FAR_ID:%u, QER_ID:%u\n",
								pdr[i]->rule_id, (pdr[i]->far)->far_id_value,
								(pdr[i]->quer[0]).qer_id);
						RTE_LOG_DP(DEBUG, DP, "Packets DROPPED: UL_GATE: CLOSED\n");
					}
				}
			}
		}
	} else if (direction == DOWNLINK) {
		/* DownLink Gate Status Check */
		for (i = 0; i < n; i++) {
			if (ISSET_BIT(*pkts_mask, i)) {
				/* Currently we apply 1st qer */
				if (pdr[i]->qer_count) {
					if ((pdr[i]->quer[0]).gate_status.dl_gate == CLOSE) {
						RESET_BIT(*pkts_mask, i);
						RTE_LOG_DP(DEBUG, DP, "Matched PDR_ID:%u, FAR_ID:%u, QER_ID:%u\n",
								pdr[i]->rule_id, (pdr[i]->far)->far_id_value,
								(pdr[i]->quer[0]).qer_id);
						RTE_LOG_DP(DEBUG, DP, "Packets DROPPED: DL_GATE: CLOSED\n");
					}
				}
			}
		}
	}
}

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
		uint64_t *pkts_mask, pfcp_session_datat_t **sess_data,
		pdr_info_t **pdr)
{
	/*TODO: Do we need to update TEID in GTP header?*/
	uint16_t len;
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			len = rte_pktmbuf_data_len(pkts[i]);
			len = len - ETH_HDR_SIZE;

			if (app.spgw_cfg == SGWU) {
				/*TODO : Make readable*/
				uint32_t s5s8_pgwu_addr =
					sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.ipv4_address;
				construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP,
						ntohl(app.s5s8_sgwu_ip), s5s8_pgwu_addr);
			}else if (app.spgw_cfg == PGWU) {
				uint32_t s5s8_sgwu_addr =
					sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.ipv4_address;
				construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP,
						ntohl(app.s5s8_pgwu_ip), s5s8_sgwu_addr);
			}

			/* VS: Update the GTP-U header teid of S5S8 PGWU*/
			((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
					ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.teid);

		}
		/* Fill the PDR info form the session data */
		if (sess_data[i] != NULL) {
			pdr[i] = sess_data[i]->pdrs;
		}
	}
}

void
update_enb_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, pfcp_session_datat_t **sess_data,
		pdr_info_t **pdr)
{
	uint16_t len = 0;
	uint32_t i = 0;

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			len = rte_pktmbuf_data_len(pkts[i]);
			len = len - ETH_HDR_SIZE;

			uint32_t enb_addr =
					sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.ipv4_address;
			construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP,
					ntohl(app.s1u_ip), enb_addr);

			/*Update tied in GTP U header*/
			((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
					ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.teid);

			/* Fill the PDR info form the session data */
			pdr[i] = sess_data[i]->pdrs;
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
 * @brief create hash table.
 *
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

#ifdef PCAP_GEN
void up_pcap_init(void)
{

	printf("\n\npcap files will be overwritten...\n");

	char east_file[PCAP_FILENAME_LEN] = {0};
	char west_file[PCAP_FILENAME_LEN] = {0};

	switch(app.spgw_cfg) {
		case SAEGWU:
			strncpy(east_file, SPGW_SGI_PCAP_FILE,
					sizeof(SPGW_SGI_PCAP_FILE));
			strncpy(west_file, SPGW_S1U_PCAP_FILE,
					sizeof(SPGW_S1U_PCAP_FILE));
			break;

		case SGWU:
			strncpy(east_file, SGW_S5S8_PCAP_FILE,
					sizeof(SGW_S5S8_PCAP_FILE));
			strncpy(west_file, SGW_S1U_PCAP_FILE,
					sizeof(SGW_S1U_PCAP_FILE));
			break;

		case PGWU:
			strncpy(east_file, PGW_SGI_PCAP_FILE,
					sizeof(PGW_SGI_PCAP_FILE));
			strncpy(west_file, PGW_S5S8_PCAP_FILE,
					sizeof(PGW_S5S8_PCAP_FILE));
			break;

		default:
		break;
	}

	pcap_dumper_east = init_pcap(east_file);
	pcap_dumper_west = init_pcap(west_file);

}



/**
 * initialize pcap dumper.
 * @param pcap_filename
 *  pointer to pcap output filename.
 */
pcap_dumper_t *
init_pcap(char* pcap_filename)
{
	pcap_dumper_t *pcap_dumper = NULL;
	pcap_t *pcap = NULL;
	pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);

	if ((pcap_dumper = pcap_dump_open(pcap, pcap_filename)) == NULL) {
		RTE_LOG_DP(ERR, DP, "Error in opening pcap file.\n");
		return NULL;
	}
	return pcap_dumper;
}

/**
 * write into pcap file.
 * @param pkts
 *  pointer to mbuf of packets.
 * @param n
 *  number of pkts.
 * @param pcap_dumper
 *  pointer to pcap dumper.
 */
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
#endif /* PCAP_GEN */
