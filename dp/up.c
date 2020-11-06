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
#include "ipv6.h"
#include "util.h"
#include "up_acl.h"
#include "up_ether.h"
#include "pfcp_util.h"
#include "interface.h"
#include "gw_adapter.h"
#include "epc_packet_framework.h"

pcap_dumper_t *pcap_dumper_east;
pcap_dumper_t *pcap_dumper_west;
extern int clSystemLog;
extern struct in_addr cp_comm_ip;
extern struct in_addr dp_comm_ip;
extern uint16_t dp_comm_port;
extern uint16_t cp_comm_port;
extern struct rte_hash *conn_hash_handle;
extern struct app_params app;
struct in6_addr dp_comm_ipv6;

static inline void
reset_udp_hdr_checksum(struct rte_mbuf *m, uint8_t ip_type)
{
	struct udp_hdr *udp_hdr;

	/* IF IP_TYPE = 1 i.e IPv4 , 2: IPv6*/
	if (ip_type == IPV6_TYPE) {
		udp_hdr = get_mtoudp_v6(m);
		/* update Udp checksum */
		udp_hdr->dgram_cksum = 0;
		struct ipv6_hdr *ipv6_hdr;

		ipv6_hdr = get_mtoip_v6(m);
		udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udp_hdr);
	} else if (ip_type == IPV4_TYPE) {
		udp_hdr = get_mtoudp(m);
		/* update Udp checksum */
		udp_hdr->dgram_cksum = 0;
		struct ipv4_hdr *ipv4_hdr;

		ipv4_hdr = get_mtoip(m);
		udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
	}
}

/* Tranlator of the IP header */
/* If ip_type = 0; Covert IP header from IPv6 to IPv4 */
/* If ip_type = 1; Covert IP header from IPv4 to IPv6 */
static int
translator_ip_hdr(struct rte_mbuf *m, uint8_t ip_type)
{
	void *ret = NULL;
	uint8_t *pkt_ptr = NULL;
	if (ip_type) {
		/* If ip_type = 1; Covert IP header from IPv4 to IPv6 */
		/* Remove IPv4 header from the packet, IPv4 hdr= 20 Bytes */
		ret = rte_pktmbuf_adj(m, IPv4_HDR_SIZE);
		if (ret == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: Failed to remove IPv4 header\n", LOG_VALUE);
			return -1;
		}
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"TRANS:Remove IPv4 header, modified mbuf offset %d, data len %d, pkt len%u\n",
			LOG_VALUE, m->data_off, m->data_len, m->pkt_len);

		/* Prepend IPv6 header from the packet, IPv6 hdr= 40 Bytes */
		pkt_ptr = (uint8_t *) rte_pktmbuf_prepend(m, IPv6_HDR_SIZE);
		if (pkt_ptr == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to add IPv6 IP header\n", LOG_VALUE);
			return -1;
		}

		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"TRANS:Prepend IPv6 header, modified mbuf offset %d, data len %d, pkt len%u\n",
			LOG_VALUE, m->data_off, m->data_len, m->pkt_len);
	} else {
		/* If ip_type = 0; Covert IP header from IPv6 to IPv4 */
		/* Remove IPv6 header from the packet, IPv6 hdr= 40 Bytes */
		ret = rte_pktmbuf_adj(m, IPv6_HDR_SIZE);
		if (ret == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: Failed to remove IPv6 header\n", LOG_VALUE);
			return -1;
		}
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"TRANS:Remove IPv6 header, modified mbuf offset %d, data len %d, pkt len%u\n",
			LOG_VALUE, m->data_off, m->data_len, m->pkt_len);

		/* Prepend IPv4 header from the packet, IPv4 hdr= 20 Bytes */
		pkt_ptr = (uint8_t *) rte_pktmbuf_prepend(m, IPv4_HDR_SIZE);
		if (pkt_ptr == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to add IPv4 IP header\n", LOG_VALUE);
			return -1;
		}

		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"TRANS:Prepend IPv4 header, modified mbuf offset %d, data len %d, pkt len%u\n",
			LOG_VALUE, m->data_off, m->data_len, m->pkt_len);
	}
	return 0;
}

void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *decap_pkts_mask)
{
	uint32_t i;
	int ret = 0;
	struct ether_hdr *ether = NULL;
	struct ipv4_hdr *ipv4_hdr = NULL;
	struct ipv6_hdr *ipv6_hdr = NULL;
	struct udp_hdr *udp_hdr = NULL;
	struct gtpu_hdr *gtpu_hdr = NULL;
	struct epc_meta_data *meta_data = NULL;

	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*decap_pkts_mask, i))
			continue;

		/* Get the ether header info */
		ether = (struct ether_hdr *)rte_pktmbuf_mtod(pkts[i], uint8_t *);

		/* Process the IPv4 data packets */
		if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
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
			/* Copy eNB IPv4 Address */
			meta_data->ip_type_t.enb_ipv4 = ntohl(ipv4_hdr->src_addr);

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Received tunneled packet with teid 0x%X\n",
				LOG_VALUE, ntohl(meta_data->teid));

			ret = DECAP_GTPU_HDR(pkts[i], NOT_PRESENT);
			if (ret < 0){
				RESET_BIT(*pkts_mask, i);
#ifdef STATS
				--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#endif /* STATS */
			}
		} else if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
			/* Process the IPv6 data packets */

			/* reject if not with s1u/logical intf ipv6 */
			ipv6_hdr = get_mtoip_v6(pkts[i]);
			if (memcmp(&ipv6_hdr->dst_addr, &app.wb_ipv6, IPV6_ADDRESS_LEN) &&
					(memcmp(&ipv6_hdr->dst_addr, &app.wb_li_ipv6, IPV6_ADDRESS_LEN))) {
				RESET_BIT(*pkts_mask, i);
				continue;
			}

			/* reject un-tunneled packet */
			udp_hdr = get_mtoudp_v6(pkts[i]);
			if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
				RESET_BIT(*pkts_mask, i);
				continue;
			}

			/* reject teid zero or non PDU gtpu packet */
			gtpu_hdr = get_mtogtpu_v6(pkts[i]);
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
			/* Get the TEID */
			meta_data->teid = ntohl(gtpu_hdr->teid);
			/* Copy eNB IPv6 Address */
			memcpy(&meta_data->ip_type_t.enb_ipv6, &ipv6_hdr->src_addr, IPV6_ADDRESS_LEN);

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Received tunneled packet with teid 0x%X\n",
				LOG_VALUE, ntohl(meta_data->teid));

			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"From UE IPv6 ADDR:" IPv6_FMT "\n",
					LOG_VALUE, IPv6_PRINT(GTPU_INNER_SRC_IPV6(pkts[i])));

			ret = DECAP_GTPU_HDR(pkts[i], PRESENT);
			if (ret < 0){
				RESET_BIT(*pkts_mask, i);
#ifdef STATS
				--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#endif /* STATS */
			}

		}
	}
}

void
gtpu_encap(pdr_info_t **pdrs, pfcp_session_datat_t **sess_data, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, uint64_t *fd_pkts_mask, uint64_t *pkts_queue_mask)
{
	uint16_t len = 0;
	uint32_t i = 0;
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

		/* Construct the IPv4/IPv6 header */
		if ((pdr->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc == GTPU_UDP_IPv4) {
			if (ENCAP_GTPU_HDR(m,
						(pdr->far)->frwdng_parms.outer_hdr_creation.teid, NOT_PRESENT) < 0) {
#ifdef STATS
				--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Failed to ENCAP GTPU HEADER \n", LOG_VALUE);
				RESET_BIT(*pkts_mask, i);
				continue;
			}
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4: ENCAP Pkt with GTPU HEADER \n", LOG_VALUE);

			len = rte_pktmbuf_data_len(m);
			len = len - ETH_HDR_SIZE;

			/* Construct IPv4 header */
			uint32_t src_addr = 0;
			uint32_t dst_addr = 0;
			/* construct iphdr with destination IP Address */
			dst_addr = ntohl((pdr->far)->frwdng_parms.outer_hdr_creation.ipv4_address);

			/* Validate the Destination IP Address subnet */
			if (validate_Subnet(dst_addr, app.wb_net, app.wb_bcast_addr)) {
				/* construct iphdr with local IP Address */
				src_addr = app.wb_ip;
			} else if (validate_Subnet(dst_addr, app.wb_li_net, app.wb_li_bcast_addr)) {
				/* construct iphdr with local IP Address */
				src_addr = app.wb_li_ip;
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Destination IPv4 Addr "IPV4_ADDR" "
						"is NOT in local intf subnet\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dst_addr));
				RESET_BIT(*pkts_mask, i);
				continue;
			}

			/* Check SRC or DST Address are not Zero */
			if ((!src_addr) || (!dst_addr)) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Not Found Src or Dest IPv4 Addr, SrcAddr: "IPV4_ADDR", "
						"DstAddr: "IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(src_addr),
						IPV4_ADDR_HOST_FORMAT(dst_addr));
				RESET_BIT(*pkts_mask, i);
				continue;
			}

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPv4 hdr: SRC ADDR:"IPV4_ADDR", DST ADDR:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(src_addr),
				IPV4_ADDR_HOST_FORMAT(dst_addr));

			construct_ipv4_hdr(m, len, IP_PROTO_UDP, src_addr, dst_addr);

			len = len - IPv4_HDR_SIZE;

			/* construct udphdr */
			construct_udp_hdr(m, len, UDP_PORT_GTPU, UDP_PORT_GTPU, NOT_PRESENT);
		} else if ((pdr->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc == GTPU_UDP_IPv6) {
			/* If next hop support IPv6 */
			if (ENCAP_GTPU_HDR(m,
						(pdr->far)->frwdng_parms.outer_hdr_creation.teid, PRESENT) < 0) {
#ifdef STATS
				--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Failed to ENCAP GTPU HEADER \n", LOG_VALUE);
				RESET_BIT(*pkts_mask, i);
				continue;
			}
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: ENCAP Pkt with GTPU HEADER \n", LOG_VALUE);
			len = rte_pktmbuf_data_len(m);
			len = len - ETH_HDR_SIZE;

			/* Construct IPv6 header */
			struct in6_addr src_addr = {0};
			struct in6_addr dst_addr = {0};
			struct in6_addr tmp_addr = {0};

			/* construct iphdr with destination IPv6 Address */
			memcpy(&dst_addr.s6_addr,
					(struct in6_addr *)(pdr->far)->frwdng_parms.outer_hdr_creation.ipv6_address,
					IPV6_ADDRESS_LEN);

			/* Validate the Destination IPv6 Address Network */
			if (validate_ipv6_network(dst_addr, app.wb_ipv6,
						app.wb_ipv6_prefix_len)) {
				/* Source interface IPv6 address */
				memcpy(&src_addr, &app.wb_ipv6, sizeof(struct in6_addr));

			} else if (validate_ipv6_network(dst_addr, app.wb_li_ipv6,
					app.wb_li_ipv6_prefix_len)) {
				/* Source interface IPv6 address */
				memcpy(&src_addr, &app.wb_li_ipv6, sizeof(struct in6_addr));

			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Destination S5S8 intf IPv6 addr "IPv6_FMT" "
						"is NOT in local intf Network\n",
						LOG_VALUE, IPv6_PRINT(dst_addr));
				RESET_BIT(*pkts_mask, i);
				continue;
			}

			/* Check SRC or DST IPv6 Address are not Zero */
			if ((!memcmp(&src_addr, &tmp_addr, IPV6_ADDRESS_LEN)) ||
					(!memcmp(&dst_addr, &tmp_addr, IPV6_ADDRESS_LEN))) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Not Found Src or Dest IPv6 Addr, SrcAddr: "IPv6_FMT", "
						"DstAddr: "IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(src_addr), IPv6_PRINT(dst_addr));
				RESET_BIT(*pkts_mask, i);
				continue;
			}

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPv6 hdr: SRC ADDR:"IPv6_FMT", DST ADDR:"IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(src_addr), IPv6_PRINT(dst_addr));

			/* Calculate the payload length for IPv6 header */
			len = len - IPv6_HDR_SIZE;
			construct_ipv6_hdr(m, len, IP_PROTO_UDP, &src_addr, &dst_addr);
			/* construct udphdr */
			construct_udp_hdr(m, len, UDP_PORT_GTPU, UDP_PORT_GTPU, PRESENT);
		}
	}
}

void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *snd_err_pkts_mask,
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

		struct ether_hdr *ether = NULL;
		struct udp_hdr *udp_hdr = NULL;
		struct gtpu_hdr *gtpu_hdr = NULL;

		/* Get the ether header info */
		ether = (struct ether_hdr *)rte_pktmbuf_mtod(pkts[j], uint8_t *);
		if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
			struct ipv4_hdr *ipv4_hdr = NULL;
			/* reject if not with Wstbnd ip */
			ipv4_hdr = get_mtoip(pkts[j]);
			if ((ntohl(ipv4_hdr->dst_addr) != app.wb_ip) &&
					(ntohl(ipv4_hdr->dst_addr) != app.wb_li_ip)) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4: WB_IP or WB_LI_IP is not valid dst ip address:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ipv4_hdr->dst_addr));
#ifdef STATS
				--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#endif /* STATS */
				continue;
			}

			/* reject un-tunneled packet */
			udp_hdr = get_mtoudp(pkts[j]);
			if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4: GTPU UDP PORT is not valid\n", LOG_VALUE);
				continue;
			}

			/* reject pkt if not valid type or teid zero */
			gtpu_hdr = get_mtogtpu(pkts[j]);
			if (gtpu_hdr->teid == 0 ||
					((gtpu_hdr->msgtype != GTP_GPDU) &&
					 (gtpu_hdr->msgtype != GTPU_END_MARKER_REQUEST))) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4: GTPU TEID and MSG TYPE is not valid\n", LOG_VALUE);
				continue;
			}
			key[j].teid = ntohl(gtpu_hdr->teid);
		} else if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
			struct ipv6_hdr *ipv6_hdr = NULL;
			/* reject if not with Wstbnd ip */
			ipv6_hdr = get_mtoip_v6(pkts[j]);

			/* Destination IPv6 Address */
			struct in6_addr ho_addr = {0};
			memcpy(&ho_addr.s6_addr, &ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN);

			/* Validate the destination address is S1U/WB_IPv6 or not */
			if ((memcmp(&(app.wb_ipv6), &ho_addr, IPV6_ADDRESS_LEN))
					&& (memcmp(&(app.wb_li_ipv6), &ho_addr, IPV6_ADDRESS_LEN))) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: WB_IP or WB_LI_IP (Expected:"IPv6_FMT") "
					"is not valid dst ip address:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(app.wb_ipv6), IPv6_PRINT(ho_addr));
#ifdef STATS
				--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#endif /* STATS */
				continue;
			}

			/* reject un-tunneled packet */
			udp_hdr = get_mtoudp_v6(pkts[j]);
			if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: GTPU UDP PORT is not valid\n", LOG_VALUE);
				continue;
			}

			/* reject pkt if not valid type or teid zero */
			gtpu_hdr = get_mtogtpu_v6(pkts[j]);
			if (gtpu_hdr->teid == 0 ||
					((gtpu_hdr->msgtype != GTP_GPDU) &&
					 (gtpu_hdr->msgtype != GTPU_END_MARKER_REQUEST))) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: GTPU TEID and MSG TYPE is not valid\n", LOG_VALUE);
				continue;
			}
			key[j].teid = ntohl(gtpu_hdr->teid);
		}
	}

	if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr[0], n,
			&hit_mask, (void **)sess_data)) < 0) {
		hit_mask = 0;
	}

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
			SET_BIT(*snd_err_pkts_mask, j);
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
		uint64_t *pkts_queue_mask, uint64_t *snd_err_pkts_mask)
{
	uint32_t j = 0, ul_count = 0, dl_count = 0;
	void *key_ptr[MAX_BURST_SZ] = {NULL};
	void *key_ptr_t[MAX_BURST_SZ] = {NULL};
	uint32_t dst_addr = 0;
	uint64_t hit_mask = 0;
	struct dl_bm_key key[MAX_BURST_SZ] = {0};
	struct ul_bm_key key_t[MAX_BURST_SZ] = {0};
        int ul_index[MAX_BURST_SZ] = {0};
        int dl_index[MAX_BURST_SZ] = {0};
        pfcp_session_datat_t *ul_sess_data[MAX_BURST_SZ] = {NULL};
        pfcp_session_datat_t *dl_sess_data[MAX_BURST_SZ] = {NULL};


	/* TODO: downlink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		struct ether_hdr *ether = NULL;
		struct udp_hdr *udp_hdr = NULL;
		struct gtpu_hdr *gtpu_hdr = NULL;

		/* Get the ether header info */
		ether = (struct ether_hdr *)rte_pktmbuf_mtod(pkts[j], uint8_t *);
		/* Handle the IPv4 packets */
		if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
			struct ipv4_hdr *ipv4_hdr = NULL;

			udp_hdr = get_mtoudp(pkts[j]);
			if ((ntohs(udp_hdr->dst_port) == UDP_PORT_GTPU)
					|| (udp_hdr->dst_port == UDP_PORT_GTPU_NW_ORDER)) {


				/* tunnel packets */
				/* reject if not with wb ip */
				ipv4_hdr = get_mtoip(pkts[j]);
				if ((ntohl(ipv4_hdr->dst_addr) != app.eb_ip)
						&& (ntohl(ipv4_hdr->dst_addr) != app.eb_li_ip)) {
					RESET_BIT(*pkts_mask, j);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"IPv4:EB IP is not valid, Exp IP:"IPV4_ADDR" or "IPV4_ADDR","
							"Rcvd_IP:"IPV4_ADDR"\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(app.eb_ip),
							IPV4_ADDR_HOST_FORMAT(app.eb_li_ip),
							IPV4_ADDR_HOST_FORMAT(ntohl(ipv4_hdr->dst_addr)));
#ifdef STATS
					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
					continue;
				}

				gtpu_hdr = get_mtogtpu(pkts[j]);
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
					if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GEMR) {
						RESET_BIT(*pkts_mask, j);
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"IPv4:GTPU TEID:%u and MSG_TYPE:%x is not valid\n",
							LOG_VALUE, gtpu_hdr->teid, gtpu_hdr->msgtype);
						continue;
					}
				}

				ul_index[ul_count] = j;
				key_ptr_t[ul_count] = &key_t[ul_count];
				key_t[ul_count].teid = ntohl(gtpu_hdr->teid);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4:DL_KEY: TEID:%u\n", LOG_VALUE, key_t[ul_count].teid);
				ul_count++;

			} else {
				key[dl_count].ue_ip.ue_ipv4 = 0;
				memset(&key[dl_count].ue_ip.ue_ipv6, 0, sizeof(struct in6_addr));
				key_ptr[dl_count] = &key[dl_count];
				dl_index[dl_count] = j;


				ipv4_hdr = get_mtoip(pkts[j]);
				dst_addr = ipv4_hdr->dst_addr;

				key[dl_count].ue_ip.ue_ipv4 = dst_addr;
				struct epc_meta_data *meta_data =
				(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
									META_DATA_OFFSET);
				meta_data->key.ue_ip.ue_ipv4 = key[dl_count].ue_ip.ue_ipv4;
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4:BEAR SESS LKUP:DL_KEY UE IP:"IPV4_ADDR "\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(meta_data->key.ue_ip.ue_ipv4));
					dl_count++;
			}
		} else if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
			/* Handle the IPv6 Pkts */
			struct ipv6_hdr *ipv6_hdr = NULL;

			udp_hdr = get_mtoudp_v6(pkts[j]);
			if ((ntohs(udp_hdr->dst_port) == UDP_PORT_GTPU)
					|| (udp_hdr->dst_port == UDP_PORT_GTPU_NW_ORDER)) {


				/* tunnel packets */
				/* reject if not with eb ip */
				ipv6_hdr = get_mtoip_v6(pkts[j]);

				/* Destination IPv6 Address */
				struct in6_addr ho_addr = {0};
				memcpy(&ho_addr.s6_addr, &ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN);
				/* Validate the destination address is S1U/WB_IPv6 or not */
				if ((memcmp(&(app.eb_ipv6), &ho_addr, IPV6_ADDRESS_LEN))
						&& (memcmp(&(app.eb_li_ipv6), &ho_addr, IPV6_ADDRESS_LEN))) {
					RESET_BIT(*pkts_mask, j);
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6: EB_IP or EB_LI_IP (Expected:"IPv6_FMT" or "IPv6_FMT") "
						"is not valid dst ip address:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(app.eb_ipv6), IPv6_PRINT(app.eb_li_ipv6),
						IPv6_PRINT(ho_addr));
#ifdef STATS
					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
#endif /* STATS */
					continue;
				}

				gtpu_hdr = get_mtogtpu_v6(pkts[j]);
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
					if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GEMR) {
						RESET_BIT(*pkts_mask, j);
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"IPv6:GTPU TEID:%u and MSG_TYPE:%x is not valid\n",
								LOG_VALUE, gtpu_hdr->teid, gtpu_hdr->msgtype);
						continue;
					}
				}

				ul_index[ul_count] = j;
				key_ptr_t[ul_count] = &key_t[ul_count];
				key_t[ul_count].teid = ntohl(gtpu_hdr->teid);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"IPv6:DL_KEY: TEID:%u\n",
						LOG_VALUE, key_t[ul_count].teid);
				ul_count++;

			} else {
				key[dl_count].ue_ip.ue_ipv4 = 0;
				memset(&key[dl_count].ue_ip.ue_ipv6, 0, sizeof(struct in6_addr));
				key_ptr[dl_count] = &key[dl_count];
	 			dl_index[dl_count] = j;

				ipv6_hdr = get_mtoip_v6(pkts[j]);
				memcpy(&key[dl_count].ue_ip.ue_ipv6, &ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN);

				struct epc_meta_data *meta_data =
				(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
									META_DATA_OFFSET);
				memcpy(&meta_data->key.ue_ip.ue_ipv6, &key[dl_count].ue_ip.ue_ipv6,
						IPV6_ADDRESS_LEN);
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6:BEAR SESS LKUP:DL_KEY UE IP:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)meta_data->key.ue_ip.ue_ipv6));
                                dl_count++;

			}
		}
	}

	if (ul_count && key_ptr_t[0] != NULL) {
		if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr_t[0], ul_count,
						&hit_mask, (void **)ul_sess_data)) < 0) {
			    hit_mask = 0;
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"SDF BEAR Bulk LKUP:FAIL\n", LOG_VALUE);
		}

		for (j = 0; j < ul_count; j++) {
			if (!ISSET_BIT(hit_mask, j)) {
				RESET_BIT(*pkts_mask, ul_index[j]);
				SET_BIT(*snd_err_pkts_mask, ul_index[j]);
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"SDF BEAR LKUP FAIL!! DL KEY "
						"TEID:%u\n", LOG_VALUE, key_t[j].teid);
				si[ul_index[j]] = NULL;
			} else {
				si[ul_index[j]] = ul_sess_data[j];
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SESSION INFO:"
						"TEID:%u, Session State:%u\n", LOG_VALUE, key_t[j].teid,
						(ul_sess_data[j])->sess_state);

				/** Check downlink bearer is ACTIVE or IDLE */
				if (ul_sess_data[j]->sess_state != CONNECTED) {
#ifdef STATS
					--epc_app.dl_params[SGI_PORT_ID].pkts_in;
					++epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts;
#endif /* STATS */
					RESET_BIT(*pkts_mask, ul_index[j]);
					SET_BIT(*pkts_queue_mask, ul_index[j]);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Enqueue Pkts Set the Pkt Mask:%u\n",
							LOG_VALUE, pkts_queue_mask);
				}

			}
		}
	}

	if (dl_count && key_ptr[0] != NULL) {
		if ((iface_lookup_downlink_bulk_data((const void **)&key_ptr[0], dl_count,
				&hit_mask, (void **)dl_sess_data)) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"SDF BEAR Bulk LKUP:FAIL\n", LOG_VALUE);
		}
		for (j = 0; j < dl_count; j++) {
			if (!ISSET_BIT(hit_mask, j)) {
				RESET_BIT(*pkts_mask, dl_index[j]);
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"SDF BEAR LKUP FAIL!! DL KEY "
						"UE IP:"IPV4_ADDR" or "IPv6_FMT"\n", LOG_VALUE,
						IPV4_ADDR_HOST_FORMAT((key[j]).ue_ip.ue_ipv4),
						IPv6_PRINT(*(struct in6_addr *)(key[j]).ue_ip.ue_ipv6));
				si[dl_index[j]] = NULL;
			} else {
				si[dl_index[j]] = dl_sess_data[j];
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SESSION INFO:"
						"UE IP:"IPV4_ADDR" or "IPv6_FMT", ACL TABLE Index: %u "
						"Session State:%u\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT((dl_sess_data[j])->ue_ip_addr),
					IPv6_PRINT(IPv6_CAST((dl_sess_data[j])->ue_ipv6_addr)),
					(dl_sess_data[j])->acl_table_indx, (dl_sess_data[j])->sess_state);
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
		pdr_info_t **pdr, uint8_t loopback_flag)
{
	uint32_t i;
	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			if (construct_ether_hdr(pkts[i], portid, &pdr[i], loopback_flag) < 0)
				RESET_BIT(*pkts_mask, i);
		}
		/* TODO: Set checksum offload.*/
	}
}

void
update_nexts5s8_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *fwd_pkts_mask, uint64_t *loopback_pkts_mask,
		pfcp_session_datat_t **sess_data, pdr_info_t **pdr)
{
	uint32_t i;
	uint16_t len;

	for (i = 0; i < n; i++) {
		if ((ISSET_BIT(*pkts_mask, i)) && (ISSET_BIT(*fwd_pkts_mask, i))) {
			if ((sess_data[i]->pdrs != NULL) &&
					((sess_data[i]->pdrs)->far != NULL)) {
				struct ether_hdr *ether = NULL;
				/* Get the ether header info */
				ether = (struct ether_hdr *)rte_pktmbuf_mtod(pkts[i], uint8_t *);

				/* Construct the IPv4/IPv6 header */
				if (((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc == GTPU_UDP_IPv4) {
					/* Retrieve Next Hop Destination Address */
					uint32_t next_hop_addr =
						ntohl(((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.ipv4_address);

					uint32_t src_addr = 0;
					/* LoopBack: Re-direct Inputs packets to another node from same intf */
					if (((sess_data[i]->pdrs)->pdi.src_intfc.interface_value == ACCESS) &&
							(((sess_data[i]->pdrs)->far)->frwdng_parms.dst_intfc.interface_value == ACCESS)) {
						/* If PDR and FAR info have interface type ACCESS:0, i.e needs to loopback pkts */
						/* Validate the Destination IPv4 Address subnet */
						if (validate_Subnet(next_hop_addr, app.wb_net, app.wb_bcast_addr)) {
							/* Source interface IPv4 address */
							src_addr = app.wb_ip;
						} else if (validate_Subnet(next_hop_addr, app.wb_li_net, app.wb_li_bcast_addr)) {
							/* Source interface IPv4 address */
							src_addr = app.wb_li_ip;
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Destination West Bound intf IPv4 Addr "IPV4_ADDR" "
									"is NOT in local intf subnet\n",
									LOG_VALUE, IPV4_ADDR_HOST_FORMAT(next_hop_addr));
							RESET_BIT(*pkts_mask, i);
							continue;
						}
						SET_BIT(*loopback_pkts_mask, i);
						RESET_BIT(*pkts_mask, i);
					} else {
						/* Validate the Destination IPv4 Address subnet */
						if (validate_Subnet(next_hop_addr, app.eb_net, app.eb_bcast_addr)) {
							/* Source interface IPv4 address */
							src_addr = app.eb_ip;
						} else if (validate_Subnet(next_hop_addr, app.eb_li_net, app.eb_li_bcast_addr)) {
							/* Source interface IPv4 address */
							src_addr = app.eb_li_ip;
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Destination East Bound intf IPv4 Addr "IPV4_ADDR" "
									"is NOT in local intf subnet\n",
									LOG_VALUE, IPV4_ADDR_HOST_FORMAT(next_hop_addr));

							RESET_BIT(*pkts_mask, i);
							continue;
						}
					}

					/* Translator to convert IPv6 header to IPv4 header */
					if ((ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))) {
						if (translator_ip_hdr(pkts[i], NOT_PRESENT)) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Failed to translate IP HDR from IPv6 to IPv4\n",
									LOG_VALUE);
							RESET_BIT(*pkts_mask, i);
							continue;
						}
					}
					len = rte_pktmbuf_data_len(pkts[i]);
					len = len - ETH_HDR_SIZE;
					/* Update the GTP-U header teid of S5S8 PGWU */
					((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
							ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.teid);

					/* Fill the Source and Destination IP address in the IPv4 Header */
					/* RCVD: CORE --> SEND: ACCESS */
					/* RCVD: ACCESS --> SEND: CORE */
					construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP, src_addr, next_hop_addr);
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv4 hdr: SRC ADDR:"IPV4_ADDR", DST ADDR:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(src_addr),
						IPV4_ADDR_HOST_FORMAT(next_hop_addr));

					/* Update the UDP checksum */
					reset_udp_hdr_checksum(pkts[i], IPV4_TYPE);

				} else if (((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc == GTPU_UDP_IPv6) {
					/* Retrieve Next Hop Destination Address */
					struct in6_addr next_hop_addr = {0};

					/* Copy destination address from FAR */
					memcpy(&next_hop_addr.s6_addr,
							((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.ipv6_address,
							IPV6_ADDRESS_LEN);

					/* VS: Validate the Destination IPv6 Address Subnet */
					struct in6_addr src_addr = {0};
					/* LoopBack: Re-direct Inputs packets to another node from same intf */
					if (((sess_data[i]->pdrs)->pdi.src_intfc.interface_value == ACCESS) &&
							(((sess_data[i]->pdrs)->far)->frwdng_parms.dst_intfc.interface_value == ACCESS)) {
						/* If PDR and FAR info have interface type ACCESS:0, i.e needs to loopback pkts */
						/* Validate the Destination IPv6 Address Network */
						if (validate_ipv6_network(next_hop_addr, app.wb_ipv6,
									app.wb_ipv6_prefix_len)) {
							/* Source interface IPv6 address */
							memcpy(&src_addr, &app.wb_ipv6, sizeof(struct in6_addr));
						} else if (validate_ipv6_network(next_hop_addr, app.wb_li_ipv6,
									app.wb_li_ipv6_prefix_len)) {
							/* Source interface IPv6 address */
							memcpy(&src_addr, &app.wb_li_ipv6, sizeof(struct in6_addr));
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Destination S5S8 intf IPv6 addr "IPv6_FMT" "
									"is NOT in local intf Network\n",
									LOG_VALUE, IPv6_PRINT(next_hop_addr));
							RESET_BIT(*pkts_mask, i);
							continue;
						}
						SET_BIT(*loopback_pkts_mask, i);
						RESET_BIT(*pkts_mask, i);
					} else {
						/* Validate the Destination IPv6 Address Network */
						if (validate_ipv6_network(next_hop_addr, app.eb_ipv6,
									app.eb_ipv6_prefix_len)) {
							/* Source interface IPv6 address */
							memcpy(&src_addr, &app.eb_ipv6, sizeof(struct in6_addr));
						} else if (validate_ipv6_network(next_hop_addr, app.eb_li_ipv6,
									app.eb_li_ipv6_prefix_len)) {
							/* Source interface IPv6 address */
							memcpy(&src_addr, &app.eb_li_ipv6, sizeof(struct in6_addr));
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Destination S5S8 intf IPv6 addr "IPv6_FMT" "
									"is NOT in local intf Network\n",
									LOG_VALUE, IPv6_PRINT(next_hop_addr));
							RESET_BIT(*pkts_mask, i);
							continue;
						}
					}

					/* Translator to convert IPv4 header to IPv6 header */
					if ((ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
						if (translator_ip_hdr(pkts[i], PRESENT)) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Failed to translate IP HDR from IPv4 to IPv6\n",
									LOG_VALUE);
							RESET_BIT(*pkts_mask, i);
							continue;
						}
					}

					/* Calculate payload length*/
					len = rte_pktmbuf_data_len(pkts[i]);
					len = len - (ETH_HDR_SIZE + IPv6_HDR_SIZE);
					/* Update the GTP-U header teid of S5S8 PGWU */
					((struct gtpu_hdr *)get_mtogtpu_v6(pkts[i]))->teid  =
							ntohl(((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.teid);

					/* Fill the Source and Destination IP address in the IPv6 Header */
					/* RCVD: CORE --> SEND: ACCESS */
					/* RCVD: ACCESS --> SEND: CORE */
					construct_ipv6_hdr(pkts[i], len, IP_PROTO_UDP, &src_addr, &next_hop_addr);

					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6 hdr: SRC ADDR:"IPv6_FMT", DST ADDR:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(src_addr), IPv6_PRINT(next_hop_addr));

					/* Update the UDP checksum */
					reset_udp_hdr_checksum(pkts[i], IPV6_TYPE);

				} else {
					RESET_BIT(*pkts_mask, i);
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ERR: Outer header Creation Not Set approprietly\n", LOG_VALUE);
				}
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
			if(sess_data[i] != NULL) {
				if ((sess_data[i]->pdrs != NULL) &&
						((sess_data[i]->pdrs)->far != NULL)) {
					struct ether_hdr *ether = NULL;
					/* Get the ether header info */
					ether = (struct ether_hdr *)rte_pktmbuf_mtod(pkts[i], uint8_t *);

					/* Construct the IPv4/IPv6 header */
					if ((((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc == GTPU_UDP_IPv4)
							&& (sess_data[i]->hdr_crt == GTPU_UDP_IPv4)) {
						/* Next hop or destination IPv4 Address */
						uint32_t enb_addr =
							ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.ipv4_address);

						uint32_t src_addr = 0;
						/* Validate the Destination IPv4 Address subnet */
						if (validate_Subnet(enb_addr, app.wb_net, app.wb_bcast_addr)) {
							/* Source interface IPv4 address */
							src_addr = app.wb_ip;
						} else if (validate_Subnet(enb_addr, app.wb_li_net, app.wb_li_bcast_addr)) {
							/* Source interface IPv4 address */
							src_addr = app.wb_li_ip;
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Destination eNB IPv4 Addr "IPV4_ADDR" "
									"is NOT in local intf subnet\n",
									LOG_VALUE, IPV4_ADDR_HOST_FORMAT(enb_addr));
							RESET_BIT(*pkts_mask, i);
							continue;
						}

						/* Translator to convert IPv6 header to IPv4 header */
						if ((ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))) {
							if (translator_ip_hdr(pkts[i], NOT_PRESENT)) {
								clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"Failed to translate IP HDR from IPv6 to IPv4\n",
										LOG_VALUE);
								RESET_BIT(*pkts_mask, i);
								continue;
							}
						}
						/* Calculate the IPv4 header length */
						len = rte_pktmbuf_data_len(pkts[i]);
						len = len - ETH_HDR_SIZE;

						/* Update tied in GTP U header*/
						((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
							ntohl(sess_data[i]->pdrs->far->frwdng_parms.outer_hdr_creation.teid);

						/* Fill the Source and Destination IP address in the IPv4 Header */
						construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP, src_addr, enb_addr);

						/* Update the UDP checksum */
						reset_udp_hdr_checksum(pkts[i], IPV4_TYPE);

						/* Fill the PDR info form the session data */
						pdr[i] = sess_data[i]->pdrs;

					} else if ((((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc == GTPU_UDP_IPv6)
							&& (sess_data[i]->hdr_crt == GTPU_UDP_IPv6)) {
						/* Retrieve Next Hop Destination Address */
						struct in6_addr enb_addr = {0};

						/* Copy destination address from FAR */
						memcpy(&enb_addr.s6_addr,
								((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.ipv6_address,
								IPV6_ADDRESS_LEN);

						/* VS: Validate the Destination IPv6 Address Subnet */
						struct in6_addr src_addr = {0};
						/* Validate the Destination IPv6 Address Network */
						if (validate_ipv6_network(enb_addr, app.wb_ipv6,
									app.wb_ipv6_prefix_len)) {
							/* Source interface IPv6 address */
							memcpy(&src_addr, &app.wb_ipv6, sizeof(struct in6_addr));

						} else if (validate_ipv6_network(enb_addr, app.wb_li_ipv6,
									app.wb_li_ipv6_prefix_len)) {
							/* Source interface IPv6 address */
							memcpy(&src_addr, &app.wb_li_ipv6, sizeof(struct in6_addr));

						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Destination S5S8 intf IPv6 addr "IPv6_FMT" "
									"is NOT in local intf Network\n",
									LOG_VALUE, IPv6_PRINT(enb_addr));
							RESET_BIT(*pkts_mask, i);
							continue;
						}

						/* Translator to convert IPv4 header to IPv6 header */
						if ((ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
							if (translator_ip_hdr(pkts[i], PRESENT)) {
								clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"Failed to translate IP HDR from IPv4 to IPv6\n",
										LOG_VALUE);
								RESET_BIT(*pkts_mask, i);
								continue;
							}
						}

						/* Calculate the payload length */
						len = rte_pktmbuf_data_len(pkts[i]);
						len = len - (ETH_HDR_SIZE + IPv6_HDR_SIZE);

						/* Update the GTP-U header teid of S5S8 PGWU */
						((struct gtpu_hdr *)get_mtogtpu_v6(pkts[i]))->teid  =
							ntohl(((sess_data[i]->pdrs)->far)->frwdng_parms.outer_hdr_creation.teid);

						/* Fill the Source and Destination IP address in the IPv6 Header */
						construct_ipv6_hdr(pkts[i], len, IP_PROTO_UDP, &src_addr, &enb_addr);

						/* Update the UDP checksum */
						reset_udp_hdr_checksum(pkts[i], IPV6_TYPE);

						/* Fill the PDR info form the session data */
						pdr[i] = sess_data[i]->pdrs;
					}
				} else {
					RESET_BIT(*pkts_mask, i);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Session Data don't have PDR info\n", LOG_VALUE);
					sess_data[i]->pdrs = NULL;
					pdr[i] = NULL;
				}
			} else {
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Session Data not found\n", LOG_VALUE);
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
	if (app.generate_pcap == PCAP_GEN_ON && pcap_dumper != NULL) {
		dump_pcap(pkts, n, pcap_dumper);
	}
}

static
void dump_core_pkts_in_pcap(struct rte_mbuf **pkts, uint32_t n,
		pcap_dumper_t *pcap_dumper, uint64_t *pkts_mask)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			struct pcap_pkthdr pcap_hdr;
			uint8_t *pkt = rte_pktmbuf_mtod(pkts[i], uint8_t *);

			pcap_hdr.len = pkts[i]->pkt_len;
			pcap_hdr.caplen = pcap_hdr.len;
			gettimeofday(&(pcap_hdr.ts), NULL);

			pcap_dump((u_char *)pcap_dumper, &pcap_hdr, pkt);
			pcap_dump_flush((pcap_dumper_t *)pcap_dumper);
		}
	}
	return;
}
void
up_core_pcap_dumper(pcap_dumper_t *pcap_dumper,
		struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask)
{
	if (app.generate_pcap == PCAP_GEN_ON && pcap_dumper != NULL) {
		dump_core_pkts_in_pcap(pkts, n, pcap_dumper, pkts_mask);
	}
}

static int update_periodic_timer_value(const int periodic_timer_value) {
	peerData *conn_data = NULL;
	const void *key;
	uint32_t iter = 0;
	app.periodic_timer = periodic_timer_value;
	if(conn_hash_handle != NULL) {
		while (rte_hash_iterate(conn_hash_handle, &key, (void **)&conn_data, &iter) >= 0) {

			/* If Initial timer value was set to 0, then start the timer */
			if (!conn_data->pt.ti_ms) {
					conn_data->pt.ti_ms = (periodic_timer_value * 1000);
					if (startTimer( &conn_data->pt ) < 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Periodic Timer failed to start...\n", LOG_VALUE);
					}
			} else {
					conn_data->pt.ti_ms = (periodic_timer_value * 1000);
			}
		}
	}
	return 0;
}

static int update_transmit_timer_value(const int transmit_timer_value) {
	peerData *conn_data = NULL;
	const void *key;
	uint32_t iter = 0;
	app.transmit_timer = transmit_timer_value;
	if(conn_hash_handle != NULL) {
		while (rte_hash_iterate(conn_hash_handle, &key, (void **)&conn_data, &iter) >= 0) {

			/* If Initial timer value was set to 0, then start the timer */
			if (!conn_data->tt.ti_ms) {
					conn_data->tt.ti_ms = (transmit_timer_value * 1000);
					if (startTimer( &conn_data->tt ) < 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Transmit Timer failed to start...\n", LOG_VALUE);
					}
			} else {
					conn_data->tt.ti_ms = (transmit_timer_value * 1000);
			}
		}
	}
	return 0;
}

int8_t fill_dp_configuration(dp_configuration_t  *dp_configuration)
{
	dp_configuration->dp_type = OSS_USER_PLANE;
	dp_configuration->restoration_params.transmit_cnt = app.transmit_cnt;
	dp_configuration->restoration_params.transmit_timer = app.transmit_timer;
	dp_configuration->restoration_params.periodic_timer = app.periodic_timer;

	dp_configuration->ddf2_port = app.ddf2_port;
	dp_configuration->ddf3_port = app.ddf3_port;
	strncpy(dp_configuration->ddf2_ip, app.ddf2_ip, IPV6_STR_LEN);
	strncpy(dp_configuration->ddf3_ip, app.ddf3_ip, IPV6_STR_LEN);

	strncpy(dp_configuration->ddf2_local_ip, app.ddf2_local_ip, IPV6_STR_LEN);
	strncpy(dp_configuration->ddf3_local_ip, app.ddf3_local_ip, IPV6_STR_LEN);

	strncpy(dp_configuration->wb_iface_name, app.wb_iface_name, MAX_LEN);
	strncpy(dp_configuration->eb_iface_name, app.eb_iface_name, MAX_LEN);

	dp_configuration->wb_li_mask = htonl(app.wb_li_mask);
	dp_configuration->wb_li_ip = htonl(app.wb_li_ip);
	dp_configuration->wb_li_ipv6 = app.wb_li_ipv6;
	dp_configuration->wb_li_ipv6_prefix_len = app.wb_li_ipv6_prefix_len;
	strncpy(dp_configuration->wb_li_iface_name, app.wb_li_iface_name, MAX_LEN);

	dp_configuration->eb_li_mask = htonl(app.eb_li_mask);
	dp_configuration->eb_li_ip = htonl(app.eb_li_ip);
	dp_configuration->eb_li_ipv6 = app.eb_li_ipv6;
	dp_configuration->eb_li_ipv6_prefix_len = app.eb_li_ipv6_prefix_len;
	strncpy(dp_configuration->eb_li_iface_name, app.eb_li_iface_name, MAX_LEN);

	dp_configuration->gtpu_seqnb_out = app.gtpu_seqnb_out;
	dp_configuration->gtpu_seqnb_in = app.gtpu_seqnb_in;

	dp_configuration->numa_on = app.numa_on;
	dp_configuration->teidri_val = app.teidri_val;
	dp_configuration->teidri_timeout = app.teidri_timeout;
	dp_configuration->generate_pcap = app.generate_pcap;
	dp_configuration->dp_comm_ip.s_addr = dp_comm_ip.s_addr;
	dp_configuration->dp_comm_port = ntohs(dp_comm_port);
	dp_configuration->dp_comm_ipv6 = dp_comm_ipv6;
	dp_configuration->pfcp_ipv6_prefix_len = app.pfcp_ipv6_prefix_len;

	dp_configuration->wb_ip = htonl(app.wb_ip);
	dp_configuration->wb_mask = htonl(app.wb_mask);
	set_mac_value(dp_configuration->wb_mac, app.wb_ether_addr.addr_bytes);
	dp_configuration->wb_ipv6 = app.wb_ipv6;
	dp_configuration->wb_ipv6_prefix_len = app.wb_ipv6_prefix_len;

	dp_configuration->eb_ip = htonl(app.eb_ip);
	dp_configuration->eb_mask = htonl(app.eb_mask);
	set_mac_value(dp_configuration->eb_mac, app.eb_ether_addr.addr_bytes);
	dp_configuration->eb_ipv6 = app.eb_ipv6;
	dp_configuration->eb_ipv6_prefix_len = app.eb_ipv6_prefix_len;

	dp_configuration->wb_gw_ip = app.wb_gw_ip;
	dp_configuration->eb_gw_ip = app.eb_gw_ip;
	strncpy(dp_configuration->cli_rest_ip_buff, app.cli_rest_ip_buff, IPV6_STR_LEN);
	dp_configuration->cli_rest_port = app.cli_rest_port;

	return 0;

}

int8_t post_periodic_timer(const int periodic_timer_value) {
	update_periodic_timer_value(periodic_timer_value);
	return 0;
}

int8_t post_transmit_timer(const int transmit_timer_value) {
	update_transmit_timer_value(transmit_timer_value);
	return 0;
}

int8_t post_transmit_count(const int transmit_count) {
	app.transmit_cnt = transmit_count;
	return 0;
}

int8_t post_pcap_status(const int pcap_status) {

	if (app.generate_pcap == pcap_status) {
		return 1;
	}

	app.generate_pcap = pcap_status;

	switch (app.generate_pcap) {
		case PCAP_GEN_ON:
			{
				up_pcap_init();
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"PCAP : Open file for store Packet\n", LOG_VALUE);
				break;
			}
		case PCAP_GEN_OFF:
			{
				close_up_pcap_dump();
				break;
			}
		case PCAP_GEN_RESTART:
			{
				close_up_pcap_dump();
				up_pcap_init();
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"PCAP : Restarted Pcap generation\n", LOG_VALUE);

				app.generate_pcap = PCAP_GEN_ON;
				break;
			}
		default :
			app.generate_pcap = PCAP_GEN_OFF;
			break;
	}
	return 0;
}

int get_periodic_timer(void) {
	return app.periodic_timer;
}

int get_transmit_timer(void) {
	return app.transmit_timer;
}

int get_transmit_count(void) {
	return app.transmit_cnt;
}

int8_t get_pcap_status(void) {
	return app.generate_pcap;
}
