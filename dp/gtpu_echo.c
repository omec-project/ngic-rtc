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

#include <rte_log.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "gw_adapter.h"
#include "ipv4.h"
#include "ipv6.h"
#include "gtpu.h"
#include "util.h"

extern uint8_t dp_restart_cntr;
extern int clSystemLog;
extern struct rte_mbuf *arp_pkt[NUM_SPGW_PORTS];
/* VS: */
//static uint8_t resp_cnt = 1;

/**
 * @brief  : Function to set echo request as echo response
 * @param  : echo_pkt rte_mbuf pointer
 * @param  : ip type
 * @return : Returns nothing
 */
static void reset_req_pkt_as_resp(struct rte_mbuf *echo_pkt, uint8_t ip_type) {
	/* Swap src and destination mac addresses */
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(echo_pkt, struct ether_hdr *);
	struct ether_addr tmp_mac;
	ether_addr_copy(&eth_h->d_addr, &tmp_mac);
	ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
	ether_addr_copy(&tmp_mac, &eth_h->s_addr);

	uint16_t len = rte_pktmbuf_data_len(echo_pkt) - ETH_HDR_LEN;

	struct udp_hdr *udphdr = NULL;
	/* Swap src and dst IP addresses */
	if (ip_type == IPV6_TYPE) {
		len = len - IPv6_HDR_SIZE;
		struct ipv6_hdr *ip_hdr = get_mtoip_v6(echo_pkt);
		uint8_t tmp_addr[16] = {0};
		memcpy(tmp_addr, ip_hdr->dst_addr, IPV6_ADDR_LEN);
		memcpy(ip_hdr->dst_addr, ip_hdr->src_addr, IPV6_ADDR_LEN);
		memcpy(ip_hdr->src_addr, tmp_addr, IPV6_ADDR_LEN);
		ip_hdr->payload_len = htons(len);

		udphdr = get_mtoudp_v6(echo_pkt);
	} else {
		struct ipv4_hdr *ip_hdr = get_mtoip(echo_pkt);
		uint32_t tmp_ip = ip_hdr->dst_addr;
		ip_hdr->dst_addr = ip_hdr->src_addr;
		ip_hdr->src_addr = tmp_ip;
		ip_hdr->total_length = htons(len);
		udphdr = get_mtoudp(echo_pkt);
		len = len - IPV4_HDR_LEN;
	}

	/* Swap src and dst UDP ports */
	uint16_t tmp_port = udphdr->dst_port;
	udphdr->dst_port = udphdr->src_port;
	udphdr->src_port = tmp_port;
	udphdr->dgram_len = htons(len);
}

/**
 * @brief  : Function to set recovery IE
 * @param  : echo_pkt rte_mbuf pointer
 * @param  : ip type
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int set_recovery(struct rte_mbuf *echo_pkt, uint8_t port_id, uint8_t ip_type)
{
	uint16_t len = 0;
	struct gtpu_hdr *gtpu_hdr = get_mtogtpu(echo_pkt);
	gtpu_recovery_ie *recovery_ie = NULL;

	if (ip_type == IPV6_TYPE) {
		struct ipv6_hdr *ip_hdr = get_mtoip_v6(echo_pkt);
		gtpu_hdr = get_mtogtpu_v6(echo_pkt);
		len = ip_hdr->payload_len + IPv6_HDR_SIZE;
	} else {
		struct ipv4_hdr *ip_hdr = get_mtoip(echo_pkt);
		gtpu_hdr = get_mtogtpu(echo_pkt);
		len = ip_hdr->total_length;
	}

	/* VS: Fix the recovery IE issue for response */
	/* Get the extra len bytes for recovery */
	uint16_t extra_len = echo_pkt->pkt_len - (ETHER_HDR_LEN + ntohs(len));

	if (extra_len < sizeof(gtpu_recovery_ie)) {
		recovery_ie = (gtpu_recovery_ie *)rte_pktmbuf_append(echo_pkt, (sizeof(gtpu_recovery_ie) - extra_len));
		/* Checking the sufficient header room lenght for the recovery */
		if ((echo_pkt->pkt_len - (ETHER_HDR_LEN + len)) <  sizeof(gtpu_recovery_ie)) {
			fprintf(stderr, "ERROR: For recovery there is not sufficient lenght is allocated\n");
			return -1;
		}
	}

	/* Point to the current location of the recovery ie */
	recovery_ie = (gtpu_recovery_ie*)((char*)gtpu_hdr + GTPU_HDR_SIZE + ntohs(gtpu_hdr->msglen));

	if (recovery_ie == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Couldn't "
			"append %lu bytes to memory buffer",
			LOG_VALUE, sizeof(gtpu_recovery_ie));
		 return -1;
	}

	gtpu_hdr->msgtype = GTPU_ECHO_RESPONSE;
	gtpu_hdr->msglen = htons(ntohs(gtpu_hdr->msglen)+
		sizeof(gtpu_recovery_ie));
	recovery_ie->type = GTPU_ECHO_RECOVERY;
	recovery_ie->restart_cntr = 0;
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"DP restart count: %d, recovery ie restart counter: %d \n",
		LOG_VALUE, dp_restart_cntr, recovery_ie->restart_cntr);
	return 0;
}

/**
 * @brief  : Function to set checksum of IPv4 and UDP header
 * @param  : echo_pkt rte_mbuf pointer
 * @param  : ip type
 * @return : Returns nothing
 */
static void set_checksum(struct rte_mbuf *echo_pkt, uint8_t ip_type)
{
	if (ip_type == IPV6_TYPE) {
		struct ipv6_hdr *ipv6hdr = get_mtoip_v6(echo_pkt);
		struct udp_hdr *udphdr = get_mtoudp_v6(echo_pkt);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6hdr, udphdr);
	} else {
		struct ipv4_hdr *ipv4hdr = get_mtoip(echo_pkt);
		ipv4hdr->hdr_checksum = 0;
		struct udp_hdr *udphdr = get_mtoudp(echo_pkt);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4hdr, udphdr);
		ipv4hdr->hdr_checksum = rte_ipv4_cksum(ipv4hdr);
	}
}

void process_echo_request(struct rte_mbuf *echo_pkt, uint8_t port_id, uint8_t ip_type) {
	int ret;
	ret = set_recovery(echo_pkt, port_id, ip_type);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to create echo response\n", LOG_VALUE);
		return;
	}

	reset_req_pkt_as_resp(echo_pkt, ip_type);
	set_checksum(echo_pkt, ip_type);
}

/**
 * @brief  : Function to set error indication header information 
 * @param  : gtpu_pkt rte_mbuf pointer
 * @param  : ip type
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int set_err_ind_hdr_info(struct rte_mbuf *gtpu_pkt, uint8_t port_id,
		uint8_t ip_type)
{
	uint16_t len = 0, gtpu_len = 0;
	uint32_t teid = 0;
	struct gtpu_hdr *gtpu_hdr = NULL;
	gtpu_peer_address_ie *peer_addr_ie = NULL;
	struct teid_data_identifier *teid_1 = NULL;

	if (ip_type == IPV6_TYPE) {
		gtpu_hdr = (struct gtpu_hdr *)get_mtogtpu_v6(gtpu_pkt);
	} else {
		gtpu_hdr = (struct gtpu_hdr *)get_mtogtpu(gtpu_pkt);
	}

	/* Get the gtpu pkt len and teid */
	gtpu_len = gtpu_hdr->msglen;
	teid = gtpu_hdr->teid;
	gtpu_hdr->teid = 0;
	gtpu_hdr->seq = 0;

	/* Reset the gtpu payload */
	gtpu_hdr->msglen = 0;

	/* Update the gtpu pkt type*/
	gtpu_hdr->msgtype = GTPU_ERROR_INDICATION;
	/* Update the pkt len*/
	gtpu_hdr->msglen = htons(sizeof(struct teid_data_identifier));

	teid_1 = (struct teid_data_identifier *)((char *)gtpu_hdr + GTPU_HDR_SIZE);
	if (teid_1 == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERR_IND:teid_1:Couldn't "
			"append %lu bytes to memory buffer",
			LOG_VALUE, sizeof(teid_1));
		 return -1;
	}

	/* Update the teid type */
	teid_1->type = GTPU_TEID_DATA_TYPE;
	/* Update the teid */
	teid_1->teid_data_identifier = teid;

	/* Point to the current location of the recovery ie */
	peer_addr_ie = (gtpu_peer_address_ie *)((char*)gtpu_hdr + GTPU_HDR_SIZE + ntohs(gtpu_hdr->msglen));

	if (peer_addr_ie == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERR_IND:peer_addr_ie:Couldn't "
			"append %lu bytes to memory buffer",
			LOG_VALUE, sizeof(peer_addr_ie));
		 return -1;
	}

	memset(peer_addr_ie, 0, sizeof(gtpu_peer_address_ie));

	/* Fill the error indication info */	
	peer_addr_ie->type = GTPU_PEER_ADDRESS;
	len += (sizeof(peer_addr_ie->type) + sizeof(peer_addr_ie->length));

	/* Fill the IP Address of the header */ 
	if (ip_type == IPV6_TYPE) {
		struct ipv6_hdr *ip_hdr = get_mtoip_v6(gtpu_pkt);
		memcpy(peer_addr_ie->addr.ipv6_addr, ip_hdr->dst_addr, IPV6_ADDR_LEN);
		peer_addr_ie->length = htons(IPV6_ADDR_LEN);
		len += IPV6_ADDR_LEN;
	} else {
		struct ipv4_hdr *ip_hdr = get_mtoip(gtpu_pkt);
		peer_addr_ie->addr.ipv4_addr = ip_hdr->dst_addr;
		peer_addr_ie->length = htons(sizeof(peer_addr_ie->addr.ipv4_addr));
		len += sizeof(peer_addr_ie->addr.ipv4_addr);
	}

	/* Update the gtpu payload length */
	gtpu_hdr->msglen = htons(len + sizeof(struct teid_data_identifier));
	gtpu_pkt->pkt_len = (gtpu_pkt->pkt_len - ntohs(gtpu_len)) + ntohs(gtpu_hdr->msglen);
	gtpu_pkt->data_len = gtpu_pkt->pkt_len;
	
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Pkt descarded and sends error indication to peer node.\n",
		LOG_VALUE);
	return 0;
}

void send_error_indication_pkt(struct rte_mbuf *gtpu_pkt, uint8_t port_id)
{
	int ret = 0;
	uint8_t ip_type = 0;

	/* Find the IP Type */
	struct ether_hdr *ether = NULL;
	ether = (struct ether_hdr *)rte_pktmbuf_mtod(gtpu_pkt, uint8_t *);
	if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		ip_type = IPV4_TYPE;
	} else if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		ip_type = IPV6_TYPE;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to send error indication pkt, IP Address type not set \n", LOG_VALUE);
		return;
	}

	ret = set_err_ind_hdr_info(gtpu_pkt, port_id, ip_type);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to update error indication pkt\n", LOG_VALUE);
		return;
	}

	reset_req_pkt_as_resp(gtpu_pkt, ip_type);
	set_checksum(gtpu_pkt, ip_type);

	/* Send the pkt to peer node */
	/* Send ICMPv6 Router Advertisement resp */
	int pkt_size =
		RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
	/* arp_pkt @arp_xmpool[port_id] */
	struct rte_mbuf *pkt1 = arp_pkt[port_id];
	if (pkt1) {
		memcpy(pkt1, gtpu_pkt, pkt_size);
		if (rte_ring_enqueue(shared_ring[port_id], pkt1) == -ENOBUFS) {
			rte_pktmbuf_free(pkt1);
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"RA:Can't queue pkt- ring full"
					" Dropping pkt\n", LOG_VALUE);
			return;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"ERROR_INDICATION: Sends the Error Indication pkts to peer node.\n",LOG_VALUE);
	}
#ifdef STATS
	if(port_id == SGI_PORT_ID) {
		++epc_app.dl_params[port_id].pkts_err_out;
	} else {
		++epc_app.ul_params[port_id].pkts_err_out;
	}
#endif /* STATS */
}
