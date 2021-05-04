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

#include "ipv4.h"
#include "ipv6.h"
#include "gtpu.h"
#include "util.h"
#include "pfcp_util.h"
#include "gw_adapter.h"

#define IP_PROTO_UDP   17
#define UDP_PORT_GTPU  2152
#define GTPU_OFFSET    50
#define GTPu_VERSION	0x20
#define GTPu_PT_FLAG	0x10
#define GTPu_E_FLAG		0x04
#define GTPu_S_FLAG		0x02
#define GTPu_PN_FLAG	0x01
#define PKT_SIZE    54

extern int clSystemLog;

/**
 * @brief  : Function to set checksum of IPv4 and UDP header
 * @param  : echo_pkt rte_mbuf pointer
 * @param  : IP header type, IPv4 or IPv6
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

/**
 * @brief  : Encapsulate gtpu header
 * @param  : m, rte_mbuf pointer
 * @param  : gtpu_seqnb, sequence number
 * @param  : type, message type
 * @param  : IP header type, IPv4 or IPv6
 * @return : Returns nothing
 */
static __inline__ void encap_gtpu_hdr(struct rte_mbuf *m, uint16_t gtpu_seqnb,
		uint8_t type, uint8_t ip_type)
{
	uint32_t teid = 0;
	uint16_t len = 0;
	gtpuHdr_t  *gtpu_hdr = NULL;

	/* Insert the headers on pkts */
	if (ip_type == IPV6_TYPE) {
		len = rte_pktmbuf_data_len(m) - (ETH_HDR_LEN + IPv6_HDR_SIZE + UDP_HDR_LEN);
		gtpu_hdr = (gtpuHdr_t*)(rte_pktmbuf_mtod(m, unsigned char *) +
			ETH_HDR_LEN + IPv6_HDR_SIZE + UDP_HDR_LEN);
	} else {
		len = rte_pktmbuf_data_len(m) - (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN);
		gtpu_hdr = (gtpuHdr_t*)(rte_pktmbuf_mtod(m, unsigned char *) +
			ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN);
	}

	len -= GTPU_HDR_LEN;

	/* Filling GTP-U header */
	gtpu_hdr->version_flags = (GTPU_VERSION << 5) | (GTP_PROTOCOL_TYPE_GTP << 4) | (GTP_FLAG_SEQNB);
	gtpu_hdr->msg_type = type;
	gtpu_hdr->teid = htonl(teid);
	gtpu_hdr->seq_no = htons(gtpu_seqnb);
	gtpu_hdr->tot_len = htons(len);
}


/**
 * @brief  : Create and initialize udp header
 * @param  : m, rte_mbuf pointer
 * @param  : entry, peer node information
 * @param  : IP header type, IPv4 or IPv6
 * @return : Returns nothing
 */
static __inline__ void create_udp_hdr(struct rte_mbuf *m, peerData *entry,
		uint8_t ip_type)
{
	uint16_t len = 0;
	struct udp_hdr *udp_hdr = NULL;
	/* Get the UDP Header */
	if (ip_type == IPV6_TYPE) {
		len = rte_pktmbuf_data_len(m)- ETH_HDR_LEN - IPv6_HDR_SIZE;
		udp_hdr = (struct udp_hdr*)(rte_pktmbuf_mtod(m, unsigned char *) +
				ETH_HDR_LEN + IPv6_HDR_SIZE);
	} else {
		len = rte_pktmbuf_data_len(m)- ETH_HDR_LEN - IPV4_HDR_LEN;
		udp_hdr = (struct udp_hdr*)(rte_pktmbuf_mtod(m, unsigned char *) +
				ETH_HDR_LEN + IPV4_HDR_LEN);
	}

	udp_hdr->src_port = htons(UDP_PORT_GTPU);
	udp_hdr->dst_port = htons(UDP_PORT_GTPU);
	udp_hdr->dgram_len = htons(len);
	udp_hdr->dgram_cksum = 0;
}


/**
 * @brief  : Create and initialize ipv4 header
 * @param  : m, rte_mbuf pointer
 * @param  : entry, peer node information
 * @param  : IP header type, IPv4 or IPv6
 * @return : Returns nothing
 */
static __inline__ void create_ip_hdr(struct rte_mbuf *m, peerData *entry,
		uint8_t ip_type)
{
	uint16_t len = rte_pktmbuf_data_len(m)- ETH_HDR_LEN;

	if (ip_type == IPV6_TYPE) {
		struct ipv6_hdr *ipv6_hdr =
			(struct ipv6_hdr*)(rte_pktmbuf_mtod(m, unsigned char*) + ETH_HDR_LEN);
		/* construct IPv6 header with hardcode values */
		ipv6_hdr->vtc_flow = IPv6_VERSION;
		ipv6_hdr->payload_len = htons(len - IPv6_HDR_SIZE);
		ipv6_hdr->proto = IP_PROTO_UDP;
		ipv6_hdr->hop_limits = 0;
		memcpy(&ipv6_hdr->src_addr, &entry->srcIP.ipv6_addr,
				IPV6_ADDR_LEN);
		memcpy(&ipv6_hdr->dst_addr, &entry->dstIP.ipv6_addr,
				IPV6_ADDR_LEN);
	} else {
		struct ipv4_hdr *ipv4_hdr =
			(struct ipv4_hdr*)(rte_pktmbuf_mtod(m, unsigned char*) + ETH_HDR_LEN);
		ipv4_hdr->version_ihl = 0x45;
		ipv4_hdr->type_of_service = 0;
		ipv4_hdr->packet_id = 0x1513;
		ipv4_hdr->fragment_offset = 0;
		ipv4_hdr->time_to_live = 64;
		ipv4_hdr->next_proto_id = IP_PROTO_UDP;
		ipv4_hdr->total_length = htons(len);
		ipv4_hdr->src_addr = entry->srcIP.ipv4_addr;
		ipv4_hdr->dst_addr = entry->dstIP.ipv4_addr;
		ipv4_hdr->hdr_checksum = 0;
	}
}


/**
 * @brief  : Create and initialize ether header
 * @param  : m, rte_mbuf pointer
 * @param  : entry, peer node information
 * @param  : IP header type, IPv4 or IPv6
 * @return : Returns nothing
 */
static __inline__ void create_ether_hdr(struct rte_mbuf *m, peerData *entry,
		uint8_t ip_type)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod(m, void*);
	ether_addr_copy(&entry->dst_eth_addr, &eth_hdr->d_addr);
	ether_addr_copy(&entry->src_eth_addr, &eth_hdr->s_addr);

	if (ip_type == IPV6_TYPE) {
		eth_hdr->ether_type = htons(ETHER_TYPE_IPv6);
	} else {
		eth_hdr->ether_type = htons(ETHER_TYPE_IPv4);
	}
}


void build_echo_request(struct rte_mbuf *echo_pkt, peerData *entry, uint16_t gtpu_seqnb)
{
	if (echo_pkt != NULL) {
		echo_pkt->pkt_len = PKT_SIZE;
		echo_pkt->data_len = PKT_SIZE;

		if (entry->dstIP.ip_type == IPV6_TYPE) {
			echo_pkt->pkt_len -= IPV4_HDR_LEN;
			echo_pkt->pkt_len += IPv6_HDR_SIZE;
			echo_pkt->data_len = echo_pkt->pkt_len;

			encap_gtpu_hdr(echo_pkt, gtpu_seqnb, GTPU_ECHO_REQUEST, IPV6_TYPE);
			create_udp_hdr(echo_pkt, entry, IPV6_TYPE);
			create_ip_hdr(echo_pkt, entry, IPV6_TYPE);
			create_ether_hdr(echo_pkt, entry, IPV6_TYPE);
		} else {
			encap_gtpu_hdr(echo_pkt, gtpu_seqnb, GTPU_ECHO_REQUEST, IPV4_TYPE);
			create_udp_hdr(echo_pkt, entry, IPV4_TYPE);
			create_ip_hdr(echo_pkt, entry, IPV4_TYPE);
			create_ether_hdr(echo_pkt, entry, IPV4_TYPE);
		}

		/* Set outer IP and UDP checksum, after inner IP and UDP checksum is set.
		 */
		set_checksum(echo_pkt, entry->dstIP.ip_type);
	}
}

void build_endmarker_and_send(struct sess_info_endmark *edmk)
{
	static uint16_t seq = 0;
	uint16_t len = 0;
	peerData entry = {0};
	gtpuHdr_t *gtpu_hdr = NULL;

	entry.dstIP = edmk->dst_ip;
	entry.srcIP = edmk->src_ip;

	memcpy(&(entry.src_eth_addr), &(edmk->source_MAC), sizeof(struct ether_addr));
	memcpy(&(entry.dst_eth_addr), &(edmk->destination_MAC), sizeof(struct ether_addr));

	struct rte_mbuf *endmk_pkt = rte_pktmbuf_alloc(echo_mpool);
	endmk_pkt->pkt_len = PKT_SIZE;
	endmk_pkt->data_len = PKT_SIZE;

	if (entry.dstIP.ip_type == IPV6_TYPE) {
		/* Update the packet length */
		endmk_pkt->pkt_len -= IPV4_HDR_LEN;
		endmk_pkt->pkt_len += IPv6_HDR_SIZE;
		endmk_pkt->data_len = endmk_pkt->pkt_len;

		len = rte_pktmbuf_data_len(endmk_pkt) - (ETH_HDR_LEN + IPv6_HDR_SIZE + UDP_HDR_LEN);

		len -= GTPU_HDR_LEN;

		gtpu_hdr = (gtpuHdr_t*)(rte_pktmbuf_mtod(endmk_pkt, unsigned char *) +
				ETH_HDR_LEN + IPv6_HDR_SIZE + UDP_HDR_LEN);

	} else if (entry.dstIP.ip_type == IPV4_TYPE) {
		len = rte_pktmbuf_data_len(endmk_pkt) - (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN);

		len -= GTPU_HDR_LEN;

		gtpu_hdr = (gtpuHdr_t*)(rte_pktmbuf_mtod(endmk_pkt, unsigned char *) +
				ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN);
	}

	gtpu_hdr->version_flags = (GTPU_VERSION << 5) | (GTP_PROTOCOL_TYPE_GTP << 4) | (GTP_FLAG_SEQNB);
	gtpu_hdr->msg_type = GTPU_END_MARKER_REQUEST;
	gtpu_hdr->teid = htonl(edmk->teid);
	gtpu_hdr->seq_no = htons(++seq);
	gtpu_hdr->tot_len = htons(len);

	if (entry.dstIP.ip_type == IPV6_TYPE) {
		create_udp_hdr(endmk_pkt, &entry, IPV6_TYPE);
		create_ip_hdr(endmk_pkt, &entry, IPV6_TYPE);
		create_ether_hdr(endmk_pkt, &entry, IPV6_TYPE);

		set_checksum(endmk_pkt, IPV6_TYPE);
	} else if (entry.dstIP.ip_type == IPV4_TYPE) {
		create_udp_hdr(endmk_pkt, &entry, IPV4_TYPE);
		create_ip_hdr(endmk_pkt, &entry, IPV4_TYPE);
		create_ether_hdr(endmk_pkt, &entry, IPV4_TYPE);

		set_checksum(endmk_pkt, IPV4_TYPE);
	}


	if (rte_ring_enqueue(shared_ring[S1U_PORT_ID], endmk_pkt) == -ENOBUFS) {
		rte_pktmbuf_free(endmk_pkt);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Can't Queue Endmarker "
			"PKT because shared ring full so Dropping PKT\n", LOG_VALUE);
		return;
	}

	(edmk->dst_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"END_MAKER: Send the End Marker pkts to ipv6_addr:"IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(edmk->dst_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"END_MAKER: Send the End Marker pkts to ipv4_addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(edmk->dst_ip.ipv4_addr));
}
