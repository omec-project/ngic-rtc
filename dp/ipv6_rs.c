/*
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

extern int clSystemLog;

uint16_t remove_hdr_len = 0;


/**
 * @brief  : Function to set router solicitation request as router advertisement response
 * @param  : pkt rte_mbuf pointer
 * @return : Returns nothing
 */
static void reset_req_pkt_as_resp(struct rte_mbuf *pkt) {
	uint16_t len = 0;
	struct udp_hdr *udphdr = NULL;
	/* Get the Pkt Len */
	len = rte_pktmbuf_data_len(pkt);

	/* Swap src and destination mac addresses */
	struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ether_addr tmp_mac;
	ether_addr_copy(&eth->d_addr, &tmp_mac);
	ether_addr_copy(&eth->s_addr, &eth->d_addr);
	ether_addr_copy(&tmp_mac, &eth->s_addr);

	/* Swap src and dst IP addresses */
	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		struct ipv4_hdr *ip_hdr = get_mtoip(pkt);
		uint32_t tmp_ip = ip_hdr->dst_addr;
		ip_hdr->dst_addr = ip_hdr->src_addr;
		ip_hdr->src_addr = tmp_ip;

		len = len - ETH_HDR_SIZE;
		ip_hdr->total_length = htons(len);

		/* Update len for UDP Header */
		len = len - IPv4_HDR_SIZE;
		udphdr = get_mtoudp(pkt);
	} else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		struct ipv6_hdr *ip_hdr = get_mtoip_v6(pkt);
		uint8_t tmp_ip[IPV6_ADDR_LEN] = {0};
		memcpy(&tmp_ip, &ip_hdr->dst_addr, IPV6_ADDR_LEN);
		memcpy(&ip_hdr->dst_addr, &ip_hdr->src_addr, IPV6_ADDR_LEN);
		memcpy(&ip_hdr->src_addr, &tmp_ip, IPV6_ADDR_LEN);

		len = len - (IPv6_HDR_SIZE + ETH_HDR_SIZE);
		ip_hdr->payload_len = htons(len);

		udphdr = get_mtoudp_v6(pkt);
	}

	/* Swap src and dst UDP ports */
	uint16_t tmp_port = udphdr->dst_port;
	udphdr->dst_port = udphdr->src_port;
	udphdr->src_port = tmp_port;

	udphdr->dgram_len = htons(len);
}

/**
 * @brief  : Function to set ipv6 router advertisement IE
 * @param  : pkt rte_mbuf pointer
 * @param  : teid tunnel identifier
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int set_ipv6_ra(struct rte_mbuf *pkt, uint32_t teid)
{
	uint16_t len = 0, total_len = 0;
	struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct gtpu_hdr *gtpu_hdr = NULL;
	struct ipv6_hdr *ipv6_hdr = NULL;
	struct icmp6_hdr_ra *router_advert = NULL;

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		gtpu_hdr = get_mtogtpu(pkt);
		total_len += IPV4_HDR_LEN;
	} else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		gtpu_hdr = get_mtogtpu_v6(pkt);
		total_len += IPv6_HDR_SIZE;
	}
	total_len += (ETHER_HDR_LEN + UDP_HDR_SIZE + GTPU_HDR_SIZE + IPv6_HDR_SIZE);

	/* Update Inner IPv6 header */
	ipv6_hdr = (struct ipv6_hdr*)((char*)gtpu_hdr + GTPU_HDR_SIZE);
	len = sizeof(struct icmp6_hdr_ra) - htons(ipv6_hdr->payload_len);
	remove_hdr_len = htons(ipv6_hdr->payload_len);

	router_advert = (struct icmp6_hdr_ra *)rte_pktmbuf_append(pkt, len);
	if ((pkt->pkt_len - total_len) < sizeof(struct icmp6_hdr_ra)) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"RA:Couldn't "
			"append %u bytes to memory buffer, pkt_len:%u, total_len:%u, ipv6_payload_len:%u\n",
			LOG_VALUE, len, pkt->pkt_len, total_len, htons(ipv6_hdr->payload_len));
		 return -1;
	}

	/* Update the payload entry */
	ipv6_hdr->payload_len = htons(sizeof(struct icmp6_hdr_ra));

	/* Swap Src Addr to DST Address */
	memcpy(&ipv6_hdr->dst_addr, &ipv6_hdr->src_addr, IPV6_ADDR_LEN);

	/* Point to the current location of the router advertisement ie */
	router_advert = (struct icmp6_hdr_ra*)((char*)gtpu_hdr + GTPU_HDR_SIZE + IPv6_HDR_SIZE);
	if (router_advert == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"RA:Couldn't "
			"append %u bytes to memory buffer",
			LOG_VALUE, len);
		 return -1;
	}

	/* Setting the GTPU Header Info */
	gtpu_hdr->msgtype = GTP_GPDU;
	gtpu_hdr->teid = teid;
	gtpu_hdr->msglen = htons(IPv6_HDR_SIZE +
		sizeof(struct icmp6_hdr_ra));

	memset(router_advert, 0, sizeof(struct icmp6_hdr_ra));

	/* Fill the router advertisement message information */
	router_advert->icmp.icmp6_type = ICMPv6_ROUTER_ADVERTISEMENT;
	router_advert->icmp.icmp6_code = 0;
	router_advert->icmp.icmp6_data.icmp6_data8[0] = 64;
	router_advert->icmp.icmp6_data.icmp6_data8[1] = 0;
	router_advert->icmp.icmp6_data.icmp6_data16[1] = 65535;
	router_advert->icmp6_reachable_time = 0;
	router_advert->icmp6_retrans_time = 0;
	router_advert->opt.type = PREFIX_INFORMATION;
	router_advert->opt.flags = 0;
	router_advert->opt.valid_lifetime = 0xffffffff;
	router_advert->opt.preferred_lifetime = 0xffffffff;
	router_advert->opt.reserved = 0;
	router_advert->opt.length = 4;
	router_advert->opt.prefix_length = 0;
	memset(&router_advert->opt.prefix_addr, 0, IPV6_ADDR_LEN);

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"RA: Added Router Advert IE in the pkt. \n", LOG_VALUE);
	return 0;
}

/**
 * @brief  : Function to set checksum of IPv4 and UDP header
 * @param  : pkt rte_mbuf pointer
 * @return : Returns nothing
 */
void ra_set_checksum(struct rte_mbuf *pkt)
{
	struct udp_hdr *udphdr = NULL;
	struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		struct ipv4_hdr *ipv4hdr = get_mtoip(pkt);
		ipv4hdr->hdr_checksum = 0;
		udphdr = get_mtoudp(pkt);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4hdr, udphdr);
		ipv4hdr->hdr_checksum = rte_ipv4_cksum(ipv4hdr);
	}else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		/* Note: IPv6 header not contain the checksum */
		struct ipv6_hdr *ipv6hdr = get_mtoip_v6(pkt);
		udphdr = get_mtoudp_v6(pkt);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6hdr, udphdr);
	}
}

void process_router_solicitation_request(struct rte_mbuf *pkt, uint32_t teid)
{
	int ret;
	remove_hdr_len = 0;

	ret = set_ipv6_ra(pkt, teid);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to create router advert resp msg\n", LOG_VALUE);
		return;
	}

	reset_req_pkt_as_resp(pkt);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"RS: Resp packet created for router advert resp msg\n", LOG_VALUE);
}
