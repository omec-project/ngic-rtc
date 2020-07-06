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

#ifndef _IPV4_H_
#define _IPV4_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane IPv4 header constructor.
 */
#include <stdint.h>
#include <rte_ip.h>
#include "util.h"
#ifdef DP_BUILD
#include "up_main.h"
#endif /* DP_BUILD */

/**
 * @brief  : Function to return pointer to ip headers, assuming ether header is untagged.
 * @param  : m, mbuf pointer
 * @return : pointer to ipv4 headers
 */
static inline struct ipv4_hdr *get_mtoip(struct rte_mbuf *m)
{
#ifdef DPDK_2_1
	return (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE);
#else
	return rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
				       sizeof(struct ether_hdr));
#endif

}

/**
 * @brief  : Function to construct IPv4 header with default values.
 * @param  : m, mbuf pointer
 * @return : Returns nothing
 */
static inline void build_ipv4_default_hdr(struct rte_mbuf *m)
{
	struct ipv4_hdr *ipv4_hdr;

	ipv4_hdr = get_mtoip(m);

	/* construct IPv4 header with hardcode values */
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->packet_id = 0x1513;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->time_to_live = 64;
	ipv4_hdr->total_length = 0;
	ipv4_hdr->next_proto_id = 0;
	ipv4_hdr->src_addr = 0;
	ipv4_hdr->dst_addr = 0;
}

/**
 * @brief  : Function to construct IPv4 header with default values.
 * @param  : m, mbuf pointer
 * @param  : len, len of header
 * @param  : protocol, next protocol id
 * @param  : src_ip, Source ip address
 * @param  : dst_ip, destination ip address
 * @return : Returns nothing
 */
static inline void
set_ipv4_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
	     uint32_t src_ip, uint32_t dst_ip)
{
	struct ipv4_hdr *ipv4_hdr;

	ipv4_hdr = get_mtoip(m);

	/* Set IPv4 header values */
	ipv4_hdr->total_length = htons(len);
	ipv4_hdr->next_proto_id = protocol;
	ipv4_hdr->src_addr = htonl(src_ip);
	ipv4_hdr->dst_addr = htonl(dst_ip);

}

/**
 * @brief  : Function to construct ipv4 header.
 * @param  : m, mbuf pointer
 * @param  : len, len of header
 * @param  : protocol, next protocol id
 * @param  : src_ip, Source ip address
 * @param  : dst_ip, destination ip address
 * @return : Returns nothing
 */
void
construct_ipv4_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
		   uint32_t src_ip, uint32_t dst_ip);

#endif				/* _IPV4_H_ */
