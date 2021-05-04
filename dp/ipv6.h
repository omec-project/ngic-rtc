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

#ifndef _IPV6_H_
#define _IPV6_H_
#include <stdint.h>
#include <rte_ip.h>

#include "util.h"
#include "gtpu.h"

/* ICMPv6 Messages define */
#define ICMPv6_ROUTER_SOLICITATION    (0x85)
#define ICMPv6_ROUTER_ADVERTISEMENT   (0x86)
#define ICMPv6_NEIGHBOR_SOLICITATION  (0x87)
#define ICMPv6_NEIGHBOR_ADVERTISEMENT (0x88)

/* ICMPv6 Options */
/* Source Link Layer Address */
#define SRC_LINK_LAYER_ADDR (0x01)
/* Target Link Layer Address */
#define TRT_LINK_LAYER_ADDR (0x02)
/* Prefix information */
#define PREFIX_INFORMATION  (0x03)


struct icmpv6_header {
	uint8_t  icmp6_type;            /* ICMP6 packet type. */
	uint8_t  icmp6_code;            /* ICMP6 packet code. */
	uint16_t icmp6_cksum;           /* ICMP6 packet checksum. */
	union {
		uint32_t icmp6_data32[1];   /* type-specific field */
		uint16_t icmp6_data16[2];   /* type-specific field: Router lifetime */
		uint8_t icmp6_data8[4];     /* type-specific field: Cur Hop limit, flags */
	}icmp6_data;
}__attribute__((__packed__));

struct icmp6_prefix_options {
	uint8_t  type;                           /* Prefix Information */
	uint8_t  length;                         /* Length */
	uint8_t  prefix_length;                  /* Prefix Length */
	uint8_t  flags;                          /* Flags */
	uint32_t valid_lifetime;                 /* Valid Lifetime */
	uint32_t preferred_lifetime;             /* Preferred Lifetime */
	uint32_t reserved;                       /* Reserved */
	uint8_t  prefix_addr[IPV6_ADDR_LEN];     /* Prefix */
}__attribute__((__packed__));

struct icmp6_options {
	uint8_t type;                            /* Source link-layer address */
	uint8_t length;                          /* Length */
	uint8_t link_layer_addr[ETHER_ADDR_LEN]; /* Source/Target Link Layer Address */
}__attribute__((__packed__));

/* ICMPv6 Router Solicitation Struct */
struct icmp6_hdr_rs {
	uint8_t  icmp6_type;            /* ICMP6 packet type. */
	uint8_t  icmp6_code;            /* ICMP6 packet code. */
	uint16_t icmp6_cksum;           /* ICMP6 packet checksum. */
	uint32_t icmp6_reserved;        /* ICMP6 packet Reserved. */
	struct   icmp6_options opt;     /* ICMP6 Possible options */
}__attribute__((__packed__));

/* ICMPv6 Router Advertisement Struct */
struct icmp6_hdr_ra {
	struct   icmpv6_header icmp;    /* ICMPv6 header */
	uint32_t icmp6_reachable_time;  /* ICMP6 packet Reachable time */
	uint32_t icmp6_retrans_time;    /* ICMP6 packet Retrans time */
	struct   icmp6_prefix_options opt;     /* ICMP6 Possible options */
}__attribute__((__packed__));

/* ICMPv6 Neighbor Solicitation Struct */
struct icmp6_hdr_ns {
	uint8_t  icmp6_type;            /* ICMP6 packet type. */
	uint8_t  icmp6_code;            /* ICMP6 packet code. */
	uint16_t icmp6_cksum;           /* ICMP6 packet checksum. */
	uint32_t icmp6_reserved;        /* ICMP6 packet Reserved. */
	struct in6_addr icmp6_target_addr; /* ICMP6 Target address. */
	struct   icmp6_options opt;     /* ICMP6 Possible options */
}__attribute__((__packed__));

/* ICMPv6 Neighbor Advertisement Struct */
struct icmp6_hdr_na {
	uint8_t  icmp6_type;            /* ICMP6 packet type. */
	uint8_t  icmp6_code;            /* ICMP6 packet code. */
	uint16_t icmp6_cksum;           /* ICMP6 packet checksum. */
	uint32_t icmp6_flags;           /* ICMP6 packet flags, R:Router flag, S:Solicited flag, O:Override flag */
	struct in6_addr icmp6_target_addr; /* ICMP6 Target address. */
	struct   icmp6_options opt;     /* ICMP6 Possible options */
}__attribute__((__packed__));

/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane IPv6 header constructor.
 */

/**
 * @brief  : Function to return pointer to ip headers, assuming ether header is untagged.
 * @param  : m, mbuf pointer
 * @return : pointer to ipv6 headers
 */
static inline struct ipv6_hdr *get_mtoip_v6(struct rte_mbuf *m)
{
#ifdef DPDK_2_1
	return (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE);
#else
	return rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
				       sizeof(struct ether_hdr));
#endif

}

/**
 * @brief  : Function to return pointer to encapsulated ipv6 headers, assuming ether header is untagged.
 * @param  : m, mbuf pointer
 * @return : pointer to ipv6 headers
 */
static inline struct ipv6_hdr *get_inner_mtoipv6(struct rte_mbuf *m)
{
	uint8_t *ptr;
	ptr =  (uint8_t *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE + IPv6_HDR_SIZE + UDP_HDR_SIZE);
	ptr += GPDU_HDR_SIZE_DYNAMIC(*ptr);
	return (struct ipv6_hdr *)ptr;
}

/**
 * @brief  : Function to return pointer to inner icmpv6 ICMP headers.
 * @param  : m, mbuf pointer
 * @return : Returns pointer to udp headers
 */
static inline struct icmp_hdr *get_inner_mtoicmpv6(struct rte_mbuf *m)
{
	uint8_t *ptr;
	ptr =  (uint8_t *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE + IPv6_HDR_SIZE + UDP_HDR_SIZE);
	ptr += GPDU_HDR_SIZE_DYNAMIC(*ptr) + IPv6_HDR_SIZE;
	return (struct icmp_hdr *)ptr;
}

/**
 * @brief  : Function to return pointer to icmpv6 ICMP headers.
 * @param  : m, mbuf pointer
 * @return : Returns pointer to udp headers
 */
static inline struct icmp_hdr *get_mtoicmpv6(struct rte_mbuf *m)
{
	return (struct icmp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
				    ETH_HDR_SIZE + IPv6_HDR_SIZE);
}

/**
 * @brief  : Function to return pointer to icmpv6 Router Solicitation headers.
 * @param  : m, mbuf pointer
 * @return : Returns pointer to udp headers
 */
static inline struct icmp6_hdr_rs *get_mtoicmpv6_rs(struct rte_mbuf *m)
{
	uint8_t *ptr;
	ptr =  (uint8_t *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE + IPv6_HDR_SIZE + UDP_HDR_SIZE);
	ptr += GPDU_HDR_SIZE_DYNAMIC(*ptr) + IPv6_HDR_SIZE;
	return (struct icmp6_hdr_rs *)ptr;
}

/**
 * @brief  : Function to return pointer to icmpv6 Router Advertisement headers.
 * @param  : m, mbuf pointer
 * @return : Returns pointer to udp headers
 */
static inline struct icmp6_hdr_ra *get_mtoicmpv6_ra(struct rte_mbuf *m)
{
	uint8_t *ptr;
	ptr =  (uint8_t *)(rte_pktmbuf_mtod(m, unsigned char *) +
				   ETH_HDR_SIZE + IPv6_HDR_SIZE + UDP_HDR_SIZE);
	ptr += GPDU_HDR_SIZE_DYNAMIC(*ptr) + IPv6_HDR_SIZE;
	return (struct icmp6_hdr_ra *)ptr;
}

/**
 * @brief  : Function to return pointer to icmpv6 Neighbor Solicitation headers.
 * @param  : m, mbuf pointer
 * @return : Returns pointer to udp headers
 */
static inline struct icmp6_hdr_ns *get_mtoicmpv6_ns(struct rte_mbuf *m)
{
	return (struct icmp6_hdr_ns *)(rte_pktmbuf_mtod(m, unsigned char *) +
				    ETH_HDR_SIZE + IPv6_HDR_SIZE);
}

/**
 * @brief  : Function to return pointer to icmpv6 Neighbor Advertisement headers.
 * @param  : m, mbuf pointer
 * @return : Returns pointer to udp headers
 */
static inline struct icmp6_hdr_na *get_mtoicmpv6_na(struct rte_mbuf *m)
{
	return (struct icmp6_hdr_na *)(rte_pktmbuf_mtod(m, unsigned char *) +
				    ETH_HDR_SIZE + IPv6_HDR_SIZE);
}

/**
 * @brief  : Function to construct IPv6 header with default values.
 * @param  : m, mbuf pointer
 * @return : Returns nothing
 */
static inline void build_ipv6_default_hdr(struct rte_mbuf *m)
{
	struct ipv6_hdr *ipv6_hdr;

	ipv6_hdr = get_mtoip_v6(m);

	/* construct IPv6 header with hardcode values */
	ipv6_hdr->vtc_flow = IPv6_VERSION;
	ipv6_hdr->payload_len = 0;
	ipv6_hdr->proto = 0;
	ipv6_hdr->hop_limits = 0;
	memset(&ipv6_hdr->src_addr, 0, IPV6_ADDR_LEN);
	memset(&ipv6_hdr->dst_addr, 0, IPV6_ADDR_LEN);
}

/**
 * @brief  : Function to construct IPv6 header with default values.
 * @param  : m, mbuf pointer
 * @param  : len, len of header
 * @param  : protocol, next protocol id
 * @param  : src_ip, Source ip address
 * @param  : dst_ip, destination ip address
 * @return : Returns nothing
 */
static inline void
set_ipv6_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
	     struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	struct ipv6_hdr *ipv6_hdr;

	ipv6_hdr = get_mtoip_v6(m);

	/* Set IPv6 header values */
	ipv6_hdr->payload_len = htons(len);
	/* Fill the protocol identifier */
	ipv6_hdr->proto = protocol;
	/* Fill the SRC IPv6 Addr */
	memcpy(&ipv6_hdr->src_addr, &src_ip->s6_addr, IPV6_ADDR_LEN);
	/* Fill the DST IPv6 Addr */
	memcpy(&ipv6_hdr->dst_addr, &dst_ip->s6_addr, IPV6_ADDR_LEN);
}

/**
 * @brief  : Function to construct ipv6 header.
 * @param  : m, mbuf pointer
 * @param  : len, len of header
 * @param  : protocol, next protocol id
 * @param  : src_ip, Source ip address
 * @param  : dst_ip, destination ip address
 * @return : Returns nothing
 */
void
construct_ipv6_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
		   struct in6_addr *src_ip, struct in6_addr *dst_ip);

/**
 * Process the IPv6 ICMPv6 checksum.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param icmp_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
ipv6_icmp_cksum(const struct ipv6_hdr *ipv6_hdr, const void *icmp_hdr)
{
	uint32_t cksum;
	uint32_t icmp_len;

	icmp_len = rte_be_to_cpu_16(ipv6_hdr->payload_len);

	cksum = rte_raw_cksum(icmp_hdr, icmp_len);
	cksum += rte_ipv6_phdr_cksum(ipv6_hdr, 0);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

/**
 * @brief  : Function to set checksum of IPv4 and UDP header
 * @param  : pkt rte_mbuf pointer
 * @return : Returns nothing
 */
void ra_set_checksum(struct rte_mbuf *pkt);
#endif				/* _IPV6_H_ */
