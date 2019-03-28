/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <search.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "vepc_cp_dp_api.h"
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane utilities.
 */

/**
 * ipv4 header size.
 */
#define IPv4_HDR_SIZE		20

/**
 * udp header size.
 */
#define UDP_HDR_SIZE		8

/**
 * ethernet header size for untagged packet.
 */
#define ETH_HDR_SIZE		14

 /**
 * macro to define next protocol udp in
 * ipv4 header.
 */
#define IP_PROTO_UDP		17

/**
 * GTPU port
 */
#define UDP_PORT_GTPU		2152

/**
 * network order DNS src port for udp
 */
#define N_DNS_RES_SRC_PORT      0x3500

/**
 * ipv4 address format.
 */
#define IPV4_ADDR "%u.%u.%u.%u"
#define IPV4_ADDR_FORMAT(a)	(uint8_t)((a) & 0x000000ff), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0xff000000) >> 24)
#define IPV4_ADDR_HOST_FORMAT(a)	(uint8_t)(((a) & 0xff000000) >> 24), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)((a) & 0x000000ff)

struct table {
	char name[MAX_LEN];
	void *root;
	uint16_t num_entries;
	uint16_t max_entries;
	uint8_t active;
	int (*compare)(const void *r1p, const void *r2p);
	void (*print_entry)(const void *nodep, const VISIT which, const int depth);
};

/**
 * Function to return pointer to udp headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	pointer to udp headers
 */
static inline struct udp_hdr *get_mtoudp(struct rte_mbuf *m)
{
	return (struct udp_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
				    ETH_HDR_SIZE + IPv4_HDR_SIZE);
}

/**
 * Function to construct udp header.
 *
 * @param m
 *	mbuf pointer
 * @param len
 *	len of header
 * @param sport
 *	src port
 * @param dport
 *	dst port
 *
 * @return
 *	None
 */
void
construct_udp_hdr(struct rte_mbuf *m, uint16_t len,
		  uint16_t sport, uint16_t dport);

#endif /*_UTIL_H_ */
