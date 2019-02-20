/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _ETHER_H_
#define _ETHER_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane ethernet constructor.
 */
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "main.h"

#define ETH_TYPE_IPv4 0x0800

/**
 * Function to return pointer to L2 headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	address to l2 hdr
 */
static inline struct ether_hdr *get_mtoeth(struct rte_mbuf *m)
{
	return (struct ether_hdr *)rte_pktmbuf_mtod(m, unsigned char *);
}

/**
 * Function to construct L2 headers.
 *
 * @param m
 *	mbuf pointer
 * @param portid
 *	port id
 * @param sess_info
 *	pointer to session bear info
 * @return
 *	- 0  on success
 *	- -1 on failure (ARP lookup fail)
 */
int construct_ether_hdr(struct rte_mbuf *m, uint8_t portid,
		struct dp_sdf_per_bearer_info **sess_info);

#endif				/* _ETHER_H_ */
