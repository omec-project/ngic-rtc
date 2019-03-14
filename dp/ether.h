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
