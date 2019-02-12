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

#include <stdio.h>
#include <stdlib.h>

#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "main.h"

/**
 *	RX_NUM_DESC < 1024:
 *		Increased sensivity kernel packet processing core sched jitters
 */
#define RX_NUM_DESC		2048

/**
 * macro to config tx ring size.
 */
#define TX_NUM_DESC		(RX_NUM_DESC*1)	/* TX_NUM_DESC = 2048 */

/**
 * DPDK default value optimial.
 */
#define MBUF_CACHE_SIZE	512

/**
 * NUM_MBUFS >= 2x RX_NUM_DESC::
 *		Else rte_eth_dev_start(...) { FAIL; ...}
 *	NUM_MBUFS >= 1.5x MBUF_CACHE_SIZE::
 *		Else rte_pktmbuf_pool_create(...) { FAIL; ...}
 */
/*#define NUM_MBUFS		(TX_NUM_DESC*2)	*/ /* 2048, (TX_NUM_DESC*2) */	/* NUM_MBUFS = 4096 */
#define NUM_MBUFS		(TX_NUM_DESC*2) > (1.5 * MBUF_CACHE_SIZE) ? \
						(TX_NUM_DESC*2) : (2 * MBUF_CACHE_SIZE)

/**
 * default port config structure .
 */
const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .offloads =
            DEV_RX_OFFLOAD_IPV4_CKSUM |
            DEV_RX_OFFLOAD_UDP_CKSUM |
            DEV_RX_OFFLOAD_TCP_CKSUM |
            DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
            DEV_RX_OFFLOAD_CRC_STRIP,
        /* Enable hw_crc_strip for PF/VF drivers */
        .hw_strip_crc = 1}
};

/**
 * Function to Initialize a given port using global settings and with the rx
 * buffers coming from the mbuf_pool passed as parameter
 * @param port
 *	port number.
 * @param mbuf_pool
 *	memory pool pointer.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
//	const uint16_t rx_rings = 1, tx_rings = 1;  //tx_rings = rte_lcore_count() - 1;
	/* ASR- TST_Probe: tx_rings = 2 */
	const uint16_t rx_rings = 1, tx_rings = 2;  //tx_rings = rte_lcore_count() - 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;
	/* TODO: use q 1 for arp */

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_NUM_DESC,
				rte_eth_dev_socket_id(port),
				NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_NUM_DESC,
				rte_eth_dev_socket_id(port),
				NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */

	rte_eth_macaddr_get(port, &ports_eth_addr[port]);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			ports_eth_addr[port].addr_bytes[0],
			ports_eth_addr[port].addr_bytes[1],
			ports_eth_addr[port].addr_bytes[2],
			ports_eth_addr[port].addr_bytes[3],
			ports_eth_addr[port].addr_bytes[4],
			ports_eth_addr[port].addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	/* rte_eth_promiscuous_enable(port); */
	rte_eth_promiscuous_disable(port);

	return 0;
}

void dp_port_init(void)
{
	struct rte_mempool *s1u_mempool;
	struct rte_mempool *sgi_mempool;
	uint32_t nb_ports;
	enum {
		S1U_PORT = 0,
		SGI_PORT = 1
	};

	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be two\n");
	printf("ASR Trace:%s::"
			"\n\tRX_NUM_DESC= %d; TX_NUM_DESC= %d;"
			"\n\tNUM_MBUFS=%d; MBUF_CACHE_SIZE=%d;"
			"\n\tRTE_MBUF_DEFAULT_BUF_SIZE=%d\n",
			__func__,
			RX_NUM_DESC, TX_NUM_DESC,
			NUM_MBUFS, MBUF_CACHE_SIZE,
			RTE_MBUF_DEFAULT_BUF_SIZE);

	/* Create S1U mempool to hold the mbufs. */
	s1u_mempool = rte_pktmbuf_pool_create("S1U_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (s1u_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create s1u_mempool !!!\n");
	/* Create SGi mempool to hold the mbufs. */
	sgi_mempool = rte_pktmbuf_pool_create("SGI_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (sgi_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create sgi_mempool !!!\n");

	/* Initialize S1U & SGi ports. */
	if (port_init(S1U_PORT, s1u_mempool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				S1U_PORT);
	if (port_init(SGI_PORT, sgi_mempool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				SGI_PORT);

	printf("DP Port initialization completed.\n");
}
