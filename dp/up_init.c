/*
 * Copyright (c) 2019 Sprint
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
#include <unistd.h>

#include "up_main.h"

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

/* Macro to specify size of  shared_ring */
#define SHARED_RING_SIZE 8192

struct rte_mempool *s1u_mempool;
struct rte_mempool *sgi_mempool;
struct rte_mempool *kni_mpool;
struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

/* VS: Route table Discovery */
/**
 * Routing table hash params.
 */
static struct rte_hash_parameters route_hash_params = {
	.name = "ROUTE_TABLE",
	.entries = 64*64,
	.reserved = 0,
	.key_len = sizeof(uint32_t),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

/**
 * Route rte hash handler.
 */
struct rte_hash *route_hash_handle;

uint32_t nb_ports = 0 ;

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

struct rte_ring *shared_ring[NUM_SPGW_PORTS] = {NULL, NULL};

struct rte_ring *dl_ring_container = NULL;

uint32_t num_dl_rings = 0;

struct rte_ring *notify_ring = NULL;

struct rte_mempool *notify_msg_pool = NULL;

struct sockaddr_in dest_addr_t = {0};

struct in_addr cp_comm_ip;

uint16_t cp_comm_port;

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
	const uint16_t rx_rings = 1, tx_rings = 1;  //tx_rings = rte_lcore_count() - 1;
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

	/* Allocate ring on UL and DL core to share data between
	 * Master core and UL/DL */
	char *ring_name = "UL_MCT_ring";
	if (port == SGI_PORT_ID) {
		ring_name = "DL_MCT_ring";
	}

	shared_ring[port] = rte_ring_create(ring_name, SHARED_RING_SIZE,
			rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (shared_ring[port] == NULL) {
		printf ("Error in creating shared ring!!!");
		return -1;
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
	uint8_t port_id;
	enum {
		S1U_PORT = 0,
		SGI_PORT = 1
	};
	int i = 0, j; //GCC_Security flag

	nb_ports = rte_eth_dev_count();
	printf ("nb_ports cnt is %u\n", nb_ports);
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be two\n");

	/* Create S1U mempool to hold the mbufs. */
	s1u_mempool = rte_pktmbuf_pool_create("S1U_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (s1u_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create s1u_mempool !!!\n");

	/* Create kni mempool to hold the kni pkts mbufs. */
	kni_mpool = rte_pktmbuf_pool_create("KNI_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (kni_mpool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create kni_mpool !!!\n");

	/* Create SGi mempool to hold the mbufs. */
	sgi_mempool = rte_pktmbuf_pool_create("SGI_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (sgi_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create sgi_mempool !!!\n");

	/* Initialize KNI interface on s1u and sgi port */
	/* Check if the configured port ID is valid */
	for (port_id = 0; port_id < nb_ports; port_id++) {
		if (kni_port_params_array[port_id] && port_id >= nb_ports)
			rte_exit(EXIT_FAILURE, "Configured invalid "
					"port ID %u\n", port_id);
		kni_port_params_array[port_id] =
			rte_zmalloc("KNI_port_params",
					sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);

		kni_port_params_array[port_id]->port_id = port_id;

		if (port_id == 0) {
			kni_port_params_array[port_id]->lcore_rx =
				(uint8_t)epc_app.core_ul[S1U_PORT_ID];
			kni_port_params_array[port_id]->lcore_tx = (uint8_t)epc_app.core_mct;
			printf("KNI lcore on port :%u rx :%u tx :%u\n", port_id,
					kni_port_params_array[port_id]->lcore_rx,
					kni_port_params_array[port_id]->lcore_tx);
		} else if (port_id == 1) {
			kni_port_params_array[port_id]->lcore_rx =
				(uint8_t)epc_app.core_dl[SGI_PORT_ID];
			kni_port_params_array[port_id]->lcore_tx = (uint8_t)epc_app.core_mct;
			printf("KNI lcore on port :%u rx :%u tx :%u\n", port_id,
					kni_port_params_array[port_id]->lcore_rx,
					kni_port_params_array[port_id]->lcore_tx);
		}

		for (j = 0; i < 3 && j < KNI_MAX_KTHREAD; i++, j++) {
			kni_port_params_array[port_id]->lcore_k[j] = 0;
		}
		kni_port_params_array[port_id]->nb_lcore_k = 0;

	}

	/* Check that options were parsed ok */
	if (validate_parameters(app.ports_mask) < 0) {
		rte_exit(EXIT_FAILURE, "Invalid portmask\n");
	}

	/* Initialize KNI subsystem */
	init_kni();

	/* Initialize S1U & SGi ports. */
	if (port_init(S1U_PORT, s1u_mempool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				S1U_PORT);
	/* Alloc kni on interface. */
	kni_alloc(S1U_PORT);
	if (port_init(SGI_PORT, sgi_mempool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				SGI_PORT);
	kni_alloc(SGI_PORT);

	/* Routing Discovery : Create route hash for s1u and sgi port */
	route_hash_params.socket_id = rte_socket_id();
	route_hash_handle = rte_hash_create(&route_hash_params);
	if (!route_hash_handle)
		rte_panic("%s hash create failed: %s (%u)\n.",
				route_hash_params.name, rte_strerror(rte_errno),
				rte_errno);

	check_all_ports_link_status(nb_ports, app.ports_mask);
	printf("KNI: DP Port Mask:%u\n", app.ports_mask);
	printf("DP Port initialization completed.\n");
}

void
dp_ddn_init(void)
{
	/** For notification of modify_session so that buffered packets
	 * can be dequeued
	 */
	notify_ring = rte_ring_create("NOTIFY_RING", NOTIFY_RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);

	if (notify_ring == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating notify ring!!!\n");
	}

	/** Holds a set of rings to be used for downlink data buffering */
	dl_ring_container = rte_ring_create("RING_CONTAINER", DL_RING_CONTAINER_SIZE,
			rte_socket_id(),
			RING_F_SC_DEQ);

	if (dl_ring_container == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating dl ring container!!!\n");
	}

	/** Create mempool for notification to hold pkts mbufs. */
	notify_msg_pool = rte_pktmbuf_pool_create("NOTIFY_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());

	if (notify_msg_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create notify_msg_pool !!!\n");


	/* VS: TODO Temp. filled CP comm IP and PORT*/
	dest_addr_t.sin_family = AF_INET;
	dest_addr_t.sin_addr.s_addr = cp_comm_ip.s_addr;
	dest_addr_t.sin_port = htons(cp_comm_port);

}
