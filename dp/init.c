/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
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
#ifdef USE_AF_PACKET
/* if_nametoindex() */
#include <net/if.h>
#endif
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

/* Macro to specify size of  shared_ring */
#define SHARED_RING_SIZE 8192

#ifdef USE_AF_PACKET
struct rte_mempool *afs1u_mempool;
struct rte_mempool *afsgi_mempool;
#endif
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

#ifdef DP_DDN
struct rte_ring *dl_ring_container = NULL;

uint32_t num_dl_rings = 0;

struct rte_ring *notify_ring = NULL;

struct rte_mempool *notify_msg_pool = NULL;

#endif /* DP_DDN */

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

#ifdef USE_AF_PACKET
void
af_config_network_monitor_interface(uint16_t port_id);

void
init_af_socks()
{
	uint16_t port;
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;
	char dev_name[LINE_MAX];

	for (port = S1U_PORT_VETH_ID; port < S1U_PORT_VETH_ID + NUM_SPGW_PORTS; port++) {

		int ifidx;
		char peer_ifname[IF_NAMESIZE];

		switch (port) {
		case S1U_PORT_VETH_ID:
			ifidx = if_nametoindex(app.ul_iface_name);
			break;
		case SGI_PORT_VETH_ID:
			ifidx = if_nametoindex(app.dl_iface_name);
			break;
		default:
			rte_panic("Unknown port_id: %hu\n", port);
		}

		if (ifidx == 0)
			rte_panic("Failed to retrieve ifidx for port: %hu\n", port);
		/* create full string for net_af_packet */
		if (if_indextoname(ifidx - 1, peer_ifname) == NULL)
			rte_panic("Failed to retrieve interface name of peer veth\n");
		sprintf(dev_name, "net_af_packet%d,iface=%s", port, peer_ifname);

		retval = rte_eth_dev_attach(dev_name, &port);

		if (retval < 0 || port < NUM_SPGW_PORTS)
			rte_panic("S1U --> dev_str: %s, retval=%d, port_id=%d",
				  dev_name, retval, port);

		/* Configure the Ethernet device. */
		retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
		if (retval != 0)
			rte_panic("Failed to configure port %d\n", port);

		/* Allocate and set up RX queue per Ethernet port. */
		for (q = 0; q < rx_rings; q++) {
			retval = rte_eth_rx_queue_setup(port, q, RX_NUM_DESC,
							rte_eth_dev_socket_id(port),
							NULL, (port == S1U_PORT_VETH_ID) ?
							afs1u_mempool :
							afsgi_mempool);
			if (retval < 0)
				rte_panic("Failed to set up rx queues for port %d\n", port);
		}

		/* Allocate and set up TX queue per Ethernet port. */
		for (q = 0; q < tx_rings; q++) {
			retval = rte_eth_tx_queue_setup(port, q, TX_NUM_DESC,
							rte_eth_dev_socket_id(port),
							NULL);
			if (retval < 0)
				rte_panic("Failed to set up tx queues for port %d\n", port);
		}

		/* Start the Ethernet port. */
		retval = rte_eth_dev_start(port);
		if (retval < 0)
			rte_panic("Failed to start port %d\n", port);

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

		af_config_network_monitor_interface(port);
		app.ports_mask |= (1 << port);
	}
}
#endif /* !USE_AF_PACKET */

void dp_port_init(void)
{
#ifndef USE_AF_PACKET
	uint8_t port_id;
	int i = 0, j; //GCC_Security flag
#endif
	enum {
		S1U_PORT = 0,
		SGI_PORT = 1
	};

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
#ifdef USE_AF_PACKET
	afs1u_mempool = rte_pktmbuf_pool_create("AFS1U_MPOOL", NUM_MBUFS,
						MBUF_CACHE_SIZE, 0,
						RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());
	afsgi_mempool = rte_pktmbuf_pool_create("AFSGI_MPOOL", NUM_MBUFS,
						MBUF_CACHE_SIZE, 0,
						RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());

	if (afs1u_mempool == NULL || afsgi_mempool == NULL)
		rte_exit(EXIT_FAILURE,
			 "Failed to create pool(s) for afs1u_mempool and/or afsgi_mempool !!! \n");
#else
	/* Create kni mempool to hold the kni pkts mbufs. */
	kni_mpool = rte_pktmbuf_pool_create("KNI_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (kni_mpool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create kni_mpool !!!\n");
#endif
	/* Create SGi mempool to hold the mbufs. */
	sgi_mempool = rte_pktmbuf_pool_create("SGI_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (sgi_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create sgi_mempool !!!\n");
#ifndef USE_AF_PACKET
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
#endif
	/* Initialize S1U & SGi ports. */
	if (port_init(S1U_PORT, s1u_mempool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				S1U_PORT);
#ifndef USE_AF_PACKET
	/* Alloc kni on interface. */
	kni_alloc(S1U_PORT);
#endif
	if (port_init(SGI_PORT, sgi_mempool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				SGI_PORT);
#ifndef USE_AF_PACKET
	kni_alloc(SGI_PORT);
#endif
	/* Routing Discovery : Create route hash for s1u and sgi port */
	route_hash_params.socket_id = rte_socket_id();
	route_hash_handle = rte_hash_create(&route_hash_params);
	if (!route_hash_handle)
		rte_panic("%s hash create failed: %s (%u)\n.",
				route_hash_params.name, rte_strerror(rte_errno),
				rte_errno);

#ifdef USE_AF_PACKET
	init_af_socks();
	/* adding veth ports as well */
	check_all_ports_link_status(nb_ports + NUM_SPGW_PORTS, app.ports_mask);
#else
	check_all_ports_link_status(nb_ports, app.ports_mask);
#endif
	printf("KNI: DP Port Mask:%u\n", app.ports_mask);
	printf("DP Port initialization completed.\n");
}

#ifdef DP_DDN
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

}
#endif /* DP_DDN */
