/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_arp.h>

/* KNI specific headers */
#include <rte_kni.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_bus_pci.h>

#include "main.h"
#include "pipeline/epc_arp.h"

#define TX_QUEUE 1

struct ether_addr mac = {0};
/* Macros for printing using RTE_LOG */

unsigned int fd_array[2];
extern struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

extern struct rte_mempool *kni_mpool;

#define NB_RXD                  1024

extern struct rte_eth_conf port_conf_default;

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);

#ifdef USE_AF_PACKET
static const char *port_str[] = {
	"S1U_PORT_ID", "SGI_PORT_ID",
	"S1U_PORT_VETH_ID", "SGI_PORT_VETH_ID"
};
/**
 * Sibling function of kni_config_network_interface() that initializes
 * a socket that DP uses for ARP resolution at run time (works only for
 * sockets bound to veth ifaces). This is its *more "cleaned-up" version.
 */
void
af_config_network_monitor_interface(uint16_t port_id)
{
	/* Create udp socket */
	int client_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (client_fd < 0) {
		fprintf(stderr, "cannot create socket\n");
		exit(EXIT_FAILURE);
	}

	fd_array[port_id - NUM_SPGW_PORTS] = client_fd;
}
#endif
void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

int
validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		printf("No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
			(!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE, "portmask is not consistent "
				"to port ids specified %u\n", portmask);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_rx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d receiving not enabled\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d transmitting not enabled\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);

	}

	return 0;
}

/**
 * Burst rx from dpdk interface and transmit burst to kni interface.
 * Pkts transmitted to KNI interface, onwards linux will handle whatever pkts rx
 * on kni interface
 */
void
kni_ingress(struct kni_port_params *p,
		struct rte_mbuf *pkts_burst[PKT_BURST_SZ],
		unsigned nb_rx) {
	if (p == NULL) {
		printf("KNI port params is NULL!!!\n");
		return;
	}

	for (uint32_t i = 0; i < p->nb_kni; i++) {
		/* Burst rx from eth */
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG_DP(ERR, KNI, "Error receiving from eth\n");
			return;
		}

		if (nb_rx > 0) {
			RTE_LOG_DP(DEBUG, KNI, "KNI- kni_probe:%s::"
					"\n\tnb_rx=%u\n",
					__func__, nb_rx);
		}

		/* Burst tx to kni */
		unsigned int num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
		}
	}
}

/**
 * Burst rx from kni interface and enqueue rx pkts in ring.
 */
void
kni_egress(struct kni_port_params *p)
{
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ] = {NULL};

	if (p == NULL)
		return;

	for (uint32_t i = 0; i < p->nb_kni; i++) {
		/* Burst rx from kni */
		unsigned nb_rx = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG_DP(ERR, KNI, "Error receiving from KNI\n");
			return;
		}

		if (nb_rx > 0) {
			RTE_LOG_DP(DEBUG, KNI, "KNI- kni_probe:%s::"
					"\n\tnb_rx=%u\n",
					__func__, nb_rx);
		}

		for (uint32_t pkt_cnt = 0; pkt_cnt < nb_rx; ++pkt_cnt) {
			int ret = rte_ring_enqueue(shared_ring[p->port_id], pkts_burst[pkt_cnt]);
			if (ret == -ENOBUFS) {
				rte_pktmbuf_free(pkts_burst[pkt_cnt]);
				RTE_LOG_DP(ERR, DP, "%s::Can't queue pkt- ring full..."
						" Dropping pkt", __func__);
				continue;
			}
		}
	}
}

/* Initialize KNI subsystem */
void init_kni(void) {
	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params **params = kni_port_params_array;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < nb_ports; i++) {
		if (kni_port_params_array[i]) {
			num_of_kni_ports += (params[i]->nb_lcore_k ?
				params[i]->nb_lcore_k : 1);
		}
	}

	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}

/* Check the link status of all ports in up to 9s, and print them finally */
void check_all_ports_link_status(uint16_t port_num, uint32_t port_mask) {
#define CHECK_INTERVAL 10 /* 100ms */
#define MAX_CHECK_TIME 9 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up - speed %uMbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	if (port_id >= rte_eth_dev_count()) {
		RTE_LOG_DP(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG_DP(INFO, KNI, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf_default, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG_DP(ERR, KNI, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	rte_eth_dev_info_get(port_id, &dev_info);
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	struct rte_mempool *mbuf_pool = kni_mpool;

	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool);
	if (ret < 0) {
		RTE_LOG_DP(ERR, KNI, "Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG_DP(ERR, KNI, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

static int
kni_free_kni(uint16_t port_id)
{
	uint8_t i;
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	for (i = 0; i < p[port_id]->nb_kni; i++) {
		if (rte_kni_release(p[port_id]->kni[0]))
			printf("Fail to release kni\n");
		p[port_id]->kni[i] = NULL;
	}
	rte_eth_dev_stop(port_id);

	return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG_DP(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG_DP(INFO, KNI, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	 } else { /* Configure network interface down */
		rte_eth_dev_stop(port_id);
	 }

	/*Create udp socket*/
	//int client_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	int client_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if(client_fd < 0) {
		fprintf(stderr, "cannot create socket\n");
		exit(1);
	}

	fd_array[port_id] = client_fd;

	//struct sockaddr_in servaddr;
	//servaddr.sin_family = AF_INET;
	//servaddr.sin_port = htons(SOCKET_PORT);

	//if (port_id == 0)
	//	servaddr.sin_addr.s_addr = app.s1u_ip;
	//else if (port_id == 1)
	//	servaddr.sin_addr.s_addr = app.sgi_ip;
	//else
	//	rte_exit(EXIT_FAILURE, "Error: port %u is not configured.\n", port_id);

	//if ( bind(fd_array[port_id], (const struct sockaddr *)&servaddr,
	//			sizeof(servaddr)) < 0 )
	//{
	//	perror("bind failed");
	//	exit(EXIT_FAILURE);
	//} else {
	//	printf("KNI: Initialize and Configure interface %s socket_fd.\n",
	//			inet_ntoa(*((struct in_addr *)&servaddr.sin_addr.s_addr)));
	//}

	if (ret < 0)
		RTE_LOG_DP(ERR, KNI, "Failed to start port %d\n", port_id);

	return ret;
}

static void
print_ethaddr(const char *name, struct ether_addr *mac_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG_DP(INFO, KNI, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
	int ret = 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG_DP(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG_DP(INFO, KNI, "Configure mac address of %d\n", port_id);
	print_ethaddr("Address:", (struct ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					       (struct ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG_DP(ERR, KNI, "Failed to config mac_addr for port %d\n",
			port_id);

	return ret;
}

int
kni_alloc(uint16_t port_id)
{
	uint8_t i;
	struct rte_kni *kni = NULL;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;

	/* select the mempool to be used based on port_id */
	struct rte_mempool *mbuf_pool = kni_mpool;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
				params[port_id]->nb_lcore_k : 1;

	for (i = 0; i < params[port_id]->nb_kni; i++) {
		/* Clear conf at first */
		memset(&conf, 0, sizeof(conf));
		if (params[port_id]->nb_lcore_k) {
			snprintf(conf.name, RTE_KNI_NAMESIZE,
					"vEth%u_%u", port_id, i);
			conf.core_id = params[port_id]->lcore_k[i];
			conf.force_bind = 1;
		} else {
			if (port_id == 0) {
				memcpy(conf.name, app.ul_iface_name,
						RTE_KNI_NAMESIZE);
			} else if (port_id == 1) {
				memcpy(conf.name, app.dl_iface_name,
						RTE_KNI_NAMESIZE);
			}
		}

		conf.group_id = port_id;
		conf.mbuf_size = MAX_PACKET_SZ;

		/* Get the interface default mac address */
		rte_eth_macaddr_get(port_id,
				(struct ether_addr*)&conf.mac_addr);
		/*
		 * The first KNI device associated to a port
		 * is the master, for multiple kernel thread
		 * environment.
		 */
		if (i == 0) {
			struct rte_kni_ops ops;
			struct rte_eth_dev_info dev_info;

			memset(&dev_info, 0, sizeof(dev_info));
			rte_eth_dev_info_get(port_id, &dev_info);
			if (dev_info.pci_dev) {
				conf.addr = dev_info.pci_dev->addr;
				conf.id = dev_info.pci_dev->id;
			}

			rte_eth_dev_get_mtu(port_id, &conf.mtu);

			memset(&ops, 0, sizeof(ops));
			ops.port_id = port_id;
			ops.change_mtu = kni_change_mtu;
			ops.config_network_if = kni_config_network_interface;
			ops.config_mac_address = kni_config_mac_address;

			kni = rte_kni_alloc(mbuf_pool, &conf, &ops);
		} else {
			kni = rte_kni_alloc(mbuf_pool, &conf, NULL);
		}

		if (!kni)
			rte_exit(EXIT_FAILURE, "Fail to create kni for "
						"port: %d\n", port_id);
		params[port_id]->kni[i] = kni;
	}

	return 0;
}

void
free_kni_ports(void) {
	uint8_t ports = 0;
	uint16_t nb_sys_ports = rte_eth_dev_count();

	rte_kni_close();
	for (ports = 0; ports < nb_sys_ports; ports++) {
		if (!(app.ports_mask & (1 << ports)))
			continue;
		kni_free_kni(ports);
	}
	for (ports = 0; ports < RTE_MAX_ETHPORTS; ports++) {
		if (kni_port_params_array[ports]) {
			rte_free(kni_port_params_array[ports]);
			kni_port_params_array[ports] = NULL;
		}
	}
}

#ifdef USE_AF_PACKET
#define VETH_TX_RETRIES_LIMIT		5

inline void
kern_packet_ingress(int portid,
		   struct rte_mbuf *pkts_burst[PKT_BURST_SZ],
		   unsigned nb_rx)
{
	/* Send e.g. ARP packets to the kernel */
	uint32_t pkt_indx = 0, retries = 0, i;
	while (nb_rx && retries < VETH_TX_RETRIES_LIMIT) {

		uint16_t tx_cnt = rte_eth_tx_burst(portid + NUM_SPGW_PORTS,
						   0, &pkts_burst[pkt_indx], nb_rx);
		nb_rx -= tx_cnt;
		pkt_indx += tx_cnt;
		retries++;
	}

	/* free those mbufs that failed to get transmitted */
	for (i = 0; i < nb_rx; i++, pkt_indx++) {
		RTE_LOG_DP(ERR, DP, "Failed to transmit pkt from %s --> %s\n",
			   port_str[portid], port_str[portid + NUM_SPGW_PORTS]);
		rte_pktmbuf_free(pkts_burst[pkt_indx]);
	}
}

inline void
kern_packet_egress(int portid)
{
	uint32_t rx_cnt, pkt_indx, retries, i;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	pkt_indx = retries = 0;

	/* Fetch packets from kernel */
	rx_cnt = rte_eth_rx_burst(portid + NUM_SPGW_PORTS, 0,
				  pkts_burst, PKT_BURST_SZ);

	/* Send the packets out of the physical port */
	while (rx_cnt && retries < VETH_TX_RETRIES_LIMIT) {
		uint16_t tx_cnt = rte_eth_tx_burst(portid,
						   0, &pkts_burst[pkt_indx], rx_cnt);
		rx_cnt -= tx_cnt;
		pkt_indx += tx_cnt;
		retries++;
	}

	/* free those mbufs that failed to get transmitted */
	for (i = 0; i < rx_cnt; i++, pkt_indx++) {
		RTE_LOG_DP(ERR, DP, "Failed to transmit pkt from %s --> %s\n",
			   port_str[portid], port_str[portid + NUM_SPGW_PORTS]);
		rte_pktmbuf_free(pkts_burst[pkt_indx]);
	}
}
#endif /* !USE_AF_PACKET */
