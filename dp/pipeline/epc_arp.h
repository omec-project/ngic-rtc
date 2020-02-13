/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef __EPC_ARP_ICMP_H__
#define __EPC_ARP_ICMP_H__
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of ARP packet processing.
 */
#include <rte_ether.h>
#include <rte_rwlock.h>

/**
 * seconds between ARP request retransmission.
 */
#define ARP_TIMEOUT 2

/**
 * ring size.
 */
/* #define ARP_BUFFER_RING_SIZE 128 */
/* #define ARP_BUFFER_RING_SIZE 8191 */
#define ARP_BUFFER_RING_SIZE 512

/**
 * ARP entry populated and echo reply received.
 */
#define COMPLETE   1
/**
 * ARP entry populated and awaiting ARP reply.
 */
#define INCOMPLETE 0
/**
 * set to enable debug.
 */
#define ARPICMP_DEBUG 0

/** Pipeline arguments */
struct pipeline_arp_icmp_in_port_h_arg {
	/** rte pipeline */
	struct  pipeline_arp_icmp *p;
	/** in port id */
	uint8_t in_port_id;
};

/**
 * print mac format.
 */
#define FORMAT_MAC  \
	"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8
/**
 * print eth_addr.
 */
#define FORMAT_MAC_ARGS(eth_addr)  \
	(eth_addr).addr_bytes[0],  \
(eth_addr).addr_bytes[1],  \
(eth_addr).addr_bytes[2],  \
(eth_addr).addr_bytes[3],  \
(eth_addr).addr_bytes[4],  \
(eth_addr).addr_bytes[5]

/** IPv4 key for ARP table. */
struct arp_ipv4_key {
	/** ipv4 address */
	uint32_t ip;
};

/** ARP table entry. */

struct arp_entry_data {
	/** ipv4 address */
	uint32_t ip;
	/** ether address */
	struct ether_addr eth_addr;
	/** status: COMPLETE/INCOMPLETE */
	uint8_t status;
	/** last update time */
	time_t last_update;
	/** pkts queued */
	struct rte_ring *queue;
	/** UL || DL port id */
	uint8_t port;
} __attribute__((packed));

/**
 * Print ARP packet.
 *
 * @param pkt
 *	ARP packet.
 *
 */
void print_pkt1(struct rte_mbuf *pkt);

/**
 * Send ARP request.
 *
 * @param port_id
 *	port id.
 * @param ip
 *	ip address to resolve the mac.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int send_arp_req(unsigned port_id, uint32_t ip);

/**
 * Retrieve MAC address.
 *
 * @param ipaddr
 *	dst IP address.
 * @param phy_port
 *	port no.
 * @param hw_addr
 *	mac address.
 * @param nhip
 *	next hop ip.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int arp_icmp_get_dest_mac_address(__rte_unused const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr, uint32_t *nhip);

/**
 * Retrieve ARP entry.
 *
 * @param arp_key
 *	key.
 * @param portid
 *	port id
 *
 * @return
 *	arp entry data if found.
 *	neg value if error.
 */
struct arp_entry_data *retrieve_arp_entry(
			const struct arp_ipv4_key arp_key,
			uint8_t portid);

/**
 * Queue unresolved arp pkts.
 *
 * @param arp_data
 *	arp entry data.
 * @param m
 *	packet pointer.
 * @param portid
 *	port.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int arp_qunresolved_ulpkt(struct arp_entry_data *arp_data,
				struct rte_mbuf *m, uint8_t portid);

int arp_qunresolved_dlpkt(struct arp_entry_data *arp_data,
				struct rte_mbuf *m, uint8_t portid);

#ifdef USE_AF_PACKET
int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu);

int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);
#endif
#endif /*__EPC_ARP_ICMP_H__ */
