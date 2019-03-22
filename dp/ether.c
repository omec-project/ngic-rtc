/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <arpa/inet.h>

#include <rte_ip.h>

#include "main.h"
#include "ether.h"
#include "util.h"
#include "ipv4.h"
#include "pipeline/epc_arp.h"

extern unsigned int fd_array[2];

#ifndef STATIC_ARP
static struct sockaddr_in dest_addr[2];
#endif /* STATIC_ARP */
/**
 * Function to set ethertype.
 *
 * @param m
 *	mbuf pointer
 * @param type
 *	type
 *
 * @return
 *	None
 */
static inline void set_ether_type(struct rte_mbuf *m, uint16_t type)
{
	struct ether_hdr *eth_hdr = get_mtoeth(m);
	/* src/dst mac will be updated by send_to() */
	eth_hdr->ether_type = htons(type);
}

/**
 * Function to construct L2 headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	- 0  on success
 *	- -1 on failure (ARP lookup fail)
 */
int construct_ether_hdr(struct rte_mbuf *m, uint8_t portid,
		struct dp_sdf_per_bearer_info **sess_info)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, void *);
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
	struct arp_ipv4_key tmp_arp_key = {
		.ip = ipv4_hdr->dst_addr
	};

	if (app.spgw_cfg == SPGWU) {
		if (portid == app.s1u_port) {
			if (app.s1u_gw_ip != 0 &&
					(tmp_arp_key.ip & app.s1u_mask) != app.s1u_net)
				tmp_arp_key.ip = app.s1u_gw_ip;
		} else if(portid == app.sgi_port) {
			if (app.sgi_gw_ip != 0 &&
					(tmp_arp_key.ip & app.sgi_mask) != app.sgi_net)
				tmp_arp_key.ip = app.sgi_gw_ip;
		}
	} else if (app.spgw_cfg == SGWU) {
		if (portid == app.s1u_port) {
			if (app.s1u_gw_ip != 0)
				tmp_arp_key.ip = app.s1u_gw_ip;
		} else if (portid == app.s5s8_sgwu_port) {
			if (app.sgw_s5s8gw_ip != 0 &&
					(tmp_arp_key.ip & app.sgw_s5s8gw_mask) != app.sgw_s5s8gw_net) {
				tmp_arp_key.ip = app.sgw_s5s8gw_ip;
			} else {
				uint32_t s5s8_pgwu_addr =
				sess_info[0]->bear_sess_info->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr;
				if (s5s8_pgwu_addr != 0)
					tmp_arp_key.ip = htonl(s5s8_pgwu_addr);
			}

		}
	} else if(app.spgw_cfg == PGWU) {
		if (portid == app.sgi_port) {
			if (app.sgi_gw_ip != 0)
				tmp_arp_key.ip = app.sgi_gw_ip;
		} else if (portid == app.s5s8_pgwu_port) {
			if (app.pgw_s5s8gw_ip != 0 &&
					(tmp_arp_key.ip & app.pgw_s5s8gw_mask) != app.pgw_s5s8gw_net) {
				tmp_arp_key.ip = app.pgw_s5s8gw_ip;
			} else {
				uint32_t s5s8_sgwu_addr =
					sess_info[0]->bear_sess_info->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr;
				if (s5s8_sgwu_addr != 0)
					tmp_arp_key.ip = htonl(s5s8_sgwu_addr);
			}

		}
	}

	/* IPv4 L2 hdr */
	eth_hdr->ether_type = htons(ETH_TYPE_IPv4);

	struct arp_entry_data *ret_arp_data = NULL;
	if (ARPICMP_DEBUG)
		printf("%s::"
				"\n\tretrieve_arp_entry for ip 0x%x\n",
				__func__, tmp_arp_key.ip);
	ret_arp_data = retrieve_arp_entry(tmp_arp_key, portid);

	if (ret_arp_data == NULL) {
		RTE_LOG_DP(DEBUG, DP, "%s::"
				"\n\tretrieve_arp_entry failed for ip 0x%x\n",
				__func__, tmp_arp_key.ip);
		return -1;
	}


	if (ret_arp_data->status == INCOMPLETE)	{

#ifndef STATIC_ARP
		RTE_LOG_DP(INFO, DP, "Sendto:: ret_arp_data->ip= %s\n",
					inet_ntoa(*(struct in_addr *)&ret_arp_data->ip));

		/* setting sendto destination addr */
		dest_addr[portid].sin_family = AF_INET;
		dest_addr[portid].sin_addr.s_addr = ret_arp_data->ip;
		dest_addr[portid].sin_port = htons(SOCKET_PORT);

		char *data = (char *)((char *)(m)->buf_addr + (m)->data_off);
		if ((sendto(fd_array[portid], data, m->data_len, 0, (struct sockaddr *)
					&dest_addr[portid], sizeof(struct sockaddr_in))) < 0) {
			perror("send failed");
			return -1;
		}
#endif /* STATIC_ARP */

		if (portid == app.sgi_port) {

			if (arp_qunresolved_ulpkt(ret_arp_data, m, portid) == 0) {
				RTE_LOG_DP(DEBUG, DP, "%s::arp_queue_unresolved_packet::"
						"\n\treturn -1; arp_key.ip= 0x%X\n",
						__func__, tmp_arp_key.ip);
				return -1;
			}
		}
		if (portid == app.s1u_port) {

			if (arp_qunresolved_dlpkt(ret_arp_data, m, portid) == 0) {
				RTE_LOG_DP(DEBUG, DP, "%s::arp_queue_unresolved_packet::"
						"\n\treturn -1; arp_key.ip= 0x%X\n",
						__func__, tmp_arp_key.ip);
				return -1;
			}
		}
		return -1;

	}

	RTE_LOG_DP(DEBUG, DP,
			"MAC found for ip %s"
			", port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(*(struct in_addr *)&tmp_arp_key.ip), portid,
					ret_arp_data->eth_addr.addr_bytes[0],
					ret_arp_data->eth_addr.addr_bytes[1],
					ret_arp_data->eth_addr.addr_bytes[2],
					ret_arp_data->eth_addr.addr_bytes[3],
					ret_arp_data->eth_addr.addr_bytes[4],
					ret_arp_data->eth_addr.addr_bytes[5]);

	ether_addr_copy(&ret_arp_data->eth_addr, &eth_hdr->d_addr);
	ether_addr_copy(&ports_eth_addr[portid], &eth_hdr->s_addr);

#ifdef NGCORE_SHRINK
#ifdef STATS
	if(portid == SGI_PORT_ID) {
		++epc_app.ul_params[S1U_PORT_ID].pkts_out;
	} else if(portid == S1U_PORT_ID) {
		++epc_app.dl_params[SGI_PORT_ID].pkts_out;
	}
#endif /* STATS */
#endif /* NGCORE_SHRINK */
	return 0;
}
