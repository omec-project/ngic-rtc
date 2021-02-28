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

#include <arpa/inet.h>
#include <rte_ip.h>

#include "gtpu.h"
#include "util.h"
#include "ipv4.h"
#include "up_ether.h"
#include "clogger.h"
#include "pipeline/epc_arp.h"

extern unsigned int fd_array[2];

#ifndef STATIC_ARP
static struct sockaddr_in dest_addr[2];
#endif /* STATIC_ARP */

/**
 * @brief  : Function to set ethertype.
 * @param  : m, mbuf pointer
 * @param  : type, type
 * @return : Returns nothing
 */
static inline void set_ether_type(struct rte_mbuf *m, uint16_t type)
{
	struct ether_hdr *eth_hdr = get_mtoeth(m);
	/* src/dst mac will be updated by send_to() */
	eth_hdr->ether_type = htons(type);
}

int construct_ether_hdr(struct rte_mbuf *m, uint8_t portid,
			pdr_info_t **pdr)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, void *);
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
	struct arp_ipv4_key tmp_arp_key = {
		.ip = ipv4_hdr->dst_addr
	};

	/* Retrieve Gateway Routing IP Address of the next hop */
	if (portid == app.wb_port) {
		if (app.wb_gw_ip != 0 &&
				(tmp_arp_key.ip & app.wb_mask) != app.wb_net) {
			/* UPLINK */
			tmp_arp_key.ip = app.wb_gw_ip;
		}
	} else if (portid == app.eb_port) {
		if (app.eb_gw_ip != 0 &&
				(tmp_arp_key.ip & app.eb_mask) != app.eb_net) {
			/* DOWNLINK */
			tmp_arp_key.ip = app.eb_gw_ip;
		}
	}

	/* IPv4 L2 hdr */
	eth_hdr->ether_type = htons(ETH_TYPE_IPv4);

	struct arp_entry_data *ret_arp_data = NULL;
	if (ARPICMP_DEBUG)
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"\n\tRetrieve_arp_entry for IP "IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip)));

	ret_arp_data = retrieve_arp_entry(tmp_arp_key, portid);

	if (ret_arp_data == NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Retrieve_arp_entry failed for IP "IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip)));
		return -1;
	}


	if (ret_arp_data->status == INCOMPLETE) {

#ifndef STATIC_ARP
		clLog(clSystemLog, eCLSeverityInfo,
			LOG_FORMAT"Sendto ret arp data IP: "IPV4_ADDR"\n", LOG_VALUE,
			IPV4_ADDR_HOST_FORMAT(ntohl(ret_arp_data->ip)));

		/* setting sendto destination addr */
		dest_addr[portid].sin_family = AF_INET;
		dest_addr[portid].sin_addr.s_addr = ret_arp_data->ip;
		dest_addr[portid].sin_port = htons(SOCKET_PORT);

		char *data = (char *)((char *)(m)->buf_addr + (m)->data_off);
		if ((sendto(fd_array[portid], data, m->data_len, 0, (struct sockaddr *)
					&dest_addr[portid], sizeof(struct sockaddr_in))) < 0) {
			perror("up_ether.c:construct_ether_hdr:103: ERROR: Failed to send packet on KNI TAB:");
			return -1;
		}
#endif /* STATIC_ARP */

		if (portid == app.eb_port) {

			if (arp_qunresolved_ulpkt(ret_arp_data, m, portid) == 0) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"EB:Arp queue unresolved packet arp key IP: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip)));
				return -1;
			}
		}
		if (portid == app.wb_port) {

			if (arp_qunresolved_dlpkt(ret_arp_data, m, portid) == 0) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"WB:Arp queue unresolved packet arp key IP: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip)));
				return -1;
			}
		}
		return -1;

	}

	clLog(clSystemLog, eCLSeverityDebug,
			"MAC found for ip "IPV4_ADDR""
			", port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
			IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip)), portid,
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
	struct gtpu_hdr *gtpu_hdr = NULL;
	gtpu_hdr = get_mtogtpu(m);
	if ((gtpu_hdr != NULL) && (gtpu_hdr->msgtype == GTP_GEMR)) {
		if(portid == SGI_PORT_ID) {
			--epc_app.ul_params[S1U_PORT_ID].pkts_in;
		} else if(portid == S1U_PORT_ID) {
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
		}

		return 0;
	}

	if(portid == SGI_PORT_ID) {
		++epc_app.ul_params[S1U_PORT_ID].pkts_out;
	} else if(portid == S1U_PORT_ID) {
		++epc_app.dl_params[SGI_PORT_ID].pkts_out;
	}
#endif /* STATS */
#endif /* NGCORE_SHRINK */
	return 0;
}
