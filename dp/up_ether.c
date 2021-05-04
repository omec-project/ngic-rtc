/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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
#include "ipv6.h"
#include "pfcp_util.h"
#include "up_ether.h"
#include "pipeline/epc_arp.h"
#include "gw_adapter.h"

#define IP_HDR_IPv4_VERSION	0x45

extern int fd_array_v4[2];
extern int fd_array_v6[2];
extern int clSystemLog;

#ifndef STATIC_ARP
static struct sockaddr_in dest_addr[2];
static struct sockaddr_in6 ipv6_addr[2];
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
			pdr_info_t **pdr, uint8_t flag)
{
	/* Construct the ether header */
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, void *);
	uint8_t *ptr = (uint8_t *)(rte_pktmbuf_mtod(m, unsigned char *) + ETH_HDR_SIZE);
	struct arp_ip_key tmp_arp_key = {0};

	/* Check L3 IP packet type its IPv4 or IPv6 */
	if (*ptr == IP_HDR_IPv4_VERSION) {
		/* Fill the ether header for IPv4 packet */
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
		tmp_arp_key.ip_type.ipv4 = PRESENT;
		tmp_arp_key.ip_addr.ipv4 = ipv4_hdr->dst_addr;

		/* Retrieve Gateway Routing IP Address of the next hop */
		if (portid == app.wb_port) {
			if (app.wb_gw_ip != 0 &&
					(tmp_arp_key.ip_addr.ipv4 & app.wb_mask) != app.wb_net) {
				/* UPLINK */
				tmp_arp_key.ip_addr.ipv4 = app.wb_gw_ip;
			}
		} else if (portid == app.eb_port) {
			if (app.eb_gw_ip != 0 &&
					(tmp_arp_key.ip_addr.ipv4 & app.eb_mask) != app.eb_net) {
				/* DOWNLINK */
				tmp_arp_key.ip_addr.ipv4 = app.eb_gw_ip;
			}
		}

		/* IPv4 L2 hdr */
		eth_hdr->ether_type = htons(ETH_TYPE_IPv4);

	} else if (*ptr == IPv6_VERSION) {
		/* Fill the ether header for IPv6 packet */
		struct ipv6_hdr *ipv6_hdr = (struct ipv6_hdr *)&eth_hdr[1];
		tmp_arp_key.ip_type.ipv6 = PRESENT;

		/* Fill the IPv6 destination Address*/
		memcpy(&tmp_arp_key.ip_addr.ipv6.s6_addr, &ipv6_hdr->dst_addr,
				IPV6_ADDRESS_LEN);

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"DST IPv6: "IPv6_FMT", ARP Key:"IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->dst_addr),
				IPv6_PRINT(tmp_arp_key.ip_addr.ipv6));

		/* TODO: Add the support if remote proxy IP configure in the config file, GW STATIC Entry  */

		/* IPv6 L2 hdr */
		eth_hdr->ether_type = htons(ETH_TYPE_IPv6);
	} else {
		if (*pdr) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"IP type in header is not set appropriate,"
					"IP Type:%x, Outer HDR Desc:%u\n", LOG_VALUE, *ptr,
					((*pdr)->far)->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc);
		} else { 
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"IP type in header is not set appropriate,"
					"IP type:%x\n", LOG_VALUE, *ptr);
		}
		return -1;
	}

	/* Get the entry for IP address, if not present than create it */
	struct arp_entry_data *ret_arp_data = NULL;
	ret_arp_data = retrieve_arp_entry(tmp_arp_key, portid);
	if (ret_arp_data == NULL) {
		if (tmp_arp_key.ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Retrieve arp entry failed for ipv4: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip_addr.ipv4)));
		} else if (tmp_arp_key.ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Retrieve arp entry failed for ipv6: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(tmp_arp_key.ip_addr.ipv6));
		}
		return -1;
	}

	if (ret_arp_data->status == INCOMPLETE) {
#ifndef STATIC_ARP
		if (tmp_arp_key.ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityInfo,
					LOG_FORMAT"Sendto ret arp data IPv4: "IPV4_ADDR"\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT(ntohl(ret_arp_data->ipv4)));

			if (fd_array_v4[portid] > 0) {
				/* setting sendto destination addr */
				dest_addr[portid].sin_family = AF_INET;
				dest_addr[portid].sin_addr.s_addr = ret_arp_data->ipv4;
				dest_addr[portid].sin_port = htons(SOCKET_PORT);

				char *data = (char *)((char *)(m)->buf_addr + (m)->data_off);
				if ((sendto(fd_array_v4[portid], data, m->data_len, 0, (struct sockaddr *)
								&dest_addr[portid], sizeof(struct sockaddr_in))) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							"IPv4:"LOG_FORMAT"port:%u ERROR: Failed to send packet on KNI TAB.\n",
							LOG_VALUE, portid);
					perror("Socket Error:");
					return -1;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						"IPv4:"LOG_FORMAT"port:%u ERROR: FD for ipv4 intf not created, Failed to send packet on KNI TAB.\n",
						LOG_VALUE, portid);
				return -1;
			}
		} else if (tmp_arp_key.ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityInfo,
					LOG_FORMAT"Sendto ret arp data IPv6: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(tmp_arp_key.ip_addr.ipv6));

			if (fd_array_v6[portid] > 0) {
				/* setting sendto destination addr */
				ipv6_addr[portid].sin6_family = AF_INET6;
				memcpy(&ipv6_addr[portid].sin6_addr, &ret_arp_data->ipv6, IPV6_ADDRESS_LEN);
				ipv6_addr[portid].sin6_port = htons(SOCKET_PORT);

				char *data = (char *)((char *)(m)->buf_addr + (m)->data_off);
				if ((sendto(fd_array_v6[portid], data, m->data_len, 0, (struct sockaddr *)
								&ipv6_addr[portid], sizeof(struct sockaddr_in6))) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							"IPv6:"LOG_FORMAT"port:%u ERROR: Failed to send packet on KNI TAB.\n",
							LOG_VALUE, portid);
					perror("Socket Error:");
					return -1;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						"IPv6:"LOG_FORMAT"port:%u ERROR: FD for v6 intf not created yet, Failed to send packet on KNI TAB.\n",
						LOG_VALUE, portid);
				return -1;
			}
		}

#endif /* STATIC_ARP */

		if (portid == app.eb_port) {
			if (arp_qunresolved_ulpkt(ret_arp_data, m, portid) == 0) {
				if (tmp_arp_key.ip_type.ipv4) {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"EB:Arp queue unresolved packet arp key IPv4: "IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip_addr.ipv4)));
				} else if (tmp_arp_key.ip_type.ipv6) {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"EB:Arp queue unresolved packet arp key IPv6: "IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(tmp_arp_key.ip_addr.ipv6));
				}
				return -1;
			}
		}
		if (portid == app.wb_port) {
			if (arp_qunresolved_dlpkt(ret_arp_data, m, portid) == 0) {
				if (tmp_arp_key.ip_type.ipv4) {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"WB:Arp queue unresolved packet arp key IPv4: "IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip_addr.ipv4)));
				} else if (tmp_arp_key.ip_type.ipv6) {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"WB:Arp queue unresolved packet arp key IPv6: "IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(tmp_arp_key.ip_addr.ipv6));
				}
				return -1;
			}
		}
		return -1;
	}

	if (tmp_arp_key.ip_type.ipv4) {
		clLog(clSystemLog, eCLSeverityDebug,
				"MAC found for IPv4 "IPV4_ADDR""
				", port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
				IPV4_ADDR_HOST_FORMAT(ntohl(tmp_arp_key.ip_addr.ipv4)), portid,
						ret_arp_data->eth_addr.addr_bytes[0],
						ret_arp_data->eth_addr.addr_bytes[1],
						ret_arp_data->eth_addr.addr_bytes[2],
						ret_arp_data->eth_addr.addr_bytes[3],
						ret_arp_data->eth_addr.addr_bytes[4],
						ret_arp_data->eth_addr.addr_bytes[5]);
	} else if (tmp_arp_key.ip_type.ipv6) {
		clLog(clSystemLog, eCLSeverityDebug,
				"MAC found for IPv6 "IPv6_FMT""
				", port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
				IPv6_PRINT(tmp_arp_key.ip_addr.ipv6), portid,
						ret_arp_data->eth_addr.addr_bytes[0],
						ret_arp_data->eth_addr.addr_bytes[1],
						ret_arp_data->eth_addr.addr_bytes[2],
						ret_arp_data->eth_addr.addr_bytes[3],
						ret_arp_data->eth_addr.addr_bytes[4],
						ret_arp_data->eth_addr.addr_bytes[5]);
	}
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

	if (flag) {
		if(portid == SGI_PORT_ID) {
			++epc_app.dl_params[SGI_PORT_ID].pkts_out;
		} else if(portid == S1U_PORT_ID) {
			++epc_app.ul_params[S1U_PORT_ID].pkts_out;
		}
	} else {
		if(portid == SGI_PORT_ID) {
			++epc_app.ul_params[S1U_PORT_ID].pkts_out;
		} else if(portid == S1U_PORT_ID) {
			++epc_app.dl_params[SGI_PORT_ID].pkts_out;
		}
	}
#endif /* STATS */
#endif /* NGCORE_SHRINK */
	return 0;
}
