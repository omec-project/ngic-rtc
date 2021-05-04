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

#include <unistd.h>
#include <locale.h>
#include <signal.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <sys/time.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>

#include "up_main.h"
#include "epc_arp.h"
#include "teid_upf.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_association.h"
#include "ngic_timer.h"

#include "gw_adapter.h"
#include "gtpu.h"

#define OFFSET 		2208988800ULL


/* Generate new pcap for s1u port */
extern pcap_dumper_t *pcap_dumper_west;
extern pcap_dumper_t *pcap_dumper_east;
extern int fd_array_v4[2];
extern int fd_array_v6[2];
static peer_addr_t dest_addr[2];

/* DP restart conuter */
extern uint8_t dp_restart_cntr;
extern int clSystemLog;
extern uint16_t dp_comm_port;
/**
 * rte hash handler.
 */
/* 2 hash handles, one for S1U and another for SGI */
extern struct rte_hash *arp_hash_handle[NUM_SPGW_PORTS];

/* GW should allow/deny sending error indication pkts to peer node: 1:allow, 0:deny */
bool error_indication_snd;

/**
 * @brief  : memory pool for queued data pkts.
 */
static char *echo_mpoolname = {
	"echo_mpool",
};

int32_t conn_cnt = 0;
static uint16_t gtpu_seqnb      = 0;
static uint16_t gtpu_sgwu_seqnb = 0;
static uint16_t gtpu_sx_seqnb   = 1;

/**
 * @brief  : Connection hash params.
 */
static struct rte_hash_parameters
	conn_hash_params = {
			.name = "CONN_TABLE",
			.entries = NUM_CONN,
			.reserved = 0,
			.key_len = sizeof(node_address_t),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0
};

/**
 * rte hash handler.
 *
 * hash handles connection for S1U, SGI and PFCP
 */
struct rte_hash *conn_hash_handle;


const char
*eth_addr(struct ether_addr *eth_h)
{

	static char *str;
	snprintf(str, MAX_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
			eth_h->addr_bytes[0],
			eth_h->addr_bytes[1],
			eth_h->addr_bytes[2],
			eth_h->addr_bytes[3],
			eth_h->addr_bytes[4],
			eth_h->addr_bytes[5]);
	return str;

}

/**
 * @brief  : Print ethernet address
 * @param  : eth_h, ethernet address
 * @param  : type, source or destination
 * @return : Returns nothing
 */
static void
print_eth(struct ether_addr *eth_h, uint8_t type)
{
	if (type == 0) {
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"\n ETH : src=%02X:%02X:%02X:%02X:%02X:%02X\n", LOG_VALUE,
		eth_h->addr_bytes[0],
		eth_h->addr_bytes[1],
		eth_h->addr_bytes[2],
		eth_h->addr_bytes[3],
		eth_h->addr_bytes[4],
		eth_h->addr_bytes[5]);
	} else if (type == 1) {
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"\n ETH : dst = %02X:%02X:%02X:%02X:%02X:%02X\n", LOG_VALUE,
		eth_h->addr_bytes[0],
		eth_h->addr_bytes[1],
		eth_h->addr_bytes[2],
		eth_h->addr_bytes[3],
		eth_h->addr_bytes[4],
		eth_h->addr_bytes[5]);
	}

}

/**
 * @brief  : Send arp send
 * @param  : conn_data, peer node connection information
 * @return : Returns 0 in case of success , -1 otherwise
 */
static
uint8_t arp_req_send(peerData *conn_data)
{

	if ((fd_array_v4[conn_data->portId] > 0) || (fd_array_v6[conn_data->portId] > 0)) {
		/* Buffer setting */
		char tmp_buf[ARP_SEND_BUFF] = {0};

		int k = 0;
		for(k = 0; k < ARP_SEND_BUFF; k++) {
			tmp_buf[k] = 'v';
		}
		tmp_buf[ARP_SEND_BUFF] = 0;
		if (conn_data->dstIP.ip_type == IPV6_TYPE) {
			/* IPv6 */
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sendto neighbor solicitation IP: "IPv6_FMT"\n", LOG_VALUE,
					IPv6_PRINT(IPv6_CAST(&conn_data->dstIP.ipv6_addr)));

			/* setting sendto destination addr */
			dest_addr[conn_data->portId].ipv6.sin6_family = AF_INET6;
			memcpy(&dest_addr[conn_data->portId].ipv6.sin6_addr, &conn_data->dstIP.ipv6_addr, IPV6_ADDRESS_LEN);
			dest_addr[conn_data->portId].ipv6.sin6_port = htons(SOCKET_PORT);

			if ((sendto(fd_array_v6[conn_data->portId], tmp_buf, strlen(tmp_buf), 0, (struct sockaddr *)
							&dest_addr[conn_data->portId].ipv6, sizeof(struct sockaddr_in6))) < 0) {
				perror("IPv6:Send Failed:");
				return -1;
			}
		} else {
			/* IPv4 */
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sendto ret arp data IP: %s\n", LOG_VALUE,
					inet_ntoa(*(struct in_addr *)&conn_data->dstIP.ipv4_addr));

			/* setting sendto destination addr */
			dest_addr[conn_data->portId].ipv4.sin_family = AF_INET;
			dest_addr[conn_data->portId].ipv4.sin_addr.s_addr = conn_data->dstIP.ipv4_addr;
			dest_addr[conn_data->portId].ipv4.sin_port = htons(SOCKET_PORT);
			/*TODO : change strlen with strnlen with proper size (n)*/
			if ((sendto(fd_array_v4[conn_data->portId], tmp_buf, strlen(tmp_buf), 0,
							(struct sockaddr *)&dest_addr[conn_data->portId].ipv4,
							sizeof(struct sockaddr_in))) < 0) {
				perror("IPv4:Send Failed");
				return -1;
			}
		}
	}
	return 0;
}

uint8_t
get_dp_restart_cntr(void) {
	FILE *fd = NULL;
	int tmp_rstcnt = 0;

	if ((fd = fopen(FILE_NAME, "r")) == NULL ) {
		/* Creating new file */
		if ((fd = fopen(FILE_NAME,"w")) == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error! creating dp_rstCnt.txt file\n", LOG_VALUE);
		}
		return tmp_rstcnt;
	}

	/* */
	if (fscanf(fd,"%d", &tmp_rstcnt) < 0) {
		fclose(fd);
		RTE_LOG(NOTICE, DP, "DP Restart Count : %d\n", tmp_rstcnt);
		return tmp_rstcnt;
	}

	fclose(fd);
	RTE_LOG(NOTICE, DP, "DP Restart Count : %d\n", tmp_rstcnt);
	return tmp_rstcnt;
}

void
update_dp_restart_cntr(void) {
	FILE *fd;

	if ((fd = fopen(FILE_NAME,"w")) == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error! creating dp_rstCnt.txt file\n", LOG_VALUE);
	}

	fseek(fd, 0L, SEEK_SET);
	fprintf(fd, "%d\n", ++dp_restart_cntr);

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Updated restart counter Value of rstcnt: %d\n",
			LOG_VALUE, dp_restart_cntr);
	fclose(fd);
}

void timerCallback( gstimerinfo_t *ti, const void *data_t )
{
	peerData *md = (peerData*)data_t;
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(echo_mpool);

	/* CLI Address buffer */
	peer_address_t peer_addr;
	if (md->dstIP.ip_type == IPV6_TYPE) {
		memcpy(&peer_addr.ipv6.sin6_addr, &md->dstIP.ipv6_addr, IPV6_ADDR_LEN);
		peer_addr.type = IPV6_TYPE;
	} else {
		peer_addr.ipv4.sin_addr.s_addr = md->dstIP.ipv4_addr;
		peer_addr.type = IPV4_TYPE;
	}

	(md->dstIP.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"%s - %s: IPv6:"IPv6_FMT":%u.%s (%dms) has expired\n", LOG_VALUE, getPrintableTime(),
				md->name, IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr)), md->portId,
				ti == &md->pt ? "Periodic_Timer" :
				ti == &md->tt ? "Transmit_Timer" : "unknown",
				ti->ti_ms ):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"%s - %s: IPv4:%s:%u.%s (%dms) has expired\n", LOG_VALUE, getPrintableTime(),
				md->name, inet_ntoa(*(struct in_addr *)&md->dstIP.ipv4_addr), md->portId,
				ti == &md->pt ? "Periodic_Timer" :
				ti == &md->tt ? "Transmit_Timer" : "unknown",
				ti->ti_ms );

		md->itr = app.transmit_cnt;

	if (md->itr_cnt == md->itr) {
		/* Stop transmit timer for specific Peer Node */
		stopTimer( &md->tt );
		/* Stop periodic timer for specific Peer Node */
		stopTimer( &md->pt );
		/* Deinit transmit timer for specific Peer Node */
		deinitTimer( &md->tt );
		/* Deinit transmit timer for specific Peer Node */
		deinitTimer( &md->pt );

		if (md->dstIP.ip_type == IPV6_TYPE) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Stopped Periodic/transmit timer, peer node IPv6 "IPv6_FMT" is not reachable\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr)));
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Peer node IPv6 "IPv6_FMT" is not reachable\n", LOG_VALUE,
				IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr)));
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Stopped Periodic/transmit timer, peer node IPv4 %s is not reachable\n",
				LOG_VALUE, inet_ntoa(*(struct in_addr *)&md->dstIP.ipv4_addr));
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Peer node IPv4 %s is not reachable\n", LOG_VALUE,
				inet_ntoa(*(struct in_addr *)&md->dstIP.ipv4_addr));
		}

		update_peer_status(&peer_addr, FALSE);
		delete_cli_peer(&peer_addr);

		if ((md->portId == S1U_PORT_ID) || (md->portId == SGI_PORT_ID)) {
			del_entry_from_hash(&md->dstIP);
#ifdef USE_CSID
			if (md->portId == S1U_PORT_ID) {
				up_del_pfcp_peer_node_sess(&md->dstIP, S1U_PORT_ID);
			} else {
				up_del_pfcp_peer_node_sess(&md->dstIP, SGI_PORT_ID);
			}
#endif /* USE_CSID */
		} else if (md->portId == SX_PORT_ID) {
			delete_entry_heartbeat_hash(&md->dstIP);
#ifdef USE_CSID
			up_del_pfcp_peer_node_sess(&md->dstIP, SX_PORT_ID);
#endif /* USE_CSID */

		}
		return;
	}

	if (md->activityFlag == 1) {
		(md->dstIP.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Channel is active for NODE IPv6:"IPv6_FMT", No need to send echo to it's peer node\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr))) :
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Channel is active for NODE IPv4:%s, No need to send echo to it's peer node\n",
					LOG_VALUE, inet_ntoa(*(struct in_addr *)&md->dstIP.ipv4_addr));

		/* Reset activity flag */
		md->activityFlag = 0;
		md->itr_cnt = 0;

		/* Stop Timer transmit timer for specific Peer Node */
		stopTimer( &md->tt );
		/* Stop Timer periodic timer for specific Peer Node */
		stopTimer( &md->pt );

		/* VS: Restet Periodic Timer */
		if ( startTimer( &md->pt ) < 0)
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Periodic Timer failed to start\n", LOG_VALUE);
		return;
	}

	if (md->portId == SX_PORT_ID) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Send PFCP HeartBeat Request to "IPv6_FMT"\n",
			LOG_VALUE, IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr)));

		/* Socket Address buffer */
		peer_addr_t dest_addr_t = {0};
		if (md->dstIP.ip_type == IPV6_TYPE) {
			dest_addr_t.type = IPV6_TYPE;
			dest_addr_t.ipv6.sin6_family = AF_INET6;
			memcpy(&dest_addr_t.ipv6.sin6_addr.s6_addr, &md->dstIP.ipv6_addr,
					IPV6_ADDR_LEN);
			dest_addr_t.ipv6.sin6_port = dp_comm_port;
		} else {
			dest_addr_t.type = IPV4_TYPE;
			dest_addr_t.ipv4.sin_family = AF_INET;
			dest_addr_t.ipv4.sin_addr.s_addr = md->dstIP.ipv4_addr;
			dest_addr_t.ipv4.sin_port = dp_comm_port;
		}

		if (ti == &md->pt){
			gtpu_sx_seqnb = get_pfcp_sequence_number(PFCP_HEARTBEAT_REQUEST, gtpu_sx_seqnb);;
		}

		/* Send heartbeat request to peer node */
		process_pfcp_heartbeat_req(dest_addr_t, gtpu_sx_seqnb);

		if (ti == &md->tt)
		{
			(md->itr_cnt)++;
			update_peer_timeouts(&peer_addr, md->itr_cnt);
		}
		if (ti == &md->pt) {
			if ( startTimer( &md->tt ) < 0)
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Transmit Timer failed to start\n", LOG_VALUE);

			/* Stop periodic timer for specific Peer Node */
			stopTimer( &md->pt );
		}
		return;
	}

	if (md->dst_eth_addr.addr_bytes[0] == 0)
	{
		int ret;
		struct arp_ip_key arp_key = {0};
		struct arp_entry_data *ret_data = NULL;
		/* Fill the Arp Key */
		if (md->dstIP.ip_type == IPV6_TYPE) {
			/* IPv6: ARP Key */
			arp_key.ip_type.ipv6 = PRESENT;
			memcpy(&arp_key.ip_addr.ipv6.s6_addr, &md->dstIP.ipv6_addr, IPV6_ADDR_LEN);
		} else {
			/* IPv4: ARP Key */
			arp_key.ip_type.ipv4 = PRESENT;
			arp_key.ip_addr.ipv4 = md->dstIP.ipv4_addr;
		}

		ret = rte_hash_lookup_data(arp_hash_handle[md->portId],
				&arp_key, (void **)&ret_data);
		if (ret < 0) {
			(md->dstIP.ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ARP is not resolved for NODE IPv6:"IPv6_FMT"\n", LOG_VALUE,
						IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr))) :
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ARP is not resolved for NODE IPv4:%s\n", LOG_VALUE,
						inet_ntoa(*(struct in_addr *)&md->dstIP.ipv4_addr));
			/* Send Arp request to peer node through linux kernal */
			if ((arp_req_send(md)) < 0) {
				(md->dstIP.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to send ARP request to Node IPv6:%s\n",LOG_VALUE,
							IPv6_PRINT(IPv6_CAST(md->dstIP.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to send ARP request to Node IPv4:%s\n",LOG_VALUE,
							inet_ntoa(*(struct in_addr *)&md->dstIP));
			}
			return;
		}

		ether_addr_copy(&ret_data->eth_addr, &md->dst_eth_addr);

		if (md->portId == S1U_PORT_ID) {
			if (ti == &md->pt)
				gtpu_seqnb++;
			build_echo_request(pkt, md, gtpu_seqnb);
		} else if(md->portId == SGI_PORT_ID) {
			if (ti == &md->pt)
				gtpu_sgwu_seqnb++;
			build_echo_request(pkt, md, gtpu_sgwu_seqnb);
		}
	} else {
		if (md->portId == S1U_PORT_ID) {
			if (ti == &md->pt)
				gtpu_seqnb++;
			build_echo_request(pkt, md, gtpu_seqnb);
		} else if(md->portId == SGI_PORT_ID) {
			if (ti == &md->pt)
				gtpu_sgwu_seqnb++;
			build_echo_request(pkt, md, gtpu_sgwu_seqnb);
		}

	}

	if(pkt == NULL) {
		return;
	}

	if (md->portId == S1U_PORT_ID) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Pkts enqueue for S1U port\n", LOG_VALUE);

		if (rte_ring_enqueue(shared_ring[S1U_PORT_ID], pkt) == -ENOBUFS) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Can't queue PKT ring full"
				" Dropping pkt\n", LOG_VALUE);
		} else {
			update_cli_stats(&peer_addr, GTPU_ECHO_REQUEST, SENT, S1U);
		}

		if (ti == &md->tt) {
			(md->itr_cnt)++;
			update_peer_timeouts(&peer_addr, md->itr_cnt);
		}
	} else if(md->portId == SGI_PORT_ID) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"PKTS enqueue for SGI port\n", LOG_VALUE);

		if (rte_ring_enqueue(shared_ring[SGI_PORT_ID], pkt) == -ENOBUFS) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Can't queue PKT ring full so dropping PKT\n", LOG_VALUE);
		} else {
			update_cli_stats(&peer_addr, GTPU_ECHO_REQUEST, SENT, S5S8);
		}

		if (ti == &md->tt) {
			(md->itr_cnt)++;
			update_peer_timeouts(&peer_addr, md->itr_cnt);
		}
	}
	if (ti == &md->pt) {
		if ( startTimer( &md->tt ) < 0)
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Transmit Timer failed to start\n", LOG_VALUE);

		/* Stop periodic timer for specific Peer Node */
		stopTimer( &md->pt );
	}
}

uint8_t add_node_conn_entry(node_address_t dstIp, uint64_t sess_id, uint8_t portId)
{
	int ret = 0;
	peerData *conn_data = NULL;
	struct arp_entry_data *ret_conn_data = NULL;
	struct arp_ip_key arp_key = {0};
	/* Cli Struct */
	peer_address_t address;
	CLIinterface it;

	/* Validate the IP Type*/
	if ((dstIp.ip_type != IPV6_TYPE) && (dstIp.ip_type != IPV4_TYPE)) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"ERR: Not setting appropriate IP Type(IPv4:1 or IPv6:2),"
				"IP_TYPE:%u\n", LOG_VALUE, dstIp.ip_type);
		return -1;
	}

	ret = rte_hash_lookup_data(conn_hash_handle,
				&dstIp, (void **)&conn_data);
	if ( ret < 0) {
		(dstIp.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Add entry in conn table IPv6:"IPv6_FMT", up_seid:%lu\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(dstIp.ipv6_addr)), sess_id) :
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Add entry in conn table IPv4:"IPV4_ADDR", up_seid:%lu\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dstIp.ipv4_addr), sess_id);


		/* No conn entry for dstIp
		 * Add conn_data for dstIp at
		 * conn_hash_handle
		 * */

		conn_data = rte_malloc_socket(NULL,
						sizeof(peerData),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (conn_data == NULL ){
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failure to allocate memory for connection data entry : %s\n",
				LOG_VALUE, rte_strerror(rte_errno));
			return -1;
		}

		if (portId == S1U_PORT_ID) {
				/* CLI: Setting interface details */
				it = S1U;

				if (dstIp.ip_type == IPV6_TYPE) {
					/* Validate the Destination IPv6 Address Network */
					if (validate_ipv6_network(IPv6_CAST(dstIp.ipv6_addr), app.wb_ipv6,
								app.wb_ipv6_prefix_len)) {
						memcpy(&(conn_data->srcIP).ipv6_addr, &app.wb_ipv6.s6_addr, IPV6_ADDR_LEN);
					} else if (validate_ipv6_network(IPv6_CAST(dstIp.ipv6_addr),
								app.wb_li_ipv6, app.wb_li_ipv6_prefix_len)) {
						memcpy(&(conn_data->srcIP).ipv6_addr, &app.wb_li_ipv6.s6_addr, IPV6_ADDR_LEN);
					} else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Destination IPv6 Addr "IPv6_FMT" is NOT in local intf subnet\n",
								LOG_VALUE, IPv6_PRINT(IPv6_CAST(dstIp.ipv6_addr)));
						return -1;
					}
					/* Set the IP Type of the Source IP */
					(conn_data->srcIP).ip_type = IPV6_TYPE;
				} else if (dstIp.ip_type == IPV4_TYPE) {
					/* Validate the Destination IPv4 Address subnet */
					if (validate_Subnet(ntohl(dstIp.ipv4_addr), app.wb_net, app.wb_bcast_addr)) {
						(conn_data->srcIP).ipv4_addr = htonl(app.wb_ip);
					} else if (validate_Subnet(ntohl(dstIp.ipv4_addr), app.wb_li_net, app.wb_li_bcast_addr)) {
						(conn_data->srcIP).ipv4_addr = htonl(app.wb_li_ip);
					} else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Destination IPv4 Addr "IPV4_ADDR" is NOT in local intf subnet\n",
								LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dstIp.ipv4_addr));
						return -1;
					}
					/* Set the IP Type of the Source IP */
					(conn_data->srcIP).ip_type = IPV4_TYPE;
				}

				/* Fill the source physical address */
				conn_data->src_eth_addr = app.wb_ether_addr;

		} else if (portId == SGI_PORT_ID) {
				/* CLI: Setting interface details */
				it = S5S8;

				if (dstIp.ip_type == IPV6_TYPE) {
					/* Validate the Destination IPv6 Address Network */
					if (validate_ipv6_network(IPv6_CAST(dstIp.ipv6_addr), app.eb_ipv6,
								app.eb_ipv6_prefix_len)) {
						memcpy(&(conn_data->srcIP).ipv6_addr, &app.eb_ipv6.s6_addr, IPV6_ADDR_LEN);
					} else if (validate_ipv6_network(IPv6_CAST(dstIp.ipv6_addr),
								app.eb_li_ipv6, app.eb_li_ipv6_prefix_len)) {
						memcpy(&(conn_data->srcIP).ipv6_addr, &app.eb_li_ipv6.s6_addr, IPV6_ADDR_LEN);
					} else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Destination IPv6 Addr "IPv6_FMT" is NOT in local intf subnet\n",
								LOG_VALUE, IPv6_PRINT(IPv6_CAST(dstIp.ipv6_addr)));
						return -1;
					}
					/* Set the IP Type of the Source IP */
					(conn_data->srcIP).ip_type = IPV6_TYPE;
				} else if (dstIp.ip_type == IPV4_TYPE) {
					/* Validate the Destination IPv4 Address subnet */
					if (validate_Subnet(ntohl(dstIp.ipv4_addr), app.eb_net, app.eb_bcast_addr)) {
						(conn_data->srcIP).ipv4_addr = htonl(app.eb_ip);
					} else if (validate_Subnet(ntohl(dstIp.ipv4_addr), app.eb_li_net, app.eb_li_bcast_addr)) {
						(conn_data->srcIP).ipv4_addr = htonl(app.eb_li_ip);
					} else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Destination IPv4 Addr "IPV4_ADDR" is NOT in local intf subnet\n",
								LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dstIp.ipv4_addr));
						return -1;
					}
					/* Set the IP Type of the Source IP */
					(conn_data->srcIP).ip_type = IPV4_TYPE;
				}

				/* Fill the source physical address */
				conn_data->src_eth_addr = app.eb_ether_addr;
		}

		/* CLI: Setting interface details */
		if (portId == SX_PORT_ID)
		{
			it = SX;
		}

		conn_data->portId = portId;
		conn_data->activityFlag = 0;
		conn_data->dstIP = dstIp;
		conn_data->itr = app.transmit_cnt;
		conn_data->itr_cnt = 0;

		/* Fill the info for CLI and ARP Key */
		if (dstIp.ip_type == IPV6_TYPE) {
			memcpy(&address.ipv6.sin6_addr, &dstIp.ipv6_addr, IPV6_ADDR_LEN);
			address.type = IPV6_TYPE;
			/* IPv6: ARP Key */
			arp_key.ip_type.ipv6 = PRESENT;
			memcpy(&arp_key.ip_addr.ipv6.s6_addr,  &dstIp.ipv6_addr, IPV6_ADDR_LEN);
		} else if (dstIp.ip_type == IPV4_TYPE) {
			address.ipv4.sin_addr.s_addr = dstIp.ipv4_addr;
			address.type = IPV4_TYPE;
			/* IPv4: ARP Key */
			arp_key.ip_type.ipv4 = PRESENT;
			arp_key.ip_addr.ipv4 = dstIp.ipv4_addr;
		}

		/* Retrieve the destination interface MAC Address */
		if ((portId == S1U_PORT_ID) || (portId == SGI_PORT_ID)) {
			ret = rte_hash_lookup_data(arp_hash_handle[portId],
							&arp_key, (void **)&ret_conn_data);
			if (ret < 0) {
				if ((arp_req_send(conn_data)) < 0) {
					(conn_data->dstIP.ip_type == IPV6_TYPE)?
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to send neighbor solicitaion request to Node:"IPv6_FMT"\n",
								LOG_VALUE, IPv6_PRINT(IPv6_CAST(conn_data->dstIP.ipv6_addr))) :
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to send ARP request to Node:%s\n",
								LOG_VALUE, inet_ntoa(*(struct in_addr *)&conn_data->dstIP.ipv4_addr));
				}
			} else {
				(dstIp.ip_type == IPV6_TYPE)?
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"ARP Entry found for IPv6:"IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(IPv6_CAST(conn_data->dstIP.ipv6_addr))) :
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"ARP Entry found for IPv4:%s\n",
							LOG_VALUE, inet_ntoa(*(struct in_addr *)&conn_data->dstIP.ipv4_addr));

				ether_addr_copy(&ret_conn_data->eth_addr, &conn_data->dst_eth_addr);
			}
		}

		/* VS: Add peer node entry in connection hash table */
		if ((rte_hash_add_key_data(conn_hash_handle,
				&dstIp, conn_data)) < 0 ) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry in hash table", LOG_VALUE);
			return -1;
		}

		/* Initialized Timer entry */
		if (!initpeerData(conn_data, "PEER_NODE",
					(app.periodic_timer * 1000), (app.transmit_timer * 1000)))
		{
		   clLog(clSystemLog, eCLSeverityCritical,
				   LOG_FORMAT"%s - initialization of %s failed\n",
				   LOG_VALUE, getPrintableTime(), conn_data->name);
		   return -1;
		}

		/* Add the entry for CLI stats */
		add_cli_peer((peer_address_t *) &address, it);
		update_peer_status((peer_address_t *) &address, TRUE);

		/* Start periodic timer */
		if ( startTimer( &conn_data->pt ) < 0)
			clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Periodic Timer failed to start\n", LOG_VALUE);

		conn_cnt++;

	} else {
		(dstIp.ip_type == IPV6_TYPE)?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Conn entry already exit in conn table for IPv6:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(*((struct in6_addr *)dstIp.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Conn entry already exit in conn table for IPv4:%s\n", LOG_VALUE,
					inet_ntoa(*((struct in_addr *)&dstIp)));
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Current Active Conn Cnt:%u\n", LOG_VALUE, conn_cnt);
	return 0;

}

void
echo_table_init(void)
{

	/* Create conn_hash for maintain each port peer connection details */
	/* Create arp_hash for each port */
	conn_hash_params.socket_id = rte_socket_id();
	conn_hash_handle =
			rte_hash_create(&conn_hash_params);
	if (!conn_hash_handle) {
		rte_panic("%s::"
				"\n\thash create failed::"
				"\n\trte_strerror= %s; rte_errno= %u\n",
				conn_hash_params.name,
				rte_strerror(rte_errno),
				rte_errno);
	}

	/* Create echo_pkt TX mmempool for each port */
	echo_mpool = rte_pktmbuf_pool_create(
			echo_mpoolname,
			NB_ECHO_MBUF, 32,
			0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (echo_mpool == NULL) {
		rte_panic("rte_pktmbuf_pool_create failed::"
				"\n\techo_mpoolname= %s;"
				"\n\trte_strerror= %s\n",
				echo_mpoolname,
				rte_strerror(abs(errno)));
		return;
	}

}

void rest_thread_init(void)
{
	echo_table_init();

	sigset_t sigset;

	/* mask SIGALRM in all threads by default */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGRTMIN + 1);
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	if (!gst_init())
	{
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"%s - gstimer_init() failed!!\n",
			LOG_VALUE, getPrintableTime() );
		rte_panic(LOG_FORMAT"Cration of timer thread failed.\n", LOG_VALUE);
	}

}

void
teidri_timer_cb(gstimerinfo_t *ti, const void *data_t ) {

	int ret = 0;
	/* send the error indication, if bearer context not found */
	error_indication_snd = TRUE;
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	peerData *data =  (peerData *) data_t;
#pragma GCC diagnostic pop   /* require GCC 4.6 */

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"TEIDRI Timer Callback Start \n", LOG_VALUE);

	/* flush data for inactive peers and recreate file with data of active peers*/
	ret = flush_inactive_teidri_data(TEIDRI_FILENAME, &upf_teidri_blocked_list, &upf_teidri_allocated_list,
			&upf_teidri_free_list, app.teidri_val);
	if(ret != 0){
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Error in flushing data of inactive peers\n", LOG_VALUE);
	}

	if(data->pt.ti_id != 0) {
		stoptimer(&data->pt.ti_id);
		deinittimer(&data->pt.ti_id);
	}

	if (data != NULL) {
		rte_free(data);
	}
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"TEIDRI Timer Stop and Deinit : successfully \n", LOG_VALUE);
}

/* Function to add and start timer for flush the inactive teidri and peer node address from file,
 * and put active teidri and peer node address into file
 */
bool
start_dp_teidri_timer(void) {
	peerData *timer_entry = NULL;

	/* Allocate the memory. */
	timer_entry = rte_zmalloc_socket(NULL, sizeof(peerData),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_entry == NULL ){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failure to allocate timer entry : %s \n",
			LOG_VALUE, rte_strerror(rte_errno));
		return false;
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Init TEIDRI Timer Start \n", LOG_VALUE);
	if (!init_timer(timer_entry, app.teidri_timeout, teidri_timer_cb)){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Initialization of TEIDRI Timer failed erro no %d\n",
			LOG_VALUE, getPrintableTime(), errno);
		return false;
	}
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Init TEIDRI Timer END \n", LOG_VALUE);

	if (starttimer(&timer_entry->pt) < 0){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"TEIDRI Timer failed to start\n", LOG_VALUE);
		return false;
	}

	/* Don't send the error indication */
	error_indication_snd = FALSE;
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"TEIDRI Timer Started successfully \n", LOG_VALUE);
	return true;
}
