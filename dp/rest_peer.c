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

#include <unistd.h>
#include <locale.h>
#include <signal.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>
#include <sys/time.h>

#include "main.h"
#include "epc_arp.h"
#include "pfcp_association.h"

#include "../restoration/gstimer.h"

#define OFFSET 		2208988800ULL

/* Generate new pcap for s1u port */
#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_west;
extern pcap_dumper_t *pcap_dumper_east;
#endif /* PCAP_GEN */

extern unsigned int fd_array[2];
extern uint16_t cp_comm_port;
//#ifndef STATIC_ARP
static struct sockaddr_in dest_addr[2];
//#endif /* STATIC_ARP */

/**
 * rte hash handler.
 */
/* 2 hash handles, one for S1U and another for SGI */
extern struct rte_hash *arp_hash_handle[NUM_SPGW_PORTS];

/**
 * memory pool for queued data pkts.
 */
static char *echo_mpoolname = {
	"echo_mpool",
};

int32_t conn_cnt = 0;

peerData data[500] = {0};

const char
*eth_addr(struct ether_addr *eth_h)
{

	static char *str;
	sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
			eth_h->addr_bytes[0],
			eth_h->addr_bytes[1],
			eth_h->addr_bytes[2],
			eth_h->addr_bytes[3],
			eth_h->addr_bytes[4],
			eth_h->addr_bytes[5]);
	return str;
	
}

static void
print_eth(struct ether_addr *eth_h, uint8_t type)
{
	if (type == 0) {
	printf("\n  ETH:  src=%02X:%02X:%02X:%02X:%02X:%02X",
			eth_h->addr_bytes[0],
			eth_h->addr_bytes[1],
			eth_h->addr_bytes[2],
			eth_h->addr_bytes[3],
			eth_h->addr_bytes[4],
			eth_h->addr_bytes[5]);
	} else if (type == 1) {
	printf("\n  ETH:  dst=%02X:%02X:%02X:%02X:%02X:%02X",
			eth_h->addr_bytes[0],
			eth_h->addr_bytes[1],
			eth_h->addr_bytes[2],
			eth_h->addr_bytes[3],
			eth_h->addr_bytes[4],
			eth_h->addr_bytes[5]);
	}

}

static uint32_t
get_ins_pos(peerData *data, uint32_t n, uint64_t ip_addr)
{
	int itr;
	for(itr = n-1; (itr >= 0 && data[itr].dstIP <= ip_addr); itr--)
		data[itr+1] = data[itr];
	return (itr+1);
}

void timerCallback( gstimerinfo_t *ti, const void *data_t )
{
	int32_t inx = 0;
	peerData *md = (peerData*)data_t;
	uint32_t tmp_key = htonl(md->dstIP);
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(echo_mpool);
	struct sockaddr_in dest_addr;
	
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.s_addr = md->dstIP;
	dest_addr.sin_port = htons(cp_comm_port);
	
	RTE_LOG_DP(DEBUG, DP, "%s - %s:%s.%s (%dms) has expired\n", getPrintableTime(),
	      md->name, inet_ntoa(*(struct in_addr *)&tmp_key),
	      ti == &md->pt ? "Periodic_Timer" :
	      ti == &md->tt ? "Transmit_Timer" : "unknown",
	      ti->ti_ms );

	if (md->itr_cnt == md->itr) {
		//printf("port %u iteration loop exit for IP: %s  ...!!!!\n", 
		//md->portId, inet_ntoa(*(struct in_addr *)&ipv4_hdr_t->dst_addr));
		/* Stop Timer transmit timer for specific MME */
		stopTimer( &data[inx].tt );
		/* Stop Timer periodic timer for specific MME */
		stopTimer( &data[inx].pt );
		RTE_LOG_DP(ERR, DP, "Stopped Periodic/transmit timer, peer node is not reachable\n");
		flush_eNB_session(md, inx);
		return;
	}

	if (md->activityFlag == 1) {
		RTE_LOG_DP(DEBUG, DP, "Channel is active for NODE :%s, No need to send echo to it's peer node ..!!\n", 
							inet_ntoa(*(struct in_addr *)&md->dstIP));
		md->activityFlag = 0;
		md->itr_cnt = 0;
		return;
	}

	//printf("MAC:%u\n", md->dst_eth_addr.addr_bytes[0]);
	if (md->portId == SX_PORT_ID) {
		//printf(" Send PFCP HEARTBEAT REQ\n");
		/* VS:TODO: Defined this part after merging sx heartbeat*/
		//process_pfcp_heartbeat_req(md->dst_ip, up_time); /* TODO: Future Enhancement */
		process_pfcp_heartbeat_req(&dest_addr);

		if (ti == &md->tt)
			(md->itr_cnt)++;

		return;
	}

	if (md->dst_eth_addr.addr_bytes[0] == 0) 
	{
		int ret;
		struct arp_entry_data *ret_data = NULL;
		ret = rte_hash_lookup_data(arp_hash_handle[md->portId],
						&(md->dstIP), (void **)&ret_data);
		if (ret < 0) {
			return;
		}

		//printf("%s:ret:%d\n", __func__, ret);
   		inx = inx_bsearch(data, 0, (conn_cnt - 1), md->dstIP); 
		ether_addr_copy(&ret_data->eth_addr, &data[inx].dst_eth_addr);
		//ether_addr_copy(&ret_data->eth_addr, &data[pos].dst_eth_addr);
		//build_echo_request(pkt, ret_data);
		//build_echo_request(pkt, &data[pos]);
		build_echo_request(pkt, &data[inx]);
		//md->buf = pkt;
		//data[inx].buf = pkt;	
		//data[pos].buf = pkt;	
		//printf("%s:ret:%d\n", __func__, ret);
		//return;	
	} else {
   		inx = inx_bsearch(data, 0, (conn_cnt - 1), md->dstIP); 
		//ether_addr_copy(&ret_data->eth_addr, &data[pos].dst_eth_addr);
		//build_echo_request(pkt, ret_data);
		//build_echo_request(pkt, &data[pos]);
		build_echo_request(pkt, &data[inx]);

	}

	//print_eth(&data[inx].dst_eth_addr, 0);
	struct rte_mbuf *mt = pkt;
	//struct ipv4_hdr *ipv4_hdr_t = (struct ipv4_hdr*)(rte_pktmbuf_mtod(mt, unsigned char*) + 14);
	//printf("**** portId:%u : Enqueu IP DST:%s\n", md->portId, inet_ntoa(*(struct in_addr *)&ipv4_hdr_t->dst_addr));

	//printf("**** portId:%u : Enqueu IP DST:%s\n", md->portId, inet_ntoa(*(struct in_addr *)&ipv4_hdr_t->dst_addr));
/* Capture the echo packets.*/
//#ifdef PCAP_GEN
//	if (md->portId == S1U_PORT_ID) {
//		(md->itr_cnt)++;
//	        dump_pcap(&mt, 1, pcap_dumper_west);
//	} else if(md->portId == SGI_PORT_ID) {
//		(md->itr_cnt)++;
//	        dump_pcap(&mt, 1, pcap_dumper_east);
//	}
//#endif /* PCAP_GEN */
	if (md->portId == S1U_PORT_ID) {
		//printf("Send echo to eNB\n");
		RTE_LOG_DP(DEBUG, DP, "Pkts enqueue for S1U port..!!\n");

		if (rte_ring_enqueue(shared_ring[S1U_PORT_ID], pkt) == -ENOBUFS) {
			//rte_pktmbuf_free(pkt1);
			RTE_LOG_DP(ERR, DP, "%s::Can't queue pkt- ring full..."
					" Dropping pkt\n", __func__);
		}

		if (ti == &md->tt)
			(md->itr_cnt)++;

	} else if(md->portId == SGI_PORT_ID) {
		//printf("Send echo to PGWU\n");
		RTE_LOG_DP(DEBUG, DP, "Pkts enqueue for SGI port..!!\n");

		if (rte_ring_enqueue(shared_ring[SGI_PORT_ID], mt) == -ENOBUFS) {
			//rte_pktmbuf_free(pkt1);
			RTE_LOG_DP(ERR, DP, "%s::Can't queue pkt- ring full..."
					" Dropping pkt\n", __func__);
		}

		if (ti == &md->tt)
			(md->itr_cnt)++;
	}
	/* TODO: */
	if (ti == &md->pt) {
		if ( startTimer( &md->tt ) < 0)
			RTE_LOG_DP(ERR, DP, "Transmit Timer failed to start..\n");
	}
}

void
dp_flush_session(uint32_t ip_addr, uint32_t sess_id)
{
	int32_t inx = 0;
	uint32_t temp_key = htonl(ip_addr);

	RTE_LOG_DP(DEBUG, DP, "Flush sess entry from connection table of ip:%s, sess_id:%u\n", 
				inet_ntoa(*(struct in_addr *)&temp_key), sess_id);
	/* VS: TODO */
   	if ((inx = inx_bsearch(data, 0, (conn_cnt - 1), ip_addr)) < 0) {
		RTE_LOG_DP(DEBUG, DP, " Entry not found for NODE :%s\n", 
							inet_ntoa(*(struct in_addr *)&ip_addr));
		return;
	}

	/* VS: Delete sess id from connection table */
	for(uint32_t cnt = 0; cnt < data[inx].sess_cnt; cnt++) {
		if (sess_id == data[inx].sess_id[cnt]) {
			for(uint32_t pos = cnt; pos < (data[inx].sess_cnt - 1); pos++ )
				data[inx].sess_id[pos] = data[inx].sess_id[pos + 1]; 

			data[inx].sess_cnt--;
		}	
	}
	
	if (data[inx].sess_cnt == 0) {
		/* Stop Timer for specific eNB */
		stopTimer( &data[inx].tt );
		stopTimer( &data[inx].pt );
	
		deinitTimer( &data[inx].tt );
		deinitTimer( &data[inx].pt );

			
		RTE_LOG_DP(DEBUG, DP, " Delete entry from connection table of ip:%s\n", 
				inet_ntoa(*(struct in_addr *)&temp_key));

		/* VS: delete entry from connection table */
		for(uint32_t pos = inx; pos <= (conn_cnt - 1); pos++ )
			data[pos] = data[pos + 1]; 

		conn_cnt--;
		RTE_LOG_DP(DEBUG, DP, " Current Active Conn Cnt:%u\n", conn_cnt);
	}

}

void
flush_eNB_session(peerData *data_t, int32_t inx)
{

	/* Stop Timer for specific eNB */
	stopTimer( &data_t->tt );
	stopTimer( &data_t->pt );

	/* VS: Flush DP session table */
	for(uint32_t cnt = 0; cnt < data_t->sess_cnt; cnt++) {
		struct session_info sess_info = {0};
                struct dp_id dp = {0};

                dp.id = 1234;
                strncpy(dp.name,"Dummy",5);
		sess_info.sess_id = data_t->sess_id[cnt];

		RTE_LOG_DP(DEBUG, DP, " %s: Sess ID's :%lu\n", __func__, sess_info.sess_id);

		dp_session_delete(dp, &sess_info);
		
		/* TODO: VS send delete session request to peer control node  */
		//fill_pfcp_sess_del_req();
	}

	deinitTimer( &data_t->tt );
	deinitTimer( &data_t->pt );

	/* VS: delete entry from connection table */
	for(uint32_t pos = inx; pos < (conn_cnt - 1); pos++ )
		data[pos] = data[pos + 1]; 

	conn_cnt--;
	//rte_free(data_t);
	//data_t = NULL;

}

uint8_t add_node_conn_entry(uint32_t dstIp, uint64_t sess_id, uint8_t portId) 
{
	int ret;
	int32_t index = 0;
	uint32_t tmp_key = htonl(dstIp);
	struct arp_entry_data *ret_data = NULL;

   	index = inx_bsearch(data, 0, conn_cnt, dstIp); 
   	//index = inx_bsearch(data, 0, conn_cnt, htonl(dstIp)); 

	if (index < 0) {
		RTE_LOG_DP(DEBUG, DP, " Add entry in conn table :%s\n", 
					inet_ntoa(*((struct in_addr *)&tmp_key)));
		//struct rte_mbuf *pkt = rte_pktmbuf_alloc(echo_mpool);
		//build_echo_request(pkt, ret_data);

		//pos = get_ins_pos(data, conn_cnt, dstIp);

		//if (portId == S1U_PORT_ID) {
		//	data[pos].src_eth_addr = app.s1u_ether_addr;
		//	data[pos].srcIP = app.s1u_ip;
		//	//data[pos].srcIP = app.s5s8_pgwu_ip;

		//} else if (portId == SGI_PORT_ID) {
		//	data[pos].src_eth_addr = app.sgi_ether_addr;
		//	data[[pos].srcIP = app.sgi_ip;
		//	//data[pos].srcIP = app.s5s8_sgwu_ip;
		//}

		if (portId == S1U_PORT_ID) {
			data[conn_cnt].src_eth_addr = app.s1u_ether_addr;
			data[conn_cnt].srcIP = app.s1u_ip;
			//data[conn_cnt].srcIP = app.s5s8_pgwu_ip;

		} else if (portId == SGI_PORT_ID) {
			data[conn_cnt].src_eth_addr = app.sgi_ether_addr;
			data[conn_cnt].srcIP = app.sgi_ip;
			//data[conn_cnt].srcIP = app.s5s8_sgwu_ip;
		}

		//data[pos].portId = portId;	
		//data[pos].activityFlag = 0;
		////data[pos].srcIP = conn_arr_keys[i].ip;	
		//data[pos].dstIP = dstIp;
		//data[pos].dstIP = htonl(dstIp);
		//data[pos].itr = 5;	
		//data[pos].itr_cnt = 0;	
		////data[pos].buf = pkt;	
 
		data[conn_cnt].portId = portId;	
		data[conn_cnt].activityFlag = 0;
		//data[conn_cnt].srcIP = conn_arr_keys[i].ip;	
		//data[conn_cnt].dstIP = dstIp;
		data[conn_cnt].dstIP = htonl(dstIp);
		data[conn_cnt].itr = app.transmit_cnt;	
		data[conn_cnt].itr_cnt = 0;	
		//data[conn_cnt].buf = pkt;	
		data[conn_cnt].sess_id[data[conn_cnt].sess_cnt] = sess_id;	
		data[conn_cnt].sess_cnt++;	

		if ((portId == S1U_PORT_ID) || (portId == SGI_PORT_ID)) {
			ret = rte_hash_lookup_data(arp_hash_handle[portId],
							&data[conn_cnt].dstIP, (void **)&ret_data);
		
			if (ret < 0) {
				RTE_LOG_DP(DEBUG, DP, "Sendto:: ret_arp_data->ip= %s\n",
							inet_ntoa(*(struct in_addr *)&data[conn_cnt].dstIP));

				if (fd_array[portId] > 0) {
					/* setting sendto destination addr */
					dest_addr[portId].sin_family = AF_INET;
					//dest_addr[portId].sin_addr.s_addr = htonl(dstIp);
					dest_addr[portId].sin_addr.s_addr = data[conn_cnt].dstIP;
					dest_addr[portId].sin_port = htons(SOCKET_PORT);

					char *tmp_buf = (char *)malloc((512) * sizeof(char) + 1);
			
					int k = 0;
					for(k = 0; k < 512; k++) {
						tmp_buf[k] = 'v';
					}
					tmp_buf[512] = 0;

					if ((sendto(fd_array[portId], tmp_buf, strlen(tmp_buf), 0, (struct sockaddr *)
								&dest_addr[portId], sizeof(struct sockaddr_in))) < 0) {
						perror("send failed");
						return -1;
					}
				}
			} else {
				RTE_LOG_DP(DEBUG, DP, "ARP Entry found for %s\n", 
						inet_ntoa(*((struct in_addr *)&tmp_key)));
				ether_addr_copy(&ret_data->eth_addr, &data[conn_cnt].dst_eth_addr);
				//ether_addr_copy(&ret_data->eth_addr, &data[pos].dst_eth_addr);
				//struct rte_mbuf *pkt = rte_pktmbuf_alloc(echo_mpool);
				//build_echo_request(pkt, ret_data);
				//build_echo_request(pkt, &data[pos]);
				//build_echo_request(pkt, &data[conn_cnt]);
				//data[conn_cnt].buf = pkt;	
				//data[pos].buf = pkt;	
			}
		}

		//printf(" ret:%d", ret);
		/* VS: Temp for testing */
		//data[conn_cnt].dst_eth_addr = app.sgi_ether_addr;
		//struct rte_mbuf *pkt = rte_pktmbuf_alloc(echo_mpool);
		//build_echo_request(pkt, &data[conn_cnt]);
		//data[conn_cnt].buf = pkt;	

		//if ( !initpeerData( &data[pos], "PEER_NODE", (app.periodic_timer * 1000), (app.transmit_timer * 1000)) )
		//{
		//   printf( "%s - initialization of %s failed\n", getPrintableTime(), data[pos].name );
		//   //return -1;
		//}
		//
		//startTimer( &data[pos].pt );
		//startTimer( &data[pos].tt );

		if ( !initpeerData( &data[conn_cnt], "PEER_NODE", (app.periodic_timer * 1000), (app.transmit_timer * 1000)) )
		{
		   RTE_LOG_DP(ERR, DP, "%s - initialization of %s failed\n", getPrintableTime(), data[conn_cnt].name );
		   //return -1;
		}
		
		if ( startTimer( &data[conn_cnt].pt ) < 0)
			RTE_LOG_DP(ERR, DP, "Periodic Timer failed to start...\n");
		//if (startTimer( &data[conn_cnt].tt" ) < 0)
		//	RTE_LOG_DP(ERR, DP, "Transmit Timer failed to start...\n");
		conn_cnt++;

		//for(int i = 0; i < conn_cnt; i++) 
		//	printf("%d IP DST:%s\n", i, inet_ntoa(*(struct in_addr *)&data[i].dstIP));

	} else {
		/* TODO: eNB entry already exit in conn table */
		RTE_LOG_DP(DEBUG, DP, " Conn entry already exit in conn table :%s\n", 
					inet_ntoa(*((struct in_addr *)&tmp_key)));
		data[index].sess_id[data[index].sess_cnt] = sess_id;	
		data[index].sess_cnt++;	

	}

	RTE_LOG_DP(DEBUG, DP, " Current Active Conn Cnt:%u\n", conn_cnt);
	return 0;
}
 
void
echo_table_init(void)
{

	/* Create conn_hash for maintain each port peer connection details */
	//conn_hash_params.socket_id = rte_socket_id();
	//conn_hash_handle =
	//			rte_hash_create(&conn_hash_params);
	//if (!conn_hash_handle) {
	//		rte_panic("%s::"
	//				"\n\thash create failed::"
	//				"\n\trte_strerror= %s; rte_errno= %u\n",
	//				conn_hash_params.name,
	//				rte_strerror(rte_errno),
	//				rte_errno);
	//}
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
	sigaddset(&sigset, SIGRTMIN);
	sigaddset(&sigset, SIGUSR1);           
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	if (!gst_init())
	{
		RTE_LOG_DP(ERR, DP, "%s - gstimer_init() failed!!\n", getPrintableTime() );
		//return 1;
	}

	/*
	 * Create pthread to send echo request to peer nodes.
	 */
	//pthread_t thread;
	//int err;

	//err = pthread_create(&thread, NULL, &echo_req_thread, NULL);
	//if (err != 0)
	//	RTE_LOG_DP(INFO, API, "\ncan't create S1U ECHO REQ thread :[%s]", strerror(err));
	//else
	//	RTE_LOG_DP(INFO, API, "\n S1U ECHO req thread created successfully\n");

}
