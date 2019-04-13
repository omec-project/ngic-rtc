
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
#include <unistd.h>
#include <locale.h>
#include <signal.h>
#include <stdlib.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>
#include <sys/time.h>

#include "main.h"
#include "gtpv2c.h"
#include "cp.h"
#include "pfcp_association.h"

#include "../restoration/gstimer.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

char filename[256] = "../config/cp_rstCnt.txt";


extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_sgwc_sockaddr_len;
extern socklen_t s5s8_pgwc_sockaddr_len;

extern int s11_sgwc_fd_arr[MAX_NUM_SGWC];
extern int s5s8_sgwc_fd_arr[MAX_NUM_SGWC];
extern int s5s8_pgwc_fd_arr[MAX_NUM_PGWC];

extern struct pfcp_config_t pfcp_config;
extern uint8_t rstCnt;
int32_t conn_cnt = 0;

peerData data[500] = {0};

uint8_t update_rstCnt(void)
{
	FILE *fp;
	int tmp;
	
	if ((fp = fopen(filename,"rw+")) == NULL){
       		//printf("Error! opening cp_rstCnt.txt file");
		if ((fp = fopen(filename,"w")) == NULL)
       			printf("Error! creating cp_rstCnt.txt file");
	}
	
	if (fscanf(fp,"%u", &tmp) < 0) {
		/* VS: Cur pos shift to initial pos */
		fseek(fp, 0, SEEK_SET);
		fprintf(fp, "%u\n", ++rstCnt);
		fclose(fp); 
		return rstCnt;

	}
	/* VS: Cur pos shift to initial pos */
	fseek(fp, 0, SEEK_SET);

	rstCnt = tmp;	
	fprintf(fp, "%d\n", ++rstCnt);
	
	RTE_LOG_DP(DEBUG, CP, "Updated restart counter Value of rstcnt=%u\n", rstCnt);
	fclose(fp); 
	
	return rstCnt;
}
  
void timerCallback( gstimerinfo_t *ti, const void *data_t )
{
	uint16_t payload_length;
	struct sockaddr_in dest_addr;
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	peerData *md = (peerData*)data_t;
#pragma GCC diagnostic pop   /* require GCC 4.6 */	

	uint32_t tmp_key = md->dstIP;
	
	RTE_LOG_DP(DEBUG, CP, "%s - %s:%s.%s (%dms) has expired\n", getPrintableTime(),
		md->name, inet_ntoa(*(struct in_addr *)&tmp_key),
		ti == &md->pt ? "Periodic_Timer" :
		ti == &md->tt ? "Transmit_Timer" : "unknown",
		ti->ti_ms );

	if (md->itr_cnt == md->itr) {
		int32_t inx = 0;
		inx = inx_bsearch(data, 0, (conn_cnt - 1), md->dstIP);

	        /* Stop Timer transmit timer for specific MME */
	        stopTimer( &data[inx].tt );
	        /* Stop Timer periodic timer for specific MME */
	        stopTimer( &data[inx].pt );
		RTE_LOG_DP(DEBUG, CP, "Stopped Periodic/transmit timer, peer node is not reachable\n");
		//printf("port %u iteration loop exit for IP: %s  ...!!!!\n",
		//	md->portId, inet_ntoa(*(struct in_addr *)&tmp_key));
		/*VS: TODO Flush sessions */
		return;
	}

	bzero(&echo_tx_buf, sizeof(echo_tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) echo_tx_buf;

	build_gtpv2_echo_request(gtpv2c_tx);
                
	payload_length = ntohs(gtpv2c_tx->gtpc.length)
			+ sizeof(gtpv2c_tx->gtpc);

	/* setting sendto destination addr */
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.s_addr = md->dstIP;
	dest_addr.sin_port = htons(GTPC_UDP_PORT);

	if (md->portId == S11_SGW_PORT_ID) {
		gtpv2c_send(s11_sgwc_fd_arr[0], echo_tx_buf, payload_length,
		               (struct sockaddr *) &dest_addr,
		               s11_mme_sockaddr_len);
		if (ti == &md->tt)
			(md->itr_cnt)++;

	} else if (md->portId == S5S8_SGWC_PORT_ID) {

		gtpv2c_send(s5s8_sgwc_fd, echo_tx_buf, payload_length,
		                (struct sockaddr *) &dest_addr,
		                s5s8_pgwc_sockaddr_len);
		if (ti == &md->tt)
			(md->itr_cnt)++;

	} else if (md->portId == S5S8_PGWC_PORT_ID) {
		gtpv2c_send(s5s8_pgwc_fd, echo_tx_buf, payload_length,
		                (struct sockaddr *) &dest_addr,
		                s5s8_sgwc_sockaddr_len);
		if (ti == &md->tt)
			(md->itr_cnt)++;

	} else if (md->portId == SX_PORT_ID) {
		/* VS:TODO: Defined this part after merging sx heartbeat*/
		//process_pfcp_heartbeat_req(md->dst_ip, up_time); /* TODO: Future Enhancement */
		process_pfcp_heartbeat_req();
		if (ti == &md->tt)
			(md->itr_cnt)++;

	}
	/* TODO: */
	if (ti == &md->pt) {
		if ( startTimer( &md->tt ) < 0)
			RTE_LOG_DP(ERR, DP, "Transmit Timer failed to start..\n");
	}
}

uint8_t process_response(uint32_t dstIp)
{
	if (conn_cnt == 0)
	        return -1;
	
	int32_t inx = 0;
	inx = inx_bsearch(data, 0, (conn_cnt - 1), dstIp);

	if (inx >= 0) {
		data[inx].itr_cnt = 0;
		/* Stop Timer transmit timer for specific MME */
		stopTimer( &data[inx].tt );
		/* Stop Timer periodic timer for specific MME */
		stopTimer( &data[inx].pt );
		/* Reset Periodic Timer */
		if ( startTimer( &data[inx].pt ) < 0)
			RTE_LOG_DP(ERR, CP, "Periodic Timer failed to start...\n");
	
	}	
	return 0;
}


uint8_t add_node_conn_entry(uint32_t dstIp, uint8_t portId) 
{
	int32_t index = 0;
	uint32_t tmp_key = htonl(dstIp);

   	index = inx_bsearch(data, 0, conn_cnt, dstIp); 
   	//index = inx_bsearch(data, 0, conn_cnt, htonl(dstIp)); 

	if (index < 0) {
		RTE_LOG_DP(DEBUG, CP, "Add entry in conn table :%s\n", 
					inet_ntoa(*((struct in_addr *)&tmp_key)));

		//pos = get_ins_pos(data, conn_cnt, dstIp);

		//data[pos].portId = portId;	
		//data[pos].activityFlag = 0;
		//data[pos].dstIP = dstIp;
		//data[pos].dstIP = htonl(dstIp);
		//data[pos].itr = 5;	
		//data[pos].itr_cnt = 0;	
 
		data[conn_cnt].portId = portId;	
		data[conn_cnt].activityFlag = 0;
		data[conn_cnt].dstIP = dstIp;
		//data[conn_cnt].dstIP = htonl(dstIp);
		data[conn_cnt].itr = pfcp_config.transmit_cnt;	
		data[conn_cnt].itr_cnt = 0;
		data[conn_cnt].rcv_time = 0;
		//data[conn_cnt].sess_id[data[conn_cnt].sess_cnt] = sess_id;	
		//data[conn_cnt].sess_cnt++;	


		if ( !initpeerData( &data[conn_cnt], "PEER_NODE", (pfcp_config.periodic_timer * 1000), 
						(pfcp_config.transmit_timer * 1000)) )
		{
		   printf( "%s - initialization of %s failed\n", getPrintableTime(), data[conn_cnt].name );
		   return -1;
		}
	
	//	printf("VS: Timers PERIODIC:%d, TRANSMIT:%d, COUNT:%u\n",
	//				pfcp_config.periodic_timer, pfcp_config.transmit_timer, pfcp_config.transmit_cnt);	
		if ( startTimer( &data[conn_cnt].pt ) < 0)
			RTE_LOG_DP(ERR, CP, "Periodic Timer failed to start...\n");
		//startTimer( &data[conn_cnt].tt" );
		conn_cnt++;

		//for(int i = 0; i < conn_cnt; i++) 
		//	printf("%d IP DST:%s\n", i, inet_ntoa(*(struct in_addr *)&data[i].dstIP));

	} else {
		/* TODO: eNB entry already exit in conn table */
		RTE_LOG_DP(DEBUG, CP, "Conn entry already exit in conn table :%s\n", 
					inet_ntoa(*((struct in_addr *)&tmp_key)));
		//data[index].sess_id[data[index].sess_cnt] = sess_id;	
		//data[index].sess_cnt++;	

	}

	RTE_LOG_DP(DEBUG, CP, "Current Active Conn Cnt:%u\n", conn_cnt);
	return 0;
}
 
void rest_thread_init(void)
{

	sigset_t sigset;

	/* mask SIGALRM in all threads by default */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGRTMIN);
	sigaddset(&sigset, SIGUSR1);           
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	if (!gst_init())
	{
		RTE_LOG_DP(ERR, CP, "%s - gstimer_init() failed!!\n", getPrintableTime() );
		//return 1;
	}

}
