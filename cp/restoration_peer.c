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

#include <signal.h>


#include "cp.h"
#include "main.h"
#include "pfcp_messages/pfcp_set_ie.h"

#ifdef C3PO_OSS
#include "cp_stats.h"
#include "cp_config.h"
#include "cp_adapter.h"
#include "sm_struct.h"
#endif

#include "../restoration/restoration_timer.h"

//#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

char filename[256] = "../config/cp_rstCnt.txt";


extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_sockaddr_len;

extern int s11_fd;
extern int s5s8_fd;

extern pfcp_config_t pfcp_config;
extern uint8_t rstCnt;
int32_t conn_cnt = 0;

/* Sequence number allocation for echo request */
static uint16_t gtpu_mme_seqnb	= 0;
static uint16_t gtpu_sgwc_seqnb	= 0;
static uint16_t gtpu_pgwc_seqnb	= 0;
static uint16_t gtpu_sx_seqnb	= 1;

/**
 * Connection hash params.
 */
static struct rte_hash_parameters
	conn_hash_params = {
			.name = "CONN_TABLE",
			.entries = NUM_CONN,
			.reserved = 0,
			.key_len =
					sizeof(uint32_t),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0
};

/**
 * rte hash handler.
 *
 * hash handles connection for S1U, SGI and PFCP
 */
struct rte_hash *conn_hash_handle;

uint8_t update_rstCnt(void)
{
	FILE *fp;
	int tmp;

	if ((fp = fopen(filename,"rw+")) == NULL){
		if ((fp = fopen(filename,"w")) == NULL)
			printf("Error! creating cp_rstCnt.txt file");
	}

	if (fscanf(fp,"%u", &tmp) < 0) {
		/* Cur pos shift to initial pos */
		fseek(fp, 0, SEEK_SET);
		fprintf(fp, "%u\n", ++rstCnt);
		fclose(fp);
		return rstCnt;

	}
	/* Cur pos shift to initial pos */
	fseek(fp, 0, SEEK_SET);

	rstCnt = tmp;
	fprintf(fp, "%d\n", ++rstCnt);

	clLog(clSystemLog, eCLSeverityDebug, "Updated restart counter Value of rstcnt=%u\n", rstCnt);
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


	/* setting sendto destination addr */
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.s_addr = md->dstIP;
	dest_addr.sin_port = htons(GTPC_UDP_PORT);

	clLog(clSystemLog, eCLSeverityDebug, "%s - %s:%s:%u.%s (%dms) has expired\n", getPrintableTime(),
		md->name, inet_ntoa(*(struct in_addr *)&md->dstIP), md->portId,
		ti == &md->pt ? "Periodic_Timer" :
		ti == &md->tt ? "Transmit_Timer" : "unknown",
		ti->ti_ms );

	if (md->itr_cnt == md->itr) {
		/* Stop transmit timer for specific Peer Node */
		stopTimer( &md->tt );
		/* Stop periodic timer for specific Peer Node */
		stopTimer( &md->pt );
		/* Deinit transmit timer for specific Peer Node */
		deinitTimer( &md->tt );
		/* Deinit transmit timer for specific Peer Node */
		deinitTimer( &md->pt );

		clLog(clSystemLog, eCLSeverityDebug, "Stopped Periodic/transmit timer, peer node %s is not reachable\n",
				inet_ntoa(*(struct in_addr *)&md->dstIP));

		update_peer_status(md->dstIP,FALSE); //cli
		delete_cli_peer(md->dstIP);

		if (md->portId == S11_SGW_PORT_ID)
		{
			clLog(s11logger, eCLSeverityDebug, "MME status : Inactive\n");
		}

		if (md->portId == SX_PORT_ID)
		{
			clLog(sxlogger, eCLSeverityDebug, " SGWU/SPGWU/PGWU status : Inactive\n");
		}
		if (md->portId == S5S8_SGWC_PORT_ID)
		{
			clLog(s5s8logger, eCLSeverityDebug, "PGWC status : Inactive\n");
		}
		if (md->portId == S5S8_PGWC_PORT_ID)
		{
			clLog(s5s8logger, eCLSeverityDebug, "SGWC status : Inactive\n");
		}

		/* TODO: Flush sessions */
		if (md->portId == SX_PORT_ID)
			delete_entry_heartbeat_hash(&dest_addr);

		del_entry_from_hash(md->dstIP);

		return;
	}

	bzero(&echo_tx_buf, sizeof(echo_tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *) echo_tx_buf;

	if (md->portId == S11_SGW_PORT_ID) {
		if (ti == &md->pt)
			gtpu_mme_seqnb++;
		build_gtpv2_echo_request(gtpv2c_tx, gtpu_mme_seqnb);
	} else if (md->portId == S5S8_SGWC_PORT_ID) {
		if (ti == &md->pt)
			gtpu_sgwc_seqnb++;
		build_gtpv2_echo_request(gtpv2c_tx, gtpu_sgwc_seqnb);
	} else if (md->portId == S5S8_PGWC_PORT_ID) {
		if (ti == &md->pt)
			gtpu_pgwc_seqnb++;
		build_gtpv2_echo_request(gtpv2c_tx, gtpu_pgwc_seqnb);
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

	if (md->portId == S11_SGW_PORT_ID) {
		gtpv2c_send(s11_fd, echo_tx_buf, payload_length,
		               (struct sockaddr *) &dest_addr,
		               s11_mme_sockaddr_len);

		if (ti == &md->tt)
		{
			(md->itr_cnt)++;

		}

	} else if (md->portId == S5S8_SGWC_PORT_ID) {

		gtpv2c_send(s5s8_fd, echo_tx_buf, payload_length,
		                (struct sockaddr *) &dest_addr,
		                s5s8_sockaddr_len);

		if (ti == &md->tt)
		{
			(md->itr_cnt)++;
		}

	} else if (md->portId == S5S8_PGWC_PORT_ID) {
		gtpv2c_send(s5s8_fd, echo_tx_buf, payload_length,
		                (struct sockaddr *) &dest_addr,
		                s5s8_sockaddr_len);

		if (ti == &md->tt)
		{
			(md->itr_cnt)++;
		}

	} else if (md->portId == SX_PORT_ID) {
		/* TODO: Defined this part after merging sx heartbeat*/
		/* process_pfcp_heartbeat_req(md->dst_ip, up_time); */ /* TODO: Future Enhancement */

		dest_addr.sin_port = htons(pfcp_config.pfcp_port);
		//dest_addr.sin_port = htons(8805);

		if (ti == &md->pt){
			gtpu_sx_seqnb = get_pfcp_sequence_number(PFCP_HEARTBEAT_REQUEST, gtpu_sx_seqnb);;
		}

		process_pfcp_heartbeat_req(&dest_addr, gtpu_sx_seqnb);

		if (ti == &md->tt)
		{
			(md->itr_cnt)++;

		}

	}

	/*CLI:update echo/hbt req sent count*/
	get_current_time(cp_stats.stat_timestamp);
	if (md->portId != SX_PORT_ID)
	{
		update_cli_stats(md->dstIP,GTP_ECHO_REQ,SENT,
				cp_stats.stat_timestamp);
	} else {
		update_cli_stats(md->dstIP,PFCP_HEARTBEAT_REQUEST,
						SENT,cp_stats.stat_timestamp);
	}

	if(ti == &md->tt)
	{
		update_peer_timeouts(md->dstIP,md->itr_cnt); //cli
	}


	if (ti == &md->pt) {
		if ( startTimer( &md->tt ) < 0)
		{
			clLog(clSystemLog, eCLSeverityCritical, "Transmit Timer failed to start..\n");
		}

		/* Stop periodic timer for specific Peer Node */
		stopTimer( &md->pt );
	}
	return;
}

uint8_t add_node_conn_entry(uint32_t dstIp, uint8_t portId)
{
	int ret;
	peerData *conn_data = NULL;

	ret = rte_hash_lookup_data(conn_hash_handle,
				&dstIp, (void **)&conn_data);

	if ( ret < 0) {

		clLog(clSystemLog, eCLSeverityDebug, " Add entry in conn table :%s\n",
					inet_ntoa(*((struct in_addr *)&dstIp)));

		/* No conn entry for dstIp
		 * Add conn_data for dstIp at
		 * conn_hash_handle
		 * */

		conn_data = rte_malloc_socket(NULL,
						sizeof(peerData),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

		conn_data->portId = portId;
		conn_data->activityFlag = 0;
		conn_data->dstIP = dstIp;
		conn_data->itr = pfcp_config.transmit_cnt;
		conn_data->itr_cnt = 0;
		conn_data->rcv_time = 0;

		/* Add peer node entry in connection hash table */
		if ((rte_hash_add_key_data(conn_hash_handle,
				&dstIp, conn_data)) < 0 ) {
			clLog(clSystemLog, eCLSeverityCritical, "Failed to add entry in hash table");
		}

		if ( !initpeerData( conn_data, "PEER_NODE", (pfcp_config.periodic_timer * 1000),
						(pfcp_config.transmit_timer * 1000)) )
		{
		   printf( "%s - initialization of %s failed\n", getPrintableTime(), conn_data->name );
		   return -1;
		}


		/* printf("Timers PERIODIC:%d, TRANSMIT:%d, COUNT:%u\n",
		 *pfcp_config.periodic_timer, pfcp_config.transmit_timer, pfcp_config.transmit_cnt);
		 */

		if ( startTimer( &conn_data->pt ) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "Periodic Timer failed to start...\n");
			}
		conn_cnt++;

	} else {
		/* TODO: peer node entry already exit in conn table */

		clLog(clSystemLog, eCLSeverityDebug, "Conn entry already exit in conn table :%s\n",
					inet_ntoa(*((struct in_addr *)&dstIp)));
		if ( startTimer( &conn_data->pt ) < 0)
		{
			clLog(clSystemLog, eCLSeverityCritical, "Periodic Timer failed to start...\n");
		}
		//conn_cnt++;
	}

	clLog(clSystemLog, eCLSeverityDebug, "Current Active Conn Cnt:%u\n", conn_cnt);
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
	return;
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
		clLog(clSystemLog, eCLSeverityDebug, "%s - gstimer_init() failed!!\n", getPrintableTime() );
	}
	return;
}
