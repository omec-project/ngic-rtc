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

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>


//#include "../dp/meter.h"
#include "meter.h"
#include "acl_dp.h"
#include "interface.h"
#include "util.h"
#include "meter.h"
#include "dp_ipc_api.h"
#include "gtpv2c_ie.h"
#include "gtpv2c.h"
#ifdef SDN_ODL_BUILD
#include "zmqsub.h"
#include "zmqpub.h"
#ifdef CP_BUILD
#include "nb.h"
#endif
#endif
#ifndef CP_BUILD
#include "cdr.h"
#endif
#ifdef ZMQ_COMM
#include "zmq_push_pull.h"
#include "cp.h"
#endif

#include "../pfcp_messages/pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "main.h"

#include "../dp/perf_timer.h"
#include "../cp/pfcp.h"
#include "pfcp_messages.h"
#include "pfcp_association.h"
#include "pfcp_session.h"


#if 0
extern struct rte_hash *teid_fseid_hash;
#endif
#ifdef SGX_CDR
	#define DEALERIN_IP "dealer_in_ip"
	#define DEALERIN_PORT "dealer_in_port"
	#define DEALERIN_MRENCLAVE "dealer_in_mrenclave"
	#define DEALERIN_MRSIGNER "dealer_in_mrsigner"
	#define DEALERIN_ISVSVN "dealer_in_isvsvn"
	#define DP_CERT_PATH "dp_cert_path"
	#define DP_PKEY_PATH "dp_pkey_path"
#endif /* SGX_CDR */


/*
 * UDP Setup
 */
udp_sock_t my_sock;

/* VS: ROUTE DISCOVERY */
extern int route_sock;


struct in_addr dp_comm_ip;
struct in_addr cp_comm_ip;
uint16_t dp_comm_port;
uint16_t cp_comm_port;

#ifdef SDN_ODL_BUILD
struct in_addr fpc_ip;
uint16_t fpc_port;
uint16_t fpc_topology_port;

struct in_addr cp_nb_ip;
uint16_t cp_nb_port;
#endif

#ifdef ZMQ_COMM
struct in_addr zmq_cp_ip, zmq_dp_ip;
uint16_t zmq_cp_pull_port, zmq_dp_pull_port;
uint16_t zmq_cp_push_port, zmq_dp_push_port;
#endif	/* ZMQ_COMM */

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
extern void print_perf_statistics(void);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */

extern struct ipc_node *basenode;

struct rte_hash *node_id_hash;
extern struct rte_hash *associated_upf_hash;
int s11_sgwc_fd_arr[MAX_NUM_SGWC]  =  {-1} ;
int s5s8_sgwc_fd_arr[MAX_NUM_SGWC] = {-1};
int s5s8_pgwc_fd_arr[MAX_NUM_PGWC] = {-1};
int pfcp_sgwc_fd_arr[MAX_NUM_SGWC] = {-1};
int pfcp_pgwc_fd_arr[MAX_NUM_PGWC] = {-1};

/* Count of current connected data-plane */
extern int num_dp;
extern pfcp_config_t pfcp_config;
extern socklen_t s11_mme_sockaddr_len;
extern pfcp_context_t pfcp_ctxt;
extern association_context_t assoc_ctxt[100] ;

uint8_t tx_buf[MAX_GTPV2C_UDP_LEN];

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
//MME
struct in_addr s11_mme_ip_arr[MAX_NUM_MME];
struct sockaddr_in s11_mme_sockaddr_arr[MAX_NUM_MME];

//SGWC S11
in_port_t s11_sgwc_port_arr[MAX_NUM_SGWC];
struct sockaddr_in s11_sgwc_sockaddr_arr[MAX_NUM_SGWC];

//SGWC S5S8
struct in_addr s5s8_sgwc_ip_arr[MAX_NUM_SGWC];
in_port_t s5s8_sgwc_port_arr[MAX_NUM_SGWC];
struct sockaddr_in s5s8_sgwc_sockaddr_arr[MAX_NUM_SGWC];

//SGWC PFCP
in_port_t pfcp_sgwc_port_arr[MAX_NUM_SGWC];
struct sockaddr_in pfcp_sgwc_sockaddr_arr[MAX_NUM_SGWC];

//PGWC S5S8
struct in_addr s5s8_pgwc_ip_arr[MAX_NUM_PGWC];
in_port_t s5s8_pgwc_port_arr[MAX_NUM_PGWC];
struct sockaddr_in s5s8_pgwc_sockaddr_arr[MAX_NUM_PGWC];

//PGWC PFCP
struct in_addr pfcp_pgwc_ip_arr[MAX_NUM_PGWC];
in_port_t pfcp_pgwc_port_arr[MAX_NUM_PGWC];
struct sockaddr_in pfcp_pgwc_sockaddr_arr[MAX_NUM_PGWC];

//SGWU PFCP
in_port_t pfcp_sgwu_port_arr[MAX_NUM_SGWU];
struct sockaddr_in pfcp_sgwu_sockaddr_arr[MAX_NUM_SGWU];

//PGWU PFCP
in_port_t pfcp_pgwu_port_arr[MAX_NUM_PGWU];
struct sockaddr_in pfcp_pgwu_sockaddr_arr[MAX_NUM_PGWU];

//SPGWU PFCP
in_port_t pfcp_spgwu_port_arr[MAX_NUM_SPGWU];
struct sockaddr_in pfcp_spgwu_sockaddr_arr[MAX_NUM_SPGWU];

void register_comm_msg_cb(enum cp_dp_comm id,
			int (*init)(void),
			int (*send)(void *msg_payload, uint32_t size),
			int (*recv)(void *msg_payload, uint32_t size),
			int (*destroy)(void))
{
	struct comm_node *node;

	node = &comm_node[id];
	node->init = init;
	node->send = send;
	node->recv = recv;
	node->destroy = destroy;
	node->status = 0;
	node->init();
}

int set_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status == 0 && comm_node[id].init != NULL) {
		active_comm_msg = &comm_node[id];
		comm_node[id].status = 1;
	} else {
		RTE_LOG_DP(ERR, DP,"Error: Cannot set communication type\n");
		return -1;
	}
	return 0;
}

int unset_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status) {
		active_comm_msg->destroy();
		comm_node[id].status = 0;
	} else {
		RTE_LOG_DP(ERR, DP,"Error: Cannot unset communication type\n");
		return -1;
	}
	return 0;
}

int process_comm_msg(void *buf)
{
	struct msgbuf *rbuf = (struct msgbuf *)buf;
	struct ipc_node *cb;

	if (rbuf->mtype >= MSG_END)
		return -1;

	/* Callback APIs */
	cb = &basenode[rbuf->mtype];

#ifdef ZMQ_COMM
	int rc = cb->msg_cb(rbuf);
	if (rc == 0) {
		struct resp_msgbuf resp = {0};

		switch(rbuf->mtype) {
			case MSG_SESS_CRE: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = DPN_ID;
				resp.mtype = DPN_RESPONSE;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
				zmq_mbuf_push((void *)&resp, sizeof(resp));
				break;
			}
			case MSG_SESS_MOD: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = DPN_ID;
				resp.mtype = DPN_RESPONSE;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
				zmq_mbuf_push((void *)&resp, sizeof(resp));
				break;
			}
			case MSG_SESS_DEL: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = DPN_ID;
				resp.mtype = DPN_RESPONSE;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
				zmq_mbuf_push((void *)&resp, sizeof(resp));
				break;
			}
		default:
			break;
		}
	}
	return 0;
#else
	return cb->msg_cb(rbuf);
#endif  /* ZMQ_COMM */

}



#if defined(CP_BUILD) || defined(DP_BUILD)
int
process_pfcp_msg(uint8_t *buf_rx, int bytes_rx,
		struct sockaddr_in *peer_addr)
{
	pfcp_header_t *pfcp_header = (pfcp_header_t *) buf_rx;
	
#ifdef DP_BUILD
	struct msgbuf *rule_msg = NULL;
	int encoded = 0 ;
	uint8_t pfcp_msg[1024]= {0};
#else
	uint16_t payload_length;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_s11_tx = (gtpv2c_header *) tx_buf;

#endif
	//int decoded = 0 ;
	
	RTE_LOG_DP(DEBUG, DP, "Bytes received is %d\n", bytes_rx);
	RTE_LOG_DP(DEBUG, DP, "IPADDR [%u]\n",peer_addr->sin_addr.s_addr);

	switch (pfcp_header->message_type)
	{
#ifdef DP_BUILD
	case PFCP_ASSOCIATION_SETUP_REQUEST:
		{
			memset(pfcp_msg, 0, 1024);
			pfcp_association_setup_request_t *pfcp_ass_setup_req = malloc(sizeof(pfcp_association_setup_request_t));
			pfcp_association_setup_response_t pfcp_ass_setup_resp = {0} ;

			int decoded = decode_pfcp_association_setup_request(buf_rx,pfcp_ass_setup_req);
			RTE_LOG_DP(DEBUG, DP, "[DP] Decoded bytes [%d]\n",decoded);
			RTE_LOG_DP(DEBUG, DP, "recover_time[%d],cpf[%d] from CP \n",(pfcp_ass_setup_req->recovery_time_stamp.recovery_time_stamp_value),
					(pfcp_ass_setup_req->cp_function_features.supported_features));

			uint8_t cause_id = 0;
			int offend_id = 0;
			cause_check_association(pfcp_ass_setup_req, &cause_id, &offend_id);
			// TODO: /handle hash error handling 
			//fill_pfcp_association_setup_resp(&pfcp_ass_setup_resp);
			if (cause_id == CAUSE_VALUES_REQUESTACCEPTEDSUCCESS)
			{
				//Adding NODE ID into nodeid hash in DP
				int ret ;
				uint32_t value;
				//uint64_t temp = 12;	
				uint64_t *data = rte_zmalloc_socket(NULL, sizeof(uint8_t),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
				if (data == NULL)
					rte_panic("Failure to allocate node id hash: "
							"%s (%s:%d)\n",
							rte_strerror(rte_errno),
							__FILE__,
							__LINE__);
				*data = NODE_ID_TYPE_IPV4ADDRESS;	
				memcpy(&value,pfcp_ass_setup_req->node_id.node_id_value,IPV4_SIZE);
				uint32_t nodeid =(ntohl(value));
				RTE_LOG_DP(DEBUG, DP, "NODEID in INTERRFACE [%u]\n",nodeid);
				RTE_LOG_DP(DEBUG, DP, "DATA[%lu]\n",*data);

				ret = rte_hash_lookup_data(node_id_hash,(const void*) &(nodeid),
						(void **) &(data));
				if (ret == -ENOENT) {
					ret = add_node_id_hash(&nodeid, data);
				}

			}	
			fill_pfcp_association_setup_resp(&pfcp_ass_setup_resp, cause_id);
			pfcp_ass_setup_resp.up_ip_resource_info.ipv4_address = (app.s1u_ip);
			pfcp_ass_setup_resp.header.seid_seqno.no_seid.seq_no =
				 pfcp_ass_setup_req->header.seid_seqno.no_seid.seq_no;
			memcpy(&(pfcp_ass_setup_resp.node_id.node_id_value),&(dp_comm_ip.s_addr),pfcp_ass_setup_resp.node_id.node_id_value_len);

			encoded =  encode_pfcp_association_setup_response(&pfcp_ass_setup_resp, pfcp_msg);
			RTE_SET_USED(encoded);

			pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
			pfcp_hdr->message_len = htons(encoded - 4);
			RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);
			RTE_LOG_DP(DEBUG, DP, "length[%d]\n",htons(pfcp_hdr->message_len));
			free(pfcp_ass_setup_req);
			break;
		}
	case PFCP_SESSION_ESTABLISHMENT_REQUEST:
		{
			memset(pfcp_msg, 0, 1024);
			pfcp_session_establishment_request_t *pfcp_session_request = malloc(sizeof(pfcp_session_establishment_request_t));
			pfcp_session_establishment_response_t pfcp_session_response = {0};
			struct session_info sess_info = {0};//malloc(sizeof( struct session_info));
			struct dp_id dp = {0};
			//Adding dummy data to avoid compilation error in dp_session_create function.
			dp.id = 1234;
			strncpy(dp.name,"Dummy",5);
			int decoded = decode_pfcp_session_establishment_request(buf_rx, pfcp_session_request);
			RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson is %d\n", decoded);
			
			uint8_t cause_id = 0;
			int offend_id = 0 ;
			cause_check_sess_estab(pfcp_session_request, &cause_id, &offend_id);

			//sess_info filling for create session
			sess_info.ul_s1_info.sgw_teid = pfcp_session_request->create_pdr.pdi.local_fteid.teid;
            		sess_info.ul_s1_info.sgw_addr.u.ipv4_addr = pfcp_session_request->create_pdr.pdi.local_fteid.ipv4_address;
			
			//sess_info->sess_id = 5; // pfcp_session_request->cp_fseid.seid;
			sess_info.sess_id = pfcp_session_request->cp_fseid.seid;
			sess_info.num_ul_pcc_rules = 1;
			sess_info.num_dl_pcc_rules = 1;
			sess_info.ul_pcc_rule_id[0] = 1;
			sess_info.dl_pcc_rule_id[0] = 1;
            		sess_info.ue_addr.u.ipv4_addr = pfcp_session_request->create_pdr.pdi.ue_ip_address.ipv4_address ;
			RTE_LOG_DP(DEBUG, DP, "SESS ID in DP %lu\n", sess_info.sess_id);
			dp_session_create(dp,&sess_info);
			fill_pfcp_session_est_resp(&pfcp_session_response, cause_id, offend_id);

			pfcp_session_response.up_fseid.seid =
				 pfcp_session_request->header.seid_seqno.has_seid.seid;
			pfcp_session_response.header.seid_seqno.has_seid.seq_no =
				 pfcp_session_request->header.seid_seqno.has_seid.seq_no;
			pfcp_session_response.created_pdr.local_fteid.teid =
				 (pfcp_session_request->create_pdr.pdi.local_fteid.teid);
			pfcp_session_response.created_pdr.local_fteid.ipv4_address =
				 ntohl(pfcp_session_request->create_pdr.pdi.local_fteid.ipv4_address);
			memcpy(&(pfcp_session_response.node_id.node_id_value),&(dp_comm_ip.s_addr),pfcp_session_response.node_id.node_id_value_len);

			memcpy(&(pfcp_session_response.up_fseid.ipv4_address),&(dp_comm_ip.s_addr),IPV4_SIZE);
			memcpy(&(pfcp_session_response.sgwu_fqcsid.node_address.ipv4_address),&(dp_comm_ip.s_addr),IPV4_SIZE);

			encoded = encode_pfcp_session_establishment_response(&pfcp_session_response,  pfcp_msg);

			pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
			pfcp_hdr->message_len = htons(encoded - 4);
			pfcp_hdr->seid_seqno.has_seid.seid = htonll(pfcp_session_request->header.seid_seqno.has_seid.seid);

			free(pfcp_session_request);
			break;
		}
	case PFCP_SESSION_MODIFICATION_REQUEST:
		{
			
			memset(pfcp_msg, 0, 1024);
			RTE_LOG_DP(DEBUG, DP, "IN the Session Modifiation Request\n");
			pfcp_session_modification_request_t *pfcp_session_mod_req = malloc(sizeof(pfcp_session_modification_request_t));
			pfcp_session_modification_response_t  pfcp_sess_mod_res = {0};
			struct session_info sess_info = {0};
			struct dp_id dp = {0};

			//Adding dummy data to avoid compilation error in dp_session_create function.
			dp.id = 1234;
			strncpy(dp.name,"Dummy",5);
			int decoded = decode_pfcp_session_modification_request(buf_rx, pfcp_session_mod_req);
			RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson modification  is %d\n", decoded);

    			sess_info.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
    			sess_info.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			sess_info.dl_s1_info.enb_teid = pfcp_session_mod_req->create_pdr.pdi.local_fteid.teid;
			sess_info.dl_s1_info.enb_addr.u.ipv4_addr = pfcp_session_mod_req->create_pdr.pdi.local_fteid.ipv4_address;
			sess_info.sess_id = pfcp_session_mod_req->cp_fseid.seid;
            		sess_info.ue_addr.u.ipv4_addr = pfcp_session_mod_req->create_pdr.pdi.ue_ip_address.ipv4_address ;
            		RTE_LOG_DP(DEBUG, DP, "In MODIFY ENB TEID[%u] ENDIP[%u]\n",
					sess_info.dl_s1_info.enb_teid,sess_info.dl_s1_info.enb_addr.u.ipv4_addr);
			dp_session_modify(dp, &sess_info);
			uint8_t cause_id = 0;
            		int offend_id = 0;
            		cause_check_sess_modification(pfcp_session_mod_req, &cause_id, &offend_id);

			fill_pfcp_session_modify_resp(&pfcp_sess_mod_res, cause_id, offend_id);

			pfcp_sess_mod_res.created_pdr.local_fteid.teid =( sess_info.ul_s1_info.sgw_teid);
			pfcp_sess_mod_res.created_pdr.local_fteid.ipv4_address = htonl(sess_info.ul_s1_info.sgw_addr.u.ipv4_addr);
            		RTE_LOG_DP(DEBUG, DP, "In MODIFY S1U TEID[%u]\n",pfcp_sess_mod_res.created_pdr.local_fteid.teid);
			
			pfcp_sess_mod_res.header.seid_seqno.has_seid.seid = pfcp_session_mod_req->header.seid_seqno.has_seid.seid;
			pfcp_sess_mod_res.header.seid_seqno.has_seid.seq_no = pfcp_session_mod_req->header.seid_seqno.has_seid.seq_no;

			encoded = encode_pfcp_session_modification_response(&pfcp_sess_mod_res,  pfcp_msg);
			
			pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
			pfcp_hdr->message_len = htons(encoded - 4);
			RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);
			RTE_LOG_DP(DEBUG, DP, "length[%d]\n",htons(pfcp_hdr->message_len));

			free(pfcp_session_mod_req);
			break;	
		}
	case PFCP_SESSION_DELETION_REQUEST:
		{

			memset(pfcp_msg, 0, 1024);
			pfcp_session_deletion_request_t *pfcp_session_del_req = malloc(sizeof(pfcp_session_deletion_request_t));
			pfcp_session_deletion_response_t  pfcp_sess_del_res = {0};
			int decoded = decode_pfcp_session_deletion_request(buf_rx, pfcp_session_del_req);
			RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson deletion  is %d\n", decoded);
			
			struct session_info sess_info = {0};
                        struct dp_id dp = {0};

                        //Adding dummy data to avoid compilation error in dp_session_create function.
                        dp.id = 1234;
                        strncpy(dp.name,"Dummy",5);
			sess_info.sess_id = pfcp_session_del_req->header.seid_seqno.has_seid.seid;
			dp_session_delete(dp,&sess_info);
			uint8_t cause_id = 0;
			int offend_id = 0;
			cause_check_delete_session(pfcp_session_del_req, &cause_id, &offend_id);

			fill_pfcp_sess_del_resp(&pfcp_sess_del_res, cause_id, offend_id);
			pfcp_sess_del_res.header.seid_seqno.has_seid.seid = 
				pfcp_session_del_req->header.seid_seqno.has_seid.seid;
			pfcp_sess_del_res.header.seid_seqno.has_seid.seq_no =
				pfcp_session_del_req->header.seid_seqno.has_seid.seq_no;
			encoded = encode_pfcp_session_deletion_response(&pfcp_sess_del_res,  pfcp_msg);


			pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
			pfcp_hdr->message_len = htons(encoded - 4);
			RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);

			free(pfcp_session_del_req);
			break;	
		}
	case PFCP_HEARTBEAT_REQUEST:
		{
			memset(pfcp_msg, 0, 1024);
			pfcp_heartbeat_request_t *pfcp_heartbeat_req = malloc(sizeof(pfcp_heartbeat_request_t));
			pfcp_heartbeat_response_t  pfcp_heartbeat_resp = {0};
			int decoded = decode_pfcp_heartbeat_request(buf_rx, pfcp_heartbeat_req);
			RTE_SET_USED(decoded);
			fill_pfcp_heartbeat_resp(&pfcp_heartbeat_resp);
			encoded = encode_pfcp_heartbeat_response(&pfcp_heartbeat_resp,  pfcp_msg);


			pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
			pfcp_hdr->message_len = htons(encoded - 4);

			free(pfcp_heartbeat_req);

			break;
		}
 
#else

	case PFCP_ASSOCIATION_SETUP_RESPONSE:
                        {
                                pfcp_association_setup_response_t pfcp_ass_setup_resp = {0};
                                int decoded = decode_pfcp_association_setup_response(buf_rx, &pfcp_ass_setup_resp);
				RTE_LOG_DP(DEBUG, DP, "DECODED byte in Association response is %d\n",decoded);
                                RTE_LOG_DP(DEBUG, DP, "\nVG :recover_time[%d],cause[%d] upf[%d]\n",
                                              (pfcp_ass_setup_resp.recovery_time_stamp.recovery_time_stamp_value),
                                              (pfcp_ass_setup_resp.cause.cause_value),
                                              (pfcp_ass_setup_resp.up_function_features.supported_features));
                                if(pfcp_ass_setup_resp.cause.cause_value !=
                                                                CAUSE_VALUES_REQUESTACCEPTEDSUCCESS){
                                        //rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
                                        rte_panic("cause received[%d]\n", pfcp_ass_setup_resp.cause.cause_value);
                                }

				int ret =0;
				uint8_t temp = 0;	
				uint8_t *data = &temp;
				uint32_t node_ip,upf_ip ;
				memcpy(&node_ip,&pfcp_ass_setup_resp.node_id.node_id_value,IPV4_SIZE);
				upf_ip = ntohl(node_ip);
				ret = rte_hash_lookup_data(associated_upf_hash,(const void*) &(upf_ip),
						(void **) &(data));
				if (ret == -ENOENT) {
					RTE_LOG_DP(DEBUG, DP, "NO ENTRY FOUND IN UPF HASH [%u]\n", upf_ip);
				} else {
					RTE_LOG_DP(DEBUG, DP, "ENTRY FOUND IN UPF HASH [%u]\n", upf_ip);
					*data = 2;	
				}
                                pfcp_ctxt.up_supported_features = pfcp_ass_setup_resp.up_function_features.supported_features;
                                pfcp_ctxt.s1u_ip[0] = pfcp_ass_setup_resp.up_ip_resource_info.ipv4_address;
				//for(uint8_t dp_itr = 0; dp_itr <= 0 ;dp_itr++){
					for(uint8_t csr_itr = 0; csr_itr < assoc_ctxt[0].csr_cnt; csr_itr++){
					//for(uint8_t csr_itr = 0; csr_itr <= 0; csr_itr++){
						ret = process_pfcp_sess_est_request(
								(gtpv2c_header* )assoc_ctxt[0].s11_rx_buf[csr_itr], gtpv2c_s11_tx);
						payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);
						pfcp_gtpv2c_send(payload_length, tx_buf,
							(gtpv2c_header* )assoc_ctxt[0].s11_rx_buf[csr_itr]);

						bzero(assoc_ctxt[0].s11_rx_buf[csr_itr], 1000);

					}
				//}


                                break;
                        }

	case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
                        {
                                pfcp_session_establishment_response_t pfcp_sess_est_resp = {0};
                                int decoded = decode_pfcp_session_establishment_response(buf_rx,&pfcp_sess_est_resp);
				RTE_LOG_DP(DEBUG, DP, "DEOCED bytes in Sess Estab Resp is %d\n", decoded );
                                if(pfcp_sess_est_resp.cause.cause_value !=
                                                        CAUSE_VALUES_REQUESTACCEPTEDSUCCESS){
                                        //rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
                                        rte_panic("cause received[%d] \n", pfcp_sess_est_resp.cause.cause_value);
                                }

                                break;
                        }
	case PFCP_SESSION_MODIFICATION_RESPONSE:
                        {
                                pfcp_session_modification_response_t  pfcp_sess_mod_resp = {0};
                                int decoded = decode_pfcp_session_modification_response(buf_rx,
                                                                        &pfcp_sess_mod_resp);
				RTE_LOG_DP(DEBUG, DP, "DEOCED bytes in Sess Modif Resp is %d\n", decoded );
                                if(pfcp_sess_mod_resp.cause.cause_value !=
                                                        CAUSE_VALUES_REQUESTACCEPTEDSUCCESS){
                                        //rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
                                        rte_panic("cause received[%d] \n", pfcp_sess_mod_resp.cause.cause_value);
                                }
                                break;
                        }
	case PFCP_SESSION_DELETION_RESPONSE:
                        {
                                pfcp_session_deletion_response_t pfcp_sess_del_resp = {0};
                                int decoded = decode_pfcp_session_deletion_response(buf_rx, &pfcp_sess_del_resp);
				RTE_LOG_DP(DEBUG, DP, "DEOCED bytes in Sess  Delete Resp is %d\n", decoded );
                                if(pfcp_sess_del_resp.cause.cause_value !=
                                                        CAUSE_VALUES_REQUESTACCEPTEDSUCCESS){
                                        //rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
                                        rte_panic("cause received[%d] \n", pfcp_sess_del_resp.cause.cause_value);
                                }
                                break;
                        }
#endif
	default:

#ifdef DP_BUILD
		rule_msg = (struct msgbuf *) buf_rx;

		if (rule_msg->mtype == MSG_ADC_TBL_ADD) {
			cb_adc_entry_add(rule_msg);
		} else if (rule_msg->mtype == MSG_PCC_TBL_ADD) {
			cb_pcc_entry_add(rule_msg);
		} else if (rule_msg->mtype == MSG_MTR_ADD) {
			cb_meter_profile_entry_add(rule_msg);
		} else if (rule_msg->mtype == MSG_SDF_ADD) {
			cb_sdf_filter_entry_add(rule_msg);
		} else {
			RTE_LOG_DP(DEBUG, DP, "No rules received\n");
		}
#endif

		break;

	}

#ifdef DP_BUILD
	if (sendto(my_sock.sock_fd,
				(char *)pfcp_msg,
				encoded,
				MSG_DONTWAIT,
				(struct sockaddr *)peer_addr,
				sizeof(struct sockaddr_in)) < 0)
		RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
#endif
	return 0;
}

#endif
#ifdef ZMQ_COMM
#ifdef CP_BUILD
int process_resp_msg(void *buf)
{
	int rc;
	struct resp_msgbuf *rbuf = (struct resp_msgbuf *)buf;

	if (rbuf->mtype >= MSG_END)
		return -1;

	switch(rbuf->mtype) {
	case DPN_RESPONSE:
		del_resp_op_id(rbuf->op_id);
		break;

	case MSG_DDN:
		/* DDN Callback API */
		rc= cb_ddn(rbuf->sess_id);

		if (rc < 0)
				return -1;
		break;

	default:
		break;
	}

	return 0;
}
#endif /* CP_BUILD */

static int
zmq_init_socket(void)
{
	/*
	 * zmqpull/zmqpush init
	 */
	zmq_pull_create();
	return zmq_push_create();
}

static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpush send
	 */
	return zmq_mbuf_push(zmqmsgbuf, zmqmsgbufsz);
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpull recv
	 */
	int zmqmsglen = zmq_mbuf_pull(buf, zmqmsgbufsz);

	if (zmqmsglen > 0) {
		RTE_LOG_DP(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqpush/zmqpull destroy
	 */
	zmq_push_pull_destroy();
	return 0;
}

#else  /* ZMQ_COMM */

static int
udp_send_socket(void *msg_payload, uint32_t size)
{
	if (__send_udp_packet(&my_sock, msg_payload, size) < 0)
		RTE_LOG_DP(ERR, DP, "Failed to send msg !!!\n");

	/* Workaround to avoid out of order packets on DP. In case of load it
	 * is observed that packets are received out of order at DP e.g. MB is
	 * received before CS, hence causing issue in session establishment */
	usleep(50);
	return 0;
}
#if !defined(CP_BUILD) || !defined(SDN_ODL_BUILD)
static int
udp_recv_socket(void *msg_payload, uint32_t size)
{
	uint32_t bytes = recvfrom(my_sock.sock_fd, msg_payload, size, 0,
			NULL, NULL);
	if (bytes < size) {
		RTE_LOG_DP(ERR, DP, "Failed recv msg !!!\n");
		return -1;
	}
	return 0;
}
#endif  /* !CP_BUILD || !SDN_ODL_BUILD */
#ifdef CP_BUILD
/**
 * Init listen socket.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
udp_init_cp_socket(void)
{
	/*
	 * UDP init
	 */
	/* TODO IP and port parameters */
	if (__create_udp_socket(dp_comm_ip, dp_comm_port, cp_comm_port,
			&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create CP UDP Socket Failed "
			"for IP %s:%u!!!\n",
			inet_ntoa(dp_comm_ip), dp_comm_port);

	return 0;
}

#endif		/* ZMQ_COMM */
#endif		/* CP_BUILD */

#ifndef CP_BUILD
/**
 * Init listen socket.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
udp_init_dp_socket(void)
{
	if (__create_udp_socket(cp_comm_ip, cp_comm_port, dp_comm_port,
			&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create DP UDP Socket "
			"Failed for IP %s:%d!!!\n",
			inet_ntoa(cp_comm_ip), cp_comm_port);
	return 0;
}

/**
 * UDP packet receive API.
 * @param msg_payload
 *	msg_payload - message payload from communication API.
 * @param size
 *	size - size of message payload.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
/**
 * Code Rel. Jan 30, 2017
 * UDP recvfrom used for PCC, ADC, Session table initialization.
 * Needs to be from SDN controller as code & data models evolve.
 */
#ifdef SDN_ODL_BUILD
static int
zmq_init_socket(void)
{
	/*
	 * zmqsub init
	 */
	zmq_pubsocket_create();
	return zmq_subsocket_create();
}
static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	return zmq_mbuf_send(zmqmsgbuf, sizeof(struct zmqbuf));
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	int zmqmsglen = zmq_mbuf_rcv(buf, zmqmsgbufsz);

	if (zmqmsglen > 0)	{
		RTE_LOG_DP(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

#ifdef PRINT_NEW_RULE_ENTRY
/**
 * @Name : print_sel_type_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
static void print_sel_type_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		switch (adc->sel_type) {
		case DOMAIN_NAME:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Name :%s\n",
				adc->u.domain_name);
			break;

		case DOMAIN_IP_ADDR:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Ip :%d\n",
				(adc->u.domain_ip.u.ipv4_addr));
			break;

		case DOMAIN_IP_ADDR_PREFIX:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Ip :%d\n",
				(adc->u.domain_ip.u.ipv4_addr));
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Prefix :%d\n",
				adc->u.domain_prefix.prefix);
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
				adc->sel_type);
			break;
		}
	}
}

/**
 * @Name : print_adc_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
static void print_adc_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> ADC Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Rule id : %d\n", adc->rule_id);

		print_sel_type_val(adc);

		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_pcc_val
 * @arguments : [In] pointer to pcc rule structure element
 * @return : void
 * @Description : Function to print PCC rules values.
 */
static void print_pcc_val(struct pcc_rules *pcc)
{
	if (NULL != pcc) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> PCC Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Rule id : %d\n", pcc->rule_id);
		RTE_LOG_DP(DEBUG, DP, " ---> metering_method :%d\n",
			pcc->metering_method);
		RTE_LOG_DP(DEBUG, DP, " ---> charging_mode :%d\n",
			pcc->charging_mode);
		RTE_LOG_DP(DEBUG, DP, " ---> rating_group :%d\n",
			pcc->rating_group);
		RTE_LOG_DP(DEBUG, DP, " ---> rule_status :%d\n",
			pcc->rule_status);
		RTE_LOG_DP(DEBUG, DP, " ---> gate_status :%d\n",
			pcc->gate_status);
		RTE_LOG_DP(DEBUG, DP, " ---> session_cont :%d\n",
			pcc->session_cont);
		RTE_LOG_DP(DEBUG, DP, " ---> monitoring_key :%d\n",
			pcc->monitoring_key);
		RTE_LOG_DP(DEBUG, DP, " ---> precedence :%d\n",
			pcc->precedence);
		RTE_LOG_DP(DEBUG, DP, " ---> level_of_report :%d\n",
			pcc->report_level);
		RTE_LOG_DP(DEBUG, DP, " ---> mute_status :%d\n",
			pcc->mute_notify);
		RTE_LOG_DP(DEBUG, DP, " ---> drop_pkt_count :%ld\n",
			pcc->drop_pkt_count);
		RTE_LOG_DP(DEBUG, DP, " ---> redirect_info :%d\n",
			pcc->redirect_info.info);
		RTE_LOG_DP(DEBUG, DP, " ---> ul_mbr_mtr_profile_idx :%d\n",
			pcc->qos.ul_mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> dl_mbr_mtr_profile_idx :%d\n",
			pcc->qos.dl_mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> ADC Index :%d\n",
			pcc->adc_idx);
		RTE_LOG_DP(DEBUG, DP, " ---> SDF Index count:%d\n",
			pcc->sdf_idx_cnt);
		for(int i =0; i< pcc->sdf_idx_cnt; ++i)
			RTE_LOG_DP(DEBUG, DP, " ---> SDF IDx [%d]:%d\n",
				i, pcc->sdf_idx[i]);
		RTE_LOG_DP(DEBUG, DP, " ---> rule_name:%s\n", pcc->rule_name);
		RTE_LOG_DP(DEBUG, DP, " ---> sponsor_id:%s\n", pcc->sponsor_id);
		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_mtr_val
 * @arguments : [In] pointer to mtr entry structure element
 * @return : void
 * @Description : Function to print METER rules values.
 */
static void print_mtr_val(struct mtr_entry *mtr)
{
	if (NULL != mtr) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Meter Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Meter profile index :%d\n",
				mtr->mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter CIR :%ld\n",
			mtr->mtr_param.cir);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter CBS :%ld\n",
			mtr->mtr_param.cbs);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter EBS :%ld\n",
			mtr->mtr_param.ebs);
		RTE_LOG_DP(DEBUG, DP, " ---> Metering Method :%d\n",
				mtr->metering_method);
		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_sdf_val
 * @arguments : [In] pointer to pkt_filter structure element
 * @return : void
 * @Description : Function to print SDF rules values.
 */
static void print_sdf_val(struct pkt_filter *sdf)
{
	if (NULL != sdf) {
		RTE_LOG_DP(DEBUG, DP, "==========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> SDF Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "==========================================\n");

		switch (sdf->sel_rule_type) {
		case RULE_STRING:
			RTE_LOG_DP(DEBUG, DP, " ---> pcc_rule_id :%d\n",
				sdf->pcc_rule_id);
			RTE_LOG_DP(DEBUG, DP, " ---> rule_type :%d\n",
				sdf->sel_rule_type);
			RTE_LOG_DP(DEBUG, DP, " ---> rule_str : %s\n",
				sdf->u.rule_str);
			RTE_LOG_DP(DEBUG, DP, "====================================\n\n");
			break;

		case FIVE_TUPLE:
			/*TODO: rule should be in struct
			 * five_tuple_rule
			 * This field is currently not used
			 */
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
				sdf->sel_rule_type);
			break;
		}
	}
}
#endif /*PRINT_NEW_RULE_ENTRY*/

/**
 * Name : parse_adc_val
 * argument :
 * selctor type pointed to adc rule type
 * [In] pointer (arm) to zmq rcv structure element
 * [Out] pointer (adc) to adc rules structure element
 * @return
 * 0 - success
 * -1 - fail
 * Description : Function to parse adc rules values into
 * adc_rules struct.
 * Here parse values as per selector type (DOMAIN_NAME,
 * DOMAIN_IP_ADDR, and DOMAIN_IP_ADDR_PREFIX), domain name,
 * domain ip addr, domain prefix parameters values from recv buf and
 * stored into adc_rules struct.
 * ref.doc: message_sdn.docx
 * section : Table No.11 ADC Rules
 */
static int parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc)
{
	if (arm != NULL) {
		switch (sel_type) {
		case DOMAIN_NAME:
			strncpy(adc->u.domain_name, (char *)((arm)+1),
					*(uint8_t *)(arm));

#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif
			return 0;

		case DOMAIN_IP_ADDR_PREFIX:
			adc->u.domain_ip.u.ipv4_addr =
				ntohl(*(uint32_t *)(arm));
			adc->u.domain_prefix.prefix =
				rte_bswap16(*(uint16_t *)((arm) + 4));
#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif  /* PRINT_NEW_RULE_ENTRY */
			return 0;

		case DOMAIN_IP_ADDR:
			adc->u.domain_ip.u.ipv4_addr =
				ntohl(*(uint32_t *)(arm));
#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif  /* PRINT_NEW_RULE_ENTRY */
			return 0;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
				sel_type);
			return -1;
		}
	}
	return -1;
}

/**
 * @Name : get_sdf_indices
 * @argument :
 * 	[IN] sdf_idx : String containing comma separater SDF index values
 * 	[OUT] out_sdf_idx : Array of integers converted from sdf_idx
 * @return : 0 - success, -1 fail
 * @Description : Convert sdf_idx array in to array of integers for SDF index
 * values.
 * Sample input : "[0, 1, 2, 3]"
 */
static uint32_t
get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx)
{
	char *tmp = strtok (sdf_idx,",");
	int i = 0;

	while ((NULL != tmp) && (i < MAX_SDF_IDX_COUNT)) {
		out_sdf_idx[i++] = atoi(tmp);
		tmp = strtok (NULL, ",");
	}
	return i;
}

/**
 * @Name : zmq_buf_process
 * @argument :
 * 	[IN] zmqmsgbuf_rx : Pointer to received zmq buffer
 * 	[IN] zmqmsglen : Length of the zmq buffer
 * @return : 0 - success
 * @Description : Converts zmq message type to session_info or
 * respective rules info
 */

int
zmq_mbuf_process(struct zmqbuf *zmqmsgbuf_rx, int zmqmsglen)
{
	int ret;
	struct msgbuf buf = {0};
	struct zmqbuf zmqmsgbuf_tx;
	struct msgbuf *rbuf = &buf;
	struct session_info *sess = &rbuf->msg_union.sess_entry;

	memset(sess, 0, sizeof(*sess));

	rbuf->mtype = MSG_END;

	switch (zmqmsgbuf_rx->type) {
	case CREATE_SESSION: {
		struct create_session_t *csm =
			&zmqmsgbuf_rx->msg_union.create_session_msg;

		rbuf->mtype = MSG_SESS_CRE;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.iptype = IPTYPE_IPV4;
		sess->ue_addr.u.ipv4_addr = ntohl(csm->ue_ipv4);
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(csm->s1u_sgw_ipv4);
		sess->ul_s1_info.sgw_teid = csm->s1u_sgw_teid;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(csm->s1u_sgw_ipv4);
		sess->dl_s1_info.enb_teid = 0;

		switch(app.spgw_cfg) {
		case SGWU:
			/* Configure PGWU IP addr */
			sess->ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
			sess->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
			break;

		case PGWU:
			/* Configure SGWU IP addr */
			sess->dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
			sess->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
			sess->dl_s1_info.enb_teid = csm->s1u_sgw_teid;

			/* Add default pcc rule entry for dl */
			sess->num_dl_pcc_rules = 1;
			sess->dl_pcc_rule_id[0] = 1;
			break;

		default:
			break;
		}

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(csm->session_id);
		sess->client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = csm->op_id;
		zmqmsgbuf_tx.topic_id = csm->controller_topic;
		break;
	}

	case MODIFY_BEARER: {
		struct modify_bearer_t *mbm =
			&zmqmsgbuf_rx->msg_union.modify_bearer_msg;
		rbuf->mtype = MSG_SESS_MOD;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.enb_addr.u.ipv4_addr =
			ntohl(mbm->s1u_enodeb_ipv4);
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.enb_addr.u.ipv4_addr =
			ntohl(mbm->s1u_enodeb_ipv4);
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = mbm->s1u_enodeb_teid;

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;
		sess->num_dl_pcc_rules = 1;
		sess->dl_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(mbm->session_id);
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = mbm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = mbm->op_id;
		zmqmsgbuf_tx.topic_id = mbm->controller_topic;
		break;
	}

	case DELETE_SESSION: {
		struct delete_session_t *dsm =
			&zmqmsgbuf_rx->msg_union.delete_session_msg;
		rbuf->mtype = MSG_SESS_DEL;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = 0;

		sess->sess_id = rte_bswap64(dsm->session_id);

		zmqmsgbuf_tx.msg_union.dpn_response.client_id = dsm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = dsm->op_id;
		zmqmsgbuf_tx.topic_id = dsm->controller_topic;
		break;
	}

	case ADC_RULE: {
		/*
		 * @brief Coverts zmq message into ADC Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.11 ADC Table
		 */
		static uint8_t rule_num = 1;
		uint8_t *buf = (uint8_t *)&(zmqmsgbuf_rx->msg_union.adc_rule_m);
		struct adc_rules *adc =
			&(rbuf->msg_union.adc_filter_entry);

		rbuf->mtype = MSG_ADC_TBL_ADD;
		rbuf->dp_id.id = DPN_ID;

		adc->sel_type = *(uint8_t *)(buf);

		adc->rule_id = rule_num++;

		ret = parse_adc_buf(adc->sel_type, (((char *)(buf) + 1)), adc);

		if (ret < 0){
			RTE_LOG_DP(ERR, DP, "Failed to filled adc structure\n");
		}
		break;
	}

	case PCC_RULE: {
		/**
		 * @brief Coverts zmq message into PCC Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.12 PCC Table
		 */
		static uint8_t rule_id_t = 1;
		struct pcc_rules_t *pcc_t =
			&(zmqmsgbuf_rx->msg_union.pcc_rules_m);
		struct pcc_rules *pcc = &(rbuf->msg_union.pcc_entry);
		uint8_t sdf_idx[MAX_SDF_STR_LEN]={0};
		uint8_t len=0, offset = 0;

		rbuf->mtype = MSG_PCC_TBL_ADD;
		rbuf->dp_id.id = DPN_ID;

		pcc->rule_id = rule_id_t++;
		pcc->metering_method = pcc_t->metering_method;
		pcc->charging_mode = pcc_t->charging_mode;
		pcc->rating_group = rte_bswap16(pcc_t->rating_group);
		pcc->rule_status = pcc_t->rule_status;
		pcc->gate_status = pcc_t->gate_status;
		pcc->session_cont = pcc_t->session_cont;
		pcc->monitoring_key = rte_bswap32(pcc_t->monitoring_key);
		pcc->precedence = rte_bswap32(pcc_t->precedence);
		pcc->report_level = pcc_t->level_of_report;
		pcc->mute_notify = pcc_t->mute_status;
		pcc->drop_pkt_count = rte_bswap64(pcc_t->drop_pkt_count);
		pcc->qos.ul_mtr_profile_index = rte_bswap16(pcc_t->ul_mtr_profile_idx);
		pcc->qos.dl_mtr_profile_index = rte_bswap16(pcc_t->dl_mtr_profile_idx);
		pcc->redirect_info.info = pcc_t->redirect_info;
		pcc->adc_idx = rte_bswap32(pcc_t->adc_idx);

		/**
		 * ref.table no 12 PCC table info will help know the code
		 * len(SDF_FILTER_IDX), 0 : [0-4]
		 * SDF_FILTER_IDX, 5: [5 - len1]
		 * len(RULE_NAME), 5 + len1 :
		 * RULE_NAME, [5+len1] + 5
		 * len(SPONSOR_ID),  [5+len1] + [ 5 + len2]
		 * SPONSOR_ID) [5+len1] + [5+len2] + 5
		 */
		strncpy(sdf_idx, ((char *)(&(pcc_t->adc_idx))+5),
					*(uint8_t *)(&(pcc_t->adc_idx)+1));

		offset = *(uint8_t *)((char *)(&(pcc_t->adc_idx))+ 5 +
							*(uint8_t *)(&(pcc_t->adc_idx)+1));

		strncpy(pcc->rule_name, ((char *)(&(pcc_t->adc_idx)) + 6 +
					*(uint8_t *)(&(pcc_t->adc_idx)+1)), offset);

		strncpy(pcc->sponsor_id, ((char *)(&(pcc_t->adc_idx)) + 7 +
					offset + *(uint8_t *)(&(pcc_t->adc_idx)+1)), MAX_LEN);

		len = *(uint8_t *)(&(pcc_t->adc_idx)+1);

		/**sdf indices are present only if adc is not present*/
		if(-1 == pcc->adc_idx){
			/* Convert array of sdf index value to integers */
			pcc->sdf_idx_cnt = get_sdf_indices(sdf_idx, pcc->sdf_idx);
		}
#ifdef PRINT_NEW_RULE_ENTRY
		print_pcc_val(pcc);
#endif  /* PRINT_NEW_RULE_ENTRY */
		break;
	}

	case METER_RULE: {
		/**
		 * @brief Coverts zmq message into Meter Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.13 Meter Table
		 */
		struct mtr_entry_t *mtr_t =
			&(zmqmsgbuf_rx->msg_union.mtr_entry_m);
		struct mtr_entry *mtr = &(rbuf->msg_union.mtr_entry);

		rbuf->mtype = MSG_MTR_ADD;
		rbuf->dp_id.id = DPN_ID;

		mtr->mtr_profile_index =
			rte_bswap16(mtr_t->meter_profile_index);
		mtr->mtr_param.cir = rte_bswap64(mtr_t->cir);
		mtr->mtr_param.cbs = rte_bswap64(mtr_t->cbs);
		mtr->mtr_param.ebs = rte_bswap64(mtr_t->ebs);
		mtr->metering_method = mtr_t->metering_method;
#ifdef PRINT_NEW_RULE_ENTRY
		print_mtr_val(mtr);
#endif  /* PRINT_NEW_RULE_ENTRY */
		break;
	}

	case SDF_RULE: {
		/**
		 * @brief Coverts zmq message into SDF Rules info
		 * ref.Doc : Message_sdn.docx
		 * section : Table No.14 SDF Table
		 */
		static uint8_t rule_id_t = 1;
		struct sdf_entry_t *sdf_t =
			&(zmqmsgbuf_rx->msg_union.sdf_entry_m);
		struct pkt_filter *sdf = &(rbuf->msg_union.pkt_filter_entry);

		rbuf->mtype = MSG_SDF_ADD;
		rbuf->dp_id.id = DPN_ID;

		sdf->pcc_rule_id = rule_id_t++;
		sdf->sel_rule_type = sdf_t->rule_type;

		switch (sdf->sel_rule_type) {
		case RULE_STRING:
			strncpy(sdf->u.rule_str,
					(char *)(&(sdf_t->rule_type) + 5),
					MAX_LEN);
			break;

		case FIVE_TUPLE:
			/*TODO: rule should be in struct five_tuple_rule
			 * This field is currently not used
			 */
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
				sdf_t->rule_type);
			break;
		}
#ifdef PRINT_NEW_RULE_ENTRY
			print_sdf_val(sdf);
#endif  /* PRINT_NEW_RULE_ENTRY */
			break;
	}

	case DDN_ACK: {
		rbuf->mtype = MSG_DDN_ACK;
		rbuf->dp_id.id = DPN_ID;

		printf("ACK received from FPC..\n");
		break;
	}

	default:
		RTE_LOG_DP(ERR, DP, "UNKNOWN Message Type: %d\n", zmqmsgbuf_rx->type);
		break;

	}

	ret = process_comm_msg((void *)rbuf);
	if (ret < 0)
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_SYSTEM_FAILURE;
	else
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_REQUEST_ACCEPTED;

	zmqmsgbuf_tx.type = DPN_RESPONSE;
	ret = do_zmq_mbuf_send(&zmqmsgbuf_tx);

	if (ret < 0)
		RTE_LOG_DP(DEBUG, DP, "do_zmq_mbuf_send failed for type: %"PRIu8"\n",
				zmqmsgbuf_rx->type);

	return ret;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqsub destroy
	 */
	zmq_subsocket_destroy();
	return 0;
}

#endif		/* DP: SDN_ODL_BUILD */
#endif /* !CP_BUILD*/

#define IFACE_FILE "../config/interface.cfg"
#define SET_CONFIG_IP(ip, file, section, entry) \
	do {\
		entry = rte_cfgfile_get_entry(file, section, #ip);\
		if (entry == NULL)\
			rte_panic("%s not found in %s", #ip, IFACE_FILE);\
		if (inet_aton(entry, &ip) == 0)\
			rte_panic("Invalid %s in %s", #ip, IFACE_FILE);\
	} while (0)
#define SET_CONFIG_PORT(port, file, section, entry) \
	do {\
		entry = rte_cfgfile_get_entry(file, section, #port);\
		if (entry == NULL)\
			rte_panic("%s not found in %s", #port, IFACE_FILE);\
		if (sscanf(entry, "%"SCNu16, &port) != 1)\
			rte_panic("Invalid %s in %s", #port, IFACE_FILE);\
	} while (0)

static void read_interface_config(void)
{
	struct rte_cfgfile *file = rte_cfgfile_load(IFACE_FILE, 0);
	const char *file_entry;

	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				IFACE_FILE);

#ifndef SDN_ODL_BUILD /* Communication over the UDP */
	SET_CONFIG_IP(dp_comm_ip, file, "0", file_entry);
	SET_CONFIG_PORT(dp_comm_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_comm_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_comm_port, file, "0", file_entry);

#ifdef ZMQ_COMM
	const char *zmq_proto = "tcp";

#if ZMQ_DIRECT
	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(dp_comm_ip), dp_comm_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(cp_comm_ip), cp_comm_port);
#else
#ifdef CP_BUILD
	SET_CONFIG_IP(zmq_cp_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_cp_push_port, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_cp_pull_port, file, "0", file_entry);

	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_cp_ip), zmq_cp_pull_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_cp_ip), zmq_cp_push_port);
#else
	SET_CONFIG_IP(zmq_dp_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_dp_pull_port, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_dp_push_port, file, "0", file_entry);

	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_dp_ip), zmq_dp_pull_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_dp_ip), zmq_dp_push_port);
#endif

#endif  /* ZMQ_DIRECT */

#endif  /* ZMQ_COMM */
#else   /* Communication over the ZMQ */

	const char *zmq_proto = "tcp";
	struct in_addr zmq_sub_ip;
	struct in_addr zmq_pub_ip;
	uint16_t zmq_sub_port;
	uint16_t zmq_pub_port;

	SET_CONFIG_IP(fpc_ip, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_port, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_topology_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_sub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_sub_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_pub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_pub_port, file, "0", file_entry);

	snprintf(zmq_sub_ifconnect, sizeof(zmq_sub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_sub_ip), zmq_sub_port);
	snprintf(zmq_pub_ifconnect, sizeof(zmq_pub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_pub_ip), zmq_pub_port);

#endif

#ifdef SGX_CDR
	app.dealer_in_ip = rte_cfgfile_get_entry(file, "0",
			DEALERIN_IP);
	app.dealer_in_port = rte_cfgfile_get_entry(file, "0",
			DEALERIN_PORT);
	app.dealer_in_mrenclave = rte_cfgfile_get_entry(file, "0",
			DEALERIN_MRENCLAVE);
	app.dealer_in_mrsigner = rte_cfgfile_get_entry(file, "0",
			DEALERIN_MRSIGNER);
	app.dealer_in_isvsvn = rte_cfgfile_get_entry(file, "0",
			DEALERIN_ISVSVN);
	app.dp_cert_path = rte_cfgfile_get_entry(file, "0",
			DP_CERT_PATH);
	app.dp_pkey_path = rte_cfgfile_get_entry(file, "0",
			DP_PKEY_PATH);
#endif /* SGX_CDR */
}


/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void)
{
	/* Read and store ip and port for socket communication between cp and
	 * dp*/
	read_interface_config();
#ifdef ZMQ_COMM
	char command[100];
#endif
	//read_interface_config();

#ifdef ZMQ_COMM
#ifdef CP_BUILD
	snprintf(command, sizeof(command),
			        "%s %s%s%s%u%s", "timeout 1 bash -c", "'cat < /dev/null > /dev/tcp/", inet_ntoa(zmq_cp_ip), "/", zmq_cp_push_port, "' > /dev/null 2>&1");
#else
	snprintf(command, sizeof(command),
			        "%s %s%s%s%u%s", "timeout 1 bash -c", "'cat < /dev/null > /dev/tcp/", inet_ntoa(zmq_dp_ip), "/", zmq_dp_push_port, "' > /dev/null 2>&1");
#endif
	if((system(command)) > 0) {
		rte_exit(EXIT_FAILURE, "ZMQ Streamer not running, Please start ZMQ Streamer service...\n");
	} else {
		printf("ZMQ Streamer running... CUPS connectivity opened....\n");
	}
#endif

#ifdef CP_BUILD
	printf("IFACE: CP Initialization\n");
#if defined SDN_ODL_BUILD
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_cp_socket,
				udp_send_socket,
				NULL,
				NULL);
	set_comm_type(COMM_SOCKET);
#else
#ifdef ZMQ_COMM
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);

	set_comm_type(COMM_ZMQ);
#else   /* ZMQ_COMM */
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_cp_socket,
				udp_send_socket,
				udp_recv_socket,
				NULL);
	set_comm_type(COMM_SOCKET);
#endif  /* ZMQ_COMM */
#endif  /* SDN_ODL_BUILD  */
#else   /* CP_BUILD */
#ifndef SDN_ODL_BUILD
	RTE_LOG_DP(NOTICE, DP, "IFACE: DP Initialization\n");
#ifdef ZMQ_COMM
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);

	set_comm_type(COMM_ZMQ);
#else   /* ZMQ_COMM */
#ifdef PFCP_COMM
	create_udp_socket(dp_comm_ip, dp_comm_port, &my_sock);
#else  /* PFCP_COMM */
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_dp_socket,
				udp_send_socket,
				udp_recv_socket,
				NULL);
#endif /* PFCP_COMM */
#endif  /* ZMQ_COMM */
#else
/* Code Rel. Jan 30, 2017
* Note: PCC, ADC, Session table initial creation on the DP sent over UDP by CP
* Needs to be from SDN controller as code & data models evolve
* For Jan 30, 2017 release, for flow updates over SDN controller
* register ZMQSUB socket after dp_session_table_create.
*/
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
#endif  /* SDN_ODL_BUILD */
#endif  /* !CP_BUILD */
}

void sig_handler(int signo)
{
	if (signo == SIGINT) {
#ifdef SDN_ODL_BUILD
#ifdef CP_BUILD
		close_nb();
#else
		zmq_status_goodbye();
#endif
#endif

#ifdef CP_BUILD
#ifdef SYNC_STATS
		retrive_stats_entry();
		close_stats();
#endif /* SYNC_STATS */
#endif

#ifndef CP_BUILD
		close(route_sock);
		cdr_close();
#endif
#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
		print_perf_statistics();
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
		rte_exit(EXIT_SUCCESS, "received SIGINT\n");
	}
}

