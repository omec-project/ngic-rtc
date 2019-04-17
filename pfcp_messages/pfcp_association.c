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

#include <errno.h>
#include <rte_debug.h>

#include "pfcp_set_ie.h"
#include "cp.h"
#include "pfcp.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_util.h"
#include "pfcp_association.h"

#ifdef DP_BUILD
#define RTE_LOGTYPE_DP RTE_LOGTYPE_USER4
#endif


pfcp_config_t pfcp_config;
extern pfcp_context_t pfcp_ctxt;
extern struct rte_hash *heartbeat_recovery_hash;
extern struct rte_hash *node_id_hash;
extern struct rte_hash *associated_upf_hash;
extern int pfcp_sgwc_fd_arr[MAX_NUM_SGWC];
extern int pfcp_pgwc_fd_arr[MAX_NUM_PGWC];
extern struct in_addr cp_comm_ip;
extern uint16_t cp_comm_port;

void
fill_pfcp_association_release_req(pfcp_association_release_request_t *pfcp_ass_rel_req)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_rel_req,0,sizeof(pfcp_association_release_request_t)) ;

	/*filing of pfcp header*/
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_rel_req->header),PFCP_ASSOCIATION_RELEASE_REQUEST,
			NO_SEID,seq);
	/*filling of node id*/
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),pAddr, INET_ADDRSTRLEN);	
	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_rel_req->node_id),node_value);
}

void 
fill_pfcp_association_release_resp(pfcp_association_release_response_t *pfcp_ass_rel_resp)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_rel_resp,0,sizeof(pfcp_association_release_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_rel_resp->header),PFCP_ASSOCIATION_RELEASE_RESPONSE,
			NO_SEID,seq);

	// filling of node id
	const char* pAddr = "192.168.0.10";
	uint32_t node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_rel_resp->node_id),node_value);

	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_ass_rel_resp->cause), CAUSE_VALUES_REQUESTACCEPTEDSUCCESS );

}

void
fill_pfcp_association_update_req(pfcp_association_update_request_t *pfcp_ass_update_req)
{
	uint32_t seq  = 1;

	memset(pfcp_ass_update_req,0,sizeof(pfcp_association_update_request_t)) ;

	//filing of pfcp header
	 set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_update_req->header),PFCP_ASSOCIATION_UPDATE_REQUEST,
						NO_SEID,seq);
	// filling of node id
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),pAddr, INET_ADDRSTRLEN);	
	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_update_req->node_id),node_value);

	// if UPF set up function feature
	set_upf_features(&(pfcp_ass_update_req->up_function_features));

	// if CPF set up function feature
	set_cpf_features(&(pfcp_ass_update_req->cp_function_features));

	//set association release req
	set_pfcp_ass_rel_req(&(pfcp_ass_update_req->pfcp_association_release_request));

	//set raceful release period
	set_graceful_release_period(&(pfcp_ass_update_req->graceful_release_period));

}

void
fill_pfcp_association_setup_req(pfcp_association_setup_request_t *pfcp_ass_setup_req)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_setup_req,0,sizeof(pfcp_association_setup_request_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_req->header),PFCP_ASSOCIATION_SETUP_REQUEST,
						NO_SEID,seq);
	// filling of node id
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),pAddr, INET_ADDRSTRLEN);	
	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_setup_req->node_id),node_value);

	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_ass_setup_req->recovery_time_stamp));

	// if UPF set up function feature
	//set_upf_features(&(pfcp_ass_setup_req->up_function_features));

	// if CPF set up function feature
	set_cpf_features(&(pfcp_ass_setup_req->cp_function_features));
}

int
process_pfcp_association_request(void)
{
	struct in_addr upf_list[10] = {0};
	pfcp_association_setup_request_t pfcp_ass_setup_req;
	//move update message appropriately
	pfcp_association_update_request_t pfcp_ass_update_req;
	pfcp_association_release_request_t pfcp_ass_rel_req;
	pfcp_node_report_request_t pfcp_node_rep_req;

	get_upf_list(upf_list);
	get_ava_ip(upf_list);
	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);
	fill_pfcp_association_update_req(&pfcp_ass_update_req);
	fill_pfcp_association_release_req(&pfcp_ass_rel_req);
	fill_pfcp_node_report_req(&pfcp_node_rep_req);
	uint8_t pfcp_msg[256]={0};
	int encoded = encode_pfcp_association_setup_request(&pfcp_ass_setup_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if(pfcp_ctxt.flag_ava_ip == true)
	{
		for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){
			if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC ) {
				//TODO :TEMP pfcp_sgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;
				if ( pfcp_send(pfcp_sgwc_fd_arr[i],pfcp_msg,encoded,&pfcp_sgwu_sockaddr_arr[i]) < 0 ) {
					printf("Error sending\n\n");		
				}
	
			}
			else if(pfcp_config.cp_type == PGWC) {
				//TODO :TEMP pfcp_pgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;
				if (sendto(pfcp_pgwc_fd_arr[i],
							(char *) &pfcp_ass_setup_req,
							sizeof(pfcp_ass_setup_req),
							MSG_DONTWAIT,
							(struct sockaddr *)&pfcp_pgwu_sockaddr_arr[i],
							sizeof(pfcp_pgwu_sockaddr_arr[i])) < 0)
					printf("Error sending\n");
			}
		}
	}

	else
	{
		//see flow diagram for implementation

	}
return 0;
}

void
fill_pfcp_association_setup_resp(pfcp_association_setup_response_t *pfcp_ass_setup_resp, uint8_t cause )
{
	uint32_t seq  = 1;
	memset(pfcp_ass_setup_resp,0,sizeof(pfcp_association_setup_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_resp->header),PFCP_ASSOCIATION_SETUP_RESPONSE,
			NO_SEID, seq);
	// filling of node id
	uint32_t node_value = 0;// inet_addr(pAddr);
	set_node_id(&(pfcp_ass_setup_resp->node_id),node_value);

	//set cause
	set_cause(&(pfcp_ass_setup_resp->cause), cause);

	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_ass_setup_resp->recovery_time_stamp));

	// if UPF set up function feature
	set_upf_features(&(pfcp_ass_setup_resp->up_function_features));

	set_up_ip_resource_info(&(pfcp_ass_setup_resp->up_ip_resource_info));


	// if CPF set up function feature
	//set_cpf_features(&(pfcp_ass_setup_resp->cp_function_features));

	pfcp_ass_setup_resp->header.message_len =pfcp_ass_setup_resp->node_id.header.len +
		pfcp_ass_setup_resp->recovery_time_stamp.header.len +
		pfcp_ass_setup_resp->cause.header.len +
		pfcp_ass_setup_resp->up_function_features.header.len +
		pfcp_ass_setup_resp->cp_function_features.header.len ;

	pfcp_ass_setup_resp->header.message_len += sizeof(pfcp_ass_setup_resp->header.seid_seqno.no_seid);

}

void
fill_pfcp_association_update_resp(pfcp_association_update_response_t *pfcp_asso_update_resp)
{
	uint32_t seq  = 1;
	memset(pfcp_asso_update_resp,0,sizeof(pfcp_association_update_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_asso_update_resp->header),PFCP_ASSOCIATION_UPDATE_RESPONSE,
			NO_SEID, seq);
	// filling of node id
	uint32_t node_value = 0; //inet_addr(pAddr);
	set_node_id(&(pfcp_asso_update_resp->node_id),node_value);

	// filling of cause
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	 set_cause(&(pfcp_asso_update_resp->cause), CAUSE_VALUES_REQUESTACCEPTEDSUCCESS);

	// if UPF set up function feature
	set_upf_features(&(pfcp_asso_update_resp->up_function_features));

	// if CPF set up function feature
	//set_cpf_features(&(pfcp_asso_update_resp->cp_function_features));
}


void
fill_pfcp_node_report_req(pfcp_node_report_request_t *pfcp_node_rep_req)
{
	uint32_t seq  = 1;
	memset(pfcp_node_rep_req,0,sizeof(pfcp_node_report_request_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_node_rep_req->header),PFCP_NODE_REPORT_REQUEST,
			NO_SEID,seq);
	// filling of node id
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),pAddr, INET_ADDRSTRLEN);	
	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_node_rep_req->node_id),node_value);

	//filling of node report type
	set_node_report_type(&(pfcp_node_rep_req->node_report_type));

	//filling of user path failure 
	set_user_plane_path_failure_report(&(pfcp_node_rep_req->user_plane_path_failure_report));
}

void
fill_pfcp_node_report_resp(pfcp_node_report_response_t *pfcp_node_rep_resp)
{
	uint32_t seq  = 1;
	memset(pfcp_node_rep_resp,0,sizeof(pfcp_node_report_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_node_rep_resp->header),PFCP_NODE_REPORT_RESPONSE,
			NO_SEID,seq);
	// filling of node id
	uint32_t node_value = 0; //inet_addr(pAddr);
	set_node_id(&(pfcp_node_rep_resp->node_id),node_value);
     
	//set cause
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
     	set_cause(&(pfcp_node_rep_resp->cause), CAUSE_VALUES_REQUESTACCEPTEDSUCCESS);
	
	//set offending ie
	//TODO: Remove NODE_ID with actual offend ID
	set_offending_ie(&(pfcp_node_rep_resp->offending_ie), IE_NODE_ID);

}

void
fill_pfcp_heartbeat_req(pfcp_heartbeat_request_t *pfcp_heartbeat_req)
{

	uint32_t seq  = 1;

	memset(pfcp_heartbeat_req,0,sizeof(pfcp_heartbeat_request_t)) ;
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_req->header),PFCP_HEARTBEAT_REQUEST,
			NO_SEID, seq);
	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_heartbeat_req->recovery_time_stamp));
}
void
fill_pfcp_heartbeat_resp(pfcp_heartbeat_response_t *pfcp_heartbeat_resp)
{

	uint32_t seq  = 1;
	memset(pfcp_heartbeat_resp,0,sizeof(pfcp_heartbeat_response_t)) ;
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_resp->header),PFCP_HEARTBEAT_RESPONSE,
			NO_SEID, seq);
	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_heartbeat_resp->recovery_time_stamp));
}

int process_pfcp_heartbeat_req(struct sockaddr_in *peer_addr)
{
	uint8_t pfcp_msg[250]={0};
	int encoded = 0;
	pfcp_heartbeat_request_t pfcp_heartbeat_req  = {0};
	pfcp_heartbeat_response_t *pfcp_hearbeat_resp = malloc(sizeof(pfcp_heartbeat_response_t));
	memset(pfcp_hearbeat_resp,0,sizeof(pfcp_heartbeat_response_t));
	fill_pfcp_heartbeat_req(&pfcp_heartbeat_req);
	encoded = encode_pfcp_heartbeat_request(&pfcp_heartbeat_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

#ifdef CP_BUILD
	if ( pfcp_send(pfcp_sgwc_fd_arr[0], pfcp_msg, encoded, peer_addr) < 0 ) {
				RTE_LOG_DP(DEBUG, CP, "Error sending: %i\n", errno);
	}
#endif

#ifdef DP_BUILD
 if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
					RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
	}
	
#endif

	return 0;

}
