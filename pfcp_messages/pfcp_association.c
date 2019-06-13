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
#include "pfcp_session.h"
#include "../dp/main.h"
#include "../cp/cp_stats.h"


#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
#include "cdnsutil.h"
#endif /* CP_BUILD && USE_DNS_QUERY */

/*#ifdef DP_BUILD
#define RTE_LOGTYPE_DP RTE_LOGTYPE_USER4
#endif*/


pfcp_config_t pfcp_config;

association_context_t assoc_ctxt[NUM_DP] = {0};

extern pfcp_context_t pfcp_ctxt;
extern struct rte_hash *heartbeat_recovery_hash;
extern struct rte_hash *node_id_hash;
extern struct rte_hash *associated_upf_hash;
extern int pfcp_sgwc_fd_arr[MAX_NUM_SGWC];
extern int pfcp_pgwc_fd_arr[MAX_NUM_PGWC];
extern struct in_addr cp_comm_ip;
extern uint16_t cp_comm_port;
extern struct app_params app;

void
fill_pfcp_association_release_req(pfcp_association_release_request_t *pfcp_ass_rel_req)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_rel_req,0,sizeof(pfcp_association_release_request_t)) ;

	/*filing of pfcp header*/
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_rel_req->header),
			PFCP_ASSOCIATION_RELEASE_REQUEST, NO_SEID, seq);
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
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_rel_resp->header),
			PFCP_ASSOCIATION_RELEASE_RESPONSE, NO_SEID, seq);

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

	memset(pfcp_ass_update_req, 0, sizeof(pfcp_association_update_request_t)) ;

	//filing of pfcp header
	 set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_update_req->header),
			 PFCP_ASSOCIATION_UPDATE_REQUEST, NO_SEID, seq);

	// filling of node id
	char peer_addr[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]), peer_addr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(peer_addr);
	set_node_id(&(pfcp_ass_update_req->node_id), node_value);

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
	char node_addr[INET_ADDRSTRLEN] = {0};

	memset(pfcp_ass_setup_req, 0, sizeof(pfcp_association_setup_request_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_req->header),
			PFCP_ASSOCIATION_SETUP_REQUEST, NO_SEID, seq);

	if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC )
		inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]), node_addr, INET_ADDRSTRLEN);
	else
		inet_ntop(AF_INET, &(pfcp_config.pgwc_pfcp_ip[0]), node_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_ass_setup_req->node_id), node_value);

	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_ass_setup_req->recovery_time_stamp));

	// if UPF set up function feature
	//set_upf_features(&(pfcp_ass_setup_req->up_function_features));

	// if CPF set up function feature
	set_cpf_features(&(pfcp_ass_setup_req->cp_function_features));
}

#if defined(CP_BUILD)
int
process_pfcp_assoication_request(gtpv2c_header *gtpv2c_rx,
		create_session_request_t *csr, char *sgwu_fqdn)
{
	RTE_SET_USED(sgwu_fqdn);

	pfcp_association_setup_request_t pfcp_ass_setup_req;
	//move update message appropriately
	pfcp_association_update_request_t pfcp_ass_update_req;
	pfcp_association_release_request_t pfcp_ass_rel_req;
	pfcp_node_report_request_t pfcp_node_rep_req;

#ifdef USE_DNS_QUERY
	int ret;
	struct in_addr upf_list[MAX_UPF] = {0};

	ret = decode_create_session_request_t((uint8_t *) gtpv2c_rx,
			csr);
	if (!ret)
		 return ret;

	/* TODO: Do we need this? Revisit. Check both cases
	 * CSR from MME and CSR from SGW-C
	 */
	/*
	if (csr->indication.header.len &&
			csr->indication.indication_value.uimsi) {
		fprintf(stderr, "Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n");
		return -EPERM;
	}

	if (!csr->indication.header.len
			|| !csr->apn_restriction.header.len
			|| !csr->bearer_context.header.len
			|| !csr->sender_ftied.header.len
			|| !csr->s5s8pgw_pmip.header.len
			|| !csr->imsi.header.len
			|| !csr->ambr.header.len
			|| !csr->pdn_type.header.len
			|| !csr->bearer_context.bearer_qos.header.len

			|| !(csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV4) ) {
		fprintf(stderr, "Mandatory IE missing. Dropping packet\n");
		return -EPERM;
	}
	*/

	char sgwu_fqdn_res[MAX_HOSTNAME_LEN] = {0};
	int upf_count = get_upf_list(csr, upf_list, sgwu_fqdn_res);

	if (upf_count == 0) {
		fprintf(stderr, "No upf ip found. \n");
		return -EPERM;
	}

	uint8_t *data = NULL;
	data  = rte_zmalloc_socket(NULL, sizeof(uint8_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (data == NULL)
		rte_panic("Failure to allocate data associated upf hash: "
				"%s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);

	uint32_t upf_ip  = upf_list[0].s_addr;
	printf("CP:DNS discovery selected upf ip:%s\n",
				inet_ntoa(*((struct in_addr *)&upf_ip)));
	ret = rte_hash_lookup_data(associated_upf_hash,(const void*) &(upf_ip),
			(void **) &(data));

	if (ret < 0) {
		//RTE_LOG_CP(DEBUG, CP ,"NO ENTRY FOUND IN UPF HASH\n");
		ret = add_associated_upf_ip_hash(&upf_ip, data);

		assoc_ctxt[0].upf_ip = upf_ip;
		memcpy(&assoc_ctxt[0].rx_buf[0], gtpv2c_rx,1000);
		memcpy(assoc_ctxt[0].sgwu_fqdn[0], sgwu_fqdn_res,
				strlen(sgwu_fqdn_res));

		*data = 1;
		num_dp++;
	} else if (*data == 1) {
		int count = assoc_ctxt[0].csr_cnt++;
		memcpy(assoc_ctxt[0].rx_buf[count], gtpv2c_rx,1000);
		memcpy(assoc_ctxt[0].sgwu_fqdn[count], sgwu_fqdn_res,
				strlen(sgwu_fqdn_res));

		return 0;
	} else if(*data == 2) {
		memcpy(sgwu_fqdn, sgwu_fqdn_res, strlen(sgwu_fqdn_res));
		return PFCP_ASSOC_ALREADY_ESTABLISHED;
	}

#else  /* USE_DNS_QUERY */
	RTE_SET_USED(gtpv2c_rx);
	RTE_SET_USED(csr);
#endif /* USE_DNS_QUERY */

	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);
	fill_pfcp_association_update_req(&pfcp_ass_update_req);
	fill_pfcp_association_release_req(&pfcp_ass_rel_req);
	fill_pfcp_node_report_req(&pfcp_node_rep_req);
	uint8_t pfcp_msg[256]={0};
	int encoded = encode_pfcp_association_setup_request(&pfcp_ass_setup_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

		if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC ) {

				for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){
#ifdef USE_DNS_QUERY
					pfcp_sgwu_sockaddr_arr[i].sin_addr = upf_list[0];
#endif /* USE_DNS_QUERY */
					if ( pfcp_send(pfcp_sgwc_fd_arr[i],pfcp_msg,encoded,&pfcp_sgwu_sockaddr_arr[i]) < 0 ) {
						printf("Error sending\n\n");
					}else {
						cp_stats.association_setup_req_sent++;
					}
				}
		} else if(pfcp_config.cp_type == PGWC) {
			//TODO :TEMP pfcp_pgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;
			for(uint32_t i=0;i < pfcp_config.num_pgwu; i++ ) {
#ifdef USE_DNS_QUERY
				pfcp_pgwu_sockaddr_arr[i].sin_addr = upf_list[0];
#endif /* USE_DNS_QUERY */
				if ( pfcp_send(pfcp_pgwc_fd_arr[i],pfcp_msg,encoded,
							&pfcp_pgwu_sockaddr_arr[i]) < 0 ) {
					printf("Error sending\n\n");
				}else{
					cp_stats.association_setup_req_sent++;
				}
			}
		}

	return 0;
}
#endif

void
fill_pfcp_association_setup_resp(pfcp_association_setup_response_t *pfcp_ass_setup_resp,
				uint8_t cause )
{
	uint32_t seq  = 1;
	uint32_t node_value = 0;

	memset(pfcp_ass_setup_resp,0,sizeof(pfcp_association_setup_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_resp->header),
			PFCP_ASSOCIATION_SETUP_RESPONSE, NO_SEID, seq);

	set_node_id(&(pfcp_ass_setup_resp->node_id), node_value);

	//set cause
	set_cause(&(pfcp_ass_setup_resp->cause), cause);

	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_ass_setup_resp->recovery_time_stamp));

	// if UPF set up function feature
	set_upf_features(&(pfcp_ass_setup_resp->up_function_features));

	if( app.spgw_cfg == SGWU )
		pfcp_ass_setup_resp->user_plane_ip_resource_information_count = 2; /*for s1u and s5s8 sgwc ips*/
	else if ( app.spgw_cfg == PGWU || app.spgw_cfg == SAEGWU  )
		pfcp_ass_setup_resp->user_plane_ip_resource_information_count = 1; /*for s5s8 pgwc ip*/

	for( int i=0; i < pfcp_ass_setup_resp->user_plane_ip_resource_information_count; i++ )
		set_up_ip_resource_info(&(pfcp_ass_setup_resp->up_ip_resource_info[i]),i);


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
	uint32_t node_value = 0;

	memset(pfcp_asso_update_resp, 0, sizeof(pfcp_association_update_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_asso_update_resp->header),
			PFCP_ASSOCIATION_UPDATE_RESPONSE, NO_SEID, seq);

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
	char node_addr[INET_ADDRSTRLEN] = {0} ;
	memset(pfcp_node_rep_req, 0, sizeof(pfcp_node_report_request_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_node_rep_req->header),
			PFCP_NODE_REPORT_REQUEST, NO_SEID, seq);
	// filling of node id
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]), node_addr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_node_rep_req->node_id), node_value);

	//filling of node report type
	set_node_report_type(&(pfcp_node_rep_req->node_report_type));

	//filling of user path failure
	set_user_plane_path_failure_report(&(pfcp_node_rep_req->user_plane_path_failure_report));
}

void
fill_pfcp_node_report_resp(pfcp_node_report_response_t *pfcp_node_rep_resp)
{
	uint32_t seq  = 1;
	uint32_t node_value = 0;

	memset(pfcp_node_rep_resp, 0, sizeof(pfcp_node_report_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_node_rep_resp->header),
			PFCP_NODE_REPORT_RESPONSE, NO_SEID,seq);
	// filling of node id
	set_node_id(&(pfcp_node_rep_resp->node_id), node_value);

	//set cause
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_node_rep_resp->cause), CAUSE_VALUES_REQUESTACCEPTEDSUCCESS);

	//set offending ie
	//TODO: Remove NODE_ID with actual offend ID
	set_offending_ie(&(pfcp_node_rep_resp->offending_ie), IE_NODE_ID);

}

void
fill_pfcp_heartbeat_req(pfcp_heartbeat_request_t *pfcp_heartbeat_req, uint32_t seq)
{

	memset(pfcp_heartbeat_req,0,sizeof(pfcp_heartbeat_request_t)) ;
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_req->header),PFCP_HEARTBEAT_REQUEST,
			NO_SEID, seq);
	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_heartbeat_req->recovery_time_stamp));
	seq++;
}
void
fill_pfcp_heartbeat_resp(pfcp_heartbeat_response_t *pfcp_heartbeat_resp)
{

	uint32_t seq  = 1;
	memset(pfcp_heartbeat_resp,0,sizeof(pfcp_heartbeat_response_t)) ;
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_resp->header),
			PFCP_HEARTBEAT_RESPONSE, NO_SEID, seq);

	// filling of recovery time stamp
	set_recovery_time_stamp(&(pfcp_heartbeat_resp->recovery_time_stamp));
}

int process_pfcp_heartbeat_req(struct sockaddr_in *peer_addr, uint32_t seq)
{
	uint8_t pfcp_msg[250]={0};
	int encoded = 0;
	pfcp_heartbeat_request_t pfcp_heartbeat_req  = {0};
	pfcp_heartbeat_response_t *pfcp_hearbeat_resp =
						malloc(sizeof(pfcp_heartbeat_response_t));

	memset(pfcp_hearbeat_resp,0,sizeof(pfcp_heartbeat_response_t));
	fill_pfcp_heartbeat_req(&pfcp_heartbeat_req, seq);
	encoded = encode_pfcp_heartbeat_request(&pfcp_heartbeat_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

#ifdef CP_BUILD
	if((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC) ) {
		if ( pfcp_send(pfcp_sgwc_fd_arr[0], pfcp_msg, encoded, peer_addr) < 0 ) {
					RTE_LOG_DP(DEBUG, CP, "Error sending: %i\n", errno);
		}
	} else if (pfcp_config.cp_type == PGWC) {
		if ( pfcp_send(pfcp_pgwc_fd_arr[0], pfcp_msg, encoded, peer_addr) < 0 ) {
					RTE_LOG_DP(DEBUG, CP, "Error sending: %i\n", errno);
		}
	}
#endif

#ifdef DP_BUILD
	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
					RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
	}

#endif

	return 0;

}
