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

#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "cp_stats.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"


#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
#include "cdnsutil.h"
#endif /* CP_BUILD && USE_DNS_QUERY */

#ifdef DP_BUILD
extern struct app_params app;
struct in_addr cp_comm_ip;
uint16_t cp_comm_port;
#endif /* DP_BUILD */

#ifdef CP_BUILD
extern int pfcp_fd;
extern pfcp_config_t pfcp_config;

void
fill_pfcp_association_release_req(pfcp_assn_rel_req_t *pfcp_ass_rel_req)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_rel_req, 0, sizeof(pfcp_assn_rel_req_t)) ;

	/*filing of pfcp header*/
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_rel_req->header),
			PFCP_ASSOCIATION_RELEASE_REQUEST, NO_SEID, seq);
	/*filling of node id*/
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_rel_req->node_id), node_value);
}

void
fill_pfcp_association_update_req(pfcp_assn_upd_req_t *pfcp_ass_update_req)
{
	uint32_t seq  = 1;

	memset(pfcp_ass_update_req, 0, sizeof(pfcp_assn_upd_req_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_update_req->header),
			 PFCP_ASSOCIATION_UPDATE_REQUEST, NO_SEID, seq);

	char peer_addr[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), peer_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(peer_addr);
	set_node_id(&(pfcp_ass_update_req->node_id), node_value);

	set_upf_features(&(pfcp_ass_update_req->up_func_feat));

	set_cpf_features(&(pfcp_ass_update_req->cp_func_feat));

	set_pfcp_ass_rel_req(&(pfcp_ass_update_req->up_assn_rel_req));

	set_graceful_release_period(&(pfcp_ass_update_req->graceful_rel_period));

}

void
fill_pfcp_association_setup_req(pfcp_assn_setup_req_t *pfcp_ass_setup_req)
{

	uint32_t seq  = 1;
	char node_addr[INET_ADDRSTRLEN] = {0};

	memset(pfcp_ass_setup_req, 0, sizeof(pfcp_assn_setup_req_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_req->header),
			PFCP_ASSOCIATION_SETUP_REQUEST, NO_SEID, seq);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), node_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_ass_setup_req->node_id), node_value);

	set_recovery_time_stamp(&(pfcp_ass_setup_req->rcvry_time_stmp));

	set_cpf_features(&(pfcp_ass_setup_req->cp_func_feat));
}

int
process_pfcp_assoication_request(create_session_request_t *csr,
		char *sgwu_fqdn, struct in_addr *upf_ipv4)
{

	int ret = 0;
	uint32_t upf_ip = 0;
	char sgwu_fqdn_res[MAX_HOSTNAME_LENGTH] = {0};
	pfcp_assn_setup_req_t pfcp_ass_setup_req;

#ifdef USE_DNS_QUERY

	upfs_dnsres_t *entry;

	if (upflist_by_ue_hash_entry_lookup(csr->imsi.imsi,
			csr->imsi.header.len, &entry) != 0)
		return -1;

	if (entry->current_upf > entry->upf_count) {
		/* TODO: Add error log : Tried sending
		 * association request to all upf.*/
		/* Remove entry from hash ?? */
		return -1;
	}

	upf_ip = entry->upf_ip[entry->current_upf].s_addr;

	memcpy(sgwu_fqdn_res, entry->upf_fqdn[entry->current_upf],
			strlen(entry->upf_fqdn[entry->current_upf]));

	entry->current_upf++;

	RTE_LOG_DP(INFO, CP, "DNS discovery selected upf ip:%s\n",
				inet_ntoa(*((struct in_addr *)&upf_ip)));

#else  /* USE_DNS_QUERY */
	upf_ip = pfcp_config.upf_pfcp_ip.s_addr;
#endif /* USE_DNS_QUERY */

	upf_context_t *upf_context = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(upf_ip), (void **) &(upf_context));
	if (ret < 0) {
		upf_context  = rte_zmalloc_socket(NULL, sizeof(upf_context_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (upf_context == NULL) {
			fprintf(stderr, "Failure to allocate upf context: "
					"%s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);

			return -1;
		}

		ret = upf_context_entry_add(&upf_ip, upf_context);

		create_session_request_t *tmp_csr =
				rte_zmalloc_socket(NULL, sizeof(create_session_request_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

		memcpy(tmp_csr, csr, sizeof(create_session_request_t));
		upf_context->pending_csr[upf_context->csr_cnt] = (uint32_t *)tmp_csr;

		memcpy(upf_context->fqdn, sgwu_fqdn_res, strlen(sgwu_fqdn_res));

		upf_context->csr_cnt++;
		upf_context->assoc_status = ASSOC_IN_PROGRESS;

	} else if (upf_context->assoc_status == ASSOC_IN_PROGRESS) {

		create_session_request_t *tmp_csr =
						rte_zmalloc_socket(NULL, sizeof(create_session_request_t),
							RTE_CACHE_LINE_SIZE, rte_socket_id());

		memcpy(tmp_csr, csr, sizeof(create_session_request_t));

		upf_context->pending_csr[upf_context->csr_cnt] = (uint32_t *)tmp_csr;
		upf_context->csr_cnt++;

		return 0;

	} else if(upf_context->assoc_status == ASSOC_ESTABLISHED) {
		upf_ipv4->s_addr = upf_ip;
		memcpy(sgwu_fqdn, sgwu_fqdn_res, strlen(sgwu_fqdn_res));

		return ASSOC_ESTABLISHED;
	}


	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);

	uint8_t pfcp_msg[256] = {0};
	int encoded = encode_pfcp_assn_setup_req_t(&pfcp_ass_setup_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

#ifdef USE_DNS_QUERY
	upf_pfcp_sockaddr.sin_addr.s_addr = upf_ip;
#endif /* USE_DNS_QUERY */

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ) {
		printf("Error sending\n\n");
	}else {
		cp_stats.association_setup_req_sent++;
	}

	return 0;
}

void
fill_pfcp_node_report_req(pfcp_node_rpt_req_t *pfcp_node_rep_req)
{
	uint32_t seq  = 1;
	char node_addr[INET_ADDRSTRLEN] = {0} ;
	memset(pfcp_node_rep_req, 0, sizeof(pfcp_node_rpt_req_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_node_rep_req->header),
			PFCP_NODE_REPORT_REQUEST, NO_SEID, seq);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), node_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_node_rep_req->node_id), node_value);

	set_node_report_type(&(pfcp_node_rep_req->node_rpt_type));

	set_user_plane_path_failure_report(&(pfcp_node_rep_req->user_plane_path_fail_rpt));
}

void
fill_pfcp_sess_report_resp(pfcp_sess_rpt_rsp_t *pfcp_sess_rep_resp,
		 uint32_t seq)
{
	memset(pfcp_sess_rep_resp, 0, sizeof(pfcp_sess_rpt_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_resp->header),
		PFCP_SESSION_REPORT_RESPONSE, HAS_SEID, seq);

	set_cause(&(pfcp_sess_rep_resp->cause), REQUESTACCEPTED);

	//pfcp_sess_rep_resp->header.message_len = pfcp_sess_rep_resp->cause.header.len + 4;

	//pfcp_sess_rep_resp->header.message_len += sizeof(pfcp_sess_rep_resp->header.seid_seqno.has_seid);
}
#endif /* CP_BUILD */

#ifdef DP_BUILD
void
fill_pfcp_association_release_resp(pfcp_assn_rel_rsp_t *pfcp_ass_rel_resp)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_rel_resp, 0, sizeof(pfcp_assn_rel_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_rel_resp->header),
			PFCP_ASSOCIATION_RELEASE_RESPONSE, NO_SEID, seq);

	//TODO filling of node id
	const char* pAddr = "192.168.0.10";
	uint32_t node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_rel_resp->node_id), node_value);

	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_ass_rel_resp->cause), REQUESTACCEPTED);

}

void
fill_pfcp_association_setup_resp(pfcp_assn_setup_rsp_t *pfcp_ass_setup_resp,
				uint8_t cause )
{
	uint32_t seq  = 1;
	uint32_t node_value = 0;

	memset(pfcp_ass_setup_resp,0,sizeof(pfcp_assn_setup_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_resp->header),
			PFCP_ASSOCIATION_SETUP_RESPONSE, NO_SEID, seq);

	set_node_id(&(pfcp_ass_setup_resp->node_id), node_value);

	set_cause(&(pfcp_ass_setup_resp->cause), cause);

	set_recovery_time_stamp(&(pfcp_ass_setup_resp->rcvry_time_stmp));

	set_upf_features(&(pfcp_ass_setup_resp->up_func_feat));

	if( app.spgw_cfg == SGWU )
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count = 2; /*for s1u and s5s8 sgwc ips*/
	else if ( app.spgw_cfg == PGWU || app.spgw_cfg == SAEGWU  )
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count = 1; /*for s5s8 pgwc ip*/

	for( int i=0; i < pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count; i++ )
		set_up_ip_resource_info(&(pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i]),i);

	pfcp_ass_setup_resp->header.message_len =pfcp_ass_setup_resp->node_id.header.len +
		pfcp_ass_setup_resp->rcvry_time_stmp.header.len +
		pfcp_ass_setup_resp->cause.header.len +
		pfcp_ass_setup_resp->up_func_feat.header.len +
		pfcp_ass_setup_resp->cp_func_feat.header.len ;

	pfcp_ass_setup_resp->header.message_len += sizeof(pfcp_ass_setup_resp->header.seid_seqno.no_seid);

}

void
fill_pfcp_association_update_resp(pfcp_assn_upd_rsp_t *pfcp_asso_update_resp)
{
	uint32_t seq  = 1;
	uint32_t node_value = 0;

	memset(pfcp_asso_update_resp, 0, sizeof(pfcp_assn_upd_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_asso_update_resp->header),
			PFCP_ASSOCIATION_UPDATE_RESPONSE, NO_SEID, seq);

	set_node_id(&(pfcp_asso_update_resp->node_id),node_value);

	// filling of cause
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_asso_update_resp->cause), REQUESTACCEPTED);

	set_upf_features(&(pfcp_asso_update_resp->up_func_feat));

}

void
fill_pfcp_node_report_resp(pfcp_node_rpt_rsp_t *pfcp_node_rep_resp)
{
	uint32_t seq  = 1;
	uint32_t node_value = 0;

	memset(pfcp_node_rep_resp, 0, sizeof(pfcp_node_rpt_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_node_rep_resp->header),
			PFCP_NODE_REPORT_RESPONSE, NO_SEID,seq);

	set_node_id(&(pfcp_node_rep_resp->node_id), node_value);

	//set cause
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_node_rep_resp->cause), REQUESTACCEPTED);

	//set offending ie
	//TODO: Remove NODE_ID with actual offend ID
	set_offending_ie(&(pfcp_node_rep_resp->offending_ie), PFCP_IE_NODE_ID);

}

static void
set_dndl_data_srv_if_ie(pfcp_dnlnk_data_svc_info_ie_t *dl)
{

	pfcp_set_ie_header(&(dl->header), PFCP_IE_DNLNK_DATA_SVC_INFO, 3);

	dl->ppi = 0;
	dl->qfi = 0;
	dl->qfii = 0;
	dl->paging_plcy_indctn_val = 0;
	dl->dnlnk_data_svc_info_spare = 0;
	dl->dnlnk_data_svc_info_spare2 = 0;
	dl->dnlnk_data_svc_info_spare3 = 0;
}
static void
set_dldr_ie(pfcp_dnlnk_data_rpt_ie_t *dl)
{
	dl->pdr_id_count = 1;
	pfcp_set_ie_header(&(dl->header), IE_DNLNK_DATA_RPT, 13);
			/*((sizeof(pfcp_dnlnk_data_rpt_ie_t) - ((MAX_LIST_SIZE - dl->pdr_id_count) * sizeof(dl->pdr_id) - 5))));*/

	set_pdr_id(dl->pdr_id);
	set_dndl_data_srv_if_ie(&dl->dnlnk_data_svc_info);

}

static void
set_sess_report_type(pfcp_report_type_ie_t *rt)
{
	pfcp_set_ie_header(&(rt->header), PFCP_IE_REPORT_TYPE, UINT8_SIZE);
	rt->rpt_type_spare = 0;
	rt->upir  = 0;
	rt->erir  = 0;
	rt->usar  = 0;
	rt->dldr  = 1;
}

static void
fill_pfcp_sess_rep_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req,
							uint64_t sess_id)
{
	static uint32_t seq = 0;

	memset(pfcp_sess_rep_req, 0, sizeof(pfcp_sess_rpt_req_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_req->header),
		PFCP_SESSION_REPORT_REQUEST, HAS_SEID, ++seq);

	pfcp_sess_rep_req->header.seid_seqno.has_seid.seid = sess_id;

	set_sess_report_type(&pfcp_sess_rep_req->report_type);

	/* VS: TODO Need to Implement handling of other IE's when Rules implementation is done  */
	if (pfcp_sess_rep_req->report_type.dldr == 1)
		set_dldr_ie(&pfcp_sess_rep_req->dnlnk_data_rpt);

	pfcp_sess_rep_req->header.message_len = pfcp_sess_rep_req->report_type.header.len +
		pfcp_sess_rep_req->dnlnk_data_rpt.header.len + 8;
}

uint8_t
process_pfcp_session_report_req(struct sockaddr_in *peer_addr,
			struct dp_session_info *sess)
{
	int encoded = 0;
	uint8_t pfcp_msg[250]={0};

	pfcp_sess_rpt_req_t pfcp_sess_rep_req = {0};

	fill_pfcp_sess_rep_req(&pfcp_sess_rep_req, sess->sess_id);

	encoded = encode_pfcp_sess_rpt_req_t(&pfcp_sess_rep_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
			RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
			return -1;
	}

	return 0;
}
#endif /* DP_BUILD */

void
fill_pfcp_heartbeat_req(pfcp_hrtbeat_req_t *pfcp_heartbeat_req, uint32_t seq)
{

	memset(pfcp_heartbeat_req, 0, sizeof(pfcp_hrtbeat_req_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_req->header),
			PFCP_HEARTBEAT_REQUEST,	NO_SEID, seq);

	set_recovery_time_stamp(&(pfcp_heartbeat_req->rcvry_time_stmp));
	seq++;
}
void
fill_pfcp_heartbeat_resp(pfcp_hrtbeat_rsp_t *pfcp_heartbeat_resp)
{

	uint32_t seq  = 1;
	memset(pfcp_heartbeat_resp, 0, sizeof(pfcp_hrtbeat_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_resp->header),
			PFCP_HEARTBEAT_RESPONSE, NO_SEID, seq);

	set_recovery_time_stamp(&(pfcp_heartbeat_resp->rcvry_time_stmp));
}

int process_pfcp_heartbeat_req(struct sockaddr_in *peer_addr, uint32_t seq)
{
	uint8_t pfcp_msg[250]={0};
	int encoded = 0;

	pfcp_hrtbeat_req_t pfcp_heartbeat_req  = {0};
	pfcp_hrtbeat_rsp_t *pfcp_hearbeat_resp =
						malloc(sizeof(pfcp_hrtbeat_rsp_t));

	memset(pfcp_hearbeat_resp,0,sizeof(pfcp_hrtbeat_rsp_t));
	fill_pfcp_heartbeat_req(&pfcp_heartbeat_req, seq);

	encoded = encode_pfcp_hrtbeat_req_t(&pfcp_heartbeat_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

#ifdef CP_BUILD
	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
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
