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

#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

#ifdef CP_BUILD
#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "gtpv2c_error_rsp.h"
#else
#include "up_main.h"
#endif /* CP_BUILD */

#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
#include "sm_pcnd.h"
#include "cdnsutil.h"
#endif /* CP_BUILD && USE_DNS_QUERY */

#ifdef DP_BUILD
struct in_addr cp_comm_ip;
uint16_t cp_comm_port;
#endif /* DP_BUILD */

#ifdef CP_BUILD
extern int pfcp_fd;
extern pfcp_config_t pfcp_config;

uint32_t *g_gx_pending_csr[BUFFERED_ENTRIES_DEFAULT];
uint32_t g_gx_pending_csr_cnt = 0;

void
fill_pfcp_association_release_req(pfcp_assn_rel_req_t *pfcp_ass_rel_req)
{
	uint32_t seq  = 1;
	memset(pfcp_ass_rel_req, 0, sizeof(pfcp_assn_rel_req_t)) ;

	/*filing of pfcp header*/
	seq = get_pfcp_sequence_number(PFCP_ASSOCIATION_RELEASE_REQUEST, seq);
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

	seq = get_pfcp_sequence_number(PFCP_ASSOCIATION_UPDATE_REQUEST, seq);
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

	seq = get_pfcp_sequence_number(PFCP_ASSOCIATION_SETUP_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_req->header),
			PFCP_ASSOCIATION_SETUP_REQUEST, NO_SEID, seq);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), node_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_ass_setup_req->node_id), node_value);

	set_recovery_time_stamp(&(pfcp_ass_setup_req->rcvry_time_stmp));

	/* As we are not supporting this feature
	set_cpf_features(&(pfcp_ass_setup_req->cp_func_feat)); */
}

/* Fill pfd mgmt cstm ie */
uint16_t
set_pfd_contents(pfcp_pfd_contents_ie_t *pfd_conts, struct msgbuf *cstm_buf)
{
	pfd_conts->pfd_contents_spare = 0;
	pfd_conts->pfd_contents_cp = 1;
	/*pfd_conts->dn = 0;
	pfd_conts->url = 0;
	pfd_conts->fd = 0;
	pfd_conts->pfd_contents_spare2 = 0x00;*/

	if(pfd_conts->fd != 0){
		pfd_conts->len_of_flow_desc = 0;
		pfd_conts->flow_desc = 0;
	}

	if(pfd_conts->url != 0){
		pfd_conts->length_of_url = 0;
		pfd_conts->url2 = 0;
	}

	if(pfd_conts->dn != 0){
		pfd_conts->len_of_domain_nm = 0;
		pfd_conts->domain_name = 0;
	}

	if(pfd_conts->pfd_contents_cp != 0){
		uint16_t struct_len = 0;
		switch (cstm_buf->mtype) {
			case MSG_SDF_CRE:
			case MSG_ADC_TBL_CRE:
			case MSG_PCC_TBL_CRE:
			case MSG_SESS_TBL_CRE:
			case MSG_MTR_CRE:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct cb_args_table));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt, "%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt+struct_len, (uint8_t *)&cstm_buf->msg_union.msg_table,
														sizeof(cstm_buf->msg_union.msg_table));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(cstm_buf->msg_union.msg_table) + struct_len;
				break;

			case MSG_EXP_CDR:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct msg_ue_cdr));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.ue_cdr, sizeof(struct msg_ue_cdr));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct msg_ue_cdr) + struct_len;
				break;
			case MSG_SDF_DES:
			case MSG_ADC_TBL_DES:
			case MSG_PCC_TBL_DES:
			case MSG_SESS_TBL_DES:
			case MSG_MTR_DES:
				break;
			case MSG_SDF_ADD:
			case MSG_SDF_DEL:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct pkt_filter));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
													"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.pkt_filter_entry, sizeof(struct pkt_filter));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct pkt_filter)+struct_len;
				break;
			case MSG_ADC_TBL_ADD:
			case MSG_ADC_TBL_DEL:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct adc_rules));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.adc_filter_entry, sizeof(struct adc_rules));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct adc_rules)+ struct_len;
				break;
			case MSG_PCC_TBL_ADD:
			case MSG_PCC_TBL_DEL:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct pcc_rules));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.pcc_entry, sizeof(struct pcc_rules));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct pcc_rules) + struct_len;
				break;
			case MSG_SESS_CRE:
			case MSG_SESS_MOD:
			case MSG_SESS_DEL:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct session_info));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.sess_entry, sizeof(struct session_info));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct session_info) + struct_len;
				break;
			case MSG_MTR_ADD:
			case MSG_MTR_DEL:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct mtr_entry));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
													"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len ,
					  (uint8_t *)&cstm_buf->msg_union.mtr_entry, sizeof(struct mtr_entry));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct mtr_entry) + struct_len;
				break;
			case MSG_DDN_ACK:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct downlink_data_notification));
				/* Fill msg type */
				struct_len = sprintf((char *)pfd_conts->cstm_pfd_cntnt,
																"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len ,
			          (uint8_t *)&cstm_buf->msg_union.mtr_entry, sizeof(struct downlink_data_notification));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct downlink_data_notification) + struct_len;
				break;
			default:
				clLog(apilogger, eCLSeverityCritical, "build_dp_msg: Invalid msg type\n");
				break;
		}
	}
	/* set pfd contents header */
	pfcp_set_ie_header(&pfd_conts->header, PFCP_IE_PFD_CONTENTS,
			(pfd_conts->len_of_cstm_pfd_cntnt + 3));
	return (pfd_conts->len_of_cstm_pfd_cntnt + 3);
}

/* Fill pfd context */
static void
set_pfd_context(pfcp_pfd_context_ie_t *pfd_conxt)
{

	pfcp_set_ie_header(&pfd_conxt->header, IE_PFD_CONTEXT,
			(pfd_conxt->pfd_contents[0].header.len + sizeof(pfcp_ie_header_t)));
	pfd_conxt->pfd_contents_count = 1;

}

/* FIll pfd Application id  */
static void
set_pfd_application_id(pfcp_application_id_ie_t *app_id)
{
	//REVIEW: Remove this hardcoded value
	pfcp_set_ie_header(&app_id->header, PFCP_IE_APPLICATION_ID, 8);
	memcpy(app_id->app_ident, "_app_1  ", 8);

}

/* Fill pfd app id and pfd context */
static void
set_app_ids_pfds(pfcp_app_ids_pfds_ie_t *app_ids_pfds_t , uint16_t len)
{
	/* Fill app id */
	set_pfd_application_id(&app_ids_pfds_t->application_id);
	app_ids_pfds_t->pfd_context_count = 1;

	/* Fill pfd context */
	for(int i = 0; i < app_ids_pfds_t->pfd_context_count; ++i){
		set_pfd_context(&app_ids_pfds_t->pfd_context[i]);
		len = app_ids_pfds_t->pfd_context[i].header.len
			+ app_ids_pfds_t->application_id.header.len
			+ sizeof(pfcp_ie_header_t)
			+ sizeof(pfcp_ie_header_t);
	}
	/* set app id pfds header  */
	pfcp_set_ie_header(&app_ids_pfds_t->header, IE_APP_IDS_PFDS, len);
}


void
fill_pfcp_pfd_mgmt_req(pfcp_pfd_mgmt_req_t *pfcp_pfd_req, uint16_t len)
{

	uint32_t seq  = 0;
	seq = get_pfcp_sequence_number(PFCP_PFD_MGMT_REQ, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_pfd_req->header),
			PFCP_PFD_MGMT_REQ, NO_SEID, seq);
	pfcp_pfd_req->app_ids_pfds_count = 1;

	for(int i=0; i < pfcp_pfd_req->app_ids_pfds_count; ++i){
		set_app_ids_pfds(&pfcp_pfd_req->app_ids_pfds[i], len);
	}
}


int
buffer_csr_request(ue_context *context,
		upf_context_t *upf_context, uint8_t ebi)
{
	context_key *key =
					rte_zmalloc_socket(NULL, sizeof(context_key),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

	key->teid = context->s11_sgw_gtpc_teid;
	key->ebi_index = ebi;

	upf_context->pending_csr_teid[upf_context->csr_cnt] = (uint32_t *)key;
	upf_context->csr_cnt++;

	return 0;

}

#ifdef USE_DNS_QUERY
int
get_upf_ip(ue_context *ctxt, upfs_dnsres_t **_entry,
		uint32_t **upf_ip)
{
	upfs_dnsres_t *entry = NULL;

	if (upflist_by_ue_hash_entry_lookup(&ctxt->imsi,
			sizeof(ctxt->imsi), &entry) != 0)
		return -1;

	if (entry->current_upf > entry->upf_count) {
		/* TODO: Add error log : Tried sending
		 * association request to all upf.*/
		/* Remove entry from hash ?? */
		return -1;
	}

	*upf_ip = &(entry->upf_ip[entry->current_upf].s_addr);
	*_entry = entry;
	return 0;
}
#endif /* USE_DNS_QUERY */

static int
assoication_setup_request(ue_context *context, uint8_t ebi_index)
{
	int ret = 0;
	uint32_t upf_ip = 0;
	upf_context_t *upf_context = NULL;
	EInterfaceType it;
	//char sgwu_fqdn_res[MAX_HOSTNAME_LENGTH] = {0};
	pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};

	upf_ip = (context->pdns[ebi_index])->upf_ipv4.s_addr;

	upf_context  = rte_zmalloc_socket(NULL, sizeof(upf_context_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (upf_context == NULL) {
		fprintf(stderr, "Failure to allocate upf context: "
				"%s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);

		return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
	}

	ret = upf_context_entry_add(&upf_ip, upf_context);
	if (ret) {
		RTE_LOG_DP(ERR, CP, "%s : Error: %d \n", __func__, ret);
		return -1;
	}


	ret = buffer_csr_request(context, upf_context, ebi_index);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return -1;
	}
	//memcpy(upf_context->fqdn, sgwu_fqdn_res, strlen(sgwu_fqdn_res));

	upf_context->assoc_status = ASSOC_IN_PROGRESS;
	upf_context->state = PFCP_ASSOC_REQ_SNT_STATE;


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

		/*CLI: idebtify interface*/
		if (pfcp_config.cp_type == SGWC)
		{
			it = itSxa;
		} else if (pfcp_config.cp_type == PGWC)
		{
			it = itSxb;
		} else {
			it = itSxaSxb;
		}

		/*CLI:add entry for SGWU when asstn setup req sent
		 *,but status is FALSE till resp rcvd*/
		add_cli_peer(upf_ip,it);
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(upf_ip,
				pfcp_ass_setup_req.header.message_type,
				REQ,cp_stats.stat_timestamp);
	}

	return 0;
}

int
process_pfcp_assoication_request(ue_context *context, uint8_t ebi_index)
{
	int ret = 0;
	struct in_addr upf_ipv4 = {0};
	upf_context_t *upf_context = NULL;

	if ((context->pdns[ebi_index])->upf_ipv4.s_addr == 0) {
#ifdef USE_DNS_QUERY
		uint32_t *upf_ip = NULL;
		upf_ip = &upf_ipv4.s_addr;

		/* VS: Select the UPF based on DNS */
		ret = dns_query_lookup(context, ebi_index, &upf_ip);
		if (ret) {
			clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Error: %d \n",
					__file__, __func__, __LINE__, ret);
			return ret;
		}

		(context->pdns[ebi_index])->upf_ipv4.s_addr = *upf_ip;
		/* Need to think on it*/
		upf_ipv4.s_addr = *upf_ip;
#else
		(context->pdns[ebi_index])->upf_ipv4 = pfcp_config.upf_pfcp_ip;
		upf_ipv4 = pfcp_config.upf_pfcp_ip;
#endif /* USE_DNS_QUERY */

	}

	/* VS: Retrive association state based on UPF IP. */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(upf_ipv4.s_addr), (void **) &(upf_context));
	if (ret >= 0) {
		if (upf_context->state == PFCP_ASSOC_RESP_RCVD_STATE) {
			ret = process_pfcp_sess_est_request(context->s11_sgw_gtpc_teid, ebi_index);
			if (ret) {
					clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
							__func__, __LINE__, ret);
					return ret;
			}
		} else {
			ret = buffer_csr_request(context, upf_context, ebi_index);
			if (ret) {
				clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
						__func__, __LINE__, ret);
				return -1;
			}
		}
	} else {
		ret = assoication_setup_request(context, ebi_index);
		if (ret) {
				clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
						__func__, __LINE__, ret);
				return ret;
		}
	}

	return 0;
}


void
fill_pfcp_node_report_req(pfcp_node_rpt_req_t *pfcp_node_rep_req)
{
	uint32_t seq  = 1;
	char node_addr[INET_ADDRSTRLEN] = {0} ;
	memset(pfcp_node_rep_req, 0, sizeof(pfcp_node_rpt_req_t)) ;

	seq = get_pfcp_sequence_number(PFCP_NODE_REPORT_REQUEST, seq);
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

uint8_t
process_pfcp_ass_resp(msg_info *msg, struct sockaddr_in *peer_addr)
{
	int ret = 0;
	upf_context_t *upf_context = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));

	if (ret < 0) {
		clLog(sxlogger, eCLSeverityDebug, "NO ENTRY FOUND IN UPF HASH [%u]\n",
				msg->upf_ipv4.s_addr);
		return 0;
	}

	upf_context->assoc_status = ASSOC_ESTABLISHED;
	upf_context->state = PFCP_ASSOC_RESP_RCVD_STATE;

	upf_context->up_supp_features =
			msg->pfcp_msg.pfcp_ass_resp.up_func_feat.sup_feat;

	switch (pfcp_config.cp_type)
	{
		case SGWC :
			if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].src_intfc ==
					SOURCE_INTERFACE_VALUE_ACCESS )
				upf_context->s1u_ip =
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].ipv4_address;

			if( msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].assosi == 1 &&
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].src_intfc ==
					SOURCE_INTERFACE_VALUE_CORE )
				upf_context->s5s8_sgwu_ip =
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].ipv4_address;
			break;

		case PGWC :
			if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].src_intfc ==
					SOURCE_INTERFACE_VALUE_ACCESS )
				upf_context->s5s8_pgwu_ip =
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].ipv4_address;
			break;

		case SAEGWC :
			if( msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].src_intfc ==
					SOURCE_INTERFACE_VALUE_ACCESS )
				upf_context->s1u_ip =
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].ipv4_address;
			break;

	}

	/* teid_range from first user plane ip IE is used since, for same CP ,
	 * DP will assigne single teid_range , So all IE's will have same value for teid_range*/
	/* Change teid base address here */
	if(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teidri != 0){
		set_base_teid(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range);
	}

	for (uint8_t i = 0; i < upf_context->csr_cnt; i++) {

		context_key *key = (context_key *)upf_context->pending_csr_teid[i];

		ret = process_pfcp_sess_est_request(key->teid, key->ebi_index);
		if (ret) {
				clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
#ifdef CP_BUILD
					if(ret != -1) {
						cs_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
						process_error_occured_handler(&msg, NULL);
					}
#endif /* CP_BUILD */
		}

		rte_free(upf_context->pending_csr[i]);
		rte_free(upf_context->pending_csr_teid[i]);
		upf_context->csr_cnt--;
	}

	/* Adding ip to cp  heartbeat when dp returns the association response*/
	add_ip_to_heartbeat_hash(peer_addr,
			msg->pfcp_msg.pfcp_ass_resp.rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST
	if ((add_node_conn_entry((uint32_t)peer_addr->sin_addr.s_addr,
					SX_PORT_ID)) != 0) {

		RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGWU/SAEGWU");
	}

#endif/* USE_REST */
	return 0;

}

uint8_t
process_pfcp_report_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req)
{

	/*DDN Handling */
	uint8_t ebi_index;
	int ret = 0, encoded = 0;
	ue_context *context = NULL;
	uint8_t pfcp_msg[250] = {0};
	struct resp_info *resp = NULL;
	pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};
	uint64_t sess_id = pfcp_sess_rep_req->header.seid_seqno.has_seid.seid;

	uint32_t sequence = 0;
	uint32_t s11_sgw_gtpc_teid = UE_SESS_ID(sess_id);

	/* Stored the session information*/
	if (get_sess_entry(sess_id, &resp) != 0) {
		fprintf(stderr, "Failed to add response in entry in SM_HASH\n");
		return -1;
	}

	/* Retrive the s11 sgwc gtpc teid based on session id.*/
	sequence = pfcp_sess_rep_req->header.seid_seqno.has_seid.seq_no;
	resp->msg_type = PFCP_SESSION_REPORT_REQUEST;

	clLog(sxlogger, eCLSeverityDebug, "DDN Request recv from DP for sess:%lu\n", sess_id);

	if (pfcp_sess_rep_req->report_type.dldr == 1) {
		ret = ddn_by_session_id(sess_id);
		if (ret) {
			fprintf(stderr, "DDN %s: (%d) \n", __func__, ret);
			return -1;
		}
		/* Update the Session state */
		resp->state = DDN_REQ_SNT_STATE;
	}

	/* Update the UE State */
	ret = update_ue_state(s11_sgw_gtpc_teid,
			DDN_REQ_SNT_STATE);
	if (ret < 0) {
		fprintf(stderr, "%s:Failed to update UE State for teid: %u\n", __func__,
				s11_sgw_gtpc_teid);
	}

	/* Retrieve the UE context */
	ret = get_ue_context(s11_sgw_gtpc_teid, &context);
	if (ret < 0) {
			fprintf(stderr, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					s11_sgw_gtpc_teid);
	}
	context->state = DDN_REQ_SNT_STATE;

	/*Fill and send pfcp session report response. */
	fill_pfcp_sess_report_resp(&pfcp_sess_rep_resp,
			sequence);
	ebi_index = resp->eps_bearer_id;

	pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid = context->pdns[ebi_index - 5]->dp_seid;

	encoded =  encode_pfcp_sess_rpt_rsp_t(&pfcp_sess_rep_resp, pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - 4);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ) {
		clLog(sxlogger, eCLSeverityCritical, "Error REPORT REPONSE message: %i\n", errno);
		return -1;
	}
	else {
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_rep_resp.header.message_type,ACC,
							cp_stats.stat_timestamp);
	}

	return 0;
}

#endif /* CP_BUILD */

#ifdef DP_BUILD
void
fill_pfcp_association_release_resp(pfcp_assn_rel_rsp_t *pfcp_ass_rel_resp)
{
	/*take seq no from assoc release request when it is implemented*/
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

	/* As we are not supporting this feature
	set_upf_features(&(pfcp_ass_setup_resp->up_func_feat)); */

	if (app.spgw_cfg == SGWU) {
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count = 2; /*for s1u and s5s8 sgwc ips*/
		/*UPF Features IE is added for the ENDMARKER feauture which is supported in SGWU only*/
		set_upf_features(&(pfcp_ass_setup_resp->up_func_feat));
		pfcp_ass_setup_resp->up_func_feat.sup_feat |=  EMPU ;
		pfcp_ass_setup_resp->header.message_len += pfcp_ass_setup_resp->up_func_feat.header.len;


	} else if ((app.spgw_cfg == PGWU) || (app.spgw_cfg == SAEGWU)) {
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count = 1; /*for s5s8 pgwc ip*/
	}

	for( int i=0; i < pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count; i++ ){
		set_up_ip_resource_info(&(pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i]),i);
		/* Copy same teid_range in all user plane IP rsrc IEs */
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i].teidri =
					pfcp_ass_setup_resp->user_plane_ip_rsrc_info[0].teidri;
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i].teid_range =
					pfcp_ass_setup_resp->user_plane_ip_rsrc_info[0].teid_range;
		 pfcp_ass_setup_resp->header.message_len +=
			        pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i].header.len;
	}

	pfcp_ass_setup_resp->header.message_len = pfcp_ass_setup_resp->node_id.header.len +
		pfcp_ass_setup_resp->rcvry_time_stmp.header.len +
		pfcp_ass_setup_resp->cause.header.len;


	pfcp_ass_setup_resp->header.message_len += sizeof(pfcp_ass_setup_resp->header.seid_seqno.no_seid);

}

/* Fill pfd mgmt response */
void
fill_pfcp_pfd_mgmt_resp(pfcp_pfd_mgmt_rsp_t *pfd_resp, uint8_t cause_val, int offending_id)
{
	memset(pfd_resp, 0, sizeof(pfcp_pfd_mgmt_rsp_t));

	set_pfcp_header(&pfd_resp->header, PFCP_PFD_MGMT_RSP, 0);

	pfcp_set_ie_header(&pfd_resp->cause.header, PFCP_IE_CAUSE,
			sizeof(pfd_resp->cause.cause_value));
	pfd_resp->cause.cause_value = cause_val;

	pfcp_set_ie_header(&pfd_resp->offending_ie.header, PFCP_IE_OFFENDING_IE,
			sizeof(pfd_resp->offending_ie.type_of_the_offending_ie));
	pfd_resp->offending_ie.type_of_the_offending_ie = (uint16_t)offending_id;
}

void
fill_pfcp_association_update_resp(pfcp_assn_upd_rsp_t *pfcp_asso_update_resp)
{
	/*take seq no from assoc update request when it is implemented*/
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
	/*take seq no from node report request when it is implemented*/
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
				clLog(sxlogger, eCLSeverityDebug, "Error sending: %i\n", errno);
	}
#endif

#ifdef DP_BUILD
	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
					RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
	}
#endif

	return 0;

}
