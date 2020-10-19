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
#include "clogger.h"
#include "teid_upf.h"
#ifdef CP_BUILD
#include "teid.h"
#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "gtpv2c_error_rsp.h"
#include "cp_timer.h"
#include "cdr.h"
#else
#include "up_main.h"
#include "gw_adapter.h"
#endif /* CP_BUILD */

#ifdef CP_BUILD
#include "sm_pcnd.h"
#include "cdnsutil.h"
#endif /* CP_BUILD*/

#ifdef DP_BUILD
struct in_addr cp_comm_ip;
uint16_t cp_comm_port;
#endif /* DP_BUILD */

extern bool assoc_available;

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
			PFCP_ASSOCIATION_RELEASE_REQUEST, NO_SEID, seq, NO_CP_MODE_REQUIRED);
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
			 PFCP_ASSOCIATION_UPDATE_REQUEST, NO_SEID, seq, NO_CP_MODE_REQUIRED);

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
			PFCP_ASSOCIATION_SETUP_REQUEST, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), node_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_ass_setup_req->node_id), node_value);

	set_recovery_time_stamp(&(pfcp_ass_setup_req->rcvry_time_stmp));

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
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN, "%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt+struct_len, (uint8_t *)&cstm_buf->msg_union.msg_table,
														sizeof(cstm_buf->msg_union.msg_table));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(cstm_buf->msg_union.msg_table) + struct_len;
				break;

			case MSG_EXP_CDR:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct msg_ue_cdr));
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
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
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
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
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
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
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
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
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
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
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
													"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len ,
					  (uint8_t *)&cstm_buf->msg_union.mtr_entry, sizeof(struct mtr_entry));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct mtr_entry) + struct_len;
				break;
			case MSG_DDN_ACK:
				pfd_conts->cstm_pfd_cntnt = malloc(sizeof(struct downlink_data_notification));
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->cstm_pfd_cntnt, MAX_LEN,
																"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->cstm_pfd_cntnt + struct_len ,
			          (uint8_t *)&cstm_buf->msg_union.mtr_entry, sizeof(struct downlink_data_notification));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct downlink_data_notification) + struct_len;
				break;
			default:
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid msg type "
					"while Set PFD MGMT contents\n", LOG_VALUE);
				break;
		}
	}
	/* set pfd contents header */
	pfcp_set_ie_header(&pfd_conts->header, PFCP_IE_PFD_CONTENTS,
			(pfd_conts->len_of_cstm_pfd_cntnt + 3));
	return (pfd_conts->len_of_cstm_pfd_cntnt + 3);
}

/**
 * @brief  : This function fills in values to pfd context ie
 * @param  : pfd_contxt is pointer to structure of pfd context ie
 * @return : This function dose not return anything
 */
static void
set_pfd_context(pfcp_pfd_context_ie_t *pfd_conxt)
{

	pfcp_set_ie_header(&pfd_conxt->header, IE_PFD_CONTEXT,
			(pfd_conxt->pfd_contents[0].header.len + sizeof(pfcp_ie_header_t)));
	pfd_conxt->pfd_contents_count = 1;

}

/**
 * @brief  : This function fills in values to pfd application id ie
 * @param  : app_id is pointer to structure of pfd application id ie
 * @return : This function dose not return anything
 */
static void
set_pfd_application_id(pfcp_application_id_ie_t *app_id)
{
	//REVIEW: Remove this hardcoded value
	pfcp_set_ie_header(&app_id->header, PFCP_IE_APPLICATION_ID, PFCP_APPLICATION_ID_LEN);
	memcpy(app_id->app_ident, "app_1", PFCP_APPLICATION_ID_LEN);

}

/**
 * @brief  : This function fills pfd app id and pfd context
 * @param  : app_id_pfds_t is pointer to structure of  ie
 * @param  : len denotes total length of ie
 * @return : This function dose not return anything
 */
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
			PFCP_PFD_MGMT_REQ, NO_SEID, seq, NO_CP_MODE_REQUIRED);
	pfcp_pfd_req->app_ids_pfds_count = 1;

	for(int i=0; i < pfcp_pfd_req->app_ids_pfds_count; ++i){
		set_app_ids_pfds(&pfcp_pfd_req->app_ids_pfds[i], len);
	}
}


int
buffer_csr_request(ue_context *context,
		upf_context_t *upf_context, uint8_t ebi_index)
{
	context_key *key =
					rte_zmalloc_socket(NULL, sizeof(context_key),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

	key->teid = context->s11_sgw_gtpc_teid;
	key->sender_teid = context->s11_mme_gtpc_teid;
	key->sequence = context->sequence;
	key->ebi_index = ebi_index;
	key->imsi = context->imsi;

	for(uint8_t i = 0; i< MAX_BEARERS; i++){
		if(context->eps_bearers[i] != NULL)
			key->bearer_ids[i] = context->eps_bearers[i]->eps_bearer_id;
	}

	upf_context->pending_csr_teid[upf_context->csr_cnt] = (uint32_t *)key;
	upf_context->csr_cnt++;

	return 0;

}

int
get_upf_ip(ue_context *ctxt, upfs_dnsres_t **_entry,
		uint32_t *upf_ip)
{
	if(pfcp_config.use_dns){
		upfs_dnsres_t *entry = NULL;

		if (upflist_by_ue_hash_entry_lookup(&ctxt->imsi,
					sizeof(ctxt->imsi), &entry) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to extract UPF context by ue hash\n", LOG_VALUE);
			return -1;
		}

		if (entry->current_upf > entry->upf_count) {
			/* TODO: Add error log : Tried sending
			 * association request to all upf.*/
			/* Remove entry from hash ?? */
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Failure in sending association request to all upf\n", LOG_VALUE);
			return -1;
		}

		*upf_ip = entry->upf_ip[entry->current_upf].s_addr;
		*_entry = entry;
	}
	return 0;

}

/**
 * @brief  : This function creates association setup request and sends to peer
 * @param  : context holds information of ue
 * @param  : ebi_index denotes index of bearer stored in array
 * @return : This function dose not return anything
 */
static int
assoication_setup_request(pdn_connection *pdn, ue_context *context, int ebi_index)
{
	int ret = 0;
	uint32_t upf_ip = 0;
	upf_context_t *upf_context = NULL;

	pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};

	upf_ip = pdn->upf_ipv4.s_addr;
	upf_context  = rte_zmalloc_socket(NULL, sizeof(upf_context_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (upf_context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to allocate "
				"upf context: %s\n", LOG_VALUE, rte_strerror(rte_errno));
		return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
	}

	ret = upf_context_entry_add(&upf_ip, upf_context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure while adding "
			"upf context entry, Error: %d \n", LOG_VALUE, ret);
		return -1;
	}

	ret = buffer_csr_request(context, upf_context, ebi_index);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure while buffer "
			"Create Session Request, Error: %d \n",LOG_VALUE, ret);
		return -1;
	}

	upf_context->assoc_status = ASSOC_IN_PROGRESS;
	upf_context->state = PFCP_ASSOC_REQ_SNT_STATE;
	upf_context->cp_mode = context->cp_mode;

	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_assn_setup_req_t(&pfcp_ass_setup_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if(pfcp_config.use_dns)
		upf_pfcp_sockaddr.sin_addr.s_addr = upf_ip;

	/* fill and add timer entry */
	peerData *timer_entry = NULL;
	timer_entry =  fill_timer_entry_data(PFCP_IFACE, &upf_pfcp_sockaddr,
			pfcp_msg, encoded, pfcp_config.request_tries, context->s11_sgw_gtpc_teid, ebi_index);

	timer_entry->imsi = context->imsi;

	if(!(add_timer_entry(timer_entry, pfcp_config.request_timeout, association_timer_callback))) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Faild to add timer "
			"entry\n",LOG_VALUE);
	}

	upf_context->timer_entry = timer_entry;
	if (starttimer(&timer_entry->pt) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Periodic Timer "
				"failed to start\n",LOG_VALUE);
	}

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error sending PFCP "
			"Association Request\n", LOG_VALUE);

		/* Delete */
		stoptimer(&upf_context->timer_entry->pt.ti_id);
		deinittimer(&upf_context->timer_entry->pt.ti_id);
		/* free peer data when timer is de int */
		if(upf_context->timer_entry){
			rte_free(upf_context->timer_entry);
			upf_context->timer_entry = NULL;
		}
	}

	return 0;
}

int
process_pfcp_assoication_request(pdn_connection *pdn, int ebi_index)
{
	int ret = 0;
	struct in_addr upf_ipv4 = {0};
	upf_context_t *upf_context = NULL;

	/* Retrive UPF IPV4 address */
	upf_ipv4.s_addr = pdn->upf_ipv4.s_addr;

	/* Retrive association state based on UPF IP. */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(upf_ipv4.s_addr), (void **) &(upf_context));
	if (ret >= 0) {
		if (upf_context->state == PFCP_ASSOC_RESP_RCVD_STATE) {
			ret = process_pfcp_sess_est_request(pdn->context->s11_sgw_gtpc_teid,
							pdn, upf_context);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"\n "
					"Failed to process Session Eshtablishment Request, Error:%d \n",
					LOG_VALUE, ret);
				return ret;
			}
		} else {

			upf_context->cp_mode = pdn->context->cp_mode;
			ret = buffer_csr_request(pdn->context, upf_context, ebi_index);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"\n",
					"Failed to buffer Create Session Request, Error: %d ", LOG_VALUE, ret);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
		}
	} else {

		ret = assoication_setup_request(pdn, pdn->context, ebi_index);
		if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %d. ",
					"Could not process association process\n",LOG_VALUE, ret);
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
			PFCP_NODE_REPORT_REQUEST, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), node_addr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(node_addr);
	set_node_id(&(pfcp_node_rep_req->node_id), node_value);

	set_node_report_type(&(pfcp_node_rep_req->node_rpt_type));

	set_user_plane_path_failure_report(&(pfcp_node_rep_req->user_plane_path_fail_rpt));
}

void
fill_pfcp_sess_report_resp(pfcp_sess_rpt_rsp_t *pfcp_sess_rep_resp,
		 uint32_t seq, uint8_t cp_mode)
{
	memset(pfcp_sess_rep_resp, 0, sizeof(pfcp_sess_rpt_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_resp->header),
		PFCP_SESSION_REPORT_RESPONSE, HAS_SEID, seq, cp_mode);

	set_cause(&(pfcp_sess_rep_resp->cause), REQUESTACCEPTED);
}

/**
 * @brief  : This function fills the csr in resp structure
 * @param  : sess_id , session id.
 * @param  : key, pointer of context_key structure.
 * @return : returns 0 on success.
 */
int
fill_response(uint64_t sess_id, context_key *key)
{
	uint8_t index = 0;
	struct resp_info *resp = NULL;

	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session "
			"Entry Found for sess ID:%lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* stored csr for error response */
	resp->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = key->sender_teid;
	resp->gtpc_msg.csr.header.teid.has_teid.teid = key->teid;
	resp->gtpc_msg.csr.header.teid.has_teid.seq = key->sequence;
	resp->gtpc_msg.csr.imsi.imsi_number_digits = key->imsi;

	/* Maintain the ebi ids  per session object*/
	for (uint8_t itr = 0; itr < MAX_BEARERS; ++itr) {
		if(key->bearer_ids[itr] != 0){
			resp->gtpc_msg.csr.bearer_contexts_to_be_created[index].header.len =
				sizeof(uint8_t) + IE_HEADER_SIZE;
			resp->gtpc_msg.csr.bearer_contexts_to_be_created[index].eps_bearer_id.ebi_ebi =
				key->bearer_ids[itr];
			index++;
		}
	}
	/* Update the maximum bearer count value */
	resp->gtpc_msg.csr.bearer_count = index;
	return 0;
}

uint8_t
process_pfcp_ass_resp(msg_info *msg, struct sockaddr_in *peer_addr)
{
	int ret = 0;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_context = NULL;
	ue_context *context = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NO ENTRY FOUND IN UPF HASH [%u]\n",
			LOG_VALUE, msg->upf_ipv4.s_addr);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	msg->cp_mode = upf_context->cp_mode;
	upf_context->assoc_status = ASSOC_ESTABLISHED;
	upf_context->state = PFCP_ASSOC_RESP_RCVD_STATE;

	upf_context->up_supp_features =
			msg->pfcp_msg.pfcp_ass_resp.up_func_feat.sup_feat;

	/* TODO: Remove Hardcoded values */
	/* WB/S1U, WB/S5S8_Logical, EB/S5S8 Interface*/
	if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info_count == 3) {
		/* WB/S1U Interface */
		if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].src_intfc ==
				SOURCE_INTERFACE_VALUE_ACCESS ) {
			upf_context->s1u_ip =
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].ipv4_address;
		}

		/* Logical Interface of the S5S8 PGWU */
		if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].assosi == 1 &&
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].src_intfc ==
				SOURCE_INTERFACE_VALUE_ACCESS ) {
			upf_context->s5s8_pgwu_ip =
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].ipv4_address;
		}

		/* EB/S5S8 Interface */
		if(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[2].assosi == 1 &&
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[2].src_intfc ==
				SOURCE_INTERFACE_VALUE_CORE ) {
			upf_context->s5s8_sgwu_ip =
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[2].ipv4_address;

		}
	} else if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info_count == 2) {
		/* WB/S1U Interface */
		if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].src_intfc ==
				SOURCE_INTERFACE_VALUE_ACCESS ) {
			upf_context->s1u_ip =
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].ipv4_address;
			upf_context->s5s8_pgwu_ip =
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].ipv4_address;
		}

		/* EB/S5S8 Interface */
		if(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].assosi == 1 &&
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].src_intfc ==
				SOURCE_INTERFACE_VALUE_CORE ) {
			upf_context->s5s8_sgwu_ip =
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[1].ipv4_address;

		}
	}

	/* TODO: Make it generic this code */
	/* teid_range from first user plane ip IE is used since, for same CP ,
	 * DP will assigne single teid_range , So all IE's will have same value for teid_range*/
	/* Change teid base address here */
	if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teidri != 0) {
		upf_context->teidri = msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teidri;
		upf_context->teid_range = msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range;
	}else{
		upf_context->teidri = 0;
		upf_context->teid_range = 0;
	}

	uint32_t value = 0;
	memcpy(&value, &msg->pfcp_msg.pfcp_ass_resp.node_id.node_id_value_ipv4_address, IPV4_SIZE);

	uint32_t dp_ip =(ntohl(value));
	if (0 != set_base_teid(upf_context->teidri, upf_context->teid_range,
				dp_ip, &upf_teid_info_head)) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to set teid range for dp: %u\n", LOG_VALUE, dp_ip);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	int count  = 0;
	for (uint8_t i = 0; i < upf_context->csr_cnt; i++) {

		context_key *key = (context_key *)upf_context->pending_csr_teid[i];

		if (get_ue_context(key->teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"UE context not found "
				"for teid: %d\n", LOG_VALUE, key->teid);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		pdn = GET_PDN(context, key->ebi_index);
		if(pdn == NULL){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, key->ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		pdn->upf_ipv4.s_addr = upf_pfcp_sockaddr.sin_addr.s_addr;
		ret = process_pfcp_sess_est_request(key->teid, pdn, upf_context);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to process PFCP "
				"session eshtablishment request %d \n", LOG_VALUE, ret);

			fill_response(pdn->seid, key);

			return ret;
		}

		fill_response(pdn->seid, key);
		count++;
		rte_free(upf_context->pending_csr_teid[i]);
	}

	upf_context->csr_cnt = upf_context->csr_cnt - count;

	/* Adding ip to cp heartbeat when dp returns the association response*/
	add_ip_to_heartbeat_hash(peer_addr,
			msg->pfcp_msg.pfcp_ass_resp.rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST
	uint32_t ip_addr = peer_addr->sin_addr.s_addr;
	if (ip_addr != 0) {
		if ((add_node_conn_entry(ip_addr, SX_PORT_ID, upf_context->cp_mode)) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
				"connection entry for SGWU/SAEGWU\n", LOG_VALUE);
		}
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Added Connection entry "
			"for UPF:"IPV4_ADDR"\n",LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ip_addr));
	}
#endif/* USE_REST */
	return 0;

}

uint8_t
process_pfcp_report_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req)
{

	/*DDN Handling */
	int ret = 0, encoded = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint8_t pfcp_msg[250] = {0};
	struct resp_info *resp = NULL;
	pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};
	uint64_t sess_id = pfcp_sess_rep_req->header.seid_seqno.has_seid.seid;

	uint32_t sequence = 0;
	uint32_t s11_sgw_gtpc_teid = UE_SESS_ID(sess_id);
	int ebi = UE_BEAR_ID(sess_id);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
	   clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	   return -1;
	}

	/* Stored the session information*/
	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get response "
			"from session id\n", LOG_VALUE);
		return -1;
	}

	ret = get_ue_context(s11_sgw_gtpc_teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Context not found for "
			"report request\n", LOG_VALUE);
		return -1;
	}

	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to get pdn for ebi_index : %d \n", LOG_VALUE, ebi_index);
		return -1;
	}

	/* Retrive the s11 sgwc gtpc teid based on session id.*/
	sequence = pfcp_sess_rep_req->header.seid_seqno.has_seid.seq_no;
	resp->cp_mode = context->cp_mode;

	if (pfcp_sess_rep_req->report_type.dldr == 1) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DDN Request recv from DP for "
			"sess:%lu\n", LOG_VALUE, sess_id);

		ret = ddn_by_session_id(sess_id);

		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
			return -1;
		}

		resp->msg_type = PFCP_SESSION_REPORT_REQUEST;
		/* Update the Session state */
		resp->state = DDN_REQ_SNT_STATE;

		/* Update the UE State */
		ret = update_ue_state(context, DDN_REQ_SNT_STATE, ebi_index);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to update "
				"UE State for ebi_index : %d \n", LOG_VALUE, ebi_index);
		}

		pdn->state = DDN_REQ_SNT_STATE;
	}

	if (pfcp_sess_rep_req->report_type.usar == PRESENT) {
		for( int cnt = 0; cnt < pfcp_sess_rep_req->usage_report_count; cnt++ )
			fill_cdr_info_sess_rpt_req(sess_id, &pfcp_sess_rep_req->usage_report[cnt]);
	}

	/*Fill and send pfcp session report response. */
	fill_pfcp_sess_report_resp(&pfcp_sess_rep_resp,
			sequence, context->cp_mode);

	pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	encoded =  encode_pfcp_sess_rpt_rsp_t(&pfcp_sess_rep_resp, pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	/* UPF ip address  */
	upf_pfcp_sockaddr.sin_addr.s_addr = pdn->upf_ipv4.s_addr;
	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,ACC) < 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in REPORT REPONSE "
			"message: %i\n", LOG_VALUE, errno);
		return -1;
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
			PFCP_ASSOCIATION_RELEASE_RESPONSE, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	/* filling of node id */
	const char* pAddr = "192.168.0.10";
	uint32_t node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_ass_rel_resp->node_id), node_value);

	/* REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause */
	set_cause(&(pfcp_ass_rel_resp->cause), REQUESTACCEPTED);

}

void
fill_pfcp_association_setup_resp(pfcp_assn_setup_rsp_t *pfcp_ass_setup_resp,
				uint8_t cause, uint32_t peer_addr )
{
	int8_t teid_range = 0;
	uint8_t teidri_gen_flag = 0;
	uint32_t seq  = 1;
	uint32_t node_value = 0;

	memset(pfcp_ass_setup_resp, 0, sizeof(pfcp_assn_setup_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_resp->header),
			PFCP_ASSOCIATION_SETUP_RESPONSE, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	set_node_id(&(pfcp_ass_setup_resp->node_id), node_value);

	set_recovery_time_stamp(&(pfcp_ass_setup_resp->rcvry_time_stmp));

	/* As we are not supporting this feature
	set_upf_features(&(pfcp_ass_setup_resp->up_func_feat)); */

	if(app.teidri_val != 0){
		/* searching record for peer node into list of blocked teid_ranges */
		teidri_gen_flag =
			get_teidri_from_list((uint8_t *)&teid_range,
					peer_addr, &upf_teidri_blocked_list);

		if (teidri_gen_flag == 0) {
			/* Record not found in list of blocked teid_ranges
			 * searching record for peer node into list of allocated teid_ranges */

			teidri_gen_flag =
				get_teidri_from_list((uint8_t *)&teid_range, peer_addr,
						&upf_teidri_allocated_list);

			if (teidri_gen_flag == 0) {
				/* If node addr and teid range not found in allocated list, then
				 * - Assign teid range from free list
				 * - Remove record from free list
				 * - Add record to the allocated list
				 * - Add record in file
				 */
				teid_range = assign_teid_range(app.teidri_val, &upf_teidri_free_list);

				if(teid_range < 0){
					/* Failed to generate tied range, Reject association request */
					cause = NORESOURCESAVAILABLE;
				}else{
					if (add_teidri_node_entry(teid_range, peer_addr,
								TEIDRI_FILENAME, &upf_teidri_allocated_list,
								&upf_teidri_free_list) < 0) {
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"ERROR :Unable to write data into file"
								" for Node addr: %u : TEIDRI: %d \n", LOG_VALUE, peer_addr, teid_range);
					}
				}
			}
		}else{
			/* TEIDRI value found into list of blocked records */
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "TEIDRI value found into "
				"data node addr: %u : TEIDRI: %d \n", LOG_VALUE, peer_addr, teid_range);

			/* Assuming if peer node address and TEIDRI value find into file data, that's means DP Restarted */
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"PREVIOUS: DP Restart counter: %d\n", LOG_VALUE, dp_restart_cntr);

			update_dp_restart_cntr();

			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"UPDATED: DP Restart counter: %d \n ", LOG_VALUE, dp_restart_cntr);

			/* If node addr and teid range found in blocked list, then
			 * - Assign teid range from data found in blocked list
			 * - Remove record from blocked list
			 * - Add record to the allocated list
			 * - No need to update file, as record will be already present in file
			 */
			if (add_teidri_node_entry(teid_range, peer_addr, NULL, &upf_teidri_allocated_list,
						&upf_teidri_blocked_list) < 0) {
				clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"ERROR :Unable to write data into file"
						" for Node addr : %u : TEIDRI : %d \n", LOG_VALUE, peer_addr, teid_range);
			}
		}
	}else{
	    if(assoc_available == false){
			/* TEIDRI is 0. Only one CP can connect,
			 * Reject association request
			 */
			cause = NORESOURCESAVAILABLE;
		}else{
			assoc_available = false;
		}
	}

	set_cause(&(pfcp_ass_setup_resp->cause), cause);

	if (cause == REQUESTACCEPTED) {
		/* Association Response alway sends TWO TEID Pool, 1st: S1U/West_Bound Pool,
		 * 2nd: S5S8/East_Bound pool
		 * 3rd: S5S8/West_Bound Pool, if logical interface is present */

		/* WB/S1U/S5S8 and EB/S5S8 interfaces */
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count = 2;
		if (app.wb_li_ip) {
			/* WB/S5S8 Logical interface teid pool */
			pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count += 1;
		}

		/* UPF Features IE is added for the ENDMARKER feauture which is supported in SGWU only */
		set_upf_features(&(pfcp_ass_setup_resp->up_func_feat));
		pfcp_ass_setup_resp->up_func_feat.sup_feat |=  EMPU ;
		pfcp_ass_setup_resp->header.message_len += pfcp_ass_setup_resp->up_func_feat.header.len;


		/* Set UP IP resource info */
		for( int i = 0; i < pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count; i++ ){
			set_up_ip_resource_info(&(pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i]),
					i, teid_range, pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count);
			pfcp_ass_setup_resp->header.message_len +=
				pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i].header.len;
		}
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
			PFCP_ASSOCIATION_UPDATE_RESPONSE, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	set_node_id(&(pfcp_asso_update_resp->node_id),node_value);

	// filling of cause
	/* REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause */
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
			PFCP_NODE_REPORT_RESPONSE, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	set_node_id(&(pfcp_node_rep_resp->node_id), node_value);

	//set cause
	/* REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause */
	set_cause(&(pfcp_node_rep_resp->cause), REQUESTACCEPTED);

	//set offending ie
	/* Remove NODE_ID with actual offend ID */
	set_offending_ie(&(pfcp_node_rep_resp->offending_ie), PFCP_IE_NODE_ID);

}
#endif /* DP_BUILD */

void
fill_pfcp_heartbeat_req(pfcp_hrtbeat_req_t *pfcp_heartbeat_req, uint32_t seq)
{

	memset(pfcp_heartbeat_req, 0, sizeof(pfcp_hrtbeat_req_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_req->header),
			PFCP_HEARTBEAT_REQUEST,	NO_SEID, seq, NO_CP_MODE_REQUIRED);

	set_recovery_time_stamp(&(pfcp_heartbeat_req->rcvry_time_stmp));
	seq++;
}
void
fill_pfcp_heartbeat_resp(pfcp_hrtbeat_rsp_t *pfcp_heartbeat_resp)
{

	uint32_t seq  = 1;
	memset(pfcp_heartbeat_resp, 0, sizeof(pfcp_hrtbeat_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_heartbeat_resp->header),
			PFCP_HEARTBEAT_RESPONSE, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	set_recovery_time_stamp(&(pfcp_heartbeat_resp->rcvry_time_stmp));
}

int process_pfcp_heartbeat_req(struct sockaddr_in *peer_addr, uint32_t seq)
{
	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = 0;

	pfcp_hrtbeat_req_t pfcp_heartbeat_req  = {0};
	/*pfcp_hrtbeat_rsp_t *pfcp_hearbeat_resp =
						malloc(sizeof(pfcp_hrtbeat_rsp_t));

	memset(pfcp_hearbeat_resp,0,sizeof(pfcp_hrtbeat_rsp_t));*/
	fill_pfcp_heartbeat_req(&pfcp_heartbeat_req, seq);

	encoded = encode_pfcp_hrtbeat_req_t(&pfcp_heartbeat_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

#ifdef CP_BUILD
	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, peer_addr,SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,  LOG_FORMAT "Error in sending PFCP "
			"Heartbeat Request : %i\n", LOG_VALUE, errno);
	}
#endif

#ifdef DP_BUILD
	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr,SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "Error in sending PFCP "
			"Heartbeat Request : %i\n", LOG_VALUE, errno);
	}
#endif

	return 0;

}
