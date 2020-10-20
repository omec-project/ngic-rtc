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

#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "teid_upf.h"
#include "gw_adapter.h"
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
#include "debug_str.h"
#else
#include "up_main.h"
#endif /* CP_BUILD */

#ifdef CP_BUILD
#include "sm_pcnd.h"
#include "cdnsutil.h"
#endif /* CP_BUILD*/
#define PFCP_APPLICATION_ID_VALUE "app_1"
#ifdef DP_BUILD
struct in_addr cp_comm_ip;
uint16_t cp_comm_port;
#endif /* DP_BUILD */

extern bool assoc_available;
extern int clSystemLog;

#ifdef CP_BUILD
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern pfcp_config_t config;
uint32_t *g_gx_pending_csr[BUFFERED_ENTRIES_DEFAULT];
uint32_t g_gx_pending_csr_cnt = 0;

void
fill_pfcp_association_setup_req(pfcp_assn_setup_req_t *pfcp_ass_setup_req)
{

	uint32_t seq  = 1;

	memset(pfcp_ass_setup_req, 0, sizeof(pfcp_assn_setup_req_t)) ;

	seq = get_pfcp_sequence_number(PFCP_ASSOCIATION_SETUP_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_req->header),
			PFCP_ASSOCIATION_SETUP_REQUEST, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	set_recovery_time_stamp(&(pfcp_ass_setup_req->rcvry_time_stmp));

}

/* Fill pfd mgmt cstm ie */
uint16_t
set_pfd_contents(pfcp_pfd_contents_ie_t *pfd_conts, struct msgbuf *cstm_buf)
{
	pfd_conts->cp = PRESENT;
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

	if(pfd_conts->cp != 0){
		pfd_conts->cstm_pfd_cntnt = pfd_conts->data;
		uint16_t struct_len = 0;
		switch (cstm_buf->mtype) {
			case MSG_SDF_CRE:
			case MSG_ADC_TBL_CRE:
			case MSG_PCC_TBL_CRE:
			case MSG_SESS_TBL_CRE:
			case MSG_MTR_CRE:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN, "%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data+struct_len, (uint8_t *)&cstm_buf->msg_union.msg_table,
														sizeof(cstm_buf->msg_union.msg_table));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(cstm_buf->msg_union.msg_table) + struct_len;
				break;

			case MSG_EXP_CDR:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len,
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
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
													"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.pkt_filter_entry, sizeof(struct pkt_filter));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct pkt_filter)+struct_len;
				break;
			case MSG_ADC_TBL_ADD:
			case MSG_ADC_TBL_DEL:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.adc_filter_entry, sizeof(struct adc_rules));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct adc_rules)+ struct_len;
				break;
			case MSG_PCC_TBL_ADD:
			case MSG_PCC_TBL_DEL:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.pcc_entry, sizeof(struct pcc_rules));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct pcc_rules) + struct_len;
				break;
			case MSG_SESS_CRE:
			case MSG_SESS_MOD:
			case MSG_SESS_DEL:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
												"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len,
					  (uint8_t *)&cstm_buf->msg_union.sess_entry, sizeof(struct session_info));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct session_info) + struct_len;
				break;
			case MSG_MTR_ADD:
			case MSG_MTR_DEL:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
													"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len ,
					  (uint8_t *)&cstm_buf->msg_union.mtr_entry, sizeof(struct mtr_entry));
				pfd_conts->len_of_cstm_pfd_cntnt = sizeof(struct mtr_entry) + struct_len;
				break;
			case MSG_DDN_ACK:
				/* Fill msg type */
				struct_len = snprintf((char *)pfd_conts->data, MAX_LEN,
																"%"PRId64" ",cstm_buf->mtype);
				/* Fill cstm ie contents frome rule structure as string */
				memcpy(pfd_conts->data + struct_len ,
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
			(pfd_conts->len_of_cstm_pfd_cntnt + sizeof(pfd_conts->header)));
	return (pfd_conts->len_of_cstm_pfd_cntnt + sizeof(pfd_conts->header));
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
	/* TODO : remove the hardcoded value of APP ID */
	pfcp_set_ie_header(&app_id->header, PFCP_IE_APPLICATION_ID,
			strnlen(PFCP_APPLICATION_ID_VALUE, sizeof(app_id->app_ident)));
	memcpy(app_id->app_ident, PFCP_APPLICATION_ID_VALUE,
			strnlen(PFCP_APPLICATION_ID_VALUE, sizeof(app_id->app_ident)));

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
	upf_context->indir_tun_flag = 0;

	return 0;

}

int
get_upf_ip(ue_context *ctxt, pdn_connection *pdn)
{
	if(config.use_dns) {
		upfs_dnsres_t *entry = NULL;

		if (upflist_by_ue_hash_entry_lookup(&ctxt->imsi,
					sizeof(ctxt->imsi), &entry) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to extract UPF context by ue hash\n", LOG_VALUE);
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}

		if (entry->current_upf > entry->upf_count) {
			/* TODO: Add error log : Tried sending
			 * association request to all upf.*/
			/* Remove entry from hash ?? */
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Failure in sending association request to all upf\n", LOG_VALUE);
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}

		if (entry != NULL) {
			memcpy(pdn->fqdn, entry->upf_fqdn[entry->current_upf], sizeof(entry->upf_fqdn[entry->current_upf]));
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Received UPF list for DNS entry is NULL\n", LOG_VALUE);
				return GTPV2C_CAUSE_REQUEST_REJECTED;
		}

		if ((config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6
					|| config.pfcp_ip_type == PDN_TYPE_IPV6)
						&& (*entry->upf_ip[entry->current_upf].ipv6.s6_addr)) {

			memcpy(pdn->upf_ip.ipv6_addr, entry->upf_ip[entry->current_upf].ipv6.s6_addr, IPV6_ADDRESS_LEN);
			pdn->upf_ip.ip_type = PDN_TYPE_IPV6;
			entry->upf_ip_type = PDN_TYPE_IPV6;
		} else if ((config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6
					|| config.pfcp_ip_type == PDN_TYPE_IPV4)
						&& (entry->upf_ip[entry->current_upf].ipv4.s_addr != 0)) {

			pdn->upf_ip.ipv4_addr = entry->upf_ip[entry->current_upf].ipv4.s_addr;
			pdn->upf_ip.ip_type = PDN_TYPE_IPV4;
			entry->upf_ip_type = PDN_TYPE_IPV4;
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Requested type and DNS supported type are not same\n", LOG_VALUE);
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}

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
	// node_address_t upf_ip = {0};
	upf_context_t *upf_context = NULL;

	pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};
	node_address_t node_value = {0};

	upf_context  = rte_zmalloc_socket(NULL, sizeof(upf_context_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (upf_context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to allocate "
				"upf context: %s\n", LOG_VALUE, rte_strerror(rte_errno));
		return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
	}

	ret = upf_context_entry_add(&pdn->upf_ip, upf_context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure while adding "
			"upf context entry for IP Type : %s with IPv4 : "IPV4_ADDR""
			"\t IPv6 : "IPv6_FMT", Error: %d \n", LOG_VALUE,
			ip_type_str(pdn->upf_ip.ip_type),
			IPV4_ADDR_HOST_FORMAT(pdn->upf_ip.ipv4_addr),
			PRINT_IPV6_ADDR(pdn->upf_ip.ipv6_addr), ret);
		return -1;
	}

	if(context->indirect_tunnel_flag  == 0) {
		ret = buffer_csr_request(context, upf_context, ebi_index);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure while buffer "
					"Create Session Request, Error: %d \n",LOG_VALUE, ret);
			return -1;
		}
	} else {
			upf_context->sender_teid = context->s11_sgw_gtpc_teid;
			upf_context->indir_tun_flag = 1;
	}

	upf_context->assoc_status = ASSOC_IN_PROGRESS;
	upf_context->state = PFCP_ASSOC_REQ_SNT_STATE;
	upf_context->cp_mode = context->cp_mode;

	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);

	/*Filling Node ID*/
	if (pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV4) {
		uint8_t temp[IPV6_ADDRESS_LEN] = {0};
		ret = fill_ip_addr(config.pfcp_ip.s_addr, temp, &node_value);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	} else if (pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV6) {

		ret = fill_ip_addr(0, config.pfcp_ip_v6.s6_addr, &node_value);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}		

	}

	set_node_id(&pfcp_ass_setup_req.node_id, node_value);

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_assn_setup_req_t(&pfcp_ass_setup_req, pfcp_msg);

	if(config.use_dns) {
		ret = set_dest_address(pdn->upf_ip, &upf_pfcp_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	}

	/* fill and add timer entry */
	peerData *timer_entry = NULL;
	timer_entry =  fill_timer_entry_data(PFCP_IFACE, &upf_pfcp_sockaddr,
			pfcp_msg, encoded, config.request_tries, context->s11_sgw_gtpc_teid, ebi_index);

	timer_entry->imsi = context->imsi;

	if(!(add_timer_entry(timer_entry, config.request_timeout, association_timer_callback))) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Faild to add timer "
			"entry\n",LOG_VALUE);
	}

	upf_context->timer_entry = timer_entry;
	if (starttimer(&timer_entry->pt) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Periodic Timer "
				"failed to start\n",LOG_VALUE);
	}

	if ( pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr,SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error sending PFCP "
			"Association Request\n", LOG_VALUE);
	}

	return 0;
}

int
process_pfcp_assoication_request(pdn_connection *pdn, int ebi_index)
{
	int ret = 0;
	upf_context_t *upf_context = NULL;

	/* Retrive association state based on UPF IP. */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ip), (void **) &(upf_context));
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
process_pfcp_ass_resp(msg_info *msg, peer_addr_t *peer_addr)
{
	int ret = 0;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_context = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	node_address_t node_value = {0};

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(msg->upf_ip), (void **) &(upf_context));
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN UPF "
			"HASH, IP Type : %s with IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT"",
			LOG_VALUE, ip_type_str(msg->upf_ip.ip_type),
			IPV4_ADDR_HOST_FORMAT(msg->upf_ip.ipv4_addr),
			PRINT_IPV6_ADDR(msg->upf_ip.ipv6_addr));
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	msg->cp_mode = upf_context->cp_mode;
	upf_context->assoc_status = ASSOC_ESTABLISHED;
	upf_context->state = PFCP_ASSOC_RESP_RCVD_STATE;

	/* WB/S1U, WB/S5S8_Logical, EB/S5S8 Interface*/
	for (uint8_t inx = 0; inx < msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info_count; inx++) {
		if (inx == 0) {
			/* WB/S1U Interface */
			if (msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].assosi == PRESENT &&
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].src_intfc ==
					SOURCE_INTERFACE_VALUE_ACCESS ) {

				ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
						&upf_context->s5s8_pgwu_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
				}

				ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
						&upf_context->s1u_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
				}
			}
		}

		if (inx == 1) {
			/* EB/S5S8 Interface */
			if(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].assosi == PRESENT &&
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].src_intfc ==
					SOURCE_INTERFACE_VALUE_CORE ) {

				ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
						msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
						&upf_context->s5s8_sgwu_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
				}
			}
		}

		if ((inx == 2) &&
				(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].src_intfc == SOURCE_INTERFACE_VALUE_ACCESS)) {
			/* PGWU WB/S5S8 Logical Interface */
			memset(&upf_context->s5s8_pgwu_ip, 0, sizeof(node_address_t));
			ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
				&upf_context->s5s8_pgwu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
		} else if ((inx == 2) &&
				(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].src_intfc == SOURCE_INTERFACE_VALUE_CORE)) {
			/* SGWU EB/S5S8 Logical Interface:Indirect Tunnel */
			ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
				&upf_context->s5s8_li_sgwu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
		}

		if ((inx == 3) &&
				(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].src_intfc == SOURCE_INTERFACE_VALUE_CORE)) {
			/* SGWU EB/S5S8 Logical Interface:Indirect Tunnel */
			ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
				&upf_context->s5s8_li_sgwu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
		} else if ((inx == 3) &&
				(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].src_intfc == SOURCE_INTERFACE_VALUE_ACCESS)) {
			/* PGWU WB/S5S8 Logical Interface */
			memset(&upf_context->s5s8_pgwu_ip, 0, sizeof(node_address_t));
			ret = fill_ip_addr(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv4_address,
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[inx].ipv6_address,
				&upf_context->s5s8_pgwu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
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

	if (msg->pfcp_msg.pfcp_ass_resp.node_id.node_id_type == NODE_ID_TYPE_TYPE_IPV4ADDRESS) {

		node_value.ip_type = PDN_IP_TYPE_IPV4;
		node_value.ipv4_addr =
			msg->pfcp_msg.pfcp_ass_resp.node_id.node_id_value_ipv4_address;

	} else if (msg->pfcp_msg.pfcp_ass_resp.node_id.node_id_type == NODE_ID_TYPE_TYPE_IPV6ADDRESS) {

		node_value.ip_type = PDN_IP_TYPE_IPV6;
		memcpy(node_value.ipv6_addr,
			msg->pfcp_msg.pfcp_ass_resp.node_id.node_id_value_ipv6_address,
			IPV6_ADDRESS_LEN);
	}

	if (0 != set_base_teid(upf_context->teidri, upf_context->teid_range,
				node_value, &upf_teid_info_head)) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to set teid range for DP \n, "
			"IP Type : %s | IPV4_ADDR : "IPV4_ADDR" | IPV6_ADDR : "IPv6_FMT"",
			LOG_VALUE, ip_type_str(node_value.ip_type),
			IPV4_ADDR_HOST_FORMAT(node_value.ipv4_addr),
			PRINT_IPV6_ADDR(node_value.ipv6_addr));

		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if(upf_context->indir_tun_flag == 0 ) {
		for (uint8_t i = 0; i < upf_context->csr_cnt; i++) {

			context_key *key = (context_key *)upf_context->pending_csr_teid[i];

			if (get_ue_context(key->teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"UE context not found "
						"for teid: %d\n", LOG_VALUE, key->teid);

				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			if(config.use_dns) {
				/* Delete UPFList entry from UPF Hash */
				if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi)))
						< 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Error on upflist_by_ue_hash deletion of IMSI \n",
							LOG_VALUE);
				}
			}

			pdn = GET_PDN(context, key->ebi_index);
			if(pdn == NULL){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
						"pdn for ebi_index %d\n", LOG_VALUE, key->ebi_index);

				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			ret = process_pfcp_sess_est_request(key->teid, pdn, upf_context);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to process PFCP "
						"session eshtablishment request %d \n", LOG_VALUE, ret);

				fill_response(pdn->seid, key);

				return ret;
			}

			fill_response(pdn->seid, key);

			rte_free(upf_context->pending_csr_teid[i]);
			upf_context->csr_cnt--;

		}
	} else {

		if(get_sender_teid_context(upf_context->sender_teid, &context) != 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No entry found for ue in hash\n",
				LOG_VALUE);
			return -1;
		}

		ret = process_pfcp_sess_est_request(context->s11_sgw_gtpc_teid,
				context->indirect_tunnel->pdn, upf_context);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to process PFCP "
				"session eshtablishment request %d \n", LOG_VALUE, ret);

			if(ret != -1) {
				crt_indir_data_frwd_tun_error_response(msg, ret);
			}
		} else {
			if (get_sess_entry(context->indirect_tunnel->pdn->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session "
					"Entry Found for sess ID : %lu\n", LOG_VALUE,
					context->indirect_tunnel->pdn->seid);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
		}
		upf_context->csr_cnt--;
	}

	/* Adding ip to cp heartbeat when dp returns the association response*/
	node_address_t ip_addr = {0};
	get_peer_node_addr(peer_addr, &ip_addr);
	add_ip_to_heartbeat_hash(&ip_addr,
			msg->pfcp_msg.pfcp_ass_resp.rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST
	if (is_present(&ip_addr)) {
		if (add_node_conn_entry(&ip_addr, SX_PORT_ID, upf_context->cp_mode) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
				"connection entry for SGWU/SAEGWU\n", LOG_VALUE);
		}
		(ip_addr.ip_type == IPV6_TYPE)?
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Added Connection entry "
					"for UPF IPv6:"IPv6_FMT"\n",LOG_VALUE, IPv6_PRINT(IPv6_CAST(ip_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Added Connection entry "
					"for UPF IPv4:"IPV4_ADDR"\n",LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ip_addr.ipv4_addr));
	}
#endif/* USE_REST */
	return 0;

}


/**
 * @brief  : fill the pdr_ids structure.
 * @param  : pfcp_pdr_id, structure needs to filled
 * @param  : num_pdr, count of number of pdrs
 * @param  : pdr, array of pointers having rule id
 * @return : Returns ue_level struture pointer if success else null.
 */
static int
fill_pdr_ids(pdr_ids *pfcp_pdr_id, uint8_t num_pdr, pfcp_pdr_id_ie_t *pdr)
{
	uint8_t i = 0;
	uint8_t count = 0;
	uint8_t pdr_itr = 0;
	uint8_t tmp_cnt = 0;
	uint8_t temp_arr[MAX_LIST_SIZE] = {0};

	if(pfcp_pdr_id != NULL && pfcp_pdr_id->pdr_count == 0){

		for(uint8_t itr2 = 0; itr2< num_pdr; itr2++){
			uint8_t Match_found = False;
			for(uint8_t itr1 = 0; itr1< pfcp_pdr_id->pdr_count; itr1++){
				if( pfcp_pdr_id->pdr_id[itr1] == pdr[itr2].rule_id ){
					Match_found = True;
					break;
				}
			}
			if(Match_found == False){
			temp_arr[i] = pdr[itr2].rule_id;
			tmp_cnt++;
			i++;
		}

	}

	for(i=0; i<MAX_LIST_SIZE; i++){
		if(pfcp_pdr_id->pdr_id[i] == 0)
			break;
	}
	/* Save the rule id recieved in pfcp report request*/
	while(count != tmp_cnt){
		pfcp_pdr_id->pdr_id[i] = temp_arr[pdr_itr];
		i++;
		count++;
		pdr_itr++;
	}
	pfcp_pdr_id->pdr_count += tmp_cnt;

	} else {

		pfcp_pdr_id->pdr_count = num_pdr;
		for(i = 0; i< num_pdr; i++){
			pfcp_pdr_id->pdr_id[i] = pdr[i].rule_id;
		}
	}
	return 0;
}


/**
 * @brief  : fill the session info structure.
 * @param  : pfcp_pdr_id, needs to filled
 * @param  : pdr_count , count of number of pdr_id in pfcp_pdr_id array
 * @param  : num_pdr, count of number of pdrs_id needs to be filled
 * @param  : pdr, array of pointers having rule id
 * @return : Returns nothing.
 */
static void
fill_sess_info_pdr(uint16_t *pfcp_pdr_id, uint8_t *pdr_count, uint8_t num_pdr, pfcp_pdr_id_ie_t *pdr)
{
	uint8_t i = 0;
	uint8_t count = 0;
	uint8_t pdr_itr = 0;
	uint8_t tmp_cnt = 0;
	uint8_t temp_arr[MAX_LIST_SIZE] = {0};

	if(*pdr_count != 0 ){

	for(uint8_t itr2 = 0; itr2 < num_pdr; itr2++){
	uint8_t Match_found = False;
	for(uint8_t itr1 = 0; itr1< *pdr_count; itr1++){
		if( pfcp_pdr_id[itr1] == pdr[itr2].rule_id ){
			Match_found = True;
			break;
			}
		}
		if(Match_found == False){
		temp_arr[i] = pdr[itr2].rule_id;
		tmp_cnt++;
		i++;
		}

	}
	for(i=0; i<MAX_LIST_SIZE; i++){
		if(pfcp_pdr_id[i] == 0)
			break;
		}
	/* Save the rule id recieved in pfcp report request*/
	while(count != tmp_cnt){
		pfcp_pdr_id[i] = temp_arr[pdr_itr];
		i++;
		count++;
		pdr_itr++;
		}
	*pdr_count += tmp_cnt;
	} else {
		*pdr_count = num_pdr;
		for(i = 0; i< num_pdr; i++){
			pfcp_pdr_id[i] = pdr[i].rule_id;
		}
	}
}


void fill_sess_info_id(thrtle_count *thrtl_cnt, uint64_t sess_id, uint8_t pdr_count, pfcp_pdr_id_ie_t *pdr)
{
	thrtl_cnt->buffer_count = thrtl_cnt->buffer_count + 1;
	sess_info *sess_info_id = search_into_sess_info_list(thrtl_cnt->sess_ptr, sess_id);
	if(sess_info_id == NULL){

		sess_info_id = rte_zmalloc_socket(NULL, sizeof(sess_info), RTE_CACHE_LINE_SIZE, rte_socket_id());
		if(sess_info_id == NULL){
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory to session info"
					"\n\n", LOG_VALUE);
			return;
		}

		 if (insert_into_sess_info_list(thrtl_cnt->sess_ptr, sess_info_id) == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add node entry in LL\n",
					LOG_VALUE);
			rte_free(sess_info_id);
			sess_info_id = NULL;
			return;
		}

	}
	fill_sess_info_pdr(sess_info_id->pdr_id, &sess_info_id->pdr_count,
						pdr_count, pdr);

}

thrtle_count *
get_throtle_count(node_address_t *nodeip, uint8_t is_mod)
{

	thrtle_count *thrtl_cnt = NULL;
	int ret = 0;

	ret = rte_hash_lookup_data(thrtl_ddn_count_hash,
			(const void *)nodeip, (void **)&thrtl_cnt);

	if(ret < 0 ){
		/* If operation is not set to the ADD_ENTRY */
		if (is_mod) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for Node: "
				" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT""
				"\n", LOG_VALUE, ip_type_str(nodeip->ip_type),
				IPV4_ADDR_HOST_FORMAT(nodeip->ipv4_addr), PRINT_IPV6_ADDR(nodeip->ipv6_addr));
			return NULL;
		}

		/* Allocate memory and add a new thrtl_count Entry into hash */

		thrtl_cnt = rte_zmalloc_socket(NULL, sizeof(thrtle_count),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(thrtl_cnt == NULL ){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for throttling count structure, Error: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));

			return NULL;
		}
		/* Initiailize buffer count to one as avoid infinity value*/
		thrtl_cnt->buffer_count = 1;
		thrtl_cnt->sent_count = 0;
		thrtl_cnt->sess_ptr = NULL;

		ret = rte_hash_add_key_data(thrtl_ddn_count_hash,
				(const void *)nodeip, thrtl_cnt);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add entry while throttling "
					"of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT""
					"\n\tError= %d\n", LOG_VALUE, ip_type_str(nodeip->ip_type),
					IPV4_ADDR_HOST_FORMAT(nodeip->ipv4_addr), PRINT_IPV6_ADDR(nodeip->ipv6_addr),ret);

			rte_free(thrtl_cnt);
			thrtl_cnt = NULL;
			return NULL;
		}
	}
	return thrtl_cnt;
}

uint8_t
process_pfcp_report_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req)
{

	/*DDN Handling */
	int ret = 0;
	uint32_t sequence = 0;
	uint8_t cp_thrtl_fact = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pdr_ids *pfcp_pdr_id = NULL;
	ue_level_timer *timer_data = NULL;
	throttle_timer *thrtle_timer_data = NULL;
	thrtle_count *thrtl_cnt = NULL;

	uint64_t sess_id = pfcp_sess_rep_req->header.seid_seqno.has_seid.seid;
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
	resp->pfcp_seq = sequence;

	if (pfcp_sess_rep_req->report_type.dldr) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DDN Request recv from DP for "
				"sess:%lu\n", LOG_VALUE, sess_id);

		/* UE LEVEL: PFCP: DL Buffering Duration Timer delay */
		if( (rte_hash_lookup_data(dl_timer_by_teid_hash, &s11_sgw_gtpc_teid, (void **)&timer_data)) >= 0 ){
			if((rte_hash_lookup_data(pfcp_rep_by_seid_hash, &sess_id, (void **)&pfcp_pdr_id)) < 0){
				/* If not present, allocate the memory and add the entry for sess id */
				pfcp_pdr_id = rte_zmalloc_socket(NULL, sizeof(pdr_ids),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

				if(pfcp_pdr_id == NULL ){
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
							"Memory for pdr_ids structure, Error: %s \n", LOG_VALUE,
							rte_strerror(rte_errno));

					return -1;
				}
				ret = rte_hash_add_key_data(pfcp_rep_by_seid_hash,
						&sess_id, pfcp_pdr_id);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to add entry while dl buffering  with session id = %u"
							"\n\tError= %d\n", LOG_VALUE, sess_id, ret);

					rte_free(pfcp_pdr_id);
					pfcp_pdr_id = NULL;

					return -1;
				}
			}
			ret = fill_pdr_ids(pfcp_pdr_id, pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id_count,
					pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id);
			if(ret != 0){

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in dl buffer timer "
						"fill pdr ids:%lu\n", LOG_VALUE, sess_id);
				return -1;
			}
			context->pfcp_rept_resp_sent_flag = 1;
			fill_send_pfcp_sess_report_resp(context, sequence, pdn, NOT_PRESENT, TRUE);

			/*UE LEVEL: GTPv2c: Check for UE level timer */
		} else if(rte_hash_lookup_data(timer_by_teid_hash, &s11_sgw_gtpc_teid, (void **)&timer_data) >= 0){
			if((rte_hash_lookup_data(ddn_by_seid_hash, &sess_id, (void **)&pfcp_pdr_id)) < 0){
				/* If not present, allocate the memory and add the entry for sess id */
				pfcp_pdr_id = rte_zmalloc_socket(NULL, sizeof(pdr_ids),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

				if(pfcp_pdr_id == NULL ){
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
							"Memory for pdr_ids structure, Error: %s \n", LOG_VALUE,
							rte_strerror(rte_errno));

					return -1;
				}
				ret = rte_hash_add_key_data(ddn_by_seid_hash,
						&sess_id, pfcp_pdr_id);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to buffer entry for ddn with session id = %u"
							"\n\tError= %d\n", LOG_VALUE, sess_id, ret);

					rte_free(pfcp_pdr_id);
					pfcp_pdr_id = NULL;

					return -1;
				}
			}

			/* Buffer the ddn request */
			ret = fill_pdr_ids(pfcp_pdr_id, pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id_count,
					pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id);
			if(ret != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in delay timer "
						"fill pdr ids:%lu\n", LOG_VALUE, sess_id);
				return -1;
			}

			context->pfcp_rept_resp_sent_flag = 1;
			fill_send_pfcp_sess_report_resp(context, sequence, pdn, NOT_PRESENT, TRUE);

			/*Node Level: GTPv2C: Check for throttling timer */
		}else if((rte_hash_lookup_data(thrtl_timer_by_nodeip_hash,
						(const void *)&context->s11_mme_gtpc_ip, (void **)&thrtle_timer_data)) >= 0 ){

			/* Retrive the counter to calculate throttling factor */
			thrtl_cnt = get_throtle_count(&context->s11_mme_gtpc_ip, ADD_ENTRY);
			if(thrtl_cnt == NULL){
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error to get throttling count \n",
						LOG_VALUE);
				return -1;
			}

			/* Send DDN Request if caluculated throttling factor is greater than received factor value */
			for(uint8_t i = 0; i < pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id_count; i++){
				for(uint8_t j = 0; j < MAX_BEARERS; j++){
					if(pdn->eps_bearers[j] != NULL){
						for(uint8_t itr_pdr = 0; itr_pdr < pdn->eps_bearers[j]->pdr_count; itr_pdr++){
							if ((pdn->eps_bearers[j]->pdrs[itr_pdr]->pdi.src_intfc.interface_value ==
										SOURCE_INTERFACE_VALUE_CORE) &&
									(pdn->eps_bearers[j]->pdrs[itr_pdr]->rule_id ==
									 pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id[i].rule_id)){

								if(pdn->eps_bearers[j]->qos.arp.priority_level <
										config.low_lvl_arp_priority){

									/* Calculate the throttling factor*/
									if(thrtl_cnt->sent_count != 0){
										cp_thrtl_fact = (thrtl_cnt->buffer_count/thrtl_cnt->sent_count) * 100;

										if(cp_thrtl_fact > thrtle_timer_data->throttle_factor){
											pdr_ids ids;
											ids.pdr_count = ONE;
											ids.pdr_id[ZERO] = pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id[i].rule_id;
											/*Send DDN request*/
											ret = ddn_by_session_id(sess_id, &ids);

											if (ret) {
												clLog(clSystemLog, eCLSeverityCritical,
														LOG_FORMAT "Failed to process DDN request \n",
														LOG_VALUE);
												return -1;
											}
											context->pfcp_rept_resp_sent_flag = 0;
											thrtl_cnt->sent_count = thrtl_cnt->sent_count + 1;
										}else{
											pfcp_pdr_id_ie_t  pdr = {0};
											pdr.rule_id = pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id[i].rule_id;
											fill_sess_info_id(thrtl_cnt, sess_id, ONE, &pdr);

											context->pfcp_rept_resp_sent_flag = 1;
											fill_send_pfcp_sess_report_resp(context, sequence, pdn, NOT_PRESENT, TRUE);
										}
									}else{
										pdr_ids ids;
										ids.pdr_count = ONE;
										ids.pdr_id[ZERO] = pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id[i].rule_id;
										/*Send DDN request*/
										ret = ddn_by_session_id(sess_id, &ids);

										if (ret) {
											clLog(clSystemLog, eCLSeverityCritical,
													LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
											return -1;
										}
										thrtl_cnt->sent_count = thrtl_cnt->sent_count + 1;
										context->pfcp_rept_resp_sent_flag = 0;
									}
								} else {
									context->pfcp_rept_resp_sent_flag = 1;
									fill_send_pfcp_sess_report_resp(context, sequence, pdn, NOT_PRESENT, TRUE);
								}
							}
						}
					}
				}
			}
		}else{
				ret = ddn_by_session_id(sess_id, pfcp_pdr_id);

				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
					return -1;
				}
				context->pfcp_rept_resp_sent_flag = 0;
			}

		resp->msg_type = PFCP_SESSION_REPORT_REQUEST;
		/* Update the Session state */
		resp->state = DDN_REQ_SNT_STATE;
		pdn->state = DDN_REQ_SNT_STATE;
	}

	if (pfcp_sess_rep_req->report_type.usar == PRESENT) {
		for( int cnt = 0; cnt < pfcp_sess_rep_req->usage_report_count; cnt++ )
			fill_cdr_info_sess_rpt_req(sess_id, &pfcp_sess_rep_req->usage_report[cnt]);

			fill_send_pfcp_sess_report_resp(context, sequence, pdn, NOT_PRESENT, FALSE);
	}
	return 0;
}

#endif /* CP_BUILD */

#ifdef DP_BUILD

void
fill_pfcp_association_setup_resp(pfcp_assn_setup_rsp_t *pfcp_ass_setup_resp,
				uint8_t cause, node_address_t dp_node_value,
				node_address_t cp_node_value)
{
	int8_t teid_range = 0;
	uint8_t teidri_gen_flag = 0;
	uint32_t seq  = 1;

	memset(pfcp_ass_setup_resp, 0, sizeof(pfcp_assn_setup_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_ass_setup_resp->header),
			PFCP_ASSOCIATION_SETUP_RESPONSE, NO_SEID, seq, NO_CP_MODE_REQUIRED);

	pfcp_ass_setup_resp->header.message_len += set_node_id(&(pfcp_ass_setup_resp->node_id), dp_node_value);

	set_recovery_time_stamp(&(pfcp_ass_setup_resp->rcvry_time_stmp));
	pfcp_ass_setup_resp->header.message_len += pfcp_ass_setup_resp->rcvry_time_stmp.header.len;

	/* As we are not supporting this feature
	set_upf_features(&(pfcp_ass_setup_resp->up_func_feat)); */

	if(app.teidri_val != 0){
		/* searching record for peer node into list of blocked teid_ranges */
		teidri_gen_flag =
			get_teidri_from_list((uint8_t *)&teid_range,
					cp_node_value, &upf_teidri_blocked_list);

		if (teidri_gen_flag == 0) {
			/* Record not found in list of blocked teid_ranges
			 * searching record for peer node into list of allocated teid_ranges */

			teidri_gen_flag =
				get_teidri_from_list((uint8_t *)&teid_range, cp_node_value,
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
					if (add_teidri_node_entry(teid_range, cp_node_value,
								TEIDRI_FILENAME, &upf_teidri_allocated_list,
								&upf_teidri_free_list) < 0) {
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"ERROR :Unable to write data into file"
								" for Node addr: %u : TEIDRI: %d \n", LOG_VALUE,
								cp_node_value.ipv4_addr, teid_range);
					}
				}
			}
		}else{
			/* TEIDRI value found into list of blocked records */
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"TEIDRI value found into data node"
				 " addr: %u : TEIDRI: %d \n", LOG_VALUE,
				cp_node_value.ipv4_addr, teid_range);

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
			if (add_teidri_node_entry(teid_range, cp_node_value, NULL, &upf_teidri_allocated_list,
						&upf_teidri_blocked_list) < 0) {
				clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
						"ERROR :Unable to write data into file"
						" for Node addr : %u : TEIDRI : %d \n", LOG_VALUE,
						cp_node_value.ipv4_addr, teid_range);
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

	pfcp_ass_setup_resp->header.message_len += set_cause(&(pfcp_ass_setup_resp->cause), cause);

	if (cause == REQUESTACCEPTED) {
		/* Association Response alway sends TWO TEID Pool, 1st: S1U/West_Bound Pool,
		 * 2nd: S5S8/East_Bound pool
		 * 3rd: S5S8/West_Bound Pool, if logical interface is present
		 * 3rd: S5S8/East_Bound Pool, if logical interface is present */

		/* WB/S1U/S5S8 and EB/S5S8 interfaces */
		pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count = 2;

		/* UPF Features IE is added for the ENDMARKER feauture which is supported in SGWU only */
		set_upf_features(&(pfcp_ass_setup_resp->up_func_feat));
		pfcp_ass_setup_resp->up_func_feat.sup_feat.empu |=  EMPU ;
		pfcp_ass_setup_resp->header.message_len += pfcp_ass_setup_resp->up_func_feat.header.len;


		/* Set UP IP resource info */
		for( int i = 0; i < pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count; i++ ){
			set_up_ip_resource_info(&(pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i]),
					i, teid_range, NOT_PRESENT);
			pfcp_ass_setup_resp->header.message_len +=
				pfcp_ass_setup_resp->user_plane_ip_rsrc_info[i].header.len;
		}

		if (app.wb_li_ip || isIPv6Present(&app.wb_li_ipv6)) {
			set_up_ip_resource_info(&(pfcp_ass_setup_resp->user_plane_ip_rsrc_info[pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count]),
					NOT_PRESENT, teid_range, 1);
			pfcp_ass_setup_resp->header.message_len +=
				pfcp_ass_setup_resp->user_plane_ip_rsrc_info[pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count].header.len;

			/* WB/S5S8 Logical interface teid pool */
			pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count += 1;

		}

		/* EB/S5S8 Logical interfaces */
		if (app.eb_li_ip || isIPv6Present(&app.eb_li_ipv6)) {
			set_up_ip_resource_info(&(pfcp_ass_setup_resp->user_plane_ip_rsrc_info[pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count]),
					NOT_PRESENT, teid_range, 2);
			pfcp_ass_setup_resp->header.message_len +=
				pfcp_ass_setup_resp->user_plane_ip_rsrc_info[pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count].header.len;
			/* EB/S5S8 Logical interface teid pool */
			pfcp_ass_setup_resp->user_plane_ip_rsrc_info_count += 1;
		}
	}

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

int process_pfcp_heartbeat_req(peer_addr_t peer_addr, uint32_t seq)
{
	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = 0;

	pfcp_hrtbeat_req_t pfcp_heartbeat_req  = {0};

	fill_pfcp_heartbeat_req(&pfcp_heartbeat_req, seq);

	encoded = encode_pfcp_hrtbeat_req_t(&pfcp_heartbeat_req, pfcp_msg);

#ifdef CP_BUILD
	if ( pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, peer_addr, SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,  LOG_FORMAT "Error in sending PFCP "
			"Heartbeat Request : %i\n", LOG_VALUE, errno);
	}
#endif

#ifdef DP_BUILD
	if ( pfcp_send(my_sock.sock_fd, my_sock.sock_fd_v6, pfcp_msg, encoded,
												peer_addr, SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "Error in sending PFCP "
			"Heartbeat Request : %i\n", LOG_VALUE, errno);
	}
#endif

	return 0;

}
