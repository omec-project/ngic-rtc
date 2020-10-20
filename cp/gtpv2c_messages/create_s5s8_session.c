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

#include <errno.h>
#include <byteswap.h>

#include "packet_filters.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

#include "pfcp.h"
#include "gtpv2c.h"
#include "pfcp_enum.h"
#include "pfcp_util.h"
#include "sm_struct.h"
#include "../cp_stats.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_messages_encoder.h"
#include "cp_config.h"
#include "seid_llist.h"
#include "gtpc_session.h"

#ifdef CP_BUILD
#include "cp_timer.h"
#endif /* CP_BUILD */

#ifdef USE_REST
#include "main.h"
#endif /* USE_REST */


extern pfcp_config_t config;
extern int clSystemLog;
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern peer_addr_t upf_pfcp_sockaddr;
extern peer_addr_t s5s8_recv_sockaddr;
extern struct cp_stats_t cp_stats;


int
process_sgwc_s5s8_modify_bearer_response(mod_bearer_rsp_t *mb_rsp, gtpv2c_header_t *gtpv2c_s11_tx,
		ue_context **_context)
{

	int ret = 0;
	int ebi_index = 0;
	uint32_t seq = 0;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	ebi_index = GET_EBI_INDEX(mb_rsp->bearer_contexts_modified[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */

	ret = get_ue_context_by_sgw_s5s8_teid(mb_rsp->header.teid.has_teid.teid, &context);
	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
		    "Ue context for teid: %d\n",
		    LOG_VALUE, mb_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;
	*_context = context;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
			"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	/* PGW FQ-CSID */
	if (mb_rsp->pgw_fqcsid.header.len) {
		/* Remove Exsiting PGW CSID linked with session */
		if (pdn->pgw_csid.num_csid) {
			memset(&pdn->pgw_csid, 0,  sizeof(fqcsid_t));
		}

		ret = add_peer_addr_entry_for_fqcsid_ie_node_addr(
			&pdn->s5s8_pgw_gtpc_ip, &mb_rsp->pgw_fqcsid,
			S5S8_SGWC_PORT_ID);
		if (ret)
			return ret;

		/* Stored the PGW CSID by PGW Node address */
		ret = add_fqcsid_entry(&mb_rsp->pgw_fqcsid, context->pgw_fqcsid);
		if(ret)
			return ret;

		fill_pdn_fqcsid_info(&pdn->pgw_csid, context->pgw_fqcsid);

	} else {
		tmp = get_peer_addr_csids_entry(&(pdn->s5s8_pgw_gtpc_ip),
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: Failed to "
				"add PGW CSID by PGW Node addres %s \n", LOG_VALUE,
				strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		memcpy(&(tmp->node_addr),
				&(pdn->s5s8_pgw_gtpc_ip), sizeof(node_address_t));
		memcpy(&((context->pgw_fqcsid)->node_addr[(context->pgw_fqcsid)->num_csid]),
				&(pdn->s5s8_pgw_gtpc_ip), sizeof(node_address_t));
	}

	/* Link local CSID with PGW CSID */
	if (pdn->pgw_csid.num_csid) {
		if (link_gtpc_peer_csids(&pdn->pgw_csid,
					&pdn->sgw_csid, S5S8_SGWC_PORT_ID)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with PGW FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return -1;
		}

		if (link_sess_with_peer_csid(&pdn->pgw_csid, pdn, S5S8_SGWC_PORT_ID)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error : Failed to Link "
					"Session with Peer CSID\n", LOG_VALUE);
			return -1;
		}

		/* Send pfcp mod req to SGWU for pgwc csid */
		seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

		set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header),
				PFCP_SESSION_MODIFICATION_REQUEST, HAS_SEID, seq, context->cp_mode);

		pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

		node_address_t node_value = {0};
		/*Filling Node ID for F-SEID*/
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
		set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn->seid, node_value);

		/* Set PGW FQ-CSID */
		set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, &pdn->pgw_csid);

		uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
		int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
		pfcp_header_t *header = (pfcp_header_t *)pfcp_msg;
		header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

		if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr,SENT) < 0)
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Send "
					"PFCP Session Modification to SGW-U",LOG_VALUE);
		else
		{
#ifdef CP_BUILD
			add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
					&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
		}

		/* Update UE State */
		pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
		/* Set create session response */
		/*extract ebi_id from array as all the ebi's will be of same pdn.*/
		resp->linked_eps_bearer_id = mb_rsp->bearer_contexts_modified[0].eps_bearer_id.ebi_ebi;
		resp->msg_type = GTP_CREATE_SESSION_RSP;
		resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
		/* Need to think about proc in this perticuler scenario */
		return 0;
	}
#endif /* USE_CSID */
	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		/* Fill the modify bearer response */
		set_modify_bearer_response(
				gtpv2c_s11_tx, mb_rsp->header.teid.has_teid.seq,
				context, bearer, &resp->gtpc_msg.mbr);
		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;
	}else{
		set_create_session_response(
				gtpv2c_s11_tx, mb_rsp->header.teid.has_teid.seq,
				context, pdn, 0);

		pdn->state =  CONNECTED_STATE;
		pdn->proc = INITIAL_PDN_ATTACH_PROC;
		pdn->csr_sequence =0;
	}
	return 0;
}

int
process_sgwc_s5s8_mbr_for_mod_proc(mod_bearer_rsp_t *mb_rsp, gtpv2c_header_t *gtpv2c_s11_tx)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int ret = 0;
	struct resp_info *resp = NULL;
	int ebi_index = 0;

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	ebi_index = GET_EBI_INDEX(mb_rsp->bearer_contexts_modified[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}


	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */

	 ret = get_ue_context_by_sgw_s5s8_teid(mb_rsp->header.teid.has_teid.teid, &context);
	 if (ret < 0 || !context)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			" Ue context for teid: %d\n",
				LOG_VALUE, mb_rsp->header.teid.has_teid.teid);
	    return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	/* Fill the modify bearer response */
	set_modify_bearer_response_handover(
			gtpv2c_s11_tx, mb_rsp->header.teid.has_teid.seq,
			context, bearer, &resp->gtpc_msg.mbr);
	resp->state = CONNECTED_STATE;
	/* Update the UE state */
	pdn->state = CONNECTED_STATE;

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	return 0;
}

int
process_create_bearer_request(create_bearer_req_t *cbr)
{
	int ret = 0;
	int ebi_index = 0;
	uint8_t idx = 0;
	uint8_t new_ebi_index = 0;
	uint32_t  seq_no = 0;
	eps_bearer *bearers[MAX_BEARERS] = {0},*bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context_by_sgw_s5s8_teid(cbr->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"UE context for teid: %d\n", LOG_VALUE, cbr->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if(context != NULL ) {
		if(context->cbr_info.seq ==  cbr->header.teid.has_teid.seq) {
			if(context->cbr_info.status == CBR_IN_PROGRESS) {
				/* Discarding re-transmitted cbr */
				return GTPC_RE_TRANSMITTED_REQ;
			}else{
				/* Restransmitted CBR but processing already done for previous req */
				context->cbr_info.status = CBR_IN_PROGRESS;
			}
		} else {
			context->cbr_info.seq = cbr->header.teid.has_teid.seq;
			context->cbr_info.status = CBR_IN_PROGRESS;
		}
	}

	if(cbr->pres_rptng_area_act.header.len){
		store_presc_reporting_area_act_to_ue_context(&cbr->pres_rptng_area_act,
																		context);
	}

	if(context->cp_mode != PGWC) {

		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	}
	seq_no = cbr->header.teid.has_teid.seq;

	if(!cbr->lbi.header.len){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Mandatory IE"
			" (EPS bearer id) is missing in create bearer request \n",
			LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	ebi_index = GET_EBI_INDEX(cbr->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if ( pdn->proc == UE_REQ_BER_RSRC_MOD_PROC ) {
		seq_no = cbr->header.teid.has_teid.seq;
	} else {
		seq_no = bswap_32(cbr->header.teid.has_teid.seq);
		seq_no = seq_no >> 8;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	for(idx = 0; idx < cbr->bearer_cnt; ++idx) {
		bearer = rte_zmalloc_socket(NULL, (sizeof(eps_bearer)),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"Memory for Bearer, Error: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		new_ebi_index = (idx + MAX_BEARERS);
		resp->eps_bearer_ids[idx] = new_ebi_index + NUM_EBI_RESERVED;

		bearer->pdn = pdn;
		context->eps_bearers[new_ebi_index] = bearer;
		resp->bearer_count++;
		pdn->num_bearer++;
		if(!cbr->bearer_contexts[idx].eps_bearer_id.header.len){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error: Mandatory IE "
				"(EPS bearer id) is missing in bearer context in create bearer request \n",
				LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		pdn->eps_bearers[new_ebi_index] = bearer;
		if(cbr->bearer_contexts[idx].bearer_lvl_qos.header.len){
			bearer->qos.arp.preemption_vulnerability = cbr->bearer_contexts[idx].bearer_lvl_qos.pvi;

			bearer->qos.arp.priority_level = cbr->bearer_contexts[idx].bearer_lvl_qos.pl;

			bearer->qos.arp.preemption_capability = cbr->bearer_contexts[idx].bearer_lvl_qos.pci;

			bearer->qos.qci = cbr->bearer_contexts[idx].bearer_lvl_qos.qci;

			bearer->qos.ul_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_uplnk;

			bearer->qos.dl_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_dnlnk;

			bearer->qos.ul_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_uplnk;

			bearer->qos.dl_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_dnlnk;
		}
		else{
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error: Mandatory IE"
				" (bearer level QoS) is missing in Create Bearer Request\n",
				LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		ret = fill_ip_addr(cbr->bearer_contexts[idx].s58_u_pgw_fteid.ipv4_address,
								cbr->bearer_contexts[idx].s58_u_pgw_fteid.ipv6_address,
								&bearer->s5s8_pgw_gtpu_ip);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		bearer->s5s8_pgw_gtpu_teid = cbr->bearer_contexts[idx].s58_u_pgw_fteid.teid_gre_key;

		if(cbr->bearer_contexts[idx].tft.header.len){
			memset(resp->eps_bearer_lvl_tft[idx], 0, MAX_TFT_LEN);
			memcpy(resp->eps_bearer_lvl_tft[idx],
				cbr->bearer_contexts[idx].tft.eps_bearer_lvl_tft, MAX_TFT_LEN);
			resp->tft_header_len[idx] = cbr->bearer_contexts[idx].tft.header.len;
		}
		else{
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error: Mandatory IE"
				" (bearer level TFT) is missing in Create Bearer Request\n",
				LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}
		fill_dedicated_bearer_info(bearer, context, pdn, FALSE);

		pfcp_sess_mod_req.create_pdr_count += bearer->pdr_count;

		bearers[idx] = bearer;

		bearer->sequence = cbr->header.teid.has_teid.seq;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cbr->header, bearers, pdn, update_far, 0, cbr->bearer_cnt, context);
	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

	ret = set_dest_address(pdn->upf_ip, &upf_pfcp_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
							upf_pfcp_sockaddr, SENT) < 0)
	clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending "
		"modification request to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"for BRC: proc set to : %s\n",
			LOG_VALUE, get_proc_string(pdn->proc));

	if ( pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
		resp->proc = UE_REQ_BER_RSRC_MOD_PROC;
	} else {
		resp->proc = DED_BER_ACTIVATION_PROC;
		pdn->proc = DED_BER_ACTIVATION_PROC;
	}

	context->sequence = seq_no;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->gtpc_msg.cb_req = *cbr;
	resp->bearer_count = cbr->bearer_cnt;
	resp->linked_eps_bearer_id = pdn->default_bearer_id;
	resp->msg_type = GTP_CREATE_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->cp_mode = context->cp_mode;

	return 0;
}


int
process_delete_bearer_request(del_bearer_req_t *db_req, ue_context *context, uint8_t proc_type)
{
	int ebi_index = 0, ret = 0;
	uint8_t bearer_cntr = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	int default_bearer_index = 0;
	eps_bearer *bearers[MAX_BEARERS] = {0};
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	uint8_t jCnt = 0;

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	if (db_req->lbi.header.len != 0) {

		default_bearer_index = GET_EBI_INDEX(db_req->lbi.ebi_ebi);
		if (default_bearer_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		pdn = GET_PDN(context, default_bearer_index);
		if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, default_bearer_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		for (uint8_t iCnt = 0; iCnt < MAX_BEARERS; ++iCnt) {
			if (NULL != pdn->eps_bearers[iCnt]) {
				bearers[jCnt] = pdn->eps_bearers[iCnt];
				bearers[jCnt]->sequence = db_req->header.teid.has_teid.seq;
				jCnt++;
			}
		}
		bearer_cntr = pdn->num_bearer;
	} else {
		for (uint8_t iCnt = 0; iCnt < db_req->bearer_count; ++iCnt) {
			ebi_index = GET_EBI_INDEX(db_req->eps_bearer_ids[iCnt].ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			bearers[iCnt] = context->eps_bearers[ebi_index];
			bearers[iCnt]->sequence = db_req->header.teid.has_teid.seq;
		}

		pdn = GET_PDN(context, ebi_index);
		if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
		bearer_cntr = db_req->bearer_count;
	}

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, pdn, bearers, bearer_cntr);

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
							upf_pfcp_sockaddr, SENT) < 0)
	clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending Session "
		"Modification Request to SGW-U. Error: %i\n", LOG_VALUE, errno);
	else {
#ifdef CP_BUILD
		ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
				&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = db_req->header.teid.has_teid.seq;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	if (db_req->lbi.header.len != 0) {
		resp->linked_eps_bearer_id = db_req->lbi.ebi_ebi;
		resp->bearer_count = 0;
	} else {
		resp->bearer_count = db_req->bearer_count;
		for (uint8_t iCnt = 0; iCnt < db_req->bearer_count; ++iCnt) {
			resp->eps_bearer_ids[iCnt] = db_req->eps_bearer_ids[iCnt].ebi_ebi;
		}
	}

	resp->msg_type = GTP_DELETE_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = proc_type;
	resp->cp_mode = context->cp_mode;
	resp->gtpc_msg.db_req = *db_req;
	pdn->proc = proc_type;

	return 0;
}

int
process_delete_bearer_resp(del_bearer_rsp_t *db_rsp, ue_context *context, uint8_t proc_type)
{
	int ebi_index = 0;
	uint8_t bearer_cntr = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	eps_bearer *bearers[MAX_BEARERS] = {0};
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};


	for (uint8_t iCnt = 0; iCnt < db_rsp->bearer_count; ++iCnt) {
		ebi_index = GET_EBI_INDEX(db_rsp->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		bearers[iCnt] = context->eps_bearers[ebi_index];
	}

	bearer_cntr = db_rsp->bearer_count;

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	fill_pfcp_sess_mod_req_pgw_init_remove_pdr(&pfcp_sess_mod_req, pdn, bearers, bearer_cntr);

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);


	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
							upf_pfcp_sockaddr, SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error in Sending "
		"Modification Request to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	else {
#ifdef CP_BUILD
		ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		add_pfcp_if_timer_entry(db_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = db_rsp->header.teid.has_teid.seq;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->bearer_count = db_rsp->bearer_count;
	for (uint8_t iCnt = 0; iCnt < db_rsp->bearer_count; ++iCnt) {
		resp->eps_bearer_ids[iCnt] = db_rsp->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi;
	}

	resp->proc = proc_type;
	pdn->proc = proc_type;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->msg_type = GTP_DELETE_BEARER_RSP;
	resp->cp_mode = context->cp_mode;
	return 0;
}

int
process_cs_resp_cb_request(create_bearer_req_t *cbr)
{
	int ret = 0;
	int ebi_index = 0;
	uint8_t idx = 0;
	uint8_t new_ebi_index = 0;
	uint32_t  seq_no = 0;
	eps_bearer *bearers[MAX_BEARERS] = {0},*bearer = NULL,*dedicated_bearer = NULL;
	uint8_t index = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context_by_sgw_s5s8_teid(cbr->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"UE context for teid: %d\n", LOG_VALUE, cbr->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	seq_no = bswap_32(cbr->header.teid.has_teid.seq);
	seq_no = seq_no >> 8;

	ebi_index = GET_EBI_INDEX(cbr->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn = context->eps_bearers[ebi_index]->pdn;
	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No PDN found "
			"for ebi_index : %lu", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
				"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->apn_restriction = resp->gtpc_msg.cs_rsp.apn_restriction.rstrct_type_val;

	/*Reseting PDN type to Update as per the type sent in CSResp from PGW-C*/
	pdn->pdn_type.ipv4 = 0;
	pdn->pdn_type.ipv6 = 0;

	if (resp->gtpc_msg.cs_rsp.paa.pdn_type == PDN_IP_TYPE_IPV6
			|| resp->gtpc_msg.cs_rsp.paa.pdn_type == PDN_IP_TYPE_IPV4V6) {

		pdn->pdn_type.ipv6 = PRESENT;
		memcpy(pdn->ipv6.s6_addr, resp->gtpc_msg.cs_rsp.paa.paa_ipv6, IPV6_ADDRESS_LEN);
		pdn->prefix_len = resp->gtpc_msg.cs_rsp.paa.ipv6_prefix_len;
	}

	if (resp->gtpc_msg.cs_rsp.paa.pdn_type == PDN_IP_TYPE_IPV4
			|| resp->gtpc_msg.cs_rsp.paa.pdn_type == PDN_IP_TYPE_IPV4V6) {

		pdn->pdn_type.ipv4 = PRESENT;
		pdn->ipv4.s_addr = resp->gtpc_msg.cs_rsp.paa.pdn_addr_and_pfx;
	}

	ret = fill_ip_addr(resp->gtpc_msg.cs_rsp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address,
			resp->gtpc_msg.cs_rsp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv6_address,
			&pdn->s5s8_pgw_gtpc_ip);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	pdn->s5s8_pgw_gtpc_teid =
		resp->gtpc_msg.cs_rsp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.teid_gre_key;


	for (uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = pdn->eps_bearers[i];
		if(bearer == NULL)
			continue;
		/* TODO: Implement TFTs on default bearers
		 *          if (create_s5s8_session_response.bearer_tft_ie) {
		 *                     }
		 *                            */
		/* TODO: Implement PGWC S5S8 bearer QoS */
		if (resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.header.len) {
			bearer->qos.qci = resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.qci;
			bearer->qos.ul_mbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_uplnk;
			bearer->qos.dl_mbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_dnlnk;
			bearer->qos.ul_gbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_uplnk;
			bearer->qos.dl_gbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_dnlnk;
			bearer->qos.arp.preemption_vulnerability =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.pvi;
			bearer->qos.arp.spare1 =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.spare2;
			bearer->qos.arp.priority_level =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.pl;
			bearer->qos.arp.preemption_capability =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.pci;
			bearer->qos.arp.spare2 =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.spare3;
		}

		ret = fill_ip_addr(resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.ipv4_address,
			resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.ipv6_address,
			&bearer->s5s8_pgw_gtpu_ip);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
		bearer->s5s8_pgw_gtpu_teid =
			resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.teid_gre_key;
		bearer->pdn = pdn;

		update_far[index].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_pgw_gtpu_teid;

		ret = set_node_address(&update_far[index].upd_frwdng_parms.outer_hdr_creation.ipv4_address,
			update_far[index].upd_frwdng_parms.outer_hdr_creation.ipv6_address,
			bearer->s5s8_pgw_gtpu_ip);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		update_far[index].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.interface_type,
					context->cp_mode);
		update_far[index].far_id.far_id_value =
			get_far_id(bearer, update_far[index].upd_frwdng_parms.dst_intfc.interface_value);

		pfcp_sess_mod_req.update_far_count++;

		bearers[index] = bearer;
	}
#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	/* PGW FQ-CSID */
	if (resp->gtpc_msg.cs_rsp.pgw_fqcsid.header.len) {
		ret = add_peer_addr_entry_for_fqcsid_ie_node_addr(
				&pdn->s5s8_pgw_gtpc_ip, &resp->gtpc_msg.cs_rsp.pgw_fqcsid,
				S5S8_SGWC_PORT_ID);
		if (ret)
			return ret;

		/* Stored the PGW CSID by PGW Node address */
		ret = add_fqcsid_entry(&resp->gtpc_msg.cs_rsp.pgw_fqcsid, context->pgw_fqcsid);
		if(ret)
			return ret;

		fill_pdn_fqcsid_info(&pdn->pgw_csid, context->pgw_fqcsid);

	} else {
		tmp = get_peer_addr_csids_entry(&(pdn->s5s8_pgw_gtpc_ip), ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: Failed to "
					"add PGW CSID by PGW Node addres %s \n", LOG_VALUE,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		memcpy(&(tmp->node_addr), &(pdn->s5s8_pgw_gtpc_ip), sizeof(node_address_t));
		memcpy(&((context->pgw_fqcsid)->node_addr[(context->pgw_fqcsid)->num_csid]),
				&(pdn->s5s8_pgw_gtpc_ip), sizeof(node_address_t));
	}

	/* Link local CSID with PGW CSID */
	if (pdn->pgw_csid.num_csid) {
		if (link_gtpc_peer_csids(&pdn->pgw_csid,
					&pdn->sgw_csid, S5S8_SGWC_PORT_ID)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with PGW FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return -1;
		}

		if (link_sess_with_peer_csid(&pdn->pgw_csid, pdn, S5S8_SGWC_PORT_ID)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error : Failed to Link "
					"Session with Peer CSID\n", LOG_VALUE);
			return -1;
		}

		/* Set PGW FQ-CSID */
		set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, &pdn->pgw_csid);
	}
#endif /* USE_CSID */
	for(idx = 0; idx < cbr->bearer_cnt; ++idx) {
		dedicated_bearer = rte_zmalloc_socket(NULL, (sizeof(eps_bearer)),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (dedicated_bearer == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for Bearer, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		new_ebi_index = idx + MAX_BEARERS;
		resp->eps_bearer_ids[idx] = new_ebi_index + NUM_EBI_RESERVED;

		dedicated_bearer->pdn = pdn;

		context->eps_bearers[new_ebi_index] = dedicated_bearer;
		pdn->eps_bearers[new_ebi_index] = dedicated_bearer;

		dedicated_bearer->qos.arp.preemption_vulnerability = cbr->bearer_contexts[idx].bearer_lvl_qos.pvi;

		dedicated_bearer->qos.arp.priority_level = cbr->bearer_contexts[idx].bearer_lvl_qos.pl;

		dedicated_bearer->qos.arp.preemption_capability = cbr->bearer_contexts[idx].bearer_lvl_qos.pci;

		dedicated_bearer->qos.qci = cbr->bearer_contexts[idx].bearer_lvl_qos.qci;

		dedicated_bearer->qos.ul_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_uplnk;

		dedicated_bearer->qos.dl_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_dnlnk;

		dedicated_bearer->qos.ul_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_uplnk;

		dedicated_bearer->qos.dl_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_dnlnk;

		ret = fill_ip_addr(cbr->bearer_contexts[idx].s58_u_pgw_fteid.ipv4_address,
			cbr->bearer_contexts[idx].s58_u_pgw_fteid.ipv6_address,
			&dedicated_bearer->s5s8_pgw_gtpu_ip);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		dedicated_bearer->s5s8_pgw_gtpu_teid = cbr->bearer_contexts[idx].s58_u_pgw_fteid.teid_gre_key;

		memset(resp->eps_bearer_lvl_tft[idx], 0, MAX_TFT_LEN);
		memcpy(resp->eps_bearer_lvl_tft[idx],
			cbr->bearer_contexts[idx].tft.eps_bearer_lvl_tft, MAX_TFT_LEN);
		resp->tft_header_len[idx] = cbr->bearer_contexts[idx].tft.header.len;

		fill_dedicated_bearer_info(dedicated_bearer, context, pdn, FALSE);

		pfcp_sess_mod_req.create_pdr_count += dedicated_bearer->pdr_count;
		bearers[index] = dedicated_bearer;
		index++;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cbr->header, bearers, pdn,
			update_far, 0, cbr->bearer_cnt, context);

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
							upf_pfcp_sockaddr, SENT) < 0)
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error sending while "
			"session delete request at sgwc %i\n", LOG_VALUE, errno);
	else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->bearer_count = cbr->bearer_cnt;
	resp->msg_type = GTP_CREATE_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = ATTACH_DEDICATED_PROC;
	pdn->proc = ATTACH_DEDICATED_PROC;
	resp->cp_mode = context->cp_mode;

	return 0;
}

int
process_mb_request_cb_response(mod_bearer_req_t *mbr, create_bearer_rsp_t *cb_rsp)
{

	int ret = 0;
	int ebi_index = 0, index = 0, idx = 0;
	uint8_t seq_no;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL, *bearers[MAX_BEARERS] = {0}, *dedicated_bearer =  NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	eps_bearer *remove_bearers[MAX_BEARERS] = {0};

	if (mbr->header.teid.has_teid.teid) {
		ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				(const void *) &mbr->header.teid.has_teid.teid,
				(void **) &context);
		if (ret < 0 || !context) {
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
	} else {
		if (NOT_PRESENT != cb_rsp->header.teid.has_teid.teid) {
			if(get_ue_context(cb_rsp->header.teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE, cb_rsp->header.teid.has_teid.teid);

				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
		} else {
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
	}

	if (mbr->bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi) {
		ebi_index = GET_EBI_INDEX(mbr->bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		bearer = context->eps_bearers[ebi_index];
	} else {
		ebi_index = GET_EBI_INDEX(cb_rsp->bearer_contexts[idx].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		bearer = context->eps_bearers[(idx + MAX_BEARERS)];
	}

	if (get_sess_entry(bearer->pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, bearer->pdn->seid);
		return -1;
	}

	pdn = bearer->pdn;
	pfcp_sess_mod_req.update_far_count = 0;

	/*Updating the console count */
	cp_stats.modify_bearer++;

	if ((NULL != context) && (mbr->header.teid.has_teid.seq)) {
		if(context->mbr_info.seq ==  mbr->header.teid.has_teid.seq) {
			if(context->mbr_info.status == MBR_IN_PROGRESS) {
				/* Discarding re-transmitted mbr */
				return GTPC_RE_TRANSMITTED_REQ;
			}else{
				/* Restransmitted MBR but processing altready done for previous req */
				context->mbr_info.status = MBR_IN_PROGRESS;
			}
		}else{
			context->mbr_info.seq = mbr->header.teid.has_teid.seq;
			context->mbr_info.status = MBR_IN_PROGRESS;
		}
	}
	uint8_t remove_cnt = 0;

	resp->cbr_seq = resp->gtpc_msg.cb_rsp.header.teid.has_teid.seq ;
	if(resp->gtpc_msg.cb_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED) {

			for(uint8_t i = 0; i < resp->gtpc_msg.cb_rsp.bearer_cnt; i++) {
				remove_bearers[remove_cnt++] = context->eps_bearers[(i + MAX_BEARERS)];
				resp->eps_bearer_ids[idx] =
					resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi;
				resp->eps_bearer_ids[idx] =
					resp->gtpc_msg.cb_rsp.bearer_contexts[idx].cause.cause_value;
			}

	}

	if(resp->gtpc_msg.cb_rsp.cause.cause_value == GTPV2C_CAUSE_REQUEST_ACCEPTED) {

		for(idx = 0; idx < resp->gtpc_msg.cb_rsp.bearer_cnt; idx++) {
			ebi_index = GET_EBI_INDEX(resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			if(((ebi_index + NUM_EBI_RESERVED) == pdn->default_bearer_id) ||
					(((*context).bearer_bitmap & (1 << ebi_index)) == 1)  ||
					(resp->gtpc_msg.cb_rsp.bearer_contexts[idx].cause.cause_value
					 != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

				if((resp->gtpc_msg.cb_rsp.bearer_contexts[idx].cause.cause_value
					 != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

					dedicated_bearer = context->eps_bearers[(idx + MAX_BEARERS)];
					context->eps_bearers[ebi_index] = dedicated_bearer;
					pdn->eps_bearers[ebi_index] = dedicated_bearer;

				}
				remove_bearers[remove_cnt] = context->eps_bearers[(idx + MAX_BEARERS)];
				resp->eps_bearer_ids[idx] =
					resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi;
				resp->eps_bearer_ids[idx] =
					resp->gtpc_msg.cb_rsp.bearer_contexts[idx].cause.cause_value;

				remove_cnt++;
				continue;
			}

			dedicated_bearer = context->eps_bearers[(idx + MAX_BEARERS)];
			resp->eps_bearer_ids[idx] = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi;
			context->eps_bearers[ebi_index] = dedicated_bearer;
			dedicated_bearer->eps_bearer_id =
				resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi;

			(*context).bearer_bitmap |= (1 << ebi_index);

			context->eps_bearers[(idx + MAX_BEARERS )] = NULL;

			pdn->eps_bearers[ebi_index] = dedicated_bearer;
			pdn->eps_bearers[(idx + MAX_BEARERS )] = NULL;
			if (dedicated_bearer == NULL) {
				/* TODO:
				 * This mean ebi we allocated and received doesnt match
				 * In correct design match the bearer in transtient struct from sgw-u teid
				 * */
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Context not found "
						"Create Bearer Response with cause %d \n", LOG_VALUE, ret);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			ret = fill_ip_addr(resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.ipv4_address,
						resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.ipv6_address,
						&dedicated_bearer->s1u_enb_gtpu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}

			dedicated_bearer->s1u_enb_gtpu_teid = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.teid_gre_key;

			if (resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.header.len  != 0) {
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
					dedicated_bearer->s1u_enb_gtpu_teid;

				ret = set_node_address(&update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address,
					update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv6_address,
					dedicated_bearer->s1u_enb_gtpu_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}

				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
					check_interface_type(resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.interface_type,
							context->cp_mode);
				update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
					get_far_id(dedicated_bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(context);
				pfcp_sess_mod_req.update_far_count++;
			}

			bearers[index] = dedicated_bearer;
			index++;
		}
	}

	if(remove_cnt != 0 ) {
		fill_pfcp_sess_mod_req_with_remove_pdr(&pfcp_sess_mod_req, pdn, remove_bearers, remove_cnt);
	}


	if (mbr->bearer_count) {
		for(uint8_t i = 0; i < mbr->bearer_count; i++) {

			if (!mbr->bearer_contexts_to_be_modified[i].eps_bearer_id.header.len
					|| !mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Dropping packet\n",
						LOG_VALUE);
				return GTPV2C_CAUSE_INVALID_LENGTH;
			}

			ebi_index = GET_EBI_INDEX(mbr->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			/*Handling Mutiple Bearer Context in MBR*/
			if ((resp->gtpc_msg.cb_rsp.bearer_cnt != 0 ) && ((ebi_index + NUM_EBI_RESERVED) != pdn->default_bearer_id)) {
				continue;
			}

			if (!(context->bearer_bitmap & (1 << ebi_index))) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT" Received modify bearer on non-existent EBI - "
						"Dropping packet\n", LOG_VALUE);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			bearer = context->eps_bearers[ebi_index];
			if (!bearer) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Received modify bearer on non-existent EBI - "
					"for while PFCP Session Modification Request Modify Bearer "
					"Request, Dropping packet\n", LOG_VALUE);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}


			pdn = bearer->pdn;
			if (mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len  != 0){

				ret = fill_ip_addr(mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address,
					mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv6_address,
						&bearer->s1u_enb_gtpu_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}

				bearer->s1u_enb_gtpu_teid =
					mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.teid_gre_key;

				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
					bearer->s1u_enb_gtpu_teid;

				ret = set_node_address(&update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address,
					update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv6_address,
					bearer->s1u_enb_gtpu_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}

				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
					check_interface_type(mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.interface_type,
							context->cp_mode);
				update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
					get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(pdn->context);
				pfcp_sess_mod_req.update_far_count++;

			}

			bearers[index] = bearer;
			index++;

		} /*forloop*/
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &resp->gtpc_msg.cb_rsp.header, bearers, pdn,
			update_far, 0, index, context);

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	seq_no = bswap_32(resp->gtpc_msg.cb_rsp.header.teid.has_teid.seq);
	seq_no = seq_no >> 8;

#ifdef USE_CSID
	/* Generate the permant CSID for SGW */
	if (context->cp_mode != PGWC) {
		/* Get the copy of existing SGW CSID */
		fqcsid_t tmp_csid_t = {0};
		if (pdn->sgw_csid.num_csid) {
				memcpy(&tmp_csid_t, &pdn->sgw_csid, sizeof(fqcsid_t));
		}

		/* Update the entry for peer nodes */
		if (fill_peer_node_info(pdn, bearer)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill peer node info and assignment of the "
				"CSID Error: %s\n", LOG_VALUE, strerror(errno));
			return  GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (pdn->flag_fqcsid_modified == TRUE) {
			uint8_t tmp_csid = 0;
			/* Validate the exsiting CSID or allocated new one */
			for (uint8_t inx1 = 0; inx1 < tmp_csid_t.num_csid; inx1++) {
				if (pdn->sgw_csid.local_csid[pdn->sgw_csid.num_csid - 1] ==
						tmp_csid_t.local_csid[inx1]) {
					tmp_csid = tmp_csid_t.local_csid[inx1];
					break;
				}
			}

			if (!tmp_csid) {
				for (uint8_t inx = 0; inx < tmp_csid_t.num_csid; inx++) {
					/* Remove the session link from old CSID */
					sess_csid *tmp1 = NULL;
					tmp1 = get_sess_csid_entry(tmp_csid_t.local_csid[inx], REMOVE_NODE);

					if (tmp1 != NULL) {
						/* Remove node from csid linked list */
						tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

						int8_t ret = 0;
						/* Update CSID Entry in table */
						ret = rte_hash_add_key_data(seids_by_csid_hash,
										&tmp_csid_t.local_csid[inx], tmp1);
						if (ret) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
									"\n\tError= %s\n",
									LOG_VALUE, tmp_csid_t.local_csid[inx],
									rte_strerror(abs(ret)));
							return GTPV2C_CAUSE_SYSTEM_FAILURE;
						}
						if (tmp1 == NULL) {
							/* Removing temporary local CSID associated with MME */
							remove_peer_temp_csid(&pdn->mme_csid, tmp_csid_t.local_csid[inx],
									S11_SGW_PORT_ID);

							/* emoving temporary local CSID assocoated with PGWC */
							remove_peer_temp_csid(&pdn->pgw_csid, tmp_csid_t.local_csid[inx],
									S5S8_SGWC_PORT_ID);
							/* Delete Local CSID entry */
							del_sess_csid_entry(tmp_csid_t.local_csid[inx]);
						}
						/* Delete CSID from the context */
						remove_csid_from_cntx(context->sgw_fqcsid, &tmp_csid_t);

					} else {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to "
								"get Session ID entry for CSID:%u\n", LOG_VALUE,
								tmp_csid_t.local_csid[inx]);
					}

					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Remove session link from Old CSID:%u\n",
							LOG_VALUE, tmp_csid_t.local_csid[inx]);
				}
			}

			/* update entry for cp session id with link local csid */
			sess_csid *tmp = NULL;
			tmp = get_sess_csid_entry(
					pdn->sgw_csid.local_csid[pdn->sgw_csid.num_csid - 1],
					ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get session of CSID entry %s \n",
						LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Link local csid with session id */
			/* Check head node created ot not */
			if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
				sess_csid *new_node = NULL;
				/* Add new node into csid linked list */
				new_node = add_sess_csid_data_node(tmp);
				if(new_node == NULL ) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
						"ADD new node into CSID linked list : %s\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				} else {
					new_node->cp_seid = pdn->seid;
					new_node->up_seid = pdn->dp_seid;
				}

			} else {
				tmp->cp_seid = pdn->seid;
				tmp->up_seid = pdn->dp_seid;
			}
			/* Fill the fqcsid into the session est request */
			if (fill_fqcsid_sess_mod_req(&pfcp_sess_mod_req, pdn)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to fill "
					"FQ-CSID in Session Establishment Request, "
					"Error: %s\n", LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
		}
	}

#endif /* USE_CSID */

	/*ULI CHECK*/

	context->uli_flag = FALSE;
	if(resp->gtpc_msg.cb_rsp.uli.header.len != 0) {
		check_for_uli_changes(&resp->gtpc_msg.cb_rsp.uli, context);
	}

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, INTERFACE) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending MBR to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	else
	{
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(resp->gtpc_msg.cb_rsp.header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	if (mbr->header.teid.has_teid.seq) {
		context->sequence = mbr->header.teid.has_teid.seq;
	}

	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->bearer_count = resp->gtpc_msg.cb_rsp.bearer_cnt;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->cp_mode = context->cp_mode;
	memcpy(&resp->gtpc_msg.mbr, mbr, sizeof(struct mod_bearer_req_t));

	return 0;
}

