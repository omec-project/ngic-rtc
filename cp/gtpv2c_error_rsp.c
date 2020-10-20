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

#include "gtpv2c_error_rsp.h"

#ifdef CP_BUILD
#include "sm_arr.h"
#include "cp_config.h"
#include "cp_stats.h"
#include "ipc_api.h"
#include "cp_timer.h"
#include "teid.h"
#include "cp.h"
#include "ue.h"
#include "gtpc_session.h"
#include "debug_str.h"
#include "gtpv2c.h"
#include "pfcp.h"
#endif /* CP_BUILD */

peer_addr_t upf_pfcp_sockaddr;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_sockaddr_len;
extern uint16_t payload_length;
extern int s5s8_fd;
extern int s5s8_fd_v6;
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern pfcp_config_t config;
extern int gx_app_sock;
extern peer_addr_t s5s8_recv_sockaddr;
extern int clSystemLog;


int8_t
clean_up_while_error(uint8_t ebi, ue_context *context, uint32_t teid, uint64_t *imsi_val, uint32_t seq, msg_info *msg)
{
	pdn_connection *pdn = NULL;
	struct resp_info *resp;
	bool Error_sent = False;
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	if (teid != 0) {
		if (ebi_index > 0) {
			pdn = GET_PDN(context, ebi_index);
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
						"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			}

			if (pdn != NULL && context != NULL) {

				if (get_sess_entry(pdn->seid, &resp) == 0) {

					if ((resp->state == PFCP_SESS_DEL_REQ_SNT_STATE) || (resp->state == ERROR_OCCURED_STATE)
							||(resp->state == PFCP_SESS_MOD_REQ_SNT_STATE)) {
						Error_sent = True;
					}


					/*NOTE: IF SGWC receives CSR RSP with some error from PGWC,then SGWC will do clean up
					 * on its side as well as will send DSR request to PGWC for clean up at PGWC*/

					if ((SGWC == context->cp_mode) && (!context->piggyback)) {
						if(msg->gtpc_msg.cs_rsp.cause.cause_value == GTPV2C_CAUSE_REQUEST_ACCEPTED ||
								msg->msg_type == PFCP_SESSION_MODIFICATION_RESPONSE ) {

							bzero(&tx_buf, sizeof(tx_buf));
							gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
							del_sess_req_t del_sess_req = {0};

							if(msg->msg_type == PFCP_SESSION_MODIFICATION_RESPONSE) {

								fill_ds_request(&del_sess_req, context, ebi_index, pdn->s5s8_pgw_gtpc_teid);
							}
							else {
								fill_ds_request(&del_sess_req, context, ebi_index,
										msg->gtpc_msg.cs_rsp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.teid_gre_key);
							}

							payload_length = encode_del_sess_req(&del_sess_req, (uint8_t *)gtpv2c_tx);

							gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
								s5s8_recv_sockaddr, SENT);

						}
					}
					/* checking session is established or not on user plane */
					if (PFCP_SESS_EST_REQ_SNT_STATE != resp->state) {
						pfcp_sess_del_req_t pfcp_sess_del_req = {0};
						fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);

						if(msg->msg_type == PFCP_SESSION_ESTABLISHMENT_RESPONSE) {
							pfcp_sess_del_req.header.seid_seqno.has_seid.seid =
								msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid;
						}
						else {

							pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;
						}

						uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
						int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);

						if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
									upf_pfcp_sockaddr, SENT) < 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error "
									"in Sending Session Modification Request. "
									"Error : %i\n", LOG_VALUE, errno);
						} else {
							add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
									&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
						}
					}

					resp->state = ERROR_OCCURED_STATE;
					resp->msg_type = GTP_CREATE_SESSION_RSP;
					resp->linked_eps_bearer_id = ebi;
					if (context->piggyback) {
						resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
					}

				} else {
					clean_up_upf_context(pdn, context);

					if(config.use_dns) {
						/* Delete UPFList entry from UPF Hash */
						if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi)))
								< 0) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Error on upflist_by_ue_hash deletion of IMSI \n",
									LOG_VALUE);
						}
					}

					clean_context_hash(context, teid, &context->imsi, Error_sent);

				}

				pdn->state = ERROR_OCCURED_STATE;
			}
		}
	} else {
		if(config.use_dns) {
			/* Delete UPFList entry from UPF Hash */
			if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi)))
					< 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error on upflist_by_ue_hash deletion of IMSI \n",
						LOG_VALUE);
			}
		}

		clean_context_hash(NULL, teid, imsi_val, Error_sent);
	}
	return 0;
	RTE_SET_USED(seq);
}

int8_t
clean_up_while_cbr_error(uint32_t teid, uint8_t msg_type, pdn_connection *pdn)
{
	int ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearers[MAX_BEARERS];
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	struct resp_info *resp = NULL;

	if (teid == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"TEID not found while "
			"cleaning up create bearer error response", LOG_VALUE);
		return -1;
	}

	if (get_ue_context(teid, &context) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"UE context not found "
			"for teid: %d\n", LOG_VALUE, teid);
		return -1;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE, pdn->seid);
		return -1;
	}

	for (int idx = 0; idx < resp->bearer_count ; ++idx) {
		ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[idx]);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return -1;
		}
		bearers[idx] = context->eps_bearers[ebi_index];
	}

	if ((context->cp_mode == SGWC && msg_type != GTP_CREATE_BEARER_REQ) ||
		((context->cp_mode == PGWC || context->cp_mode == SAEGWC) && msg_type != GX_RAR_MSG) ) {

		fill_pfcp_sess_mod_req_pgw_init_remove_pdr(&pfcp_sess_mod_req, pdn,
		        bearers, resp->bearer_count);

		uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
		int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

		if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
								upf_pfcp_sockaddr, SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error "
			"in Sending Session Modification Request. "
			"Error : %i\n", LOG_VALUE, errno);
		else {
#ifdef CP_BUILD
			add_pfcp_if_timer_entry( teid,
					&upf_pfcp_sockaddr, pfcp_msg, encoded, GET_EBI_INDEX(pdn->default_bearer_id));
#endif /* CP_BUILD */
		}

		resp->state = ERROR_OCCURED_STATE;
		resp->proc = pdn->proc;
	}

	if(context != NULL && resp != NULL && context->eps_bearers[ebi_index]->pdn != NULL) {
		delete_dedicated_bearers(context->eps_bearers[ebi_index]->pdn,
				resp->eps_bearer_ids, resp->bearer_count);
	}

	return 0;
}

void get_error_rsp_info(msg_info *msg, err_rsp_info *rsp_info, uint8_t index)
{

	int ret = 0;
	int ebi_index = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	switch (msg->msg_type) {

	case GTP_CREATE_SESSION_REQ: {

		rsp_info->sender_teid = msg->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key;
		rsp_info->seq = msg->gtpc_msg.csr.header.teid.has_teid.seq;
		rsp_info->bearer_count = msg->gtpc_msg.csr.bearer_count;
		for (uint8_t i = 0; i < rsp_info->bearer_count; i++ ) {
			if (msg->gtpc_msg.csr.bearer_contexts_to_be_created[index].header.len) {
				rsp_info->ebi = msg->gtpc_msg.csr.bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi;
				rsp_info->bearer_id[i] =  msg->gtpc_msg.csr.bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi;
			} else
				rsp_info->offending = GTP_IE_CREATE_SESS_REQUEST_BEARER_CTXT_TO_BE_CREATED;
		}
		rsp_info->teid =  msg->gtpc_msg.csr.header.teid.has_teid.teid;

		if (!msg->gtpc_msg.csr.sender_fteid_ctl_plane.header.len)
			rsp_info->offending = GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT;

		if (!msg->gtpc_msg.csr.imsi.header.len)
			rsp_info->offending = GTP_IE_IMSI;

		if (!msg->gtpc_msg.csr.apn_ambr.header.len)
			rsp_info->offending = GTP_IE_AGG_MAX_BIT_RATE;

		if (!msg->gtpc_msg.csr.pdn_type.header.len)
			rsp_info->offending = GTP_IE_PDN_TYPE;

		for (uint8_t uiCnt = 0; uiCnt < rsp_info->bearer_count; ++uiCnt) {
			if (!msg->gtpc_msg.csr.bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.header.len)
				rsp_info->offending = GTP_IE_BEARER_QLTY_OF_SVC;
		}

		if (!msg->gtpc_msg.csr.rat_type.header.len)
			rsp_info->offending = GTP_IE_RAT_TYPE;

		if (!msg->gtpc_msg.csr.apn.header.len)
			rsp_info->offending = GTP_IE_ACC_PT_NAME;

		break;
	}

	case PFCP_ASSOCIATION_SETUP_RESPONSE:{

		upf_context_t *upf_context = NULL;
		pdn_connection *pdn = NULL;

		/*Retrive association state based on UPF IP. */
		ret = rte_hash_lookup_data(upf_context_by_ip_hash,
		                           (const void*) & (msg->upf_ip), (void **) & (upf_context));
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"UPF context "
				"not found for Msg_Type:%u, UPF IP Type : %s, UPF IPv4 : "IPV4_ADDR"\t"
				"UPF IPv6 : "IPv6_FMT"", LOG_VALUE, msg->msg_type,
				ip_type_str(msg->upf_ip.ip_type),
				IPV4_ADDR_HOST_FORMAT(msg->upf_ip.ipv4_addr),
				PRINT_IPV6_ADDR(msg->upf_ip.ipv6_addr));
			return;
		}

		context_key *key = (context_key *)upf_context->pending_csr_teid[index];
		if (get_ue_context(key->teid, &context) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE context not found "
			"for teid: %d\n", LOG_VALUE, key->teid);
		}

		pdn = GET_PDN(context, key->ebi_index);
		if(pdn == NULL){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, key->ebi_index);
		} else {
			rsp_info->bearer_count = context->bearer_count;
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->ebi = key->ebi_index + NUM_EBI_RESERVED;
			rsp_info->teid = key->teid;
			for (int i=0 ; i<MAX_BEARERS ; i++) {
				if (pdn->eps_bearers[i] != NULL) {
					uint8_t itr = 0;
					rsp_info->bearer_id[itr] =
							pdn->eps_bearers[i]->eps_bearer_id;
					itr++;
				}
			}
		}
		break;
	}

	case PFCP_SESSION_ESTABLISHMENT_RESPONSE: {


		if (get_sess_entry(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE,
					msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);
		}

		if(get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid), &context) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE context "
			"for teid: %d\n", LOG_VALUE,
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid));
		}
		rsp_info->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->bearer_count =  context->bearer_count;
			rsp_info->ebi = resp->linked_eps_bearer_id;

			for (int i=0 ; i<MAX_BEARERS ; i++) {
				if (context->eps_bearers[i] != NULL) {
					rsp_info->bearer_id[i] = context->eps_bearers[i]->eps_bearer_id;
				}
			}
		}
		break;
	}

	case GTP_CREATE_SESSION_RSP: {

		if (get_ue_context_while_error(msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE context not found "
			"for teid: %d\n", LOG_VALUE, msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid);
		}

		if (context != NULL){
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
		}
		rsp_info->bearer_count =  msg->gtpc_msg.cs_rsp.bearer_count;
		for (uint8_t i = 0; i < msg->gtpc_msg.cs_rsp.bearer_count; i++) {
			rsp_info->ebi = msg->gtpc_msg.cs_rsp.bearer_contexts_created[i].eps_bearer_id.ebi_ebi;
			rsp_info->bearer_id[i] = msg->gtpc_msg.cs_rsp.bearer_contexts_created[i].eps_bearer_id.ebi_ebi;
		}
		rsp_info->teid = msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid;
		break;
	}

	case GTP_MODIFY_BEARER_REQ: {

		rsp_info->seq = msg->gtpc_msg.mbr.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.mbr.header.teid.has_teid.teid;
		rsp_info->bearer_count = msg->gtpc_msg.mbr.bearer_count;
		for (uint8_t uiCnt = 0; uiCnt < msg->gtpc_msg.mbr.bearer_count; ++uiCnt) {
			rsp_info->ebi = msg->gtpc_msg.mbr.bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi;
			rsp_info->bearer_id[uiCnt] =  msg->gtpc_msg.mbr.bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi;
		}

		/* Fill the GTPv2c header teid from the request */
		rsp_info->sender_teid = msg->gtpc_msg.mbr.sender_fteid_ctl_plane.teid_gre_key;
		if (!rsp_info->sender_teid) {
			if (get_ue_context(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					"UE context for teid: %d\n", LOG_VALUE,
					 msg->gtpc_msg.mbr.header.teid.has_teid.teid);
			}
			if (context != NULL) {
				rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			}
		}
		break;
	}

	case GTP_MODIFY_BEARER_RSP: {

		rsp_info->seq = msg->gtpc_msg.mb_rsp.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid;
		rsp_info->bearer_count = msg->gtpc_msg.mb_rsp.bearer_count;
		/*extract ebi_id from array as all the ebi's will be of same pdn.*/
		rsp_info->ebi = msg->gtpc_msg.mb_rsp.bearer_contexts_modified[0].eps_bearer_id.ebi_ebi;
		for (uint8_t i = 0; i < msg->gtpc_msg.mb_rsp.bearer_count; i++) {
			rsp_info->bearer_id[i] = msg->gtpc_msg.mb_rsp.bearer_contexts_modified[i].eps_bearer_id.ebi_ebi;
		}

		if (get_ue_context_while_error(msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE context not found "
			"for teid: %d\n", LOG_VALUE,
			msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);
		}
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
	}

	case PFCP_SESSION_MODIFICATION_RESPONSE: {

		if(get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE,
					msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
			}

		if (get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid), &context) != 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE"
								" context for teid: %d\n", LOG_VALUE,
								UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid));
		}

		pdn_connection *pdn_cntxt = NULL;
		ebi_index = GET_EBI_INDEX(resp->linked_eps_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		pdn_cntxt = GET_PDN(context, ebi_index);
		if (pdn_cntxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}

		if (pdn_cntxt != NULL && context != NULL) {

			if (context->cp_mode == SGWC && (pdn_cntxt->proc == MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC ||
						pdn_cntxt->proc == PDN_GW_INIT_BEARER_DEACTIVATION))
				rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
			else
				rsp_info->sender_teid = context->s11_mme_gtpc_teid;

			rsp_info->seq = context->sequence;
			rsp_info->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
			rsp_info->ebi  = resp->linked_eps_bearer_id;
			rsp_info->bearer_count =  context->bearer_count;
			int cnt = 0;
			for (int i=0 ; i<MAX_BEARERS ; i++) {
				if (pdn_cntxt->eps_bearers[i] != NULL) {
					rsp_info->bearer_id[cnt++] = pdn_cntxt->eps_bearers[i]->eps_bearer_id;
				}
			}
		}
		break;
	}

	case GTP_DELETE_SESSION_REQ: {

		rsp_info->seq = msg->gtpc_msg.dsr.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.dsr.header.teid.has_teid.teid;
		rsp_info->ebi = msg->gtpc_msg.dsr.lbi.ebi_ebi;
		if (get_ue_context(msg->gtpc_msg.dsr.header.teid.has_teid.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE"
				" context not found for teid: %d\n", LOG_VALUE, msg->gtpc_msg.dsr.header.teid.has_teid.teid);
		}
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
	}

	case PFCP_SESSION_DELETION_RESPONSE: {

		if (get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid), &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE"
				" context not found for teid: %d\n", LOG_VALUE,
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid));
			return;
		}
		rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		rsp_info->seq = context->sequence;
		rsp_info->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);
		rsp_info->ebi = UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);
		break;

	}

	case GTP_DELETE_SESSION_RSP: {
		rsp_info->teid = msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid;
		rsp_info->seq = msg->gtpc_msg.ds_rsp.header.teid.has_teid.seq;
		if (get_ue_context_while_error(msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE"
				" context not found for teid: %d\n", LOG_VALUE, msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid);
		}
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
		}
		break;
	}

	case GTP_MODIFY_ACCESS_BEARER_REQ: {

	   rsp_info->seq = msg->gtpc_msg.mod_acc_req.header.teid.has_teid.seq;
	   rsp_info->teid = msg->gtpc_msg.mod_acc_req.header.teid.has_teid.teid;
	   rsp_info->bearer_count = msg->gtpc_msg.mod_acc_req.bearer_modify_count;
	   for (uint8_t uiCnt = 0; uiCnt < msg->gtpc_msg.mod_acc_req.bearer_modify_count; ++uiCnt) {
			   rsp_info->ebi = msg->gtpc_msg.mod_acc_req.bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi;
			   rsp_info->bearer_id[uiCnt] =  msg->gtpc_msg.mod_acc_req.bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi;
		}

	   if (get_ue_context(msg->gtpc_msg.mod_acc_req.header.teid.has_teid.teid,
				   &context) != 0) {

		   clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				   "UE context for teid: %d\n", LOG_VALUE,
				   msg->gtpc_msg.mbr.header.teid.has_teid.teid);
	   }

		if (context != NULL) {
			 rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
	}

	case GX_CCA_MSG: {
		uint32_t call_id = 0;

		/* Extract the call id from session id */
		ret = retrieve_call_id((char *)msg->gx_msg.cca.session_id.val, &call_id);
		if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id "
					"found for session id:%s\n", LOG_VALUE,
					 msg->gx_msg.cca.session_id.val);
		}

		/* Retrieve PDN context based on call id */
		if (ret == 0) {
			pdn = get_pdn_conn_entry(call_id);
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"PDN for CALL_ID:%u\n", LOG_VALUE, call_id);
			}
		}

		if (msg->gx_msg.cca.cc_request_type == INITIAL_REQUEST ||
				msg->gx_msg.cca.cc_request_type == UPDATE_REQUEST) {
			if(pdn != NULL && pdn->context != NULL ) {
				context = pdn->context;
				rsp_info->ebi = pdn->default_bearer_id;
				rsp_info->sender_teid = context->s11_mme_gtpc_teid;
				rsp_info->seq = context->sequence;
				rsp_info->bearer_count = context->bearer_count;
				rsp_info->teid = context->s11_sgw_gtpc_teid;
				int j = 0;
				for (int i=0 ; i<MAX_BEARERS ; i++) {
					if (pdn->eps_bearers[i] != NULL) {
						rsp_info->bearer_id[j] = pdn->eps_bearers[i]->eps_bearer_id;
						j++;
					}
				}
			}
		}
		break;
	}

	case GX_RAR_MSG: {
		uint32_t call_id = 0;

		/* Extract the call id from session id */
		ret = retrieve_call_id((char *)msg->gx_msg.rar.session_id.val, &call_id);
		if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id "
					"found for session id:%s\n", LOG_VALUE,
					msg->gx_msg.rar.session_id.val);
		}

		/* Retrieve PDN context based on call id */
		if (ret == 0) {
			pdn = get_pdn_conn_entry(call_id);
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"PDN for CALL_ID:%u\n", LOG_VALUE, call_id);
			}
		}

		if(pdn != NULL && pdn->context != NULL ) {
			context = pdn->context;
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->bearer_count = context->bearer_count;
			rsp_info->teid = context->s11_sgw_gtpc_teid;
			int j = 0;
			for (int i=0 ; i<MAX_BEARERS ; i++) {
				if (pdn->eps_bearers[i] != NULL) {
					rsp_info->bearer_id[j] = pdn->eps_bearers[i]->eps_bearer_id;
					j++;
				}
			}
		}
		break;
	}

	case GTP_UPDATE_BEARER_REQ : {
		if (get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.ub_req.header.teid.has_teid.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n",LOG_VALUE, msg->gtpc_msg.ub_req.header.teid.has_teid.teid);
		}

		pdn_connection *pdn_cntxt = NULL;
		rsp_info->seq = msg->gtpc_msg.ub_req.header.teid.has_teid.seq;

		rsp_info->teid = msg->gtpc_msg.ub_req.header.teid.has_teid.teid;

		if (!msg->gtpc_msg.ub_req.apn_ambr.header.len)
			rsp_info->offending = GTP_IE_AGG_MAX_BIT_RATE;

		for (uint8_t i = 0; i < msg->gtpc_msg.ub_req.bearer_context_count; i++) {

			if (msg->gtpc_msg.ub_req.bearer_contexts[i].header.len) {
				rsp_info->bearer_id[rsp_info->bearer_count++] =
					msg->gtpc_msg.ub_req.bearer_contexts[i].eps_bearer_id.ebi_ebi;
			} else {
				rsp_info->offending = GTP_IE_UPD_BEARER_REQUEST__BEARER_CTXT;
			}

		}

		rsp_info->ebi = msg->gtpc_msg.ub_req.bearer_contexts[0].eps_bearer_id.ebi_ebi;

		int ebi_index = GET_EBI_INDEX(rsp_info->ebi);

		pdn_cntxt = GET_PDN(context, ebi_index);
		if (pdn_cntxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}

		if (context != NULL && pdn_cntxt != NULL) {
			if (rsp_info->teid == 0)
				rsp_info->teid = context->s11_sgw_gtpc_teid;
			rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
		}
		break;
	}

	case GTP_UPDATE_BEARER_RSP: {

		if (get_ue_context(msg->gtpc_msg.ub_rsp.header.teid.has_teid.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.ub_rsp.header.teid.has_teid.teid);
		}
		pdn_connection *pdn_cntxt = NULL;
		rsp_info->seq = msg->gtpc_msg.ub_rsp.header.teid.has_teid.seq;


		if (!msg->gtpc_msg.ub_rsp.cause.header.len)
			rsp_info->offending = GTP_IE_CAUSE;

		for (uint8_t i = 0; i < msg->gtpc_msg.ub_rsp.bearer_context_count; i++) {

			if (msg->gtpc_msg.ub_rsp.bearer_contexts[i].header.len) {
				rsp_info->bearer_id[rsp_info->bearer_count++] =
					msg->gtpc_msg.ub_rsp.bearer_contexts[i].eps_bearer_id.ebi_ebi;

				if (!msg->gtpc_msg.ub_rsp.bearer_contexts[i].cause.header.len)
					rsp_info->offending = GTP_IE_CAUSE;
				if (!msg->gtpc_msg.ub_rsp.bearer_contexts[i].eps_bearer_id.header.len)
					rsp_info->offending = GTP_IE_EPS_BEARER_ID;

			} else {
				rsp_info->offending = GTP_IE_CREATE_BEARER_RESPONSE__BEARER_CTXT;
			}
		}

		ebi_index = GET_EBI_INDEX(rsp_info->bearer_id[0]);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		pdn_cntxt = GET_PDN(context, ebi_index);
		if (pdn_cntxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}

		if (context != NULL && pdn_cntxt != NULL) {
			rsp_info->teid = context->s11_sgw_gtpc_teid;
			rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
		}
		break;
	}

	case GTP_DELETE_BEARER_REQ: {
		if (get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.db_req.header.teid.has_teid.teid,
		                                    &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.db_req.header.teid.has_teid.teid);
		}
		pdn_connection *pdn_cntxt = NULL;
		rsp_info->seq = msg->gtpc_msg.db_req.header.teid.has_teid.seq;

		for (uint8_t i = 0; i < msg->gtpc_msg.db_req.bearer_count; i++) {
			rsp_info->bearer_id[rsp_info->bearer_count++] =
			    msg->gtpc_msg.db_req.eps_bearer_ids[i].ebi_ebi;
		}

		rsp_info->ebi = msg->gtpc_msg.db_req.eps_bearer_ids[0].ebi_ebi;

		ebi_index = GET_EBI_INDEX(rsp_info->ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		pdn_cntxt = GET_PDN(context, ebi_index);
		if (pdn_cntxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}

		if (context != NULL && pdn_cntxt != NULL) {
			rsp_info->teid = context->s11_sgw_gtpc_teid;
			rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
		}
		break;
	}
	case GTP_UPDATE_PDN_CONNECTION_SET_RSP: {

		rsp_info->seq = msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.seq;

		if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context)) {

			if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid,
											&context)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
									" UE context for teid: %d \n",LOG_VALUE,
									msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid);
			}
		}
		if (context != NULL) {
				rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
			break;
	}

	case GTP_CREATE_BEARER_REQ : {
		if (get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.cb_req.header.teid.has_teid.teid,
		                                    &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.cb_req.header.teid.has_teid.teid);
		}
		pdn_connection *pdn_cntxt = NULL;
		rsp_info->seq = msg->gtpc_msg.cb_req.header.teid.has_teid.seq;

		if (!msg->gtpc_msg.cb_req.lbi.header.len)
			rsp_info->offending = GTP_IE_EPS_BEARER_ID;

		for (uint8_t i = 0; i < msg->gtpc_msg.cb_req.bearer_cnt; i++) {
			if (msg->gtpc_msg.cb_req.bearer_contexts[i].header.len) {
				rsp_info->bearer_id[rsp_info->bearer_count++] =
				    msg->gtpc_msg.cb_req.bearer_contexts[i].eps_bearer_id.ebi_ebi;

			if (!msg->gtpc_msg.cb_req.bearer_contexts[i].eps_bearer_id.header.len)
				rsp_info->offending = GTP_IE_EPS_BEARER_ID;
			if (!msg->gtpc_msg.cb_req.bearer_contexts[i].bearer_lvl_qos.header.len)
				rsp_info->offending = GTP_IE_BEARER_QLTY_OF_SVC;
			if (!msg->gtpc_msg.cb_req.bearer_contexts[i].s58_u_pgw_fteid.header.len)
				rsp_info->offending = GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT;
			if (!msg->gtpc_msg.cb_req.bearer_contexts[i].tft.header.len)
				rsp_info->offending = GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL;

			} else {
				rsp_info->offending = GTP_IE_CREATE_BEARER_REQUEST__BEARER_CTXT;
			}

		}

		if (msg->gtpc_msg.cb_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi != 0) {

			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.cb_req.bearer_contexts[0].eps_bearer_id.ebi_ebi);

		} else {

			/*If Create Bearer Response is received with Zero EBI, then
			ebi_index is extracted from temporary stored location*/
			ebi_index = GET_EBI_INDEX(MAX_BEARERS + NUM_EBI_RESERVED);
		}

		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		pdn_cntxt = GET_PDN(context, ebi_index);
		if (pdn_cntxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}

		if (context != NULL && pdn_cntxt != NULL) {
			rsp_info->teid = context->s11_sgw_gtpc_teid;
			rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
		}
		break;
	}

	case GTP_DELETE_BEARER_RSP: {
		pdn_connection *pdn_cntxt = NULL;
		if (get_ue_context(msg->gtpc_msg.db_rsp.header.teid.has_teid.teid,
		                   &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.db_rsp.header.teid.has_teid.teid);
		}

		rsp_info->seq = msg->gtpc_msg.db_rsp.header.teid.has_teid.seq;
		for (uint8_t i = 0; i < msg->gtpc_msg.db_rsp.bearer_count; i++) {
			rsp_info->bearer_id[rsp_info->bearer_count++] =
		        msg->gtpc_msg.db_rsp.bearer_contexts[i].eps_bearer_id.ebi_ebi;
		}

		rsp_info->ebi = msg->gtpc_msg.db_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi;

		ebi_index = GET_EBI_INDEX(rsp_info->ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID %d\n", LOG_VALUE, ebi_index);
		}

		pdn_cntxt = GET_PDN(context, ebi_index);
		if (pdn_cntxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}

		if (context != NULL && pdn_cntxt != NULL) {
			rsp_info->teid = context->s11_sgw_gtpc_teid;

			if (context->cp_mode == SGWC)
				rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
			else
				rsp_info->sender_teid = context->s11_mme_gtpc_teid;

		}
		break;
	}
	case GTP_MODIFY_BEARER_CMD: {
		if (get_ue_context(msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.teid);
		}
		rsp_info->seq = msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.teid;
		if (!msg->gtpc_msg.mod_bearer_cmd.bearer_context.eps_bearer_id.header.len)
				rsp_info->offending = GTP_IE_BEARER_CONTEXT;

		if (!msg->gtpc_msg.mod_bearer_cmd.apn_ambr.header.len)
				rsp_info->offending = GTP_IE_AGG_MAX_BIT_RATE;

		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;

	}

	case GTP_DELETE_BEARER_CMD: {
		if (get_ue_context(msg->gtpc_msg.del_ber_cmd.header.teid.has_teid.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.del_ber_cmd.header.teid.has_teid.teid);
		}
		rsp_info->seq = msg->gtpc_msg.del_ber_cmd.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.del_ber_cmd.header.teid.has_teid.teid;
		rsp_info->bearer_count = msg->gtpc_msg.del_ber_cmd.bearer_count;
		for (uint8_t i = 0; i < msg->gtpc_msg.del_ber_cmd.bearer_count; i++) {
			rsp_info->bearer_id[i] =
			    msg->gtpc_msg.del_ber_cmd.bearer_contexts[i].eps_bearer_id.ebi_ebi;
			if (!msg->gtpc_msg.del_ber_cmd.bearer_contexts[i].eps_bearer_id.header.len)
				rsp_info->offending = GTP_IE_EPS_BEARER_ID;
		}
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
	}

	case GTP_BEARER_RESOURCE_CMD: {
			rsp_info->seq = msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.seq;
			rsp_info->teid = msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.teid;
			rsp_info->bearer_count = 1;
			if(msg->gtpc_msg.bearer_rsrc_cmd.lbi.header.len == 0) {
				rsp_info->offending = GTP_IE_EPS_BEARER_ID;
			} else {
				rsp_info->bearer_id[0] = msg->gtpc_msg.bearer_rsrc_cmd.lbi.ebi_ebi;
			}
			rsp_info->sender_teid = msg->gtpc_msg.bearer_rsrc_cmd.sender_fteid_ctl_plane.teid_gre_key;
		break;
	}

	case GTP_BEARER_RESOURCE_FAILURE_IND: {
		if (get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.ber_rsrc_fail_ind.header.teid.has_teid.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.ber_rsrc_fail_ind.header.teid.has_teid.teid);
			return;
		}

		rsp_info->seq = msg->gtpc_msg.ber_rsrc_fail_ind.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.ber_rsrc_fail_ind.header.teid.has_teid.teid;
		rsp_info->bearer_count = 1;

		if(msg->gtpc_msg.ber_rsrc_fail_ind.linked_eps_bearer_id.header.len == 0) {
			rsp_info->offending = GTP_IE_EPS_BEARER_ID;
		} else {
			rsp_info->bearer_id[0] = msg->gtpc_msg.ber_rsrc_fail_ind.linked_eps_bearer_id.ebi_ebi;
		}

		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
	}

	case GTP_DELETE_BEARER_FAILURE_IND: {
		if (get_ue_context(msg->gtpc_msg.del_fail_ind.header.teid.has_teid.teid, &context)) {
			if (get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.del_fail_ind.header.teid.has_teid.teid, &context)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.del_fail_ind.header.teid.has_teid.teid);
			}
		}
		rsp_info->seq = msg->gtpc_msg.del_fail_ind.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.del_fail_ind.header.teid.has_teid.teid;
		rsp_info->bearer_count = msg->gtpc_msg.del_fail_ind.bearer_count;
		for (uint8_t i = 0; i < msg->gtpc_msg.del_fail_ind.bearer_count; i++) {
			rsp_info->bearer_id[i] =
			    msg->gtpc_msg.del_fail_ind.bearer_context[i].eps_bearer_id.ebi_ebi;
			if (!msg->gtpc_msg.del_fail_ind.bearer_context[i].eps_bearer_id.header.len)
				rsp_info->offending = GTP_IE_EPS_BEARER_ID;
		}
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
	}
	case GTP_MODIFY_BEARER_FAILURE_IND: {
		if (get_ue_context(msg->gtpc_msg.mod_fail_ind.header.teid.has_teid.teid, &context)) {
			if (get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.mod_fail_ind.header.teid.has_teid.teid, &context)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.mod_fail_ind.header.teid.has_teid.teid);
			}
		}
		rsp_info->seq = msg->gtpc_msg.mod_fail_ind.header.teid.has_teid.seq;
		rsp_info->teid = msg->gtpc_msg.mod_fail_ind.header.teid.has_teid.teid;
		if (context != NULL) {
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;

	}

	case GTP_CREATE_BEARER_RSP: {
		pdn_connection *pdn_cntxt = NULL;

		if (get_ue_context(msg->gtpc_msg.cb_rsp.header.teid.has_teid.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.cb_rsp.header.teid.has_teid.teid);
		}

		if (msg->gtpc_msg.cb_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi != 0) {

			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.cb_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi);

		} else {

			/*If Create Bearer Response is received with Zero EBI, then
			ebi_index is extracted from temporary stored location*/
			ebi_index = GET_EBI_INDEX(MAX_BEARERS + NUM_EBI_RESERVED);
		}

		if (NULL != context) {
			rsp_info->cp_mode = context->cp_mode;
			pdn_cntxt = GET_PDN(context, ebi_index);
			if (pdn_cntxt == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
						"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			} else {
				if (get_sess_entry(pdn_cntxt->seid, &resp) != 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry "
					"Found for sess ID:%lu\n", LOG_VALUE, pdn_cntxt->seid);
				}
			}
		}

		rsp_info->seq = msg->gtpc_msg.cb_rsp.header.teid.has_teid.seq;

		if (!msg->gtpc_msg.cb_rsp.cause.header.len)
			rsp_info->offending = GTP_IE_CAUSE;

		if (resp != NULL) {
			for (uint8_t i = 0; i < resp->bearer_count ; i++) {

				if (msg->gtpc_msg.cb_rsp.bearer_contexts[i].header.len) {
					rsp_info->bearer_id[rsp_info->bearer_count++] = resp->eps_bearer_ids[i];
				} else {
					rsp_info->offending = GTP_IE_CREATE_BEARER_RESPONSE__BEARER_CTXT;
				}
				if (!msg->gtpc_msg.cb_rsp.bearer_contexts[i].cause.header.len)
					rsp_info->offending = GTP_IE_CAUSE;
				if (!msg->gtpc_msg.cb_rsp.bearer_contexts[i].eps_bearer_id.header.len)
					rsp_info->offending = GTP_IE_EPS_BEARER_ID;
			}
		}

		if (context != NULL && pdn_cntxt != NULL) {

			rsp_info->teid = context->s11_sgw_gtpc_teid;

			if (context->cp_mode == SGWC)
				rsp_info->sender_teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
			else
				rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}
		break;
		}


	case GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ :{

			rsp_info->sender_teid = msg->gtpc_msg.crt_indr_tun_req.sender_fteid_ctl_plane.teid_gre_key;
			rsp_info->seq = msg->gtpc_msg.crt_indr_tun_req.header.teid.has_teid.seq;
			rsp_info->bearer_count = msg->gtpc_msg.crt_indr_tun_req.bearer_count;
			for(uint8_t i = 0;i< rsp_info->bearer_count; i++ ){
				rsp_info->ebi = msg->gtpc_msg.crt_indr_tun_req.bearer_contexts[i].eps_bearer_id.ebi_ebi;
				rsp_info->bearer_id[i] =  msg->gtpc_msg.crt_indr_tun_req.bearer_contexts[i].eps_bearer_id.ebi_ebi;
			}

			rsp_info->teid =  msg->gtpc_msg.crt_indr_tun_req.header.teid.has_teid.teid;
			break;
		}
	case GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ: {

			rsp_info->seq = msg->gtpc_msg.dlt_indr_tun_req.header.teid.has_teid.seq;
			rsp_info->teid = msg->gtpc_msg.dlt_indr_tun_req.header.teid.has_teid.teid;
			//rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			break;
		}
}
}


void cs_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
		int iface)
{

	int ret = 0;
	uint8_t count = 1;
	ue_context *context = NULL;
	upf_context_t *upf_context = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
	                           (const void*) & (msg->upf_ip), (void **) & (upf_context));

	if (ret >= 0 && (msg->msg_type == PFCP_ASSOCIATION_SETUP_RESPONSE)
	        && (msg->pfcp_msg.pfcp_ass_resp.cause.cause_value != REQUESTACCEPTED)) {
		count = upf_context->csr_cnt;
	}

	for (uint8_t i = 0; i < count; i++) {

		err_rsp_info rsp_info = {0};
		get_error_rsp_info(msg, &rsp_info, i);
		if (rsp_info.ebi == 0)
			rsp_info.ebi = msg->gtpc_msg.csr.bearer_contexts_to_be_created[0].eps_bearer_id.ebi_ebi;

		/* Sending CCR-T in case of failure */
		/* TODO:CCR should be send in different function */
			/*Note when cp_mode is 0 it is not required to
			 * send ccrt as it will either fail while processing
			 * initial request or will fail only on serving gateway.
			 * */

		if ((config.use_gx) && msg->cp_mode != SGWC  && msg->cp_mode != 0){
			/* Check the TEID Value */
			if (!rsp_info.teid) {
				rsp_info.teid = msg->teid;
			}

			send_ccr_t_req(msg, rsp_info.ebi, rsp_info.teid);
			update_cli_stats((peer_address_t *) &config.gx_ip, OSS_CCR_TERMINATE, SENT, GX);

		}
		bzero(&tx_buf, sizeof(tx_buf));
		gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

		create_sess_rsp_t cs_resp = {0};

		set_gtpv2c_teid_header(&cs_resp.header,
		                       GTP_CREATE_SESSION_RSP,
		                       rsp_info.sender_teid,
		                       rsp_info.seq, NOT_PIGGYBACKED);

		set_cause_error_value(&cs_resp.cause, IE_INSTANCE_ZERO, cause_value,
				cause_source);

		if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
			set_ie_header(&cs_resp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
					sizeof(struct cause_ie));
			cs_resp.cause.offend_ie_type = rsp_info.offending;
			cs_resp.cause.offend_ie_len = 0;
		} else {
			set_ie_header(&cs_resp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
					sizeof(struct cause_ie_hdr_t));
		}

		cs_resp.bearer_count = rsp_info.bearer_count;
		for(uint8_t i = 0; i < rsp_info.bearer_count; i++){
		set_ie_header(&cs_resp.bearer_contexts_created[i].header, GTP_IE_BEARER_CONTEXT,
		              IE_INSTANCE_ZERO, 0);

		set_ebi(&cs_resp.bearer_contexts_created[i].eps_bearer_id, IE_INSTANCE_ZERO,
		        rsp_info.bearer_id[i]);
		cs_resp.bearer_contexts_created[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_cause_error_value(&cs_resp.bearer_contexts_created[i].cause,
				IE_INSTANCE_ZERO, cause_value, cause_source);

		cs_resp.bearer_contexts_created[i].header.len += sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;
		}

		payload_length = encode_create_sess_rsp(&cs_resp, (uint8_t *)gtpv2c_tx);

		if (rsp_info.teid != 0) {
			/* Retrieve the UE context */
			ret = get_ue_context_while_error(rsp_info.teid, &context);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
			}
		}

		if (iface == S11_IFACE) {
			if(rsp_info.seq != 0){
				if(context != NULL) {
					if(context->piggyback != TRUE) {
						gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
							s11_mme_sockaddr, REJ);
					}
				} else {
					gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				        s11_mme_sockaddr, REJ);
				}

				/* copy packet for user level packet copying or li */
				if ((context != NULL) && (context->dupl)) {
					process_pkt_for_li(
							context, S11_INTFC_OUT, tx_buf, payload_length,
							fill_ip_info(s11_mme_sockaddr.type,
									config.s11_ip.s_addr,
									config.s11_ip_v6.s6_addr),
							fill_ip_info(s11_mme_sockaddr.type,
									s11_mme_sockaddr.ipv4.sin_addr.s_addr,
									s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
							config.s11_port,
							((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
								 ntohs(s11_mme_sockaddr.ipv4.sin_port) :
								 ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
				}
			}
		} else {
				if(context != NULL) {
					if(context->piggyback != TRUE) {

						gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			        		s5s8_recv_sockaddr, REJ);
					}
				} else {

						gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
							s5s8_recv_sockaddr, REJ);

				}
			/* copy packet for user level packet copying or li */
				if ((context != NULL) && (context->dupl)) {
					process_pkt_for_li(
							context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
							fill_ip_info(s5s8_recv_sockaddr.type,
								config.s5s8_ip.s_addr,
								config.s5s8_ip_v6.s6_addr),
						fill_ip_info(s5s8_recv_sockaddr.type,
								s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
								s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
						config.s5s8_port,
						((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
							ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
							ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
				}

			}

		ret = clean_up_while_error(rsp_info.ebi, context,
				rsp_info.teid, &msg->gtpc_msg.csr.imsi.imsi_number_digits,
				rsp_info.seq, msg);

		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"CleanUp failed while Error response is recived",
				LOG_VALUE);
			return;
		}
	}
}


void mbr_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
		int iface)
{

	ue_context *context = NULL;
	err_rsp_info rsp_info = {0};
	pdn_connection *pdn_cntxt =  NULL;
	get_error_rsp_info(msg, &rsp_info, 0);
	struct resp_info *resp = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	mod_bearer_rsp_t mb_resp = {0};
	set_gtpv2c_teid_header(&mb_resp.header,
	                       GTP_MODIFY_BEARER_RSP,
	                       rsp_info.sender_teid,
	                       rsp_info.seq, 0);

	set_cause_error_value(&mb_resp.cause, IE_INSTANCE_ZERO, cause_value, cause_source);

	/* Fill the number of bearer context */
	mb_resp.bearer_count = rsp_info.bearer_count;

	for (uint8_t uiCnt = 0; uiCnt < rsp_info.bearer_count; ++uiCnt) {
		set_ie_header(&mb_resp.bearer_contexts_modified[uiCnt].header,
		              GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);

		set_cause_error_value(&mb_resp.bearer_contexts_modified[uiCnt].cause,
		                      IE_INSTANCE_ZERO, cause_value, cause_source);


		mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(struct cause_ie_hdr_t) +
		        IE_HEADER_SIZE;

		set_ebi(&mb_resp.bearer_contexts_modified[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
		        rsp_info.bearer_id[uiCnt]);

		mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		if (get_ue_context(rsp_info.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n",LOG_VALUE, rsp_info.teid);
		}

		if (context) {
			int ebi_index = GET_EBI_INDEX(rsp_info.bearer_id[uiCnt]);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			}
			if (ebi_index > 0 && context->eps_bearers[ebi_index] != NULL) {
				if (context->indication_flag.s11tf) {
					mb_resp.bearer_contexts_modified[uiCnt].header.len +=
						set_gtpc_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
								GTPV2C_IFTYPE_S11U_SGW_GTPU, IE_INSTANCE_THREE,
								context->eps_bearers[ebi_index]->s1u_sgw_gtpu_ip,
								context->eps_bearers[ebi_index]->s1u_sgw_gtpu_teid);
				} else {
					mb_resp.bearer_contexts_modified[uiCnt].header.len +=
						set_gtpc_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
								GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO,
								context->eps_bearers[ebi_index]->s1u_sgw_gtpu_ip,
								context->eps_bearers[ebi_index]->s1u_sgw_gtpu_teid);
				}
			}
		}
	}

	pdn_cntxt = GET_PDN(context, GET_EBI_INDEX(rsp_info.bearer_id[0]));
	if (pdn_cntxt != NULL) {
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry "
				"Found for sess ID: %lu\n", LOG_VALUE, pdn_cntxt->seid);
		}

		if (resp != NULL) {
			reset_resp_info_structure(resp);
		}
	}

	payload_length = encode_mod_bearer_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);

	if (iface == S11_IFACE) {
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		            s11_mme_sockaddr, REJ);

		/* copy packet for user level packet copying or li */
		if (context != NULL && context->dupl) {
			process_pkt_for_li(
			    context, S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					    config.s11_ip.s_addr,
					    config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						s11_mme_sockaddr.ipv4.sin_addr.s_addr,
						s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
			    config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					 ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					 ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
		}

	} else {
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
		            s5s8_recv_sockaddr, REJ);

		/* copy packet for user level packet copying or li */
		if (context != NULL && context->dupl) {
			process_pkt_for_li(
			    context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
			    		config.s5s8_ip.s_addr,
			    		config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
			    config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
		}
	}
}


void ds_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
		 int iface)
{
	/* uint8_t forward = 0;
	uint64_t uiImsi = 0; */
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	err_rsp_info rsp_info = {0};
	struct resp_info *resp = NULL;
	uint8_t eps_bearer_id = 0;
	int8_t ebi_index = 0;
	get_error_rsp_info(msg, &rsp_info, 0);

	eps_bearer_id = rsp_info.ebi;
	ebi_index = GET_EBI_INDEX(eps_bearer_id);

	/* Check GTPv2c Messages */
	if((get_ue_context_while_error(rsp_info.teid, &context) == 0) && (ebi_index >= 0)) {

		if(context->eps_bearers[ebi_index]) {
			pdn = context->eps_bearers[ebi_index]->pdn;
		}

		/* Check for PFCP Message */
		if((msg->msg_type == PFCP_SESSION_DELETION_RESPONSE) &&
			(get_sess_entry(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid, &resp) != 0)){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry "
				"Found for sess ID:%lu\n", LOG_VALUE,
				msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);
		} else {
			if(pdn != NULL)
			{

				if((get_sess_entry(pdn->seid, &resp) != 0)){
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry "
							"Found for sess ID:%lu\n", LOG_VALUE, pdn->seid);
				}
			}
		}

	}

	if(context != NULL) {
		if ((config.use_gx) && context->cp_mode != SGWC) {
			send_ccr_t_req(msg, eps_bearer_id, rsp_info.teid);
			update_cli_stats((peer_address_t *) &config.gx_ip, OSS_CCR_TERMINATE, SENT, GX);
		}
	}

	/* Fill and set DSResp message */
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	del_sess_rsp_t ds_resp = {0};
	set_gtpv2c_teid_header(&ds_resp.header,
	                       GTP_DELETE_SESSION_RSP,
	                       rsp_info.sender_teid,
	                       rsp_info.seq, 0);

	/* Set the Cause value */
	set_cause_error_value(&ds_resp.cause, IE_INSTANCE_ZERO, cause_value,
			cause_source);

	/* Encode the DSResp Message */
	payload_length = encode_del_sess_rsp(&ds_resp, (uint8_t *)gtpv2c_tx);

	if(context != NULL) {
		if(context->cp_mode != PGWC)
			iface = S11_IFACE;
		else
			iface = S5S8_IFACE;
	}

	if (rsp_info.seq != 0) {
		if (iface == S11_IFACE) {
			gtpv2c_send(s11_fd, s11_fd_v6,tx_buf, payload_length,
			            s11_mme_sockaddr, REJ);

		} else {
			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			            s5s8_recv_sockaddr, REJ);

		}
	}
	/* it will process only in case of SGWC timer callback.
	* when PGWC not give response for timer retry
	*
	*/
	if(context != NULL) {
		if((cause_value == GTPV2C_CAUSE_REQUEST_ACCEPTED) && (context->cp_mode == SGWC))
		{
			if(resp != NULL) {
				if (msg->msg_type == GTP_DELETE_SESSION_REQ && resp->state != PFCP_SESS_DEL_REQ_SNT_STATE) {

					pfcp_sess_del_req_t pfcp_sess_del_req = {0};
					fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);
					if(pdn != NULL) {
						pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;
					}
					uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
					int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);

					if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
											upf_pfcp_sockaddr, SENT) < 0)
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error "
						"in Sending Session Modification Request. "
						"Error : %i\n", LOG_VALUE, errno);
					else {
			#ifdef CP_BUILD
						add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
							&upf_pfcp_sockaddr, pfcp_msg, encoded,
							ebi_index);
			#endif /* CP_BUILD */
					}
				}
			}
		}
	}

	/* Cleanup the session info from the resp struct */
	if(resp != NULL)
		reset_resp_info_structure(resp);

	/* cleanup the ue info structures */
	if(context && pdn) {
		delete_sess_context(context, pdn);
	}

	return;
}

int send_ccr_t_req(msg_info *msg, uint8_t ebi, uint32_t teid) {

	int ret = 0, ret_value = 0;
	pdn_connection *pdn =  NULL;
	ue_context *context = NULL;
	gx_context_t *gx_context = NULL;
	uint16_t msglen = 0;
	uint8_t *buffer = NULL;
	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE context "
			"for teid: %d\n", LOG_VALUE, teid);
	}

	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index >= 0) {

		pdn = GET_PDN(context, ebi_index);
		if ( pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		}
	}

	if (pdn != NULL && context != NULL) {

		/* Retrive Gx_context based on Sess ID. */
		ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
						(const void*)(pdn->gx_sess_id), (void **)&gx_context);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND "
				"IN Gx HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
		} else {
			gx_msg ccr_request = {0};
			/* Set the Msg header type for CCR-T */
			ccr_request.msg_type = GX_CCR_MSG ;
			/* Set Credit Control Request type */
			ccr_request.data.ccr.presence.cc_request_type = PRESENT;
			ccr_request.data.ccr.cc_request_type = TERMINATION_REQUEST ;
			/* Set Credit Control Bearer opertaion type */
			ccr_request.data.ccr.presence.bearer_operation = PRESENT;
			ccr_request.data.ccr.bearer_operation = TERMINATION ;

			ret_value = fill_ccr_request(&ccr_request.data.ccr, context, ebi_index, pdn->gx_sess_id, 0);
			if (ret_value) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed CCR "
					"request filling process\n", LOG_VALUE);
				ret_value = 1;
			}

			if (ret_value == 0) {

				msglen = gx_ccr_calc_length(&ccr_request.data.ccr);
				ccr_request.msg_len = msglen + GX_HEADER_LEN;
				buffer = rte_zmalloc_socket(NULL, msglen + GX_HEADER_LEN, RTE_CACHE_LINE_SIZE,
																rte_socket_id());
				if (buffer == NULL) {

					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
						"Memory for Buffer, Error: %s \n", LOG_VALUE,
							rte_strerror(rte_errno));
					ret_value = 1;
				}
			}

			if ( ret_value == 0 && buffer != NULL) {

				memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
				memcpy((buffer + sizeof(ccr_request.msg_type)),
					    &ccr_request.msg_len, sizeof(ccr_request.msg_len));

			}

			if (ret_value == 0
				&& buffer != NULL
				&& gx_ccr_pack(&(ccr_request.data.ccr),
								(unsigned char *)(buffer + GX_HEADER_LEN), msglen) != 0) {


				send_to_ipc_channel(gx_app_sock, buffer, msglen + GX_HEADER_LEN);
				free_dynamically_alloc_memory(&ccr_request);

				if (rte_hash_del_key(gx_context_by_sess_id_hash, pdn->gx_sess_id) < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error on "
						"gx_context_by_sess_id_hash deletion\n",
						LOG_VALUE, strerror(ret));
				}
				RTE_SET_USED(msg);
				if (gx_context != NULL) {
					rte_free(gx_context);
					gx_context = NULL;
				}

				rte_free(buffer);

			} else {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR in Packing "
					"CCR Buffer\n", LOG_VALUE);
				rte_free(buffer);
				return -1;
			}
		}
	}
	return 0;
}

void gen_reauth_error_response(pdn_connection *pdn, int16_t error) {
	/* Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg raa = {0};
	gx_context_t *gx_context = NULL;
	uint16_t msg_body_ofs = 0;
	uint16_t rqst_ptr_ofs = 0;
	uint16_t msg_len_total = 0;


	/* Clear Policy in PDN */
	pdn->policy.count = 0;
	pdn->policy.num_charg_rule_install = 0;
	pdn->policy.num_charg_rule_modify = 0;
	pdn->policy.num_charg_rule_delete = 0;

	/* Allocate the memory for Gx Context */

	if ((gx_context_entry_lookup(pdn->gx_sess_id, &gx_context)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"gx context not found for sess id %s\n",
				LOG_VALUE, pdn->gx_sess_id);
	}

	raa.data.cp_raa.session_id.len = strnlen(pdn->gx_sess_id, MAX_LEN);
	memcpy(raa.data.cp_raa.session_id.val, pdn->gx_sess_id, raa.data.cp_raa.session_id.len);

	raa.data.cp_raa.presence.session_id = PRESENT;

	/* Set the Msg header type for CCR */
	raa.msg_type = GX_RAA_MSG;

	/* Result code */
	raa.data.cp_raa.result_code = error;
	raa.data.cp_raa.presence.result_code = PRESENT;

	/* Update UE State */
	pdn->state = RE_AUTH_ANS_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = RE_AUTH_ANS_SNT_STATE;

	/* Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_raa_calc_length(&raa.data.cp_raa);
	msg_body_ofs = GX_HEADER_LEN;
	rqst_ptr_ofs = msg_len + msg_body_ofs;
	msg_len_total = rqst_ptr_ofs + sizeof(pdn->rqst_ptr);
	raa.msg_len = msg_len_total;

	buffer = rte_zmalloc_socket(NULL, msg_len_total,
	                            RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for Buffer, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
		return;
	}

	memcpy(buffer, &raa.msg_type, sizeof(raa.msg_type));
	memcpy(buffer + sizeof(raa.msg_type),
			&raa.msg_len, sizeof(raa.msg_len));

	if (gx_raa_pack(&(raa.data.cp_raa),
		(unsigned char *)(buffer + msg_body_ofs),
		msg_len) == 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in Packing RAA "
			"Buffer\n",LOG_VALUE);
		rte_free(buffer);
		return;
	}
	memcpy((unsigned char *)(buffer + rqst_ptr_ofs), &(pdn->rqst_ptr),
	       sizeof(pdn->rqst_ptr));

	/* Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,msg_len_total);
	rte_free(buffer);
	buffer = NULL;

	return;
}

void gen_reauth_error_resp_for_wrong_seid_rcvd(msg_info *msg,gx_msg *gxmsg, int16_t cause_value) {

	/* Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	unsigned long  rqst_ptr = 0;
	uint8_t *buffer = NULL;
	uint32_t buflen = 0;
	gx_msg raa = {0};

	memcpy(raa.data.cp_raa.session_id.val, msg->gx_msg.rar.session_id.val, GX_SESSION_ID_LEN);
	raa.data.cp_raa.presence.session_id = PRESENT;

	buflen = gx_rar_calc_length (&msg->gx_msg.rar);

	raa.msg_type = GX_RAA_MSG;

	raa.data.cp_raa.result_code = cause_value;
	raa.data.cp_raa.presence.result_code = PRESENT;

	msg->state = RE_AUTH_ANS_SNT_STATE;

	msg_len = gx_raa_calc_length(&raa.data.cp_raa);

	raa.msg_len = msg_len + GX_HEADER_LEN + sizeof(unsigned long);

	buffer = rte_zmalloc_socket(NULL, msg_len + GX_HEADER_LEN + sizeof(unsigned long),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"Memory for Buffer, Error: %s \n", LOG_VALUE, rte_strerror(rte_errno));
		return;
	}

	memcpy(&rqst_ptr, ((unsigned char *)gxmsg + GX_HEADER_LEN + buflen),
			sizeof(unsigned long));

	memcpy(buffer, &raa.msg_type, sizeof(raa.msg_type));
	memcpy(buffer + sizeof(raa.msg_type),
			&raa.msg_len, sizeof(raa.msg_len));

	if (gx_raa_pack(&(raa.data.cp_raa),
				(unsigned char *)(buffer + GX_HEADER_LEN),
				msg_len) == 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in Packing RAA "
				"Buffer\n",LOG_VALUE);
		rte_free(buffer);
		return;
	}

	memcpy((unsigned char *)(buffer + msg_len + GX_HEADER_LEN), (&rqst_ptr),
			sizeof(unsigned long));

	/* Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer, raa.msg_len);
	rte_free(buffer);
	buffer = NULL;

	return;
}

void delete_bearer_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface)
{
	int ebi_index = 0, ret = 0;
	uint32_t seq = 0;
	struct resp_info *resp = NULL;
	err_rsp_info rsp_info = {0};
	pdn_connection *pdn = NULL;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	get_error_rsp_info(msg, &rsp_info, 0);
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	pfcp_update_far_ie_t *far = NULL;
	node_address_t node_value = {0};

	if (get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context))  {
		if (get_ue_context(rsp_info.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
		}
	}

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	ebi_index = GET_EBI_INDEX(rsp_info.bearer_id[0]);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID \n", LOG_VALUE);
	}

	if (ebi_index >= 0) {
		pdn = GET_PDN(context, ebi_index);
		if ( pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		} else {

			if (get_sess_entry(pdn->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %d", LOG_VALUE, pdn->seid);
			}
		}
	}

	if (context != NULL) {
		if (context->cp_mode != SGWC)
			iface = GX_IFACE;
		else
			iface = S5S8_IFACE;
	}

	if (resp != NULL && resp->msg_type != GX_RAR_MSG
		&& resp->msg_type != GTP_DELETE_BEARER_CMD
		&& resp->msg_type != GTP_DELETE_BEARER_REQ) {

		seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

		set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header),
				PFCP_SESSION_MODIFICATION_REQUEST, HAS_SEID, seq,
				context->cp_mode);

		pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

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

		for (uint8_t idx = 0; idx < rsp_info.bearer_count; idx++) {

			ebi_index = GET_EBI_INDEX(rsp_info.bearer_id[idx]);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			}

			if (pdn != NULL && ebi_index >= 0) {
				bearer = pdn->eps_bearers[ebi_index];
			}

			if (bearer != NULL) {
				for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
					far = &(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count]);

					bearer->pdrs[itr]->far.actions.forw = PRESENT;
					bearer->pdrs[itr]->far.actions.dupl = 0;
					bearer->pdrs[itr]->far.actions.drop = 0;
					set_update_far(far, &bearer->pdrs[itr]->far);

					pfcp_sess_mod_req.update_far_count++;
				}
			}

			bearer = NULL;
		}

		uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
		int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req,
												pfcp_msg);

		if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
								upf_pfcp_sockaddr, SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error "
			"in Sending Session Modification Request. "
			"Error : %i\n", LOG_VALUE, errno);
		else {
#ifdef CP_BUILD
			add_pfcp_if_timer_entry(rsp_info.teid,
				&upf_pfcp_sockaddr, pfcp_msg, encoded,
				ebi_index);
#endif /* CP_BUILD */
		}

		pdn->state = ERROR_OCCURED_STATE;
		resp->state =  ERROR_OCCURED_STATE;
		resp->proc = pdn->proc;
	}

	/* send S5S8 interface delete bearer response.*/
	if (iface == S5S8_IFACE) {

		del_bearer_rsp_t del_rsp = {0};
		set_gtpv2c_teid_header(&del_rsp.header,
		                       GTP_DELETE_BEARER_RSP,
		                       rsp_info.sender_teid,
		                       rsp_info.seq, 0);
		set_cause_error_value(&del_rsp.cause, IE_INSTANCE_ZERO,
		                      cause_value, cause_source);
		del_rsp.bearer_count = rsp_info.bearer_count;
		for (int i = 0; i < rsp_info.bearer_count; i++) {

			set_ie_header(&del_rsp.bearer_contexts[i].header, GTP_IE_BEARER_CONTEXT,
			              IE_INSTANCE_ZERO, 0);

			set_ebi(&del_rsp.bearer_contexts[i].eps_bearer_id, IE_INSTANCE_ZERO,
			        rsp_info.bearer_id[i]);
			del_rsp.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

			set_cause_error_value(&del_rsp.bearer_contexts[i].cause, IE_INSTANCE_ZERO,
			                      cause_value, cause_source );
			del_rsp.bearer_contexts[i].header.len += sizeof(uint16_t) + IE_HEADER_SIZE;
		}

		payload_length = encode_del_bearer_rsp(&del_rsp, (uint8_t *)gtpv2c_tx);

		reset_resp_info_structure(resp);

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length, s5s8_recv_sockaddr,
					REJ);
	} else {

		if (pdn != NULL) {

			if (pdn->proc == MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC) {
				delete_bearer_cmd_failure_indication(msg, cause_value,
						CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
				return;
			}

			else if (resp->msg_type == GTP_BEARER_RESOURCE_CMD) {
				send_bearer_resource_failure_indication(msg,cause_value,
						CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
				provision_ack_ccr(pdn, pdn->eps_bearers[ebi_index],
						RULE_ACTION_DELETE, RESOURCE_ALLOCATION_FAILURE);
			} else {
				if (pdn->state != RE_AUTH_ANS_SNT_STATE
					&& msg->gtpc_msg.ub_rsp.cause.cause_value != GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING ) {

						gen_reauth_error_response(pdn, DIAMETER_UNABLE_TO_COMPLY);

				}
			}
		}
	}
	return;
}


void cbr_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
		int iface)
{
	int ret = 0, ebi_index = 0, err_ret = 0;
	err_rsp_info rsp_info = {0};
	ue_context *context = NULL;
	pdn_connection *pdn_cntxt = NULL;
	get_error_rsp_info(msg, &rsp_info, 0);
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;


	if (msg->msg_type == GTP_CREATE_BEARER_REQ) {
		ret = get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context);
	} else {
		ret = get_ue_context(rsp_info.teid, &context);
	}

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
	}

	if (msg->gtpc_msg.cb_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi != 0) {

		ebi_index = GET_EBI_INDEX(msg->gtpc_msg.cb_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi);

	} else {

		/*If Create Bearer Response is received with Zero EBI, then
		ebi_index is extracted from temporary stored location*/
		ebi_index = GET_EBI_INDEX(MAX_BEARERS + NUM_EBI_RESERVED);
	}

	pdn_cntxt = GET_PDN(context, ebi_index);
	if (pdn_cntxt == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
	}

	if (context != NULL) {
		if (context->cp_mode != SGWC)
			iface = GX_IFACE;
		else
			iface = S5S8_IFACE;
	}

	if (iface ==  S5S8_IFACE) {
		create_bearer_rsp_t cbr_rsp = {0};

		set_gtpv2c_teid_header(&cbr_rsp.header,
							GTP_CREATE_BEARER_RSP,
							rsp_info.sender_teid,
							rsp_info.seq, 0);

		set_cause_error_value(&cbr_rsp.cause, IE_INSTANCE_ZERO, cause_value,
				cause_source);

		if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
			set_ie_header(&cbr_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			              sizeof(struct cause_ie));
			cbr_rsp.cause.offend_ie_type = rsp_info.offending;
			cbr_rsp.cause.offend_ie_len = 0;
		} else {
			set_ie_header(&cbr_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			              sizeof(struct cause_ie_hdr_t));
		}

		cbr_rsp.bearer_cnt = rsp_info.bearer_count;
		for (int i = 0; i < rsp_info.bearer_count; i++) {
			set_ie_header(&cbr_rsp.bearer_contexts[i].header, GTP_IE_BEARER_CONTEXT,
					IE_INSTANCE_ZERO, 0);

			set_ebi(&cbr_rsp.bearer_contexts[i].eps_bearer_id, IE_INSTANCE_ZERO,
					rsp_info.bearer_id[i]);
			cbr_rsp.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

			set_cause_error_value(&cbr_rsp.bearer_contexts[i].cause, IE_INSTANCE_ZERO,
					cause_value, cause_source);
			cbr_rsp.bearer_contexts[i].header.len += sizeof(uint16_t) + IE_HEADER_SIZE;

		}

		payload_length = encode_create_bearer_rsp(&cbr_rsp, (uint8_t *)gtpv2c_tx);

		if(context != NULL && pdn_cntxt != NULL) {

			if(context->piggyback == FALSE && cause_value !=
					GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING &&
					pdn_cntxt->state != PFCP_SESS_MOD_REQ_SNT_STATE ) {

					err_ret = clean_up_while_cbr_error(rsp_info.teid, msg->msg_type, pdn_cntxt);
					if (err_ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error while cleaning"
						      " create bearer error response.\n", LOG_VALUE);
					}
				}
		}
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
		           s5s8_recv_sockaddr, REJ);
	} else {
		struct resp_info *resp = NULL;

		if (pdn_cntxt != NULL) {

			if(get_sess_entry(pdn_cntxt->seid, &resp) != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
				"for seid: %d", LOG_VALUE, pdn_cntxt->seid);
			}

		int ebi_id = 0;
		for (int idx = 0; idx < resp->bearer_count ; ++idx) {
			ebi_id = resp->eps_bearer_ids[idx];
		}

			ebi_index = GET_EBI_INDEX(ebi_id);

		if (resp->msg_type == GTP_BEARER_RESOURCE_CMD) {
			send_bearer_resource_failure_indication(msg,cause_value,
					CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			provision_ack_ccr(pdn_cntxt, pdn_cntxt->eps_bearers[ebi_index],
					RULE_ACTION_ADD, RESOURCE_ALLOCATION_FAILURE);
		}

		err_ret = clean_up_while_cbr_error(rsp_info.teid, msg->msg_type, pdn_cntxt);
		if (err_ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error while cleaning"
			      " create bearer error response.\n", LOG_VALUE);
			return;
		}

		if (resp->msg_type != GTP_BEARER_RESOURCE_CMD)
			gen_reauth_error_response(pdn_cntxt, DIAMETER_UNABLE_TO_COMPLY);
		}
	}
}

void ubr_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface)
{

	int ret = 0;
	int ebi_index = 0;
	ue_context *context = NULL;
	err_rsp_info rsp_info = {0};
	pdn_connection *pdn_cntxt = NULL;
	struct resp_info *resp = NULL;
	/*extract ebi_id from array as all the ebi's will be of same pdn.*/

	get_error_rsp_info(msg, &rsp_info, 0);
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ebi_index = GET_EBI_INDEX(rsp_info.bearer_id[0]);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	}

	if (msg->msg_type == GTP_UPDATE_BEARER_REQ) {
		ret = get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context);
	} else {
		ret = get_ue_context(rsp_info.teid, &context);
	}
	if(ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
	}
	pdn_cntxt = GET_PDN(context, ebi_index);
	if (pdn_cntxt != NULL) {
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn_cntxt->seid);
		}
	} else {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
	}

	if (context != NULL) {
		if (context->cp_mode != SGWC)
			iface = GX_IFACE;
		else
			iface = S5S8_IFACE;
	}

	if (iface == S5S8_IFACE) {
		upd_bearer_rsp_t ubr_rsp = {0};

		set_gtpv2c_teid_header(&ubr_rsp.header,
		                       GTP_UPDATE_BEARER_RSP,
		                       rsp_info.sender_teid,
		                       rsp_info.seq, 0);

		set_cause_error_value(&ubr_rsp.cause, IE_INSTANCE_ZERO, cause_value,
				cause_source);

		if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
			set_ie_header(&ubr_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
					sizeof(struct cause_ie));
			ubr_rsp.cause.offend_ie_type = rsp_info.offending;
			ubr_rsp.cause.offend_ie_len = 0;
		} else {
			set_ie_header(&ubr_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
					sizeof(struct cause_ie_hdr_t));
		}

		ubr_rsp.bearer_context_count = rsp_info.bearer_count;
		for (int i = 0; i < rsp_info.bearer_count; i++) {

			set_ie_header(&ubr_rsp.bearer_contexts[i].header, GTP_IE_BEARER_CONTEXT,
			              IE_INSTANCE_ZERO, 0);

			set_ebi(&ubr_rsp.bearer_contexts[i].eps_bearer_id, IE_INSTANCE_ZERO,
			        rsp_info.bearer_id[i]);
			ubr_rsp.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

			set_cause_error_value(&ubr_rsp.bearer_contexts[i].cause, IE_INSTANCE_ZERO,
			                      cause_value, cause_source);
			ubr_rsp.bearer_contexts[i].header.len += sizeof(uint16_t) + IE_HEADER_SIZE;
		}

		payload_length = encode_upd_bearer_rsp(&ubr_rsp, (uint8_t *)gtpv2c_tx);
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
		            s5s8_recv_sockaddr, SENT);

		if (get_ue_context_while_error(rsp_info.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n",LOG_VALUE, rsp_info.teid);
		}

		reset_resp_info_structure(resp);

		/* copy packet for user level packet copying or li */
		if (context) {
			if (context->dupl) {
				process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						 ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						 ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

			}
		}
	} else {

		if (pdn_cntxt != NULL && resp != NULL) {

			if (resp->msg_type == GTP_BEARER_RESOURCE_CMD) {

				send_bearer_resource_failure_indication(msg,cause_value,
						CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
				provision_ack_ccr(pdn_cntxt, pdn_cntxt->eps_bearers[ebi_index],
						RULE_ACTION_MODIFY, RESOURCE_ALLOCATION_FAILURE);
				return;

			} else if(resp->msg_type == GTP_MODIFY_BEARER_CMD) {

					modify_bearer_failure_indication(msg, cause_value,
							CAUSE_SOURCE_SET_TO_0,
							context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					provision_ack_ccr(pdn_cntxt, pdn_cntxt->eps_bearers[ebi_index],
							RULE_ACTION_MODIFY, RESOURCE_ALLOCATION_FAILURE);

					/* CleanUp for HSS INITIATED FLOW and CONTEXT NOT FOUND, don't need to cleanup */
					if(cause_value != GTPV2C_CAUSE_CONTEXT_NOT_FOUND) {

						delete_bearer_request_cleanup(pdn_cntxt, context, pdn_cntxt->default_bearer_id);
					} else {
						/*PGWC should send PGWU pfcp session deletion request*/
						pfcp_sess_del_req_t pfcp_sess_del_req = {0};
						fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);

						pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn_cntxt->dp_seid;

						uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
						int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
						pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
						header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

						if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
												upf_pfcp_sockaddr, SENT) < 0)
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error "
							"in Sending Session Modification Request. "
							"Error : %i\n", LOG_VALUE, errno);

						pdn_cntxt->state = PFCP_SESS_DEL_REQ_SNT_STATE;
						resp->state = pdn_cntxt->state;
						pdn_cntxt->proc = DETACH_PROC;
						resp->proc = DETACH_PROC;
						context->mbc_cleanup_status = PRESENT;
						resp->linked_eps_bearer_id = pdn_cntxt->default_bearer_id;
						send_ccr_t_req(msg, rsp_info.ebi, rsp_info.teid);
					}
				return;
			}
			else {
				gen_reauth_error_response(pdn_cntxt, DIAMETER_UNABLE_TO_COMPLY);

				return;
			}

		}
		reset_resp_info_structure(resp);
	}
	return;
}

/* Function to Fill and Send  Version not supported response to peer node */
void send_version_not_supported(int iface, uint32_t seq) {
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;
	gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;

	set_gtpv2c_header(header, 0, GTP_VERSION_NOT_SUPPORTED_IND, 0, seq, 0);


	uint16_t msg_len = 0;
	msg_len = encode_gtpv2c_header_t(header, (uint8_t *)gtpv2c_tx);
	header->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

	payload_length = msg_len;
	if (iface == S11_IFACE) {
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		            s11_mme_sockaddr, SENT);

	} else {
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
		            s5s8_recv_sockaddr, SENT);

	}
	return;
}


void send_bearer_resource_failure_indication(msg_info *msg,
		uint8_t cause_value, uint8_t cause_source, int iface)
{
	int ret = 0;
	err_rsp_info rsp_info = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	bearer_rsrc_fail_indctn_t ber_fail_ind = {0};
	get_error_rsp_info(msg, &rsp_info, 0);

	if (msg->msg_type == GTP_BEARER_RESOURCE_FAILURE_IND) {
		ret = get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context);
	} else {
		ret = get_ue_context(rsp_info.teid, &context);
	}

	if(ret == -1) {
		ret = get_ue_context(msg->teid, &context);
		rsp_info.teid = msg->teid;
	}

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
	}

	if(context != NULL) {
		rsp_info.seq = context->ue_initiated_seq_no;
		rsp_info.sender_teid = context->s11_mme_gtpc_teid;
		set_pti(&ber_fail_ind.pti, IE_INSTANCE_ZERO, context->proc_trans_id);
	}

	if(msg->msg_type == GTP_BEARER_RESOURCE_CMD) {
		set_pti(&ber_fail_ind.pti, IE_INSTANCE_ZERO, msg->gtpc_msg.bearer_rsrc_cmd.pti.proc_trans_id);
		rsp_info.seq = msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.seq;
	}

	set_gtpv2c_teid_header(&ber_fail_ind.header,
	                       GTP_BEARER_RESOURCE_FAILURE_IND,
	                       rsp_info.sender_teid,
	                       rsp_info.seq, 0);
	set_cause_error_value(&ber_fail_ind.cause, IE_INSTANCE_ZERO,
	                      cause_value, cause_source);
	if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
		set_ie_header(&ber_fail_ind.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		              sizeof(struct cause_ie));
		ber_fail_ind.cause.offend_ie_type = rsp_info.offending;
		ber_fail_ind.cause.offend_ie_len = 0;
	}
	else {
		set_ie_header(&ber_fail_ind.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		              sizeof(struct cause_ie_hdr_t));
	}

	pdn = GET_PDN(context, GET_EBI_INDEX(rsp_info.bearer_id[0]));

	if(pdn!=NULL) {
		set_ebi(&ber_fail_ind.linked_eps_bearer_id, IE_INSTANCE_ZERO,
		        pdn->default_bearer_id);
	} else {
		set_ebi(&ber_fail_ind.linked_eps_bearer_id, IE_INSTANCE_ZERO,
		        rsp_info.bearer_id[0]);
	}

	ber_fail_ind.cause.cause_value = cause_value;

	if(context != NULL) {
		if (context->cp_mode != SGWC || context->cp_mode != SAEGWC )
			ber_fail_ind.cause.cs = 1;
		else
			ber_fail_ind.cause.cs = 0;
	}

	payload_length = encode_bearer_rsrc_fail_indctn(&ber_fail_ind, (uint8_t *)gtpv2c_tx);

	if(context != NULL) {
		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	}

	if(iface == S5S8_IFACE){
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,s5s8_recv_sockaddr
					, REJ);
		if(context != NULL) {
			context->is_sent_bearer_rsc_failure_indc = PRESENT;
		}
	} else {
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		            s11_mme_sockaddr, REJ);
	}

	if(context != NULL) {
		context->ue_initiated_seq_no = 0;
		context->proc_trans_id = 0;
	}
}

void delete_bearer_cmd_failure_indication(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface)
{
	int ret = 0;
	err_rsp_info rsp_info = {0};
	ue_context *context = NULL;
	get_error_rsp_info(msg, &rsp_info, 0);
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	del_bearer_fail_indctn_t del_fail_ind={0};
	struct resp_info *resp = NULL;
	pdn_connection *pdn_cntxt = NULL;

	set_gtpv2c_teid_header(&del_fail_ind.header,
	                       GTP_DELETE_BEARER_FAILURE_IND,
	                       rsp_info.sender_teid,
	                       rsp_info.seq, 0);
	set_cause_error_value(&del_fail_ind.cause, IE_INSTANCE_ZERO,
	                      cause_value, cause_source);
	if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
		set_ie_header(&del_fail_ind.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		              sizeof(struct cause_ie));
		del_fail_ind.cause.offend_ie_type = rsp_info.offending;
		del_fail_ind.cause.offend_ie_len = 0;
	}
	else {
		set_ie_header(&del_fail_ind.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		              sizeof(struct cause_ie_hdr_t));
	}

	for (int i = 0; i < rsp_info.bearer_count; i++) {

		set_ie_header(&del_fail_ind.bearer_context[i].header, GTP_IE_BEARER_CONTEXT,
		              IE_INSTANCE_ZERO, 0);

		set_ebi(&del_fail_ind.bearer_context[i].eps_bearer_id, IE_INSTANCE_ZERO,
		        rsp_info.bearer_id[i]);
		del_fail_ind.bearer_context[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;
		set_cause_error_value(&del_fail_ind.bearer_context[i].cause, IE_INSTANCE_ZERO,
		                      cause_value, cause_source);
		del_fail_ind.bearer_context[i].header.len += sizeof(uint16_t) + IE_HEADER_SIZE;
	}

	if (msg->msg_type == GTP_DELETE_BEARER_FAILURE_IND) {
		ret = get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context);
	} else {
		ret = get_ue_context(rsp_info.teid, &context);
	}

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
	}

	pdn_cntxt = GET_PDN(context, GET_EBI_INDEX(rsp_info.bearer_id[0]));
	if (pdn_cntxt != NULL) {
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn_cntxt->seid);
		}

		if (resp != NULL) {
			reset_resp_info_structure(resp);
		}
	}

	payload_length = encode_del_bearer_fail_indctn(&del_fail_ind, (uint8_t *)gtpv2c_tx);

	if (context != NULL) {
		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	}

	if(iface == S5S8_IFACE) {
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length, s5s8_recv_sockaddr
					, REJ);
	} else if(iface == S11_IFACE) {

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		            s11_mme_sockaddr, REJ);
	}
}

void
pfcp_modification_error_response(struct resp_info *resp, msg_info *msg, uint8_t cause_value)
{
	switch (resp->msg_type) {
		case GTP_CREATE_SESSION_RSP : {
			msg->cp_mode = resp->cp_mode;
			cs_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			break;
		}

		case GTP_MODIFY_BEARER_REQ : {
			mbr_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			break;
		}

		case GTP_MODIFY_ACCESS_BEARER_REQ : {
			mod_access_bearer_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0);
			break;
		}

		case GTP_CREATE_BEARER_REQ : {
			cbr_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
			break;
		}

		case GTP_CREATE_BEARER_RSP : {
			cbr_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
			break;
		}

		case GTP_DELETE_BEARER_REQ : {
			delete_bearer_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
			break;
		}

		case GTP_DELETE_BEARER_RSP : {
			delete_bearer_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
			break;
		}

		case GTP_DELETE_SESSION_RSP : {
			ds_error_response(msg, cause_value,CAUSE_SOURCE_SET_TO_0,
					resp->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			break;
		}
		case GTP_RELEASE_ACCESS_BEARERS_REQ :{
			release_access_bearer_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0,
					S11_IFACE);
			break;
		}
		case GTP_UPDATE_PDN_CONNECTION_SET_REQ: {
			update_pdn_connection_set_error_response(msg, cause_value, CAUSE_SOURCE_SET_TO_0);
			break;
		}
		default : {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"message type is not supported", LOG_VALUE);
			break;
		}
	}
}

void
gx_cca_error_response(uint8_t cause, msg_info *msg)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn_cntxt = NULL;
	struct resp_info *resp = NULL;
	uint8_t cp_mode = 0;

	switch(msg->gx_msg.cca.cc_request_type){
		case INITIAL_REQUEST : {
			cs_error_response(msg, cause, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(msg, NULL);
			break;
		}

		case UPDATE_REQUEST : {

			/* Extract the call id from session id */
			ret = retrieve_call_id((char *)msg->gx_msg.cca.session_id.val, &call_id);
			if (ret < 0) {
			        clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id "
						"found for session id: %s\n", LOG_VALUE,
						msg->gx_msg.cca.session_id.val);
			        return;
			}

			/* Retrieve PDN context based on call id */
			pdn_cntxt = get_pdn_conn_entry(call_id);
			if (pdn_cntxt == NULL)
			{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					"PDN found for CALL_ID : %u\n", LOG_VALUE, call_id);
				return;
			}

			/*Retrive the session information based on session id. */
			if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn_cntxt->seid);
				return;
			}

			switch(resp->msg_type) {
				case GTP_DELETE_BEARER_CMD : {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in "
					"CCA-U message for Delete Bearer Command with cause %s \n"
					, LOG_VALUE, cause_str(cause));
					break;
				}
				case GTP_BEARER_RESOURCE_CMD : {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in "
					"CCA-U message for Bearer Resource Command with cause %s \n"
					, LOG_VALUE, cause_str(cause));
					send_bearer_resource_failure_indication(msg, cause, CAUSE_SOURCE_SET_TO_0,
							msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

					break;
				}
				case GTP_MODIFY_BEARER_CMD : {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in "
					"CCA-U message for Modify Bearer Command with cause %s \n"
					, LOG_VALUE, cause_str(cause));
					modify_bearer_failure_indication(msg, cause, CAUSE_SOURCE_SET_TO_0,
							msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					ebi_index = GET_EBI_INDEX(pdn_cntxt->default_bearer_id);
					provision_ack_ccr(pdn_cntxt, pdn_cntxt->eps_bearers[ebi_index],
						RULE_ACTION_MODIFY, RESOURCE_ALLOCATION_FAILURE);
					break;

				}
			}
		}

		case TERMINATION_REQUEST : {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"CC-Request-Type:TERMINATION_REQUEST in "
			"Credit-Control message\n", LOG_VALUE);
			break;
		}

		case EVENT_REQUEST : {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"CC-Request-Type:EVENT_REQUEST in "
			"Credit-Control message\n", LOG_VALUE);
			break;
		}

		default : {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP CC-Request-Type contains unexpected value in "
			"Credit-Control message\n", LOG_VALUE);
			cp_mode = msg->cp_mode;
			if(cp_mode == 0)
 			{
				/* Extract the call id from session id */
				ret = retrieve_call_id((char *)msg->gx_msg.cca.session_id.val, &call_id);
				if (ret < 0)
				{
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id "
						"found for session id:%s\n", LOG_VALUE,
						msg->gx_msg.cca.session_id.val);
					return;
				}
				/* Retrieve PDN context based on call id */
				if (ret == 0)
 				{
					pdn_cntxt = get_pdn_conn_entry(call_id);
					if (pdn_cntxt == NULL)
 					{
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
							"PDN for CALL_ID:%u\n", LOG_VALUE, call_id);
						return;
					}
				}

				if (pdn_cntxt->context != NULL) {
					cp_mode = (pdn_cntxt->context)->cp_mode;
				} else if ((msg->cp_mode) && (pdn_cntxt->context == NULL)) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get the context,"
							"Context is NULL\n", LOG_VALUE);
						return;
				}
			}
			cs_error_response(msg, cause, CAUSE_SOURCE_SET_TO_0,
					cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(msg, NULL);
			break;
		}
	}
}

void
update_pdn_connection_set_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source)
{

	int ret = 0;
	ue_context *context = NULL;
	upd_pdn_conn_set_rsp_t upd_pdn_rsp = {0};
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = get_ue_context(msg->gtpc_msg.upd_pdn_req.header.teid.has_teid.teid, &context);

	if (ret) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE,
				msg->gtpc_msg.upd_pdn_req.header.teid.has_teid.teid);
		return;
	}

	for(uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = context->eps_bearers[i];
		if(bearer == NULL)
			continue;
		else
			break;
	}

	pdn = bearer->pdn;
	set_gtpv2c_teid_header((gtpv2c_header_t *) &upd_pdn_rsp, GTP_UPDATE_PDN_CONNECTION_SET_RSP,
			pdn->s5s8_sgw_gtpc_teid, msg->gtpc_msg.upd_pdn_req.header.teid.has_teid.seq, 0);

	set_cause_error_value(&upd_pdn_rsp.cause, IE_INSTANCE_ZERO,
	                      cause_value, cause_source);
	set_ie_header(&upd_pdn_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
							sizeof(struct cause_ie_hdr_t));

	payload_length = encode_upd_pdn_conn_set_rsp(&upd_pdn_rsp, (uint8_t *)gtpv2c_tx);

	ret = set_dest_address(pdn->s5s8_sgw_gtpc_ip, &s5s8_recv_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			s5s8_recv_sockaddr, SENT);

	/* copy packet for user level packet copying or li */
	if (context) {
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						 ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						 ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

		}
	}

	pdn->state = CONNECTED_STATE;
}

void
change_notification_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface)
{
	uint16_t teid = 0;
	int ebi_index = 0;
	ue_context *context = NULL;
	pdn_connection *pdn =  NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	change_noti_rsp_t change_notification_rsp = {0};

	ebi_index = GET_EBI_INDEX(msg->gtpc_msg.change_not_req.lbi.ebi_ebi);
	if (ebi_index == -1 && msg->msg_type != GTP_CHANGE_NOTIFICATION_RSP) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	}

	if(get_ue_context(msg->gtpc_msg.change_not_req.header.teid.has_teid.teid, &context)) {
		if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid,
											&context)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
									" UE context for teid: %d \n",LOG_VALUE,
									msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid);
		}
	}

	if(context != NULL) {

		if(ebi_index != -1) {
			pdn = context->eps_bearers[ebi_index]->pdn;
			if(context->cp_mode == PGWC) {

				teid = pdn->s5s8_sgw_gtpc_teid;
			}
		}
		else {
				teid = context->s11_mme_gtpc_teid;
		}
	}

	if(context != NULL && context->cp_mode == PGWC) {

		set_gtpv2c_teid_header((gtpv2c_header_t *) &change_notification_rsp, GTP_CHANGE_NOTIFICATION_RSP,
				teid, msg->gtpc_msg.change_not_req.header.teid.has_teid.seq, 0);
	} else {

		set_gtpv2c_teid_header((gtpv2c_header_t *) &change_notification_rsp, GTP_CHANGE_NOTIFICATION_RSP,
				teid, msg->gtpc_msg.change_not_req.header.teid.has_teid.seq, 0);
	}

	change_notification_rsp.imsi.imsi_number_digits = msg->gtpc_msg.change_not_req.imsi.imsi_number_digits;

	set_ie_header(&change_notification_rsp.imsi.header, GTP_IE_IMSI, IE_INSTANCE_ZERO,
				                 msg->gtpc_msg.change_not_req.imsi.header.len);

	set_cause_error_value(&change_notification_rsp.cause, IE_INSTANCE_ZERO,
	                      cause_value, cause_source);

	if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
			set_ie_header(&change_notification_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
									          sizeof(struct cause_ie));
			change_notification_rsp.cause.offend_ie_type = GTP_IE_RAT_TYPE;
			change_notification_rsp.cause.offend_ie_len = 0;
	} else {
			set_ie_header(&change_notification_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
							sizeof(struct cause_ie_hdr_t));
	}
	/*Encode Change Notification Rsp*/
	payload_length = encode_change_noti_rsp(&change_notification_rsp, (uint8_t *)gtpv2c_tx);

	if(context != NULL) {

		if(context->cp_mode == PGWC)

				iface = S5S8_IFACE;
		else
				iface = S11_IFACE;
	}
	if(iface == S5S8_IFACE) {
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length, s5s8_recv_sockaddr, REJ);
	}
	else if(iface == S11_IFACE) {
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		            s11_mme_sockaddr, REJ);
	}
}

void
send_error_resp(pdn_connection *pdn, uint8_t cause_value)
{
	msg_info msg = {0};

	if (pdn == NULL || pdn->context == NULL )
		return;

	msg.msg_type = GTP_CREATE_SESSION_REQ;
	msg.gtpc_msg.csr.bearer_count = pdn->num_bearer;
	for (uint8_t itr = 0; itr <  pdn->num_bearer; ++itr) {
		msg.gtpc_msg.csr.bearer_contexts_to_be_created[itr].header.len = 1;
		msg.gtpc_msg.csr.bearer_contexts_to_be_created[itr].eps_bearer_id.ebi_ebi =
			pdn->default_bearer_id;
	}

	msg.gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key =
			pdn->context->s11_mme_gtpc_teid;
	msg.gtpc_msg.csr.header.teid.has_teid.seq = pdn->csr_sequence;
	msg.gtpc_msg.csr.header.teid.has_teid.teid =
		pdn->context->s11_sgw_gtpc_teid;
	msg.cp_mode = pdn->context->cp_mode;
	cs_error_response(&msg, cause_value, CAUSE_SOURCE_SET_TO_0,
			(pdn->context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE));

}

void
release_access_bearer_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface)
{

	int ret = 0;
	uint32_t teid = 0;
	ue_context *context = NULL;
	release_access_bearer_resp_t rel_acc_ber_rsp = {0};

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;


	ret = get_ue_context(msg->gtpc_msg.rel_acc_ber_req.header.teid.has_teid.teid, &context);

	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"Ue context for teid: %d \n", LOG_VALUE, msg->gtpc_msg.rel_acc_ber_req.header.teid.has_teid.teid);
	}
	else {
		teid = context->s11_mme_gtpc_teid;
		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *) &rel_acc_ber_rsp, GTP_RELEASE_ACCESS_BEARERS_RSP,
			 teid, msg->gtpc_msg.rel_acc_ber_req.header.teid.has_teid.seq, NOT_PIGGYBACKED);

	set_cause_error_value(&rel_acc_ber_rsp.cause, IE_INSTANCE_ZERO,
	                      cause_value, cause_source);

	payload_length = encode_release_access_bearers_rsp(&rel_acc_ber_rsp, (uint8_t *)gtpv2c_tx);

	if(iface == S11_IFACE) {

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, REJ);
	}
}

void
clean_up_upf_context(pdn_connection *pdn, ue_context *context)
{
	upf_context_t *upf_context = NULL;
	context_key *key = NULL;

	if ((upf_context_entry_lookup(pdn->upf_ip, &upf_context)) ==  0) {

		if (upf_context->state < PFCP_ASSOC_RESP_RCVD_STATE) {

			for (uint8_t i = 0; i < upf_context->csr_cnt; i++) {
				key = (context_key *) upf_context->pending_csr_teid[i];
				if (key != NULL ) {
					if(key->teid == context->s11_sgw_gtpc_teid ) {
						rte_free(upf_context->pending_csr_teid[i]);
						upf_context->pending_csr_teid[i] = NULL;
						break;
					}
				}
			}

			if (upf_context->pending_csr_teid[upf_context->csr_cnt - 1]  == NULL) {

				/* Delete entry from teid info list for given upf*/
				delete_entry_from_teid_list(pdn->upf_ip, &upf_teid_info_head);
				rte_hash_del_key(upf_context_by_ip_hash, (const void *) &pdn->upf_ip);

				if (upf_context != NULL) {
					rte_free(upf_context);
					upf_context  = NULL;
				}
			}
		}
	}
	return;
}


int
clean_context_hash(ue_context *context, uint32_t teid, uint64_t *imsi_val, bool error_status)
{
	int ret = 0;
	if (teid == 0) {
		ue_context *context = NULL;
		ret = rte_hash_lookup_data(ue_context_by_imsi_hash, imsi_val, (void **) & (*context));

		if (ret == -ENOENT) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"No data found for %x imsi\n", LOG_VALUE, *imsi_val);
			if ( error_status == True )
				return -1;
			else
				return -2;
		}
	}
	rte_hash_del_key(ue_context_by_imsi_hash, (const void *) imsi_val);
	rte_hash_del_key(ue_context_by_fteid_hash, (const void *) &teid);
	if (context != NULL) {
		rte_free(context);
		context = NULL;
	}
	return 0;
}

void
modify_bearer_failure_indication(msg_info *msg, uint8_t cause_value,
									uint8_t cause_source, int iface) {

	int ret = 0;
	err_rsp_info rsp_info = {0};
	ue_context *context = NULL;
	get_error_rsp_info(msg, &rsp_info, 0);
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	mod_bearer_fail_indctn_t mod_fail_ind = {0};
	struct resp_info *resp = NULL;
	pdn_connection *pdn_cntxt = NULL;

	if (msg->msg_type == GTP_MODIFY_BEARER_FAILURE_IND) {
		ret = get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context);
	} else {
		ret = get_ue_context(rsp_info.teid, &context);
	}
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
	}

	if(context != NULL) {
		rsp_info.seq = context->ue_initiated_seq_no;
		rsp_info.sender_teid = context->s11_mme_gtpc_teid;
	}

	if(msg->msg_type == GTP_MODIFY_BEARER_CMD) {

		rsp_info.seq = msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.seq;
	}

	set_gtpv2c_teid_header(&mod_fail_ind.header,
	                       GTP_MODIFY_BEARER_FAILURE_IND,
	                       rsp_info.sender_teid,
	                       rsp_info.seq, 0);
	set_cause_error_value(&mod_fail_ind.cause, IE_INSTANCE_ZERO,
	                      cause_value, cause_source);
	if (cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ) {
		set_ie_header(&mod_fail_ind.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		              sizeof(struct cause_ie));
		mod_fail_ind.cause.offend_ie_type = rsp_info.offending;
		mod_fail_ind.cause.offend_ie_len = 0;
	}
	else {
		set_ie_header(&mod_fail_ind.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		              sizeof(struct cause_ie_hdr_t));
	}

	if (msg->msg_type == GTP_MODIFY_BEARER_FAILURE_IND) {
		ret = get_ue_context_by_sgw_s5s8_teid(rsp_info.teid, &context);
	} else {
		ret = get_ue_context(rsp_info.teid, &context);
	}

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE, rsp_info.teid);
	}

	pdn_cntxt = GET_PDN(context, GET_EBI_INDEX(rsp_info.bearer_id[0]));
	if (pdn_cntxt != NULL) {
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn_cntxt->seid);
		}

		if (resp != NULL) {
			reset_resp_info_structure(resp);
		}
	}

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_fail_indctn(&mod_fail_ind, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);
	if (context != NULL) {

		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
	}
	if(context != NULL) {

		if(context->cp_mode == PGWC)
			iface = S5S8_IFACE;
		else
			iface = S11_IFACE;
	}

	if(iface == S5S8_IFACE) {
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length, s5s8_recv_sockaddr, REJ);

	} else if(iface == S11_IFACE) {

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		           s11_mme_sockaddr, REJ);
	}

}

int cleanup_ue_and_bearer(uint32_t teid, int ebi_index)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	upf_context_t *upf_ctx = NULL;

	if (get_ue_context_while_error(teid, &context) == 0){
			pdn = GET_PDN(context ,ebi_index);
			if(pdn == NULL){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
				return -1;
			}

			if ((upf_context_entry_lookup(pdn->upf_ip, &upf_ctx)) ==  0) {
				if(upf_ctx->state < PFCP_ASSOC_RESP_RCVD_STATE){
					/* Delete entry from teid info list for given upf*/
					delete_entry_from_teid_list(pdn->upf_ip, &upf_teid_info_head);

					rte_hash_del_key(upf_context_by_ip_hash, (const void *) &pdn->upf_ip);

					for (uint8_t i = 0; i < upf_ctx->csr_cnt; i++) {
						if(upf_ctx->pending_csr_teid[i] != NULL){
							rte_free(upf_ctx->pending_csr_teid[i]);
							upf_ctx->pending_csr_teid[i] = NULL;
						}
						upf_ctx->csr_cnt--;
					}

					if (upf_ctx != NULL) {
						rte_free(upf_ctx);
						upf_ctx = NULL;
					}
				}
			}

			if (get_sess_entry(pdn->seid, &resp) == 0) {

				if(context->piggyback == TRUE) {
					delete_dedicated_bearers(pdn,
							resp->eps_bearer_ids, resp->bearer_count);
				}

				rte_hash_del_key(sm_hash, (const void *) &(pdn->seid));
				if (resp != NULL) {
					rte_free(resp);
					resp = NULL;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
					return -1;
			}

			for(int8_t idx = 0; idx < MAX_BEARERS; idx++) {
				if(context->eps_bearers[idx] == NULL) {
					continue;
				}else {
					if(context->eps_bearers[idx] != NULL){
						rte_free(pdn->eps_bearers[idx]);
						pdn->eps_bearers[idx] = NULL;
						context->eps_bearers[idx] = NULL;
						if(pdn->num_bearer != 0) {
							pdn->num_bearer--;
						}
					}
				}
			}

			if(pdn->num_bearer == 0){
				if(pdn->s5s8_sgw_gtpc_teid != 0) {
					  rte_hash_del_key(bearer_by_fteid_hash, (const void *)
								&(pdn->s5s8_sgw_gtpc_teid));
				}
				if(pdn != NULL) {
					rte_free(pdn);
					pdn = NULL;
					context->num_pdns --;
				}
			}
			if (context->num_pdns == 0){
				rte_hash_del_key(ue_context_by_imsi_hash,(const void *) &(*context).imsi);
				rte_hash_del_key(ue_context_by_fteid_hash,(const void *) &teid);
				if(context != NULL )
					rte_free(context);
				context = NULL;
			}
		}
	return 0;
}

void delete_bearer_request_cleanup(pdn_connection *pdn, ue_context *context, uint8_t lbi) {

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	uint32_t seq_no = generate_seq_number();
	int ret = 0;
	set_delete_bearer_request(gtpv2c_tx, seq_no,
			pdn, lbi, 0, 0, 1);

	uint16_t payload_len = 0;

	payload_len = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);


	if( PGWC == context->cp_mode ) {
			ret = set_dest_address(pdn->s5s8_sgw_gtpc_ip, &s5s8_recv_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}

			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_len,
	            s5s8_recv_sockaddr, REJ);

	} else {
			ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr, REJ);
	}

	pdn->state = DELETE_BER_REQ_SNT_STATE;
	context->mbc_cleanup_status = PRESENT;
}

void send_delete_session_request_after_timer_retry(ue_context *context, int ebi_index)
{
	uint8_t encoded_msg[GTP_MSG_LEN] = {0};
	int ret = 0;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	if(context != NULL)
	{
		pdn = context->eps_bearers[ebi_index]->pdn;
		if(pdn != NULL)
		{

			ret = set_dest_address(pdn->s5s8_pgw_gtpc_ip, &s5s8_recv_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			if (get_sess_entry(pdn->seid, &resp) != 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
						"while sending DSR, session ID:%lu\n", LOG_VALUE, pdn->seid);
			}
		}
		if(pdn == NULL || resp == NULL)
		{
			return;
		}
	}

	/* Indication flags not required in DSR for PGWC */
	resp->gtpc_msg.dsr.indctn_flgs.header.len = 0;
	encode_del_sess_req((del_sess_req_t *)&(resp->gtpc_msg.dsr), encoded_msg);

	gtpv2c_header *header;
	header =(gtpv2c_header*) encoded_msg;

	gen_sgwc_s5s8_delete_session_request((gtpv2c_header_t *)encoded_msg,
			gtpv2c_tx, htonl(pdn->s5s8_pgw_gtpc_teid),
			header->teid_u.has_teid.seq,
			resp->linked_eps_bearer_id);

	/* Update the session state */
	resp->state = DS_REQ_SNT_STATE;

	update_ue_state(context, DS_REQ_SNT_STATE, ebi_index);

	uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			s5s8_recv_sockaddr, SENT);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	}
}


void
crt_indir_data_frwd_tun_error_response(msg_info *msg, uint8_t cause_value)
{

	ue_context *context = NULL;
	node_address_t node_value = {0};
	int ret = 0;
	err_rsp_info rsp_info = {0};
	get_error_rsp_info(msg, &rsp_info, 0);


	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	create_indir_data_fwdng_tunn_rsp_t crt_resp = {0};

	set_gtpv2c_teid_header(&crt_resp.header,
			GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RSP,
			rsp_info.sender_teid,
			rsp_info.seq, 0);


	set_cause_error_value(&crt_resp.cause, IE_INSTANCE_ZERO, cause_value,
			CAUSE_SOURCE_SET_TO_0);

	for(uint8_t i = 0; i < rsp_info.bearer_count; i++){
		set_ie_header(&crt_resp.bearer_contexts[i].header, GTP_IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);

		set_ebi(&crt_resp.bearer_contexts[i].eps_bearer_id, IE_INSTANCE_ZERO,
				rsp_info.bearer_id[i]);
		crt_resp.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_cause_error_value(&crt_resp.bearer_contexts[i].cause, IE_INSTANCE_ZERO, cause_value,
				CAUSE_SOURCE_SET_TO_0);

		crt_resp.bearer_contexts[i].header.len += sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;
		if (context) {
			uint8_t ebi = rsp_info.bearer_id[i] - 5;

			ret = fill_ip_addr(context->eps_bearers[ebi]->s1u_sgw_gtpu_ip.ipv4_addr,
				context->eps_bearers[ebi]->s1u_sgw_gtpu_ip.ipv6_addr,
				&node_value);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}

		}

		crt_resp.bearer_contexts[i].header.len +=
			set_gtpc_fteid(&crt_resp.bearer_contexts[i].sgw_fteid_dl_data_fwdng,
				GTPV2C_IFTYPE_SGW_GTPU_DL_DATA_FRWD, IE_INSTANCE_THREE, node_value,
				rsp_info.teid);

		crt_resp.bearer_contexts[i].header.len +=
			set_gtpc_fteid(&crt_resp.bearer_contexts[i].sgw_fteid_ul_data_fwdng,
				GTPV2C_IFTYPE_SGW_GTPU_DL_DATA_FRWD, IE_INSTANCE_FIVE, node_value,
				rsp_info.teid);

	}

	cleanup_for_indirect_tunnel(&rsp_info);

	uint16_t msg_len = 0;
	msg_len = encode_create_indir_data_fwdng_tunn_rsp(&crt_resp,(uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);

	payload_length = ntohs(gtpv2c_tx->gtpc.length) + sizeof(gtpv2c_tx->gtpc);
	if(context){
		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
		}
	}
	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, REJ);


}

void
delete_indir_data_frwd_error_response(msg_info *msg, uint8_t cause_value)
{
	err_rsp_info rsp_info = {0};

	get_error_rsp_info(msg, &rsp_info, 0);


	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	del_indir_data_fwdng_tunn_resp_t dlt_resp = {0};

	set_gtpv2c_teid_header(&dlt_resp.header,
			GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RSP,
			rsp_info.teid,
			rsp_info.seq, 0);

	set_cause_error_value(&dlt_resp.cause, IE_INSTANCE_ZERO, cause_value, CAUSE_SOURCE_SET_TO_0);

	uint16_t msg_len = 0;
	msg_len = encode_del_indir_data_fwdng_tunn_rsp(&dlt_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;
	header->gtpc.message_len = htons(msg_len - 4);

	payload_length = ntohs(gtpv2c_tx->gtpc.length) + sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr,REJ);
}

void
cleanup_for_indirect_tunnel(err_rsp_info *resp)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_context = NULL;
	int ret;

	ret = rte_hash_lookup_data(ue_context_by_sender_teid_hash,
			&resp->sender_teid, (void **) &context);
	if( ret < 0){
		return;
	}

	pdn = context->indirect_tunnel->pdn;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ip), (void **) &(upf_context));
	if (ret >= 0) {
		if (upf_context->state < PFCP_ASSOC_RESP_RCVD_STATE) {
			rte_hash_del_key(upf_context_by_ip_hash,
					(const void *) &pdn->upf_ip);

			rte_free(upf_context);
			upf_context = NULL;
		}
	}

	for( uint8_t i = 0; i < resp->bearer_count; i++) {
		if(pdn->eps_bearers[i] != NULL){
			rte_free(pdn->eps_bearers[i]);
			pdn->num_bearer -- ;
		}
	}
	rte_free(pdn);
	pdn = NULL;
	context->num_pdns--;

	rte_hash_del_key(ue_context_by_sender_teid_hash, &context->s11_mme_gtpc_teid);

	if(context->num_pdns == 0){
		rte_hash_del_key(ue_context_by_imsi_hash,(const void *) &context->imsi);
		rte_hash_del_key(ue_context_by_fteid_hash,(const void *) &resp->teid);
		rte_free(context);
		context = NULL;
	}
}

void mod_access_bearer_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source)
{
	ue_context *context = NULL;
	err_rsp_info rsp_info = {0};
	int ret = 0;
	pdn_connection *pdn_cntxt =  NULL;
	get_error_rsp_info(msg, &rsp_info, 0);
	struct resp_info *resp = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	mod_acc_bearers_rsp_t mod_acc_resp = {0};
	set_gtpv2c_teid_header(&mod_acc_resp.header,
			GTP_MODIFY_ACCESS_BEARER_RSP,
			rsp_info.sender_teid,
			rsp_info.seq, 0);

	set_cause_error_value(&mod_acc_resp.cause, IE_INSTANCE_ZERO, cause_value,
			cause_source);

	for (uint8_t uiCnt = 0; uiCnt < rsp_info.bearer_count; ++ uiCnt) {
		set_ie_header(&mod_acc_resp.bearer_contexts_modified[uiCnt].header,
				GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);

		set_cause_error_value(&mod_acc_resp.bearer_contexts_modified[uiCnt].cause,
				IE_INSTANCE_ZERO, cause_value, cause_source);


		mod_acc_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(struct cause_ie_hdr_t) +
			IE_HEADER_SIZE;

		set_ebi(&mod_acc_resp.bearer_contexts_modified[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
				rsp_info.bearer_id[uiCnt]);

		mod_acc_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		node_address_t node_value = {0};

		if (get_ue_context(rsp_info.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n",LOG_VALUE, rsp_info.teid);
		}

		if (context) {
			int ebi_index = GET_EBI_INDEX(rsp_info.bearer_id[uiCnt]);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			}

			if (ebi_index > 0 && context->eps_bearers[ebi_index] != NULL)
				ret = fill_ip_addr(context->eps_bearers[ebi_index]->s1u_enb_gtpu_ip.ipv4_addr,
					context->eps_bearers[ebi_index]->s1u_enb_gtpu_ip.ipv6_addr,
					&node_value);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}
		}

		set_gtpc_fteid(&mod_acc_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
				GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, node_value,
				rsp_info.teid);

		mod_acc_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;

	}

	pdn_cntxt = GET_PDN(context, GET_EBI_INDEX(rsp_info.bearer_id[0]));
	if (pdn_cntxt != NULL) {
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry "
				"Found for sess ID: %lu\n", LOG_VALUE, pdn_cntxt->seid);
		}

		if (resp != NULL) {
			reset_resp_info_structure(resp);
		}
	}

	uint16_t msg_len = 0;
	msg_len = encode_mod_acc_bearers_rsp(&mod_acc_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);

	payload_length = ntohs(gtpv2c_tx->gtpc.length) + sizeof(gtpv2c_tx->gtpc);

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, REJ);

	if (context != NULL && context->dupl) {
		process_pkt_for_li(
				context, S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
				 ntohs(s11_mme_sockaddr.ipv4.sin_port) :
				 ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}

}
