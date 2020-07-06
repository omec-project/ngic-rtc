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
#include <rte_debug.h>

#include "packet_filters.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

#include "pfcp_messages.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "sm_struct.h"
#include "../cp_stats.h"
#include "../ue.h"
#include"cp_config.h"

extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;

/**
 * @brief  : Maintans gateway information
 */
struct gw_info {
	uint8_t eps_bearer_id;
	uint32_t s5s8_sgw_gtpc_teid;
	uint32_t s5s8_pgw_gtpc_ipv4;
	uint64_t seid;  /*NK: used to retrive seid */
};

/* PGWC S5S8 handlers:
 * static int delete_pgwc_context(...)
 * process_pgwc_s5s8_delete_session_request(...)
 *
 */

/**
 * @brief  : Parses delete session request message and handles the removal of
 *           corresponding data structures internal to the control plane - as well as
 *           notifying the data plane of such changes
 * @param  : gtpv2c_rx
 *           buffer containing create delete session request message
 * @param  : _context
 *           returns the UE context structure pertaining to the session to be deleted
 * @param  : del_teid_ptr
 *           returns pointer to s5s8_sgw_gtpc_teid to be deleted
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
//static int
//delete_pgwc_context(gtpv2c_header *gtpv2c_rx, ue_context **_context,
//		struct gw_info *resp)
//{
//	int ret = 0, i = 0;
//	gtpv2c_ie *current_ie;
//	gtpv2c_ie *limit_ie;
//	ue_context *context = NULL;
//	gtpv2c_ie *ebi_ei_to_be_removed = NULL;
//	static uint32_t process_pgwc_s5s8_ds_req_cnt;
//
//	//gtpv2c_rx->teid_u.has_teid.teid = ntohl(gtpv2c_rx->teid_u.has_teid.teid);
//	/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
//	 * key->ue_context_by_fteid_hash */
//	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
//	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
//	    (void **) &context);
//	if (ret < 0 || !context) {
//
//		clLog(s5s8logger, eCLSeverityDebug, "NGIC- delete_s5s8_session.c::"
//				"\n\tprocess_pgwc_s5s8_delete_session_request:"
//				"\n\tdelete_pgwc_context-ERROR!!!"
//				"\n\tprocess_pgwc_s5s8_ds_req_cnt= %u;"
//				"\n\tgtpv2c_s5s8_rx->teid_u.has_teid.teid= %X;"
//				"\n\trte_hash_lookup_data("
//					"ue_context_by_fteid_hash,..)= %d\n",
//				process_pgwc_s5s8_ds_req_cnt++,
//				gtpv2c_rx->teid_u.has_teid.teid,
//				ret);
//		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
//	}
//
//	/** TODO: we should verify mandatory fields within received message */
//	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
//	{
//		switch (current_ie->type) {
//		case GTP_IE_EPS_BEARER_ID:
//			if (current_ie->instance == IE_INSTANCE_ZERO)
//				ebi_ei_to_be_removed = current_ie;
//			break;
//		}
//	}
//
//	if (!ebi_ei_to_be_removed) {
//		/* TODO: should be responding with response indicating error
//		 * in request */
//		clLog(clSystemLog, eCLSeverityCritical, "Received delete session without ebi! - "
//				"dropping\n");
//		return -EPERM;
//	}
//
//	uint8_t ebi = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
//			ebi_ei_to_be_removed);
//
//	/* VS: Fill the eps bearer id in response */
//	resp->eps_bearer_id = ebi;
//
//	uint8_t ebi_index = ebi - 5;
//	if (!(context->bearer_bitmap & (1 << ebi_index))) {
//		clLog(clSystemLog, eCLSeverityCritical,
//		    "Received delete session on non-existent EBI - "
//		    "Dropping packet\n");
//		clLog(clSystemLog, eCLSeverityCritical, "ebi %u\n",
//		    *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t, ebi_ei_to_be_removed));
//		clLog(clSystemLog, eCLSeverityCritical, "ebi_index %u\n", ebi_index);
//		clLog(clSystemLog, eCLSeverityCritical, "bearer_bitmap %04x\n", context->bearer_bitmap);
//		clLog(clSystemLog, eCLSeverityCritical, "mask %04x\n", (1 << ebi_index));
//		return -EPERM;
//	}
//
//	pdn_connection *pdn = context->pdns[ebi_index];
//	resp->seid = context->pdns[ebi_index]->seid;  //NK:change for seid
//	if (!pdn) {
//		clLog(clSystemLog, eCLSeverityCritical, "Received delete session on "
//				"non-existent EBI\n");
//		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
//	}
//
//	if (pdn->default_bearer_id != ebi) {
//		clLog(clSystemLog, eCLSeverityCritical,
//		    "Received delete session referencing incorrect "
//		    "default bearer ebi");
//		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
//	}
//	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
//	 * key->ue_context_by_fteid_hash */
//	resp->s5s8_sgw_gtpc_teid = pdn->s5s8_sgw_gtpc_teid;
//	resp->s5s8_pgw_gtpc_ipv4 = pdn->s5s8_sgw_gtpc_ipv4.s_addr;
//
//	clLog(s5s8logger, eCLSeverityDebug, "NGIC- delete_s5s8_session.c::"
//			"\n\tdelete_pgwc_context(...);"
//			"\n\tprocess_pgwc_s5s8_ds_req_cnt= %u;"
//			"\n\tue_ip= pdn->ipv4= %s;"
//			"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
//			"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
//			"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
//			"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
//			"\n\trte_hash_lookup_data("
//				"ue_context_by_fteid_hash,..)= %d\n",
//			process_pgwc_s5s8_ds_req_cnt++,
//			inet_ntoa(pdn->ipv4),
//			inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
//			pdn->s5s8_sgw_gtpc_teid,
//			inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
//			pdn->s5s8_pgw_gtpc_teid,
//			ret);
//
//	eps_bearer *bearer = context->eps_bearers[ebi_index];
//	if (!bearer) {
//		clLog(clSystemLog, eCLSeverityCritical, "Received delete session on non-existent "
//				"default EBI\n");
//		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
//	}
//
//	for (i = 0; i < MAX_BEARERS; ++i) {
//		if (pdn->eps_bearers[i] == NULL)
//			continue;
//
//		if (context->eps_bearers[i] == pdn->eps_bearers[i]) {
//			bearer = context->eps_bearers[i];
//			struct session_info si;
//			memset(&si, 0, sizeof(si));
//
//			/**
//			 * ebi and s1u_sgw_teid is set here for zmq/sdn
//			 */
//			si.bearer_id = ebi;
//			si.ue_addr.u.ipv4_addr =
//				htonl(pdn->ipv4.s_addr);
//			si.ul_s1_info.sgw_teid =
//				bearer->s1u_sgw_gtpu_teid;
//			si.sess_id = SESS_ID(
//					context->s11_sgw_gtpc_teid,
//					si.bearer_id);
//			/*
//			struct dp_id dp_id = { .id = DPN_ID };
//			session_delete(dp_id, si);
//			*/
//
//			rte_free(pdn->eps_bearers[i]);
//			pdn->eps_bearers[i] = NULL;
//			context->eps_bearers[i] = NULL;
//			context->bearer_bitmap &= ~(1 << i);
//		} else {
//			rte_panic("Incorrect provisioning of bearers\n");
//		}
//	}
//	--context->num_pdns;
//	rte_free(pdn);
//	context->pdns[ebi_index] = NULL;
//	context->teid_bitmap = 0;
//
//	*_context = context;
//	return 0;
//}
//
//int
//process_pgwc_s5s8_delete_session_request(gtpv2c_header *gtpv2c_rx)
//{
//	struct gw_info _resp = {0};
//	ue_context *context = NULL;
//	struct resp_info *resp = NULL;
//
//	int ret = delete_pgwc_context(gtpv2c_rx, &context, &_resp);
//	if (ret)
//	return ret;
//
//	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
//	fill_pfcp_sess_del_req(&pfcp_sess_del_req);
//	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = _resp.seid;
//
//	pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no =
//						(htonl(gtpv2c_rx->teid_u.has_teid.seq) >> 8);
//
//	uint8_t pfcp_msg[512]={0};
//
//	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
//	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
//	header->message_len = htons(encoded - 4);
//
//	if (pfcp_send(pfcp_fd, pfcp_msg,encoded,
//				&upf_pfcp_sockaddr) < 0 )
//		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
//	else {
//		cp_stats.session_deletion_req_sent++;
//		get_current_time(cp_stats.session_deletion_req_sent_time);
//	}
//
//	/* Update the sequence number */
//	context->sequence =
//		gtpv2c_rx->teid_u.has_teid.seq;
//
//	/* Update UE State */
//	context->state = PFCP_SESS_DEL_REQ_SNT_STATE;
//
//	/* VS: Stored/Update the session information. */
//	if (get_sess_entry(_resp.seid, &resp) != 0) {
//		clLog(clSystemLog, eCLSeverityCritical, "Failed to add response in entry in SM_HASH\n");
//		return -1;
//	}
//
//	/* Store s11 struture data into sm_hash for sending delete response back to s11 */
//	resp->eps_bearer_id = _resp.eps_bearer_id;
//	resp->s5s8_sgw_gtpc_teid = _resp.s5s8_sgw_gtpc_teid;
//	resp->s5s8_pgw_gtpc_ipv4 = htonl(_resp.s5s8_pgw_gtpc_ipv4);
//	resp->msg_type = GTP_DELETE_SESSION_REQ;
//	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
//	resp->proc = context->proc;
//
//	return 0;
//}
//
///* SGWC S5S8 handlers:
// * static int delete_sgwc_context(...)
// * int process_sgwc_s5s8_delete_session_response(...)
// * int gen_sgwc_s5s8_delete_session_request(...)
// *
// */
//
///**
// * @brief  : Parses delete session request message and handles the removal of
// *           corresponding data structures internal to the control plane - as well as
// *           notifying the data plane of such changes
// * @param  : gtpv2c_rx
// *           buffer containing create delete session request message
// * @param  : _context
// *           returns the UE context structure pertaining to the session to be deleted
// * @return : - 0 if successful
// *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
// *             specified cause error value
// *           - < 0 for all other errors
// */
//static int
//delete_sgwc_context(gtpv2c_header *gtpv2c_rx, ue_context **_context, uint64_t *seid)
//{
//	int ret;
//	int i;
//	static uint32_t process_sgwc_s5s8_ds_rsp_cnt;
//	ue_context *context = NULL;
//
//	//gtpv2c_rx->teid_u.has_teid.teid = ntohl(gtpv2c_rx->teid_u.has_teid.teid);
//	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
//	 * key->ue_context_by_fteid_hash */
//	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
//	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
//	    (void **) &context);
//	if (ret < 0 || !context) {
//
//		clLog(s5s8logger, eCLSeverityDebug, "NGIC- delete_s5s8_session.c::"
//				"\n\tprocess_sgwc_s5s8_delete_session_request:"
//				"\n\tdelete_sgwc_context-ERROR!!!"
//				"\n\tprocess_sgwc_s5s8_ds_rep_cnt= %u;"
//				"\n\tgtpv2c_s5s8_rx->teid_u.has_teid.teid= %X;"
//				"\n\trte_hash_lookup_data("
//					"ue_context_by_fteid_hash,..)= %d\n",
//				process_sgwc_s5s8_ds_rsp_cnt++,
//				gtpv2c_rx->teid_u.has_teid.teid,
//				ret);
//		clLog(clSystemLog, eCLSeverityDebug,"Conext not found\n\n");
//		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
//	}
//
//	clLog(s5s8logger, eCLSeverityDebug, "NGIC- delete_s5s8_session.c::"
//			"\n\tdelete_sgwc_context(...);"
//			"\n\tprocess_sgwc_s5s8_ds_rsp_cnt= %u;"
//			"\n\tgtpv2c_rx->teid_u.has_teid.teid= %X"
//			"\n\trte_hash_lookup_data("
//				"ue_context_by_fteid_hash,..)= %d\n",
//			process_sgwc_s5s8_ds_rsp_cnt++,
//			gtpv2c_rx->teid_u.has_teid.teid,
//			ret);
//	pdn_connection *pdn_ctxt;
//
//	for (i = 0; i < MAX_BEARERS; ++i) {
//		if (context->pdns[i] == NULL) {
//			continue;
//		}
//
//		if (context->eps_bearers[i]) {
//			eps_bearer *bearer = context->eps_bearers[i];
//			pdn_ctxt = bearer->pdn;
//			struct session_info si;
//			memset(&si, 0, sizeof(si));
//
//			/**
//			 * ebi and s1u_sgw_teid is set here for zmq/sdn
//			 */
//			si.bearer_id = i + 5;
//			si.ue_addr.u.ipv4_addr =
//				htonl(pdn_ctxt->ipv4.s_addr);
//			si.ul_s1_info.sgw_teid =
//				bearer->s1u_sgw_gtpu_teid;
//			si.sess_id = SESS_ID(
//				context->s11_sgw_gtpc_teid,
//				si.bearer_id);
//			*seid = si.sess_id;
//
//			rte_free(pdn_ctxt->eps_bearers[i]);
//			pdn_ctxt->eps_bearers[i] = NULL;
//			context->eps_bearers[i] = NULL;
//			context->bearer_bitmap &= ~(1 << i);
//			rte_free(pdn_ctxt);
//		}
//	}
//	--context->num_pdns;
//	context->teid_bitmap = 0;
//
//	*_context = context;
//	return 0;
//}

int
gen_sgwc_s5s8_delete_session_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_tx, uint32_t pgw_gtpc_del_teid,
		uint32_t sequence, uint8_t del_ebi)
{

	gtpv2c_ie *current_rx_ie;
	gtpv2c_ie *limit_rx_ie;

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_DELETE_SESSION_REQ,
		    pgw_gtpc_del_teid, sequence);

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_rx_ie, limit_rx_ie)
	{
		if (current_rx_ie->type == GTP_IE_EPS_BEARER_ID &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO, del_ebi);
		} else if (current_rx_ie->type == GTP_IE_USER_LOC_INFO &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_INDICATION &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		}
	}

	return 0;
}

//int
//process_sgwc_s5s8_delete_session_response(gtpv2c_header *gtpv2c_rx,
//	gtpv2c_header *gtpv2c_tx)
//{
//	uint16_t msg_len = 0;
//	uint64_t seid = 0;
//	ue_context *context = NULL;
//	del_sess_rsp_t del_resp = {0};
//
//	int ret = delete_sgwc_context(gtpv2c_rx, &context, &seid);
//	if (ret)
//		return ret;
//
//	gtpv2c_rx->teid_u.has_teid.seq = bswap_32(gtpv2c_rx->teid_u.has_teid.seq) >> 8 ;
//	/*VS: Encode the S11 delete session response message. */
//	set_gtpv2c_teid_header((gtpv2c_header *) &del_resp, GTP_DELETE_SESSION_RSP,
//			context->s11_mme_gtpc_teid, gtpv2c_rx->teid_u.has_teid.seq);
//	set_cause_accepted_ie((gtpv2c_header *) &del_resp, IE_INSTANCE_ZERO);
//
//	del_resp.cause.header.len = ntohs(del_resp.cause.header.len);
//	/*VS: Encode the S11 delete session response message. */
//	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);
//
//	gtpv2c_tx->gtpc.length = htons(msg_len - 4);
//
//	s11_mme_sockaddr.sin_addr.s_addr =
//					htonl(context->s11_mme_gtpc_ipv4.s_addr);
//
//	clLog(clSystemLog, eCLSeverityDebug, "%s: s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
//				inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));
//
//	/* Delete entry from session entry */
//	if (del_sess_entry(seid) != 0){
//		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for Key sess ID:%lu\n", seid);
//		return -1;
//	}
//
//	/* Delete UE context entry from UE Hash */
//	/*rte_free(context);*/
//	return 0;
//}

int process_sgwc_delete_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	uint16_t msg_len = 0;
	int ret = 0;
	ue_context *context = NULL;
	del_sess_rsp_t del_resp = {0};

	uint32_t teid = UE_SESS_ID(sess_id);
	struct resp_info *resp = NULL;
	//gtpv2c_header gtpv2c_rx;

	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
				__func__, __LINE__,
				teid);
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *) &del_resp, GTP_DELETE_SESSION_RSP,
			context->s11_mme_gtpc_teid, context->sequence);
	set_cause_accepted_ie((gtpv2c_header_t *) &del_resp, IE_INSTANCE_ZERO);

	del_resp.cause.header.len = ntohs(del_resp.cause.header.len);

	/*Encode the S11 delete session response message. */
	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	s11_mme_sockaddr.sin_addr.s_addr =
		htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(s11logger, eCLSeverityDebug, "SAEGWC:%s:"
			"s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	/* Delete entry from session entry */
	if (del_sess_entry(sess_id) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for Key sess ID:%lu\n", sess_id);
		return -1;
	}
	return 0;
}



