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

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

/* PGWC S5S8 handlers:
 * static int delete_pgwc_context(...)
 * process_pgwc_s5s8_delete_session_request(...)
 *
 */

/**
 * Parses delete session request message and handles the removal of
 * corresponding data structures internal to the control plane - as well as
 * notifying the data plane of such changes
 * @param gtpv2c_rx
 *   buffer containing create delete session request message
 * @param _context
 *   returns the UE context structure pertaining to the session to be deleted
 * @param del_teid_ptr
 *   returns pointer to s5s8_sgw_gtpc_teid to be deleted
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
delete_pgwc_context(gtpv2c_header *gtpv2c_rx, ue_context **_context,
		uint32_t *del_teid_ptr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *limit_ie;
	int ret;
	int i;
	static uint32_t process_pgwc_s5s8_ds_req_cnt;
	ue_context *context = NULL;
	gtpv2c_ie *ebi_ei_to_be_removed = NULL;

	/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
	 * key->ue_context_by_fteid_hash */
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
	    (void **) &context);
	if (ret < 0 || !context) {
		RTE_LOG_DP(DEBUG, CP, "NGIC- delete_s5s8_session.c::"
				"\n\tprocess_pgwc_s5s8_delete_session_request:"
				"\n\tdelete_pgwc_context-ERROR!!!"
				"\n\tprocess_pgwc_s5s8_ds_req_cnt= %u;"
				"\n\tgtpv2c_s5s8_rx->teid_u.has_teid.teid= %X;"
				"\n\trte_hash_lookup_data("
					"ue_context_by_fteid_hash,..)= %d\n",
				process_pgwc_s5s8_ds_req_cnt++,
				gtpv2c_rx->teid_u.has_teid.teid,
				ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/** TODO: we should verify mandatory fields within received message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		switch (current_ie->type) {
		case IE_EBI:
			if (current_ie->instance == IE_INSTANCE_ZERO)
				ebi_ei_to_be_removed = current_ie;
			break;
		}
	}

	if (!ebi_ei_to_be_removed) {
		/* TODO: should be responding with response indicating error
		 * in request */
		fprintf(stderr, "Received delete session without ebi! - "
				"dropping\n");
		return -EPERM;
	}

	uint8_t ebi = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
			ebi_ei_to_be_removed);
	uint8_t ebi_index = ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
		    "Received delete session on non-existent EBI - "
		    "Dropping packet\n");
		fprintf(stderr, "ebi %u\n",
		    *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t, ebi_ei_to_be_removed));
		fprintf(stderr, "ebi_index %u\n", ebi_index);
		fprintf(stderr, "bearer_bitmap %04x\n", context->bearer_bitmap);
		fprintf(stderr, "mask %04x\n", (1 << ebi_index));
		return -EPERM;
	}

	pdn_connection *pdn = context->pdns[ebi_index];
	if (!pdn) {
		fprintf(stderr, "Received delete session on "
				"non-existent EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	if (pdn->default_bearer_id != ebi) {
		fprintf(stderr,
		    "Received delete session referencing incorrect "
		    "default bearer ebi");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}
	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */
	*del_teid_ptr = pdn->s5s8_sgw_gtpc_teid;
	RTE_LOG_DP(DEBUG, CP, "NGIC- delete_s5s8_session.c::"
			"\n\tdelete_pgwc_context(...);"
			"\n\tprocess_pgwc_s5s8_ds_req_cnt= %u;"
			"\n\tue_ip= pdn->ipv4= %s;"
			"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
			"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
			"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
			"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
			"\n\trte_hash_lookup_data("
				"ue_context_by_fteid_hash,..)= %d\n",
			process_pgwc_s5s8_ds_req_cnt++,
			inet_ntoa(pdn->ipv4),
			inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
			*del_teid_ptr,
			inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
			pdn->s5s8_pgw_gtpc_teid,
			ret);

	eps_bearer *bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr, "Received delete session on non-existent "
				"default EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	for (i = 0; i < MAX_BEARERS; ++i) {
		if (pdn->eps_bearers[i] == NULL)
			continue;

		if (context->eps_bearers[i] == pdn->eps_bearers[i]) {
			bearer = context->eps_bearers[i];
			struct session_info si;
			memset(&si, 0, sizeof(si));

			/**
			 * ebi and s1u_sgw_teid is set here for zmq/sdn
			 */
			si.bearer_id = ebi;
			si.ue_addr.u.ipv4_addr =
				htonl(pdn->ipv4.s_addr);
			si.ul_s1_info.sgw_teid = 
                	bearer->s1u_sgw_gtpu_teid;
			//si.ul_s1_info.sgw_teid =
			//	htonl(bearer->s1u_sgw_gtpu_teid);
			si.sess_id = SESS_ID(
					context->s11_sgw_gtpc_teid,
					si.bearer_id);
			struct dp_id dp_id = { .id = DPN_ID };
			session_delete(dp_id, si);

			rte_free(pdn->eps_bearers[i]);
			pdn->eps_bearers[i] = NULL;
			context->eps_bearers[i] = NULL;
			context->bearer_bitmap &= ~(1 << i);
		} else {
			rte_panic("Incorrect provisioning of bearers\n");
		}
	}
	--context->num_pdns;
	rte_free(pdn);
	context->pdns[ebi_index] = NULL;
	context->teid_bitmap = 0;

	*_context = context;
	return 0;
}

int
process_pgwc_s5s8_delete_session_request(gtpv2c_header *gtpv2c_rx,
	gtpv2c_header *gtpv2c_tx)
{
	ue_context *context = NULL;
	uint32_t s5s8_sgw_gtpc_del_teid_ptr = 0;

	int ret = delete_pgwc_context(gtpv2c_rx, &context,
					&s5s8_sgw_gtpc_del_teid_ptr);
	if (ret)
		return ret;

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_DELETE_SESSION_RSP,
				s5s8_sgw_gtpc_del_teid_ptr,
				gtpv2c_rx->teid_u.has_teid.seq);
	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);

	return 0;
}

/* SGWC S5S8 handlers:
 * static int delete_sgwc_context(...)
 * int process_sgwc_s5s8_delete_session_response(...)
 * int gen_sgwc_s5s8_delete_session_request(...)
 *
 */

/**
 * Parses delete session request message and handles the removal of
 * corresponding data structures internal to the control plane - as well as
 * notifying the data plane of such changes
 * @param gtpv2c_rx
 *   buffer containing create delete session request message
 * @param _context
 *   returns the UE context structure pertaining to the session to be deleted
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
delete_sgwc_context(gtpv2c_header *gtpv2c_rx, ue_context **_context)
{
	int ret;
	int i;
	static uint32_t process_sgwc_s5s8_ds_rsp_cnt;
	ue_context *context = NULL;

	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
	    (void **) &context);
	if (ret < 0 || !context) {
		RTE_LOG_DP(DEBUG, CP, "NGIC- delete_s5s8_session.c::"
				"\n\tprocess_sgwc_s5s8_delete_session_request:"
				"\n\tdelete_sgwc_context-ERROR!!!"
				"\n\tprocess_sgwc_s5s8_ds_rep_cnt= %u;"
				"\n\tgtpv2c_s5s8_rx->teid_u.has_teid.teid= %X;"
				"\n\trte_hash_lookup_data("
					"ue_context_by_fteid_hash,..)= %d\n",
				process_sgwc_s5s8_ds_rsp_cnt++,
				gtpv2c_rx->teid_u.has_teid.teid,
				ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	RTE_LOG_DP(DEBUG, CP, "NGIC- delete_s5s8_session.c::"
			"\n\tdelete_sgwc_context(...);"
			"\n\tprocess_sgwc_s5s8_ds_rsp_cnt= %u;"
			"\n\tgtpv2c_rx->teid_u.has_teid.teid="
			"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
			"\n\trte_hash_lookup_data("
				"ue_context_by_fteid_hash,..)= %d\n",
			process_sgwc_s5s8_ds_rsp_cnt++,
			gtpv2c_rx->teid_u.has_teid.teid,
			ret);
	pdn_connection *pdn_ctxt;
	for (i = 0; i < MAX_BEARERS; ++i) {
		if (context->pdns[i] == NULL)
			continue;

		if (context->eps_bearers[i]) {
			eps_bearer *bearer = context->eps_bearers[i];
			pdn_ctxt = bearer->pdn;
			struct session_info si;
			memset(&si, 0, sizeof(si));

			/**
			 * ebi and s1u_sgw_teid is set here for zmq/sdn
			 */
			si.bearer_id = i + 5;
			si.ue_addr.u.ipv4_addr =
				htonl(pdn_ctxt->ipv4.s_addr);
			si.ul_s1_info.sgw_teid = 
                bearer->s1u_sgw_gtpu_teid;
			//si.ul_s1_info.sgw_teid =
			//	htonl(bearer->s1u_sgw_gtpu_teid);
			si.sess_id = SESS_ID(
					context->s11_sgw_gtpc_teid,
					si.bearer_id);
			struct dp_id dp_id = { .id = DPN_ID };
			session_delete(dp_id, si);

			rte_free(pdn_ctxt->eps_bearers[i]);
			pdn_ctxt->eps_bearers[i] = NULL;
			context->eps_bearers[i] = NULL;
			context->bearer_bitmap &= ~(1 << i);
			rte_free(pdn_ctxt);
		}
	}
	--context->num_pdns;
	context->teid_bitmap = 0;

	*_context = context;
	return 0;
}

int
gen_sgwc_s5s8_delete_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx, uint32_t pgw_gtpc_del_teid,
		uint32_t sequence, uint8_t del_ebi)
{

	gtpv2c_ie *current_rx_ie;
	gtpv2c_ie *limit_rx_ie;

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_DELETE_SESSION_REQ,
		    pgw_gtpc_del_teid, sequence);

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_rx_ie, limit_rx_ie)
	{
		if (current_rx_ie->type == IE_EBI &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO, del_ebi);
		} else if (current_rx_ie->type == IE_ULI &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_INDICATION &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		}
	}

	return 0;
}

int
process_sgwc_s5s8_delete_session_response(gtpv2c_header *gtpv2c_rx,
	gtpv2c_header *gtpv2c_tx)
{
	ue_context *context = NULL;
	int ret = delete_sgwc_context(gtpv2c_rx, &context);
	if (ret)
		return ret;

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_DELETE_SESSION_RSP,
	    htonl(context->s11_mme_gtpc_teid), gtpv2c_rx->teid_u.has_teid.seq);
	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);

	return 0;
}

