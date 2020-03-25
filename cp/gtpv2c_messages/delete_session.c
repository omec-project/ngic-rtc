/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <rte_debug.h>

#include "gtpv2c_messages.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "gtpv2c_set_ie.h"
#include "ue.h"

extern struct response_info resp_t;

/**
 * Handles the removal of data structures internal to the control plane
 * as well as notifying the data plane of such changes.
 * @param ds_req
 *   structure containing create delete session request
 * @param _context
 *   returns the UE context structure pertaining to the session to be deleted
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
delete_context(delete_session_request_t *ds_req,
			ue_context **_context)
{
	int ret;
	int i;
	ue_context *context = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &ds_req->header.teid.has_teid.teid,
	    (void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if (!ds_req->linked_ebi.header.len) {
		/* TODO: should be responding with response indicating error
		 * in request */
		fprintf(stderr, "Received delete session without ebi! - "
				"dropping\n");
		return -EPERM;
	}

	uint8_t ebi_index = ds_req->linked_ebi.eps_bearer_id - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
		    "Received delete session on non-existent EBI - "
		    "Dropping packet\n");
		fprintf(stderr, "ebi %u\n", ds_req->linked_ebi.eps_bearer_id);
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

	if (pdn->default_bearer_id != ds_req->linked_ebi.eps_bearer_id) {
		fprintf(stderr,
		    "Received delete session referencing incorrect "
		    "default bearer ebi");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	eps_bearer *bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr, "Received delete session on non-existent "
				"default EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

#if defined(MULTI_UPFS)
	struct dp_info *dp = fetch_dp_context(context->dpId); 
	if (dp != NULL) {
		struct in_addr host = {0};
		host.s_addr = ntohl(pdn->ipv4.s_addr);
		release_ip_node(dp->static_pool_tree, host);
	}
#else
	if (static_addr_pool != NULL) {
		struct in_addr host = {0};
		host.s_addr = ntohl(pdn->ipv4.s_addr);
		release_ip_node(static_addr_pool, host); 
	}
#endif

#ifdef ZMQ_COMM
	/*set the delete session response */
	/*TODO: Revisit this for to handle type received from message*/
	/*resp_t.msg_type = ds_req->header.gtpc.type;*/
	resp_t.msg_type = GTP_DELETE_SESSION_REQ;
	resp_t.context_t = *context;
#endif

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
			si.bearer_id = ds_req->linked_ebi.eps_bearer_id;
			si.ue_addr.u.ipv4_addr =
				htonl(pdn->ipv4.s_addr);
			si.ul_s1_info.sgw_teid =
				htonl(bearer->s1u_sgw_gtpu_teid);
			si.sess_id = SESS_ID(
					context->s11_sgw_gtpc_teid,
					si.bearer_id);
			struct dp_id dp_id = { .id = context->dpId };
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
process_delete_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
{
	ue_context *context = NULL;
	int ret;
	delete_session_request_t ds_req = {0};

	decode_delete_session_request_t((uint8_t *) gtpv2c_rx, &ds_req);

	if (spgw_cfg == SGWC) {
		pdn_connection *pdn = NULL;
		uint32_t s5s8_pgw_gtpc_del_teid;
		static uint32_t process_sgwc_s5s8_ds_req_cnt;

		/* s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
		ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &ds_req.header.teid.has_teid.teid,
			(void **) &context);

		if (ret < 0 || !context)
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

		uint8_t del_ebi_index = ds_req.linked_ebi.eps_bearer_id - 5;
		pdn = context->pdns[del_ebi_index];
		/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
		 * key->ue_context_by_fteid_hash */
		s5s8_pgw_gtpc_del_teid = pdn->s5s8_pgw_gtpc_teid;
		ret =
			gen_sgwc_s5s8_delete_session_request(gtpv2c_rx,
				gtpv2c_s5s8_tx, s5s8_pgw_gtpc_del_teid,
				gtpv2c_rx->teid_u.has_teid.seq, ds_req.linked_ebi.eps_bearer_id);
		RTE_LOG(DEBUG, CP, "NGIC- delete_session.c::"
				"\n\tprocess_delete_session_request::case= %d;"
				"\n\tprocess_sgwc_s5s8_ds_req_cnt= %u;"
				"\n\tue_ip= pdn->ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
				"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
				"\n\tgen_delete_s5s8_session_request= %d\n",
				spgw_cfg, process_sgwc_s5s8_ds_req_cnt++,
				inet_ntoa(pdn->ipv4),
				inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
				pdn->s5s8_sgw_gtpc_teid,
				inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
				pdn->s5s8_pgw_gtpc_teid,
				ret);
		return ret;
	}

	gtpv2c_s11_tx->teid_u.has_teid.seq = gtpv2c_rx->teid_u.has_teid.seq;

#ifdef ZMQ_COMM
	resp_t.gtpv2c_tx_t = *gtpv2c_s11_tx;
#endif  /* ZMQ_COMM */

	ret = delete_context(&ds_req, &context);
	if (ret)
		return ret;

#ifndef ZMQ_COMM
	set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
	    htonl(context->s11_mme_gtpc_teid), gtpv2c_rx->teid_u.has_teid.seq);
	set_cause_accepted_ie(gtpv2c_s11_tx, IE_INSTANCE_ZERO);
#endif

	return 0;
}
