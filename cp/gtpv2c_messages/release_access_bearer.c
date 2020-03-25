/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "ue.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

extern struct response_info resp_t;

struct parse_release_access_bearer_request_t {
	ue_context *context;
};

/**
 * parses gtpv2c message and populates parse_release_access_bearer_request_t
 *   structure
 * @param gtpv2c_rx
 *   buffer containing received release access bearer request message
 * @param release_access_bearer_request
 *   structure to contain parsed information from message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
parse_release_access_bearer_request(gtpv2c_header *gtpv2c_rx,
	struct parse_release_access_bearer_request_t
	*release_access_bearer_request)
{

	uint32_t teid = ntohl(gtpv2c_rx->teid_u.has_teid.teid);
	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &teid,
	    (void **) &release_access_bearer_request->context);

	if (ret < 0 || !release_access_bearer_request->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	return 0;
}

/**
 * from parameters, populates gtpv2c message 'release access bearer
 * response' and populates required information elements as defined by
 * clause 7.2.22 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'release access bearer request' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the bearer to be modified
 */
static void
set_release_access_bearer_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context)
{
	set_gtpv2c_teid_header(gtpv2c_tx, GTP_RELEASE_ACCESS_BEARERS_RSP,
	    htonl(context->s11_mme_gtpc_teid), sequence);

	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);

}

int
process_release_access_bearer_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx)
{
	int i;
	struct dp_id dp_id = { .id = DPN_ID };
	struct parse_release_access_bearer_request_t
		release_access_bearer_request = { 0 };

	int ret = parse_release_access_bearer_request(gtpv2c_rx,
			&release_access_bearer_request);
	if (ret)
		return ret;

	dp_id.id = release_access_bearer_request.context->dpId; 

	set_release_access_bearer_response(gtpv2c_tx,
			gtpv2c_rx->teid_u.has_teid.seq,
			release_access_bearer_request.context);


	for (i = 0; i < MAX_BEARERS; ++i) {
		if (release_access_bearer_request.context->eps_bearers[i]
				== NULL)
			continue;

		eps_bearer *bearer = release_access_bearer_request.
				context->eps_bearers[i];

		bearer->s1u_enb_gtpu_teid = 0;

		/* using the s1u_sgw_gtpu_teid as unique identifier to
		 * the session */
		struct session_info session;
		memset(&session, 0, sizeof(session));
		session.ue_addr.iptype = IPTYPE_IPV4;
		session.ue_addr.u.ipv4_addr = ntohl(bearer->pdn->ipv4.s_addr);
		session.ul_s1_info.sgw_teid =
		    ntohl(bearer->s1u_sgw_gtpu_teid);
		session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.sgw_addr.u.ipv4_addr =
		    ntohl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
		    ntohl(bearer->s1u_enb_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid =
		    ntohl(bearer->s1u_enb_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
		    ntohl(bearer->s1u_enb_gtpu_ipv4.s_addr);
		session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.sgw_addr.u.ipv4_addr =
		    ntohl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
		session.bearer_id = bearer->eps_bearer_id;
		session.ul_apn_mtr_idx = ulambr_idx;
		session.dl_apn_mtr_idx = dlambr_idx;
		session.num_ul_pcc_rules = 1;
		session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
		session.num_dl_pcc_rules = 1;
		session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

		session.sess_id = SESS_ID(
			release_access_bearer_request.context->
			s11_sgw_gtpc_teid,
			bearer->eps_bearer_id);

		/* Set msg type.because this gets copied in the transaction while 
			sending DP message */
		resp_t.msg_type = GTP_RELEASE_ACCESS_BEARERS_REQ;

		if (session_modify(dp_id, session) < 0)
			rte_exit(EXIT_FAILURE,
				"Bearer Session modify fail !!!");

		return 0; /* dedicated bearer support would need change here */
	}
	return 0;
}
