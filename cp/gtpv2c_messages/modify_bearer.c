/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "ue.h"
#include "gtpv2c_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

struct parse_modify_bearer_request_t {
	ue_context *context;
	pdn_connection *pdn;
	eps_bearer *bearer;

	gtpv2c_ie *bearer_context_to_be_created_ebi;
	gtpv2c_ie *s1u_enb_fteid;
	uint8_t *delay;
	uint32_t *s11_mme_gtpc_fteid;
};
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];
extern struct response_info resp_t;

/**
 * from parameters, populates gtpv2c message 'modify bearer response' and
 * populates required information elements as defined by
 * clause 7.2.8 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'modify bearer request' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the bearer to be modified
 * @param bearer
 *   bearer data structure to be modified
 */
void
set_modify_bearer_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer)
{
	modify_bearer_response_t mb_resp = {0};

	set_gtpv2c_teid_header((gtpv2c_header *) &mb_resp, GTP_MODIFY_BEARER_RSP,
	    context->s11_mme_gtpc_teid, sequence);

	set_cause_accepted(&mb_resp.cause, IE_INSTANCE_ZERO);

	set_ie_header(&mb_resp.bearer_context.header, IE_BEARER_CONTEXT,
			IE_INSTANCE_ZERO, 0);

	set_cause_accepted(&mb_resp.bearer_context.cause, IE_INSTANCE_ZERO);
	mb_resp.bearer_context.header.len +=
		sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

	set_ebi(&mb_resp.bearer_context.ebi, IE_INSTANCE_ZERO,
			bearer->eps_bearer_id);
	mb_resp.bearer_context.header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

	struct in_addr ip;
#if defined(ZMQ_COMM) && defined(MULTI_UPFS)
	ip.s_addr = htonl(fetch_s1u_sgw_ip(context->dpId).s_addr);
#else
	ip.s_addr = htonl(s1u_sgw_ip.s_addr);
#endif
	set_ipv4_fteid(&mb_resp.bearer_context.s1u_sgw_ftied,
			GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, ip,
			htonl(bearer->s1u_sgw_gtpu_teid));
	mb_resp.bearer_context.header.len += sizeof(struct fteid_ie_hdr_t) +
		sizeof(struct in_addr) + IE_HEADER_SIZE;

	uint16_t msg_len = 0;
	encode_modify_bearer_response_t(&mb_resp, (uint8_t *)gtpv2c_tx,
			&msg_len);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);
}

int
process_modify_bearer_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx)
{
	struct dp_id dp_id = { .id = DPN_ID };
	modify_bearer_request_t mb_req = {0};
	uint32_t i;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;

	decode_modify_bearer_request_t((uint8_t *) gtpv2c_rx, &mb_req);

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &mb_req.header.teid.has_teid.teid,
	    (void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	dp_id.id = context->dpId;
	if (!mb_req.bearer_context.ebi.header.len
			|| !mb_req.bearer_context.s1u_enodeb_ftied.header.len) {
			fprintf(stderr, "Dropping packet\n");
			return -EPERM;
	}

	uint8_t ebi_index = mb_req.bearer_context.ebi.eps_bearer_id - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
			"Received modify bearer on non-existent EBI - "
			"Dropping packet\n");
		return -EPERM;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
			"Received modify bearer on non-existent EBI - "
			"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;

	/* TODO something with modify_bearer_request.delay if set */

	if (mb_req.s11_mme_fteid.header.len &&
			(context->s11_mme_gtpc_teid != mb_req.s11_mme_fteid.teid_gre))
		context->s11_mme_gtpc_teid = mb_req.s11_mme_fteid.teid_gre;

	bearer->s1u_enb_gtpu_ipv4 =
			mb_req.bearer_context.s1u_enodeb_ftied.ip.ipv4;

	bearer->s1u_enb_gtpu_teid =
			mb_req.bearer_context.s1u_enodeb_ftied.teid_gre;

	bearer->eps_bearer_id = mb_req.bearer_context.ebi.eps_bearer_id;

#ifndef ZMQ_COMM
	set_modify_bearer_response(gtpv2c_tx, mb_req.header.teid.has_teid.seq,
	    context, bearer);
#else
	/*Set modify bearer response*/
	resp_t.gtpv2c_tx_t=*gtpv2c_tx;
	resp_t.context_t=*(context);
	resp_t.bearer_t=*(bearer);
	resp_t.gtpv2c_tx_t.teid_u.has_teid.seq = mb_req.header.teid.has_teid.seq;
	resp_t.msg_type = GTP_MODIFY_BEARER_REQ;
	/*TODO: Revisit this for to handle type received from message*/
	/*resp_t.msg_type = mb_req.header.gtpc.type;*/
#endif

	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));
	 session.ue_addr.iptype = IPTYPE_IPV4;
	 session.ue_addr.u.ipv4_addr =
		 pdn->ipv4.s_addr;
	 session.ul_s1_info.sgw_teid =
		htonl(bearer->s1u_sgw_gtpu_teid);
	 session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	 session.ul_s1_info.sgw_addr.u.ipv4_addr =
		 htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	 session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	 session.ul_s1_info.enb_addr.u.ipv4_addr =
		 bearer->s1u_enb_gtpu_ipv4.s_addr;
	 session.dl_s1_info.enb_teid =
		 bearer->s1u_enb_gtpu_teid;
	 session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	 session.dl_s1_info.enb_addr.u.ipv4_addr =
		 bearer->s1u_enb_gtpu_ipv4.s_addr;
	 session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	 session.dl_s1_info.sgw_addr.u.ipv4_addr =
		 htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	 session.ul_apn_mtr_idx = 0;
	 session.dl_apn_mtr_idx = 0;
	 session.num_ul_pcc_rules = 1;
	 session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	 session.num_dl_pcc_rules = 1;
	 session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

	 session.num_adc_rules = num_adc_rules;
	 for (i = 0; i < num_adc_rules; ++i)
			 session.adc_rule_id[i] = adc_rule_id[i];

	 session.sess_id = SESS_ID(
			context->s11_sgw_gtpc_teid,
			bearer->eps_bearer_id);

	 RTE_LOG_DP(DEBUG, CP, "Sending session modify bearer request with ue IPv4 addr: ");
	 RTE_LOG_DP(DEBUG, CP, "%d.%d.%d.%d", ((session.ue_addr.u.ipv4_addr >> 24) & 0xFF),
		((session.ue_addr.u.ipv4_addr >> 16) & 0xFF),
		((session.ue_addr.u.ipv4_addr >> 8) & 0xFF),
		((session.ue_addr.u.ipv4_addr & 0xFF)));
	/* Fetch subscriber using teid and then find the dpId */
	if (session_modify(dp_id, session) < 0)
#if defined(ZMQ_COMM) && defined(MULTI_UPFS)
		RTE_LOG_DP(INFO, CP, "Bearer Session modify fail !!!\n");
#else
		rte_exit(EXIT_FAILURE, "Bearer Session modify fail !!!");
#endif
	return 0;
}
