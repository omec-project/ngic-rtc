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

#include "ue.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "../pfcp_messages/pfcp_set_ie.h"
#include "cp/cp_app.h"
#include "clogger.h"
#include "sm_enum.h"
extern pfcp_config_t pfcp_config;
/**
 * @brief  : Maintains parsed data from modify bearer request
 */
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

/**
 * @brief  : from parameters, populates gtpv2c message 'modify bearer response' and
 *           populates required information elements as defined by
 *           clause 7.2.8 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @param  : bearer
 *           bearer data structure to be modified
 * @return : Returns nothing
 */
void
set_modify_bearer_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer, mod_bearer_req_t *mbr)
{
	int ret = 0;
	uint8_t _ebi = bearer->eps_bearer_id;
	uint8_t ebi_index = _ebi - 5;
	upf_context_t *upf_ctx = NULL;

	/*Retrive bearer id from bearer --> context->pdns[]->upf_ip*/
	if ((ret = upf_context_entry_lookup(context->pdns[ebi_index]->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		return;
	}

	mod_bearer_rsp_t mb_resp = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
	    context->s11_mme_gtpc_teid, sequence, 0);

	set_cause_accepted(&mb_resp.cause, IE_INSTANCE_ZERO);

		mb_resp.bearer_count =  mbr->bearer_count;
		for (uint8_t uiCnt = 0; uiCnt < mbr->bearer_count; ++uiCnt) {
			set_ie_header(&mb_resp.bearer_contexts_modified[uiCnt].header, GTP_IE_BEARER_CONTEXT,
					IE_INSTANCE_ZERO, 0);

			set_cause_accepted(&mb_resp.bearer_contexts_modified[uiCnt].cause, IE_INSTANCE_ZERO);
			mb_resp.bearer_contexts_modified[uiCnt].header.len +=
				sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

			set_ebi(&mb_resp.bearer_contexts_modified[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
					bearer->eps_bearer_id);
			mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

			if (pfcp_config.cp_type != PGWC) {
				struct in_addr ip;
				ip.s_addr = upf_ctx->s1u_ip;

				set_ipv4_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
						GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, ip,
						bearer->s1u_sgw_gtpu_teid);

				mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
					sizeof(struct in_addr) + IE_HEADER_SIZE;
			}
		}

#ifdef USE_CSID
		/* Set the SGW FQ-CSID */
		if (context->eps_bearers[ebi_index]->pdn->proc == INITIAL_PDN_ATTACH_PROC) {
			if (pfcp_config.cp_type != PGWC) {
				if (context->sgw_fqcsid != NULL) {
					if ((context->sgw_fqcsid)->num_csid) {
						set_gtpc_fqcsid_t(&mb_resp.sgw_fqcsid, IE_INSTANCE_ONE,
								context->sgw_fqcsid);
						mb_resp.sgw_fqcsid.node_address = ntohl(context->s11_sgw_gtpc_ipv4.s_addr);
					}
				}
			}
		}
#endif /* USE_CSID */

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
}
/*MODIFY RESPONSE FUNCTION WHEN PGWC returns MBR RESPONSE to SGWC
 * in HANDOVER SCENARIO*/

void
set_modify_bearer_response_handover(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer, mod_bearer_req_t *mbr)
{
	int ret = 0;
	uint64_t _ebi = bearer->eps_bearer_id;
	uint64_t ebi_index = _ebi - 5;
	upf_context_t *upf_ctx = NULL;
	struct in_addr ip = {0};

	/*Retrive bearer id from bearer --> context->pdns[]->upf_ip*/
	if ((ret = upf_context_entry_lookup(context->pdns[ebi_index]->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		return;
	}

	mod_bearer_rsp_t mb_resp = {0};

	if((SGWC == pfcp_config.cp_type) || (SAEGWC == pfcp_config.cp_type)) {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
				context->s11_mme_gtpc_teid, sequence, 0);
	}else{
		set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
				bearer->pdn->s5s8_sgw_gtpc_teid, sequence, 0);
	}

	if(context->msisdn !=0 && PGWC == pfcp_config.cp_type) {
		set_ie_header(&mb_resp.msisdn.header, GTP_IE_MSISDN, IE_INSTANCE_ZERO, BINARY_MSISDN_LEN);
		mb_resp.msisdn.msisdn_number_digits = context->msisdn;
	}

	set_cause_accepted(&mb_resp.cause, IE_INSTANCE_ZERO);

	{
		mb_resp.bearer_count =  mbr->bearer_count;
		for (uint8_t uiCnt = 0; uiCnt < mbr->bearer_count; uiCnt++) {
			set_ie_header(&mb_resp.bearer_contexts_modified[uiCnt].header, GTP_IE_BEARER_CONTEXT,
					IE_INSTANCE_ZERO, 0);

			set_cause_accepted(&mb_resp.bearer_contexts_modified[uiCnt].cause, IE_INSTANCE_ZERO);
			mb_resp.bearer_contexts_modified[uiCnt].header.len +=
				sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

			set_ebi(&mb_resp.bearer_contexts_modified[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
					mbr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi);

			mb_resp.bearer_contexts_modified[uiCnt].header.len +=
				sizeof(uint8_t) + IE_HEADER_SIZE;

			ebi_index = mbr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi - 5;
			bearer = context->eps_bearers[ebi_index];

			if(SGWC == pfcp_config.cp_type || SAEGWC == pfcp_config.cp_type){
				if(bearer->pdn->default_bearer_id ==
						mbr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi) {
					ip.s_addr = ntohl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
				}else {
					ip.s_addr = (bearer->s1u_sgw_gtpu_ipv4.s_addr);
				}

				set_ipv4_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
						GTPV2C_IFTYPE_S1U_SGW_GTPU,
						IE_INSTANCE_ZERO,ip,
						bearer->s1u_sgw_gtpu_teid);
				mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
					sizeof(struct in_addr) + IE_HEADER_SIZE;
			} else {
				ip.s_addr = (bearer->s5s8_pgw_gtpu_ipv4.s_addr);

				set_ipv4_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
						GTPV2C_IFTYPE_S5S8_PGW_GTPU,
						IE_INSTANCE_ZERO,ip,
						bearer->s5s8_pgw_gtpu_teid);
				mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
					sizeof(struct in_addr) + IE_HEADER_SIZE;
			}
		}
	}

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
}


#if 0
int
process_modify_bearer_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_tx)
{
	struct dp_id dp_id = { .id = DPN_ID };
	mod_bearer_req_t mb_req = {0};
	uint32_t i;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;

	decode_mod_bearer_req((uint8_t *) gtpv2c_rx, &mb_req);

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &mb_req.header.teid.has_teid.teid,
	    (void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if (!mb_req.bearer_contexts_to_be_modified.eps_bearer_id.header.len
			|| !mb_req.bearer_contexts_to_be_modified.s1_enodeb_fteid.header.len) {
			clLog(clSystemLog, eCLSeverityCritical, "Dropping packet\n");
			return -EPERM;
	}

	uint8_t ebi_index = mb_req.bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
			"Received modify bearer on non-existent EBI - "
			"Dropping packet\n");
		return -EPERM;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
			"Received modify bearer on non-existent EBI - "
			"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;

	/* TODO something with modify_bearer_request.delay if set */

	if (mb_req.sender_fteid_ctl_plane.header.len &&
			(context->s11_mme_gtpc_teid != mb_req.bearer_contexts_to_be_modified.s11_u_mme_fteid.teid_gre_key))
		context->s11_mme_gtpc_teid = mb_req.bearer_contexts_to_be_modified.s11_u_mme_fteid.teid_gre_key;

	bearer->s1u_enb_gtpu_ipv4.s_addr =
			mb_req.bearer_contexts_to_be_modified.s1_enodeb_fteid.ipv4_address;

	bearer->s1u_enb_gtpu_teid =
			mb_req.bearer_contexts_to_be_modified.s1_enodeb_fteid.teid_gre_key;

	bearer->eps_bearer_id = mb_req.bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;

	set_modify_bearer_response(gtpv2c_tx, mb_req.header.teid.has_teid.seq,
	    context, bearer);

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

	if (session_modify(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE, "Bearer Session modify fail !!!");
	return 0;
}
#endif

int8_t
set_mbr_upd_sgw_csid_req(gtpv2c_header_t *gtpv2c_tx, pdn_connection *pdn,
		uint8_t eps_bearer_id)
{
	mod_bearer_req_t mbr = {0};
	struct ue_context_t *context = NULL;

	set_gtpv2c_teid_header((gtpv2c_header_t *)&mbr.header, GTP_MODIFY_BEARER_REQ,
			0, pdn->context->sequence, 0);

	mbr.header.teid.has_teid.teid = pdn->s5s8_pgw_gtpc_teid;
	context = pdn->context;

#ifdef USE_CSID
	/* Set the SGW FQ-CSID */
	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {
			set_gtpc_fqcsid_t(&mbr.sgw_fqcsid, IE_INSTANCE_ONE,
					context->sgw_fqcsid);
			mbr.sgw_fqcsid.node_address = pdn->s5s8_sgw_gtpc_ipv4.s_addr;
		}
	}
#endif /* USE_CSID */

	mbr.bearer_count = 1;

	set_ie_header(&mbr.bearer_contexts_to_be_modified[0].header, GTP_IE_BEARER_CONTEXT,
			IE_INSTANCE_ZERO, 0);
	set_ebi(&mbr.bearer_contexts_to_be_modified[0].eps_bearer_id, IE_INSTANCE_ZERO,
			eps_bearer_id);

	mbr.bearer_contexts_to_be_modified[0].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_req(&mbr, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	return 0;
}

void set_modify_bearer_request(gtpv2c_header_t *gtpv2c_tx, /*create_sess_req_t *csr,*/
		pdn_connection *pdn, eps_bearer *bearer)
{
	int len = 0 ;
	mod_bearer_req_t mbr = {0};
	struct ue_context_t *context = NULL;
	eps_bearer *def_bearer = bearer;

	set_gtpv2c_teid_header((gtpv2c_header_t *)&mbr.header, GTP_MODIFY_BEARER_REQ,
			0, pdn->context->sequence, 0);

	mbr.header.teid.has_teid.teid = pdn->s5s8_pgw_gtpc_teid;
	/* TODO: Need to verify */
	set_ipv4_fteid(&mbr.sender_fteid_ctl_plane, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
			IE_INSTANCE_ZERO,
			pdn->s5s8_sgw_gtpc_ipv4, pdn->s5s8_sgw_gtpc_teid);
	if(pdn == NULL &&  pdn->context == NULL ) {
		clLog(clSystemLog, eCLSeverityCritical,
				" %s : %s : %d UE contex not found : Warnning \n",
							__file__, __func__, __LINE__);

		return;
	}
	context = pdn->context;
	/* Note:Below condition is added for the flow ERAB Modification
	 * Update. sepcs ref: 23.401 Section 5.4.7-1*/
	if(context->second_rat_flag == 1 ) {

		mbr.secdry_rat_usage_data_rpt.spare2 = 0;
		mbr.secdry_rat_usage_data_rpt.irsgw = context->second_rat.irsgw;
		mbr.secdry_rat_usage_data_rpt.irpgw = context->second_rat.irpgw;
		mbr.secdry_rat_usage_data_rpt.secdry_rat_type = context->second_rat.rat_type;
		mbr.secdry_rat_usage_data_rpt.ebi = context->second_rat.eps_id;
		mbr.secdry_rat_usage_data_rpt.spare3 = 0;
		mbr.secdry_rat_usage_data_rpt.start_timestamp = context->second_rat.start_timestamp;
		mbr.secdry_rat_usage_data_rpt.end_timestamp = context->second_rat.end_timestamp;
		mbr.secdry_rat_usage_data_rpt.usage_data_dl = context->second_rat.usage_data_dl;
		mbr.secdry_rat_usage_data_rpt.usage_data_ul = context->second_rat.usage_data_ul;


		set_ie_header(&mbr.secdry_rat_usage_data_rpt.header, GTP_IE_SECDRY_RAT_USAGE_DATA_RPT, IE_INSTANCE_ZERO,
				sizeof(gtp_secdry_rat_usage_data_rpt_ie_t) - sizeof(ie_header_t));

	}


	if (context->uli.lai) {
		mbr.uli.lai = context->uli.lai;
		mbr.uli.lai2.lai_mcc_digit_2 = context->uli.lai2.lai_mcc_digit_2;
		mbr.uli.lai2.lai_mcc_digit_1 = context->uli.lai2.lai_mcc_digit_1;
		mbr.uli.lai2.lai_mnc_digit_3 = context->uli.lai2.lai_mnc_digit_3;
		mbr.uli.lai2.lai_mcc_digit_3 = context->uli.lai2.lai_mcc_digit_3;
		mbr.uli.lai2.lai_mnc_digit_2 = context->uli.lai2.lai_mnc_digit_2;
		mbr.uli.lai2.lai_mnc_digit_1 = context->uli.lai2.lai_mnc_digit_1;
		mbr.uli.lai2.lai_lac = context->uli.lai2.lai_lac;

		len += sizeof(mbr.uli.lai2);
	}
	if (context->uli.tai) {
		mbr.uli.tai = context->uli.tai;
		mbr.uli.tai2.tai_mcc_digit_2 = context->uli.tai2.tai_mcc_digit_2;
		mbr.uli.tai2.tai_mcc_digit_1 = context->uli.tai2.tai_mcc_digit_1;
		mbr.uli.tai2.tai_mnc_digit_3 = context->uli.tai2.tai_mnc_digit_3;
		mbr.uli.tai2.tai_mcc_digit_3 = context->uli.tai2.tai_mcc_digit_3;
		mbr.uli.tai2.tai_mnc_digit_2 = context->uli.tai2.tai_mnc_digit_2;
		mbr.uli.tai2.tai_mnc_digit_1 = context->uli.tai2.tai_mnc_digit_1;
		mbr.uli.tai2.tai_tac = context->uli.tai2.tai_tac;
		len += sizeof(mbr.uli.tai2);
	}
	if (context->uli.rai) {
		mbr.uli.rai = context->uli.rai;
		mbr.uli.rai2.ria_mcc_digit_2 = context->uli.rai2.ria_mcc_digit_2;
		mbr.uli.rai2.ria_mcc_digit_1 = context->uli.rai2.ria_mcc_digit_1;
		mbr.uli.rai2.ria_mnc_digit_3 = context->uli.rai2.ria_mnc_digit_3;
		mbr.uli.rai2.ria_mcc_digit_3 = context->uli.rai2.ria_mcc_digit_3;
		mbr.uli.rai2.ria_mnc_digit_2 = context->uli.rai2.ria_mnc_digit_2;
		mbr.uli.rai2.ria_mnc_digit_1 = context->uli.rai2.ria_mnc_digit_1;
		mbr.uli.rai2.ria_lac = context->uli.rai2.ria_lac;
		mbr.uli.rai2.ria_rac = context->uli.rai2.ria_rac;
		len += sizeof(mbr.uli.rai2);
	}
	if (context->uli.sai) {
		mbr.uli.sai = context->uli.sai;
		mbr.uli.sai2.sai_mcc_digit_2 = context->uli.sai2.sai_mcc_digit_2;
		mbr.uli.sai2.sai_mcc_digit_1 = context->uli.sai2.sai_mcc_digit_1;
		mbr.uli.sai2.sai_mnc_digit_3 = context->uli.sai2.sai_mnc_digit_3;
		mbr.uli.sai2.sai_mcc_digit_3 = context->uli.sai2.sai_mcc_digit_3;
		mbr.uli.sai2.sai_mnc_digit_2 = context->uli.sai2.sai_mnc_digit_2;
		mbr.uli.sai2.sai_mnc_digit_1 = context->uli.sai2.sai_mnc_digit_1;
		mbr.uli.sai2.sai_lac = context->uli.sai2.sai_lac;
		mbr.uli.sai2.sai_sac = context->uli.sai2.sai_sac;
		len += sizeof(mbr.uli.sai2);
	}
	if (context->uli.cgi) {
		mbr.uli.cgi = context->uli.cgi;
		mbr.uli.cgi2.cgi_mcc_digit_2 = context->uli.cgi2.cgi_mcc_digit_2;
		mbr.uli.cgi2.cgi_mcc_digit_1 = context->uli.cgi2.cgi_mcc_digit_1;
		mbr.uli.cgi2.cgi_mnc_digit_3 = context->uli.cgi2.cgi_mnc_digit_3;
		mbr.uli.cgi2.cgi_mcc_digit_3 = context->uli.cgi2.cgi_mcc_digit_3;
		mbr.uli.cgi2.cgi_mnc_digit_2 = context->uli.cgi2.cgi_mnc_digit_2;
		mbr.uli.cgi2.cgi_mnc_digit_1 = context->uli.cgi2.cgi_mnc_digit_1;
		mbr.uli.cgi2.cgi_lac = context->uli.cgi2.cgi_lac;
		mbr.uli.cgi2.cgi_ci = context->uli.cgi2.cgi_ci;
		len += sizeof(mbr.uli.cgi2);
	}
	if (context->uli.ecgi) {
		mbr.uli.ecgi = context->uli.ecgi;
		mbr.uli.ecgi2.ecgi_mcc_digit_2 = context->uli.ecgi2.ecgi_mcc_digit_2;
		mbr.uli.ecgi2.ecgi_mcc_digit_1 = context->uli.ecgi2.ecgi_mcc_digit_1;
		mbr.uli.ecgi2.ecgi_mnc_digit_3 = context->uli.ecgi2.ecgi_mnc_digit_3;
		mbr.uli.ecgi2.ecgi_mcc_digit_3 = context->uli.ecgi2.ecgi_mcc_digit_3;
		mbr.uli.ecgi2.ecgi_mnc_digit_2 = context->uli.ecgi2.ecgi_mnc_digit_2;
		mbr.uli.ecgi2.ecgi_mnc_digit_1 = context->uli.ecgi2.ecgi_mnc_digit_1;
		mbr.uli.ecgi2.ecgi_spare = context->uli.ecgi2.ecgi_spare;
		mbr.uli.ecgi2.eci = context->uli.ecgi2.eci;
		len += sizeof(mbr.uli.ecgi2);
	}
	if (context->uli.macro_enodeb_id) {
		mbr.uli.macro_enodeb_id = context->uli.macro_enodeb_id;
		mbr.uli.macro_enodeb_id2.menbid_mcc_digit_2 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_2;
		mbr.uli.macro_enodeb_id2.menbid_mcc_digit_1 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_1;
		mbr.uli.macro_enodeb_id2.menbid_mnc_digit_3 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_3;
		mbr.uli.macro_enodeb_id2.menbid_mcc_digit_3 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_3;
		mbr.uli.macro_enodeb_id2.menbid_mnc_digit_2 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_2;
		mbr.uli.macro_enodeb_id2.menbid_mnc_digit_1 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_1;
		mbr.uli.macro_enodeb_id2.menbid_spare =
			context->uli.macro_enodeb_id2.menbid_spare;
		mbr.uli.macro_enodeb_id2.menbid_macro_enodeb_id =
			context->uli.macro_enodeb_id2.menbid_macro_enodeb_id;
		mbr.uli.macro_enodeb_id2.menbid_macro_enb_id2 =
			context->uli.macro_enodeb_id2.menbid_macro_enb_id2;
		len += sizeof(mbr.uli.macro_enodeb_id2);
	}
	if (context->uli.extnded_macro_enb_id) {
		mbr.uli.extnded_macro_enb_id = context->uli.extnded_macro_enb_id;
		mbr.uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1 =
			context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1;
		mbr.uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3;
		mbr.uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3 =
			context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3;
		mbr.uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2;
		mbr.uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1;
		mbr.uli.extended_macro_enodeb_id2.emenbid_smenb =
			context->uli.extended_macro_enodeb_id2.emenbid_smenb;
		mbr.uli.extended_macro_enodeb_id2.emenbid_spare =
			context->uli.extended_macro_enodeb_id2.emenbid_spare;
		mbr.uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id =
			context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id;
		mbr.uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2 =
			context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2;
		len += sizeof(mbr.uli.extended_macro_enodeb_id2);
	}
	len += 1;
	set_ie_header(&mbr.uli.header, GTP_IE_USER_LOC_INFO, IE_INSTANCE_ZERO, len);


	set_ie_header(&mbr.serving_network.header, GTP_IE_SERVING_NETWORK, IE_INSTANCE_ZERO,
			sizeof(gtp_serving_network_ie_t) - sizeof(ie_header_t));
	mbr.serving_network.mnc_digit_1 = context->serving_nw.mnc_digit_1;
	mbr.serving_network.mnc_digit_2 = context->serving_nw.mnc_digit_2;
	mbr.serving_network.mnc_digit_3 = context->serving_nw.mnc_digit_3;
	mbr.serving_network.mcc_digit_1 = context->serving_nw.mcc_digit_1;
	mbr.serving_network.mcc_digit_2 = context->serving_nw.mcc_digit_2;
	mbr.serving_network.mcc_digit_3 = context->serving_nw.mcc_digit_3;


	if(context->indication_flag.oi == 1){
		if(context->mo_exception_flag == true){
			mbr.mo_exception_data_cntr.timestamp_value = context->mo_exception_data_counter.timestamp_value;
			mbr.mo_exception_data_cntr.counter_value = context->mo_exception_data_counter.counter_value;

			set_ie_header(&mbr.mo_exception_data_cntr.header, GTP_IE_COUNTER, IE_INSTANCE_ZERO,
					sizeof(gtp_counter_ie_t) - sizeof(ie_header_t));
			context->mo_exception_flag = false;
		}
	}

	if(context->uci_flag == true){
		mbr.uci.mnc_digit_1 = context->uci.mnc_digit_1;
		mbr.uci.mnc_digit_2 = context->uci.mnc_digit_2;
		mbr.uci.mnc_digit_3 = context->uci.mnc_digit_3;
		mbr.uci.mcc_digit_1 = context->uci.mcc_digit_1;
		mbr.uci.mcc_digit_2 = context->uci.mcc_digit_2;
		mbr.uci.mcc_digit_3 = context->uci.mcc_digit_3;
		mbr.uci.spare2 = 0;
		mbr.uci.csg_id = context->uci.csg_id;
		mbr.uci.csg_id2 = context->uci.csg_id2;
		mbr.uci.access_mode = context->uci.access_mode;
		mbr.uci.spare3 = 0;
		mbr.uci.lcsg = context->uci.lcsg;
		mbr.uci.cmi = context->uci.cmi;

		set_ie_header(&mbr.uci.header, GTP_IE_USER_CSG_INFO, IE_INSTANCE_ZERO,
				sizeof(gtp_user_csg_info_ie_t) - sizeof(ie_header_t));
	}

	if((context->ltem_rat_type_flag == true) && (context->indication_flag.oi == 1 || context->rat_type_flag == true)){
		/**
		 * Need to verify this condition
		 * if rat type is lte-m and this flag is set then send lte-m rat type
		 * else send wb-e-utran rat type
		 * since anyway rat_type will be stored automattically like this no need to check
		 * if(context->indication_flag.ltempi == 1)
		 */
		set_ie_header(&mbr.rat_type.header, GTP_IE_RAT_TYPE, IE_INSTANCE_ZERO,
				sizeof(gtp_rat_type_ie_t) - sizeof(ie_header_t));
		mbr.rat_type.rat_type = context->rat_type.rat_type;
	  }

	if (context->selection_flag) {
		mbr.selection_mode.spare2 = context->select_mode.spare2;
		mbr.selection_mode.selec_mode = context->select_mode.selec_mode;

		set_ie_header(&mbr.selection_mode.header, GTP_IE_SELECTION_MODE, IE_INSTANCE_ZERO,
			sizeof(uint8_t));
	}

	if(pdn->ue_time_zone_flag == true) {

		mbr.ue_time_zone.time_zone = pdn->ue_tz.tz;
		mbr.ue_time_zone.daylt_svng_time = pdn->ue_tz.dst;

		mbr.ue_time_zone.spare2 = 0;
		set_ie_header(&mbr.ue_time_zone.header, GTP_IE_UE_TIME_ZONE, IE_INSTANCE_ZERO, (sizeof(uint8_t) * 2));
	}else if(context->ue_time_zone_flag == true){
		mbr.ue_time_zone.time_zone = context->tz.tz;
		mbr.ue_time_zone.spare2 = 0;
		mbr.ue_time_zone.daylt_svng_time = context->tz.dst;

		set_ie_header(&mbr.ue_time_zone.header, GTP_IE_UE_TIME_ZONE,
				IE_INSTANCE_ZERO, (sizeof(uint8_t) * 2));
	}

	mbr.bearer_count = 0;

	for (uint8_t uiCnt = 0; uiCnt < MAX_BEARERS; ++uiCnt) {

		bearer = pdn->eps_bearers[uiCnt];

		if(bearer == NULL) {
			continue;
		}

		mbr.bearer_count++;
		set_ie_header(&mbr.bearer_contexts_to_be_modified[uiCnt].header, GTP_IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);
		set_ebi(&mbr.bearer_contexts_to_be_modified[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
				bearer->eps_bearer_id);

		mbr.bearer_contexts_to_be_modified[uiCnt].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		/*
		 * TODO : Below if condition is used to handle ip issue caused by use of
		 * htonl or ntohl, Need to resolve this issue
		 */
		if(def_bearer->pdn->default_bearer_id ==
				mbr.bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi) {
			bearer->s5s8_sgw_gtpu_ipv4.s_addr = htonl(bearer->s5s8_sgw_gtpu_ipv4.s_addr);
		}else{
			if(pdn->proc == MODIFICATION_PROC){
				/* Refer spec 23.274.Table 7.2.7-2 */
				bearer->s5s8_sgw_gtpu_ipv4.s_addr = (bearer->s5s8_sgw_gtpu_ipv4.s_addr);
			}else{
				bearer->s5s8_sgw_gtpu_ipv4.s_addr = htonl(bearer->s5s8_sgw_gtpu_ipv4.s_addr);
			}
		}

		set_ipv4_fteid(&mbr.bearer_contexts_to_be_modified[uiCnt].s58_u_sgw_fteid,
				GTPV2C_IFTYPE_S5S8_SGW_GTPU,
				IE_INSTANCE_ONE,bearer->s5s8_sgw_gtpu_ipv4,
				(bearer->s5s8_sgw_gtpu_teid));

		mbr.bearer_contexts_to_be_modified[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;

	}

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_req(&mbr, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

}


#if 0
void set_modify_bearer_request(gtpv2c_header *gtpv2c_tx, create_sess_req_t *csr,
		pdn_connection *pdn, eps_bearer *bearer)
{
	mod_bearer_req_t  mbr = {0};
	set_gtpv2c_teid_header((gtpv2c_header *)&mbr.header, GTP_MODIFY_BEARER_REQ,
			0, csr->header.teid.has_teid.seq);

	//AAQUIL need to remove
	mbr.header.teid.has_teid.teid = csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key;
	//0xeeffd000;

	//set_indication(&mbr.indication, IE_INSTANCE_ZERO);
	//mbr.indication.indication_value.sgwci = 1;

	pdn->s5s8_sgw_gtpc_ipv4.s_addr = htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);


	if(csr->uli.header.len !=0) {
		//set_ie_copy(gtpv2c_tx, current_rx_ie);
		set_uli(&mbr.uli, csr, IE_INSTANCE_ZERO);
	}

	if(csr->serving_network.header.len !=0) {
		set_serving_network(&mbr.serving_network, csr, IE_INSTANCE_ZERO);
	}
	if(csr->ue_time_zone.header.len !=0) {
		set_ue_timezone(&mbr.ue_time_zone, csr, IE_INSTANCE_ZERO);
	}

	set_ipv4_fteid(&mbr.sender_fteid_ctl_plane, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
			IE_INSTANCE_ZERO,
			(pdn->s5s8_sgw_gtpc_ipv4), pdn->s5s8_sgw_gtpc_teid);

	set_ie_header(&mbr.bearer_contexts_to_be_modified.header, GTP_IE_BEARER_CONTEXT,
			IE_INSTANCE_ZERO, 0);
	set_ebi(&mbr.bearer_contexts_to_be_modified.eps_bearer_id, IE_INSTANCE_ZERO,
			bearer->eps_bearer_id);

	mbr.bearer_contexts_to_be_modified.header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

	/* Refer spec 23.274.Table 7.2.7-2 */
	bearer->s5s8_sgw_gtpu_ipv4.s_addr = htonl(bearer->s5s8_sgw_gtpu_ipv4.s_addr);
	set_ipv4_fteid(&mbr.bearer_contexts_to_be_modified.s58_u_sgw_fteid,
			GTPV2C_IFTYPE_S5S8_SGW_GTPU,
			IE_INSTANCE_ONE,(bearer->s5s8_sgw_gtpu_ipv4),
			htonl(bearer->s5s8_sgw_gtpu_teid));
	//htonl(bearer->s1u_sgw_gtpu_teid));

	mbr.bearer_contexts_to_be_modified.header.len += sizeof(struct fteid_ie_hdr_t) +
		sizeof(struct in_addr) + IE_HEADER_SIZE;

	uint16_t msg_len = 0;
	encode_mod_bearer_req(&mbr, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);
	clLog(clSystemLog, eCLSeverityDebug,"The length of mbr is %d and gtpv2c is %d\n\n", mbr.bearer_contexts_to_be_modified.header.len,
			gtpv2c_tx->gtpc.length);
}

#endif
