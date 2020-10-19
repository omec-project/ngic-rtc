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
#include "pfcp.h"
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
	int ebi_index = GET_EBI_INDEX(_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	}

	upf_context_t *upf_ctx = NULL;

	/*Retrive bearer id from bearer --> context->pdns[]->upf_ip*/
	if ((ret = upf_context_entry_lookup(context->pdns[ebi_index]->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		return;
	}

	mod_bearer_rsp_t mb_resp = {0};

	if((SGWC == context->cp_mode) || (SAEGWC == context->cp_mode)) {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
				context->s11_mme_gtpc_teid, sequence, 0);
	}else{
		set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
				bearer->pdn->s5s8_sgw_gtpc_teid, sequence, 0);
	}

	if(context->msisdn !=0 && PGWC == context->cp_mode) {
		set_ie_header(&mb_resp.msisdn.header, GTP_IE_MSISDN, IE_INSTANCE_ZERO, BINARY_MSISDN_LEN);
		mb_resp.msisdn.msisdn_number_digits = context->msisdn;
	}
	set_cause_accepted(&mb_resp.cause, IE_INSTANCE_ZERO);

	mb_resp.bearer_count =  mbr->bearer_count;
	for (uint8_t uiCnt = 0; uiCnt < mbr->bearer_count; ++uiCnt) {
		int ebi_index = GET_EBI_INDEX(mbr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		bearer = context->eps_bearers[ebi_index];

		set_ie_header(&mb_resp.bearer_contexts_modified[uiCnt].header, GTP_IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);

		set_cause_accepted(&mb_resp.bearer_contexts_modified[uiCnt].cause, IE_INSTANCE_ZERO);
		mb_resp.bearer_contexts_modified[uiCnt].header.len +=
			sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

		set_ebi(&mb_resp.bearer_contexts_modified[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
				bearer->eps_bearer_id);
		mb_resp.bearer_contexts_modified[uiCnt].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		if (context->cp_mode != PGWC) {
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
	if(context->flag_fqcsid_modified == TRUE) {
		/* Set the SGW FQ-CSID */
		if (context->cp_mode != PGWC) {
			if (context->sgw_fqcsid != NULL) {
				if ((context->sgw_fqcsid)->num_csid) {
					set_gtpc_fqcsid_t(&mb_resp.sgw_fqcsid, IE_INSTANCE_ONE,
							context->sgw_fqcsid);
					mb_resp.sgw_fqcsid.node_address = context->s11_sgw_gtpc_ipv4.s_addr;
				}
			}
		} else {

			if (context->pgw_fqcsid != NULL) {
				if ((context->pgw_fqcsid)->num_csid) {
					set_gtpc_fqcsid_t(&mb_resp.pgw_fqcsid, IE_INSTANCE_ZERO,
							context->pgw_fqcsid);
					mb_resp.pgw_fqcsid.node_address = bearer->pdn->s5s8_pgw_gtpc_ipv4.s_addr;
				}
			}
		}
	}

#endif /* USE_CSID */

	/* Update status of mbr processing for ue*/
	context->mbr_info.seq = 0;
	context->mbr_info.status = MBR_PROCESS_DONE;

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

}
/*MODIFY RESPONSE FUNCTION WHEN PGWC returns MBR RESPONSE to SGWC
 * in HANDOVER SCENARIO*/

void
set_modify_bearer_response_handover(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer, mod_bearer_req_t *mbr)
{
	int ret = 0;
	int _ebi = bearer->eps_bearer_id;
	int ebi_index = GET_EBI_INDEX(_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	}

	upf_context_t *upf_ctx = NULL;
	struct in_addr ip = {0};

	/*Retrive bearer id from bearer --> context->pdns[]->upf_ip*/
	if ((ret = upf_context_entry_lookup(context->pdns[ebi_index]->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		return;
	}

	mod_bearer_rsp_t mb_resp = {0};

	if((SGWC == context->cp_mode) || (SAEGWC == context->cp_mode)) {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
				context->s11_mme_gtpc_teid, sequence, 0);
	}else{
		set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_BEARER_RSP,
				bearer->pdn->s5s8_sgw_gtpc_teid, sequence, 0);
	}

	/* Add MSISDN IE in case of only handover */
	if(context->msisdn !=0 && PGWC == context->cp_mode && context->sgwu_changed == TRUE) {
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

			ebi_index = GET_EBI_INDEX(mbr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			}
			bearer = context->eps_bearers[ebi_index];

			if ((SGWC == context->cp_mode) || (SAEGWC == context->cp_mode)) {
				if(bearer->pdn->default_bearer_id ==
						mbr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi) {
					ip.s_addr = bearer->s1u_sgw_gtpu_ipv4.s_addr;
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

	/* Update status of mbr processing for ue*/
	context->mbr_info.seq = 0;
	context->mbr_info.status = MBR_PROCESS_DONE;

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);
}


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
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

	return 0;
}

void set_modify_bearer_request(gtpv2c_header_t *gtpv2c_tx,
		pdn_connection *pdn, eps_bearer *bearer)
{
	int len = 0 ;
	mod_bearer_req_t mbr = {0};
	struct ue_context_t *context = NULL;
	eps_bearer *def_bearer = bearer;
	struct teid_value_t *teid_value = NULL;
	int ret = 0;
	teid_key_t teid_key = {0};

	/* Check PDN and Context are not NULL */
	if((pdn == NULL) &&  (pdn->context == NULL) ) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"UE contex not found : Warnning \n",
							LOG_VALUE);

		return;
	}
	/* Get the UE Context */
	context = pdn->context;

	set_gtpv2c_teid_header((gtpv2c_header_t *)&mbr.header, GTP_MODIFY_BEARER_REQ,
			0, context->sequence, 0);

	mbr.header.teid.has_teid.teid = pdn->s5s8_pgw_gtpc_teid;
	/* TODO: Need to verify */
	set_ipv4_fteid(&mbr.sender_fteid_ctl_plane, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
			IE_INSTANCE_ZERO,
			pdn->s5s8_sgw_gtpc_ipv4, pdn->s5s8_sgw_gtpc_teid);

	teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (teid_value == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
		"memory for teid value, Error : %s\n", LOG_VALUE,
		rte_strerror(rte_errno));
		return;
	}
	teid_value->teid = pdn->s5s8_sgw_gtpc_teid;
	teid_value->msg_type = gtpv2c_tx->gtpc.message_type;

	snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(pdn->proc),
					context->sequence);

	/* Add the entry for sequence and teid value for error handling */
	if (context->cp_mode != SAEGWC) {
		ret = add_seq_number_for_teid(teid_key, teid_value);
		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"Sequence number for TEID: %u\n", LOG_VALUE,
					teid_value->teid);
			return;
		}
	}

	/* Note:Below condition is added for the flow ERAB Modification
	 * Update. sepcs ref: 23.401 Section 5.4.7-1*/
	if(context->second_rat_flag == TRUE ) {
		uint8_t instance = 0;
		mbr.second_rat_count = context->second_rat_count;
		for(uint8_t i = 0; i < context->second_rat_count; i++) {
			mbr.secdry_rat_usage_data_rpt[i].spare2 = 0;
			mbr.secdry_rat_usage_data_rpt[i].irsgw = context->second_rat[i].irsgw;
			mbr.secdry_rat_usage_data_rpt[i].irpgw = context->second_rat[i].irpgw;
			mbr.secdry_rat_usage_data_rpt[i].secdry_rat_type = context->second_rat[i].rat_type;
			mbr.secdry_rat_usage_data_rpt[i].ebi = context->second_rat[i].eps_id;
			mbr.secdry_rat_usage_data_rpt[i].spare3 = 0;
			mbr.secdry_rat_usage_data_rpt[i].start_timestamp = context->second_rat[i].start_timestamp;
			mbr.secdry_rat_usage_data_rpt[i].end_timestamp = context->second_rat[i].end_timestamp;
			mbr.secdry_rat_usage_data_rpt[i].usage_data_dl = context->second_rat[i].usage_data_dl;
			mbr.secdry_rat_usage_data_rpt[i].usage_data_ul = context->second_rat[i].usage_data_ul;


			set_ie_header(&mbr.secdry_rat_usage_data_rpt[i].header, GTP_IE_SECDRY_RAT_USAGE_DATA_RPT, instance++,
					sizeof(gtp_secdry_rat_usage_data_rpt_ie_t) - sizeof(ie_header_t));

		}
	}

	if(context->uli_flag != FALSE) {
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
	}

	if(context->serving_nw_flag == TRUE) {

		set_ie_header(&mbr.serving_network.header, GTP_IE_SERVING_NETWORK, IE_INSTANCE_ZERO,
				sizeof(gtp_serving_network_ie_t) - sizeof(ie_header_t));
		mbr.serving_network.mnc_digit_1 = context->serving_nw.mnc_digit_1;
		mbr.serving_network.mnc_digit_2 = context->serving_nw.mnc_digit_2;
		mbr.serving_network.mnc_digit_3 = context->serving_nw.mnc_digit_3;
		mbr.serving_network.mcc_digit_1 = context->serving_nw.mcc_digit_1;
		mbr.serving_network.mcc_digit_2 = context->serving_nw.mcc_digit_2;
		mbr.serving_network.mcc_digit_3 = context->serving_nw.mcc_digit_3;
	}

	if(context->indication_flag.oi == 1){
		if(context->mo_exception_flag == TRUE){
			mbr.mo_exception_data_cntr.timestamp_value = context->mo_exception_data_counter.timestamp_value;
			mbr.mo_exception_data_cntr.counter_value = context->mo_exception_data_counter.counter_value;

			set_ie_header(&mbr.mo_exception_data_cntr.header, GTP_IE_COUNTER, IE_INSTANCE_ZERO,
					sizeof(gtp_counter_ie_t) - sizeof(ie_header_t));
			context->mo_exception_flag = FALSE;
		}
	}

	if(context->uci_flag == TRUE){
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

	if((context->ltem_rat_type_flag == TRUE) && (context->indication_flag.oi == 1 || context->rat_type_flag == TRUE)){
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

	if (context->selection_flag == TRUE) {
		mbr.selection_mode.spare2 = context->select_mode.spare2;
		mbr.selection_mode.selec_mode = context->select_mode.selec_mode;

		set_ie_header(&mbr.selection_mode.header, GTP_IE_SELECTION_MODE, IE_INSTANCE_ZERO,
			sizeof(uint8_t));
	}

	if(context->ue_time_zone_flag == TRUE) {

		mbr.ue_time_zone.time_zone = context->tz.tz;
		mbr.ue_time_zone.daylt_svng_time = context->tz.dst;
		mbr.ue_time_zone.spare2 = 0;
		set_ie_header(&mbr.ue_time_zone.header, GTP_IE_UE_TIME_ZONE, IE_INSTANCE_ZERO, (sizeof(uint8_t) * 2));
	}

		if(context->indication_flag.oi == 1) {
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
					bearer->s5s8_sgw_gtpu_ipv4.s_addr = bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				}else{

					bearer->s5s8_sgw_gtpu_ipv4.s_addr = (bearer->s5s8_sgw_gtpu_ipv4.s_addr);
					/*TODO: NEED to revist here: why below condition was there
					if(pdn->proc == MODIFICATION_PROC){
						// Refer spec 23.274.Table 7.2.7-2
						bearer->s5s8_sgw_gtpu_ipv4.s_addr = (bearer->s5s8_sgw_gtpu_ipv4.s_addr);
					}else{
						bearer->s5s8_sgw_gtpu_ipv4.s_addr = bearer->s5s8_sgw_gtpu_ipv4.s_addr;
					} */

				}

				set_ipv4_fteid(&mbr.bearer_contexts_to_be_modified[uiCnt].s58_u_sgw_fteid,
						GTPV2C_IFTYPE_S5S8_SGW_GTPU,
						IE_INSTANCE_ONE,bearer->s5s8_sgw_gtpu_ipv4,
						(bearer->s5s8_sgw_gtpu_teid));

				mbr.bearer_contexts_to_be_modified[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
					sizeof(struct in_addr) + IE_HEADER_SIZE;
			}
		}

		if(context->flag_fqcsid_modified == TRUE) {

#ifdef USE_CSID
			/* Set the SGW FQ-CSID */
			if (context->sgw_fqcsid != NULL) {
				if ((context->sgw_fqcsid)->num_csid) {
					set_gtpc_fqcsid_t(&mbr.sgw_fqcsid, IE_INSTANCE_ONE,
							context->sgw_fqcsid);
					mbr.sgw_fqcsid.node_address = pdn->s5s8_sgw_gtpc_ipv4.s_addr;
				}
			}
			/* Set the MME FQ-CSID */
			if (context->mme_fqcsid != NULL) {
				if ((context->mme_fqcsid)->num_csid) {
					set_gtpc_fqcsid_t(&mbr.mme_fqcsid, IE_INSTANCE_ZERO,
							context->mme_fqcsid);
				}
			}
#endif /* USE_CSID */
		}

	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_req(&mbr, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

}

int mbr_req_pre_check(mod_bearer_req_t *mbr)
{
	if(mbr->bearer_count == 0)
	{
		if((mbr->uli.header.len == 0) &&
				(mbr->serving_network.header.len == 0) &&
				(mbr->selection_mode.header.len == 0) &&
				(mbr->indctn_flgs.header.len == 0) &&
				(mbr->ue_time_zone.header.len == 0) &&
				(mbr->second_rat_count == 0)) {

			return GTPV2C_CAUSE_CONDITIONAL_IE_MISSING;
		}
	}
	return 0;
}

