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
#include "gtpv2c_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "../pfcp_messages/pfcp_set_ie.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

extern pfcp_config_t pfcp_config;

extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];

void
set_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer)
{
	int ret = 0;
	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(context->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		RTE_LOG_DP(ERR, CP, "%s : Error: %d \n", __func__, ret);
		return;
	}

	create_session_response_t cs_resp = {0};

	set_gtpv2c_teid_header((gtpv2c_header *)&cs_resp.header,
			GTP_CREATE_SESSION_RSP, context->s11_mme_gtpc_teid,
			sequence);

	set_cause_accepted(&cs_resp.cause, IE_INSTANCE_ZERO);

	struct in_addr ip;
	ip.s_addr = ntohl(pfcp_config.s11_ip.s_addr);

	set_ipv4_fteid(&cs_resp.s11_ftied, GTPV2C_IFTYPE_S11S4_SGW_GTPC,
			IE_INSTANCE_ZERO,
			ip, context->s11_sgw_gtpc_teid);


	if (pfcp_config.cp_type != SAEGWC) {
		set_ipv4_fteid(&cs_resp.pgws5s8_pmip, GTPV2C_IFTYPE_S5S8_PGW_GTPC,
				IE_INSTANCE_ONE,
				pdn->s5s8_pgw_gtpc_ipv4, pdn->s5s8_pgw_gtpc_teid);
	}

	set_ipv4_paa(&cs_resp.paa, IE_INSTANCE_ZERO, pdn->ipv4);

	set_apn_restriction(&cs_resp.apn_restriction, IE_INSTANCE_ZERO,
			pdn->apn_restriction);
	{

		set_ie_header(&cs_resp.bearer_context.header, IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);


		set_ebi(&cs_resp.bearer_context.ebi, IE_INSTANCE_ZERO,
				bearer->eps_bearer_id);

		cs_resp.bearer_context.header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_cause_accepted(&cs_resp.bearer_context.cause, IE_INSTANCE_ZERO);

		cs_resp.bearer_context.header.len += sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

		if (bearer->s11u_mme_gtpu_teid) {
			printf("S11U Detect- set_create_session_response-"
					"\n\tbearer->s11u_mme_gtpu_teid= %X;"
					"\n\tGTPV2C_IFTYPE_S11U_MME_GTPU= %X\n",
					htonl(bearer->s11u_mme_gtpu_teid),
					GTPV2C_IFTYPE_S11U_SGW_GTPU);

			/* TODO: set fteid values to create session response member */
			/*
			printf("S11U Detect- set_create_session_response-"
					"\n\tbearer->s11u_mme_gtpu_teid= %X;"
					"\n\tGTPV2C_IFTYPE_S11U_MME_GTPU= %X\n",
					bearer->s11u_mme_gtpu_teid,
					GTPV2C_IFTYPE_S11U_SGW_GTPU);
			add_grouped_ie_length(bearer_context_group,
		    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S11U_SGW_GTPU,
				    IE_INSTANCE_SIX, s1u_sgw_ip,
				    bearer->s1u_sgw_gtpu_teid));
			*/

		} else {

			ip.s_addr = upf_ctx->s1u_ip;

		    set_ipv4_fteid(&cs_resp.bearer_context.s1u_sgw_ftied,
			GTPV2C_IFTYPE_S1U_SGW_GTPU,
				IE_INSTANCE_ZERO, ip,
				(bearer->s1u_sgw_gtpu_teid));
			cs_resp.bearer_context.header.len += sizeof(struct fteid_ie_hdr_t) +
				sizeof(struct in_addr) + IE_HEADER_SIZE;
		}

		set_ipv4_fteid(&cs_resp.bearer_context.s5s8_pgw,
				GTPV2C_IFTYPE_S5S8_PGW_GTPU,
				IE_INSTANCE_TWO, bearer->s5s8_pgw_gtpu_ipv4,
				htonl(bearer->s5s8_pgw_gtpu_teid));

		cs_resp.bearer_context.header.len += sizeof(struct fteid_ie_hdr_t) +
				sizeof(struct in_addr) + IE_HEADER_SIZE;
	}

	uint16_t msg_len = 0;
	encode_create_session_response_t(&cs_resp, (uint8_t *)gtpv2c_tx,
			&msg_len);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);
}

int
process_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
{
	create_session_request_t csr = { 0 };
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	struct in_addr ue_ip;
	int ret;
	static uint32_t process_sgwc_s5s8_cs_req_cnt;
	static uint32_t process_spgwc_s11_cs_res_cnt;

	ret = decode_create_session_request_t((uint8_t *) gtpv2c_rx,
			&csr);
	if (!ret)
		 return ret;

	if (csr.indication.header.len &&
			csr.indication.indication_value.uimsi) {
		fprintf(stderr, "Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n");
		return -EPERM;
	}

	if (!csr.indication.header.len
			|| !csr.apn_restriction.header.len
			|| !csr.bearer_context.header.len
			|| !csr.sender_ftied.header.len
			|| !csr.s5s8pgw_pmip.header.len
			|| !csr.imsi.header.len
			|| !csr.ambr.header.len
			|| !csr.pdn_type.header.len
			|| !csr.bearer_context.bearer_qos.header.len
			|| !csr.msisdn.header.len
			|| !(csr.pdn_type.pdn_type == PDN_IP_TYPE_IPV4) ) {
		fprintf(stderr, "Mandatory IE missing. Dropping packet\n");
		return -EPERM;
	}

	if (csr.pdn_type.pdn_type == PDN_IP_TYPE_IPV6 ||
			csr.pdn_type.pdn_type == PDN_IP_TYPE_IPV4V6) {
			fprintf(stderr, "IPv6 Not Yet Implemented - Dropping packet\n");
			return GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
	}

	apn *apn_requested = get_apn((char *)csr.apn.apn, csr.apn.header.len);

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	uint8_t ebi_index = csr.bearer_context.ebi.eps_bearer_id - 5;

	ret = acquire_ip(&ue_ip);
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

	/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
	ret = create_ue_context(csr.imsi.imsi, csr.imsi.header.len,
			csr.bearer_context.ebi.eps_bearer_id, &context);
	if (ret)
		return ret;

	if (csr.mei.header.len)
		memcpy(&context->mei, csr.mei.mei, csr.mei.header.len);

	memcpy(&context->msisdn, &csr.msisdn.msisdn, csr.msisdn.header.len);

	context->s11_sgw_gtpc_ipv4 = pfcp_config.s11_ip;
	context->s11_mme_gtpc_teid = csr.sender_ftied.teid_gre;
	context->s11_mme_gtpc_ipv4 = pfcp_config.s11_mme_ip;

	pdn = context->pdns[ebi_index];
	{
		pdn->apn_in_use = apn_requested;
		pdn->apn_ambr.ambr_downlink = csr.ambr.apn_ambr_dl;
		pdn->apn_ambr.ambr_uplink = csr.ambr.apn_ambr_ul;
		pdn->apn_restriction = csr.apn_restriction.restriction_type;
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);

		if (csr.pdn_type.pdn_type == PDN_TYPE_IPV4)
			pdn->pdn_type.ipv4 = 1;
		else if (csr.pdn_type.pdn_type == PDN_TYPE_IPV6)
			pdn->pdn_type.ipv6 = 1;
		else if (csr.pdn_type.pdn_type == PDN_TYPE_IPV4_IPV6) {
			pdn->pdn_type.ipv4 = 1;
			pdn->pdn_type.ipv6 = 1;
		}

		if (csr.charging_characteristics.header.len)
			memcpy(&pdn->charging_characteristics,
					&csr.charging_characteristics.value,
					sizeof(csr.charging_characteristics.value));

		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		/* Note: s5s8_sgw_gtpc_teid =
		 * s11_sgw_gtpc_teid
		 */
		pdn->s5s8_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
		/* Note: s5s8_pgw_gtpc_teid updated by
		 * process_sgwc_s5s8_create_session_response (...)
		 */
		pdn->s5s8_pgw_gtpc_ipv4 = csr.s5s8pgw_pmip.ip.ipv4;
	}

	bearer = context->eps_bearers[ebi_index];
	{
		/* TODO: Implement TFTs on default bearers
		   if (create_session_request.bearer_tft_ie) {
		   }
		   */

		bearer->qos.qos.ul_mbr =
			csr.bearer_context.bearer_qos.maximum_bit_rate_for_uplink;
		bearer->qos.qos.dl_mbr =
			csr.bearer_context.bearer_qos.maximum_bit_rate_for_downlink;
		bearer->qos.qos.ul_gbr =
			csr.bearer_context.bearer_qos.guaranteed_bit_rate_for_uplink;
		bearer->qos.qos.dl_gbr =
			csr.bearer_context.bearer_qos.guaranteed_bit_rate_for_downlink;

		set_s1u_sgw_gtpu_teid(bearer, context);
		/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
		 * Computation same as s1u_sgw_gtpu_teid
		 */
		set_s5s8_sgw_gtpu_teid(bearer, context);
		bearer->pdn = pdn;
	}

	if (spgw_cfg == SGWC) {
		char sgwu_fqdn[MAX_HOSTNAME_LENGTH] = {0};
		ret =
			gen_sgwc_s5s8_create_session_request(gtpv2c_rx,
				gtpv2c_s5s8_tx, csr.header.teid.has_teid.seq,
				pdn, bearer, sgwu_fqdn);
		RTE_LOG_DP(DEBUG, CP, "NGIC- create_session.c::"
				"\n\tprocess_create_session_request::case= %d;"
				"\n\tprocess_sgwc_s5s8_cs_req_cnt= %u;"
				"\n\tgen_create_s5s8_session_request= %d\n",
				spgw_cfg, process_sgwc_s5s8_cs_req_cnt++,
				ret);
		return ret;
	}

	set_create_session_response(
			gtpv2c_s11_tx, csr.header.teid.has_teid.seq,
			context, pdn, bearer);

	RTE_LOG_DP(DEBUG, CP, "NGIC- create_session.c::"
			"\n\tprocess_create_session_request::case= %d;"
			"\n\tprocess_spgwc_s11_cs_res_cnt= %u;"
			"\n\tset_create_session_response::done...\n",
			spgw_cfg, process_spgwc_s11_cs_res_cnt++);

	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));

	session.ue_addr.iptype = IPTYPE_IPV4;
	session.ue_addr.u.ipv4_addr = pdn->ipv4.s_addr;
	session.ul_s1_info.sgw_teid = htonl(bearer->s1u_sgw_gtpu_teid);
	session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);

	if (bearer->s11u_mme_gtpu_teid) {
		/* If CIOT: [enb_addr,enb_teid] =
		 * s11u[mme_gtpu_addr, mme_gtpu_teid]
		 */
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
			htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid =
			htonl(bearer->s11u_mme_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
			htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
	} else {
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
			htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid =
			htonl(bearer->s1u_enb_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
			htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
	}

	session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	session.ul_apn_mtr_idx = ulambr_idx;
	session.dl_apn_mtr_idx = dlambr_idx;
	session.num_ul_pcc_rules = 1;
	session.num_dl_pcc_rules = 1;
	session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

	/* using ue ipv4 addr as unique identifier for an UE.
	 * and sess_id is combination of ue addr and bearer id.
	 * formula to set sess_id = (ue_ipv4_addr << 4) | bearer_id
	 */
	session.sess_id = SESS_ID(context->s11_sgw_gtpc_teid,
						bearer->eps_bearer_id);

	struct dp_id dp_id = { .id = DPN_ID };

	if (session_create(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

	if (bearer->s11u_mme_gtpu_teid) {
		session.num_dl_pcc_rules = 1;
		session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

		session.num_adc_rules = num_adc_rules;
		uint32_t i;
		for (i = 0; i < num_adc_rules; ++i)
			        session.adc_rule_id[i] = adc_rule_id[i];

		if (session_modify(dp_id, session) < 0)
			rte_exit(EXIT_FAILURE, "Bearer Session create CIOT implicit modify fail !!!");
	}
	return 0;
}
