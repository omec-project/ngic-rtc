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
/* TODO: Verify */
#include "ue.h"
#include "packet_filters.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "../pfcp_messages/pfcp_set_ie.h"
#include "cp_config.h"
#include "cp_stats.h"
#include "sm_struct.h"
#include "pfcp_set_ie.h"
#include "gx.h"

extern pfcp_config_t config;
extern int clSystemLog;
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];

uint16_t
set_create_session_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		uint8_t is_piggybacked)
{
	int ret = 0;
	eps_bearer *bearer = NULL;
	upf_context_t *upf_ctx = NULL;
	create_sess_rsp_t cs_resp = {0};
	struct resp_info *resp = NULL;
	uint8_t cause_value = 0;
	if ((ret = upf_context_entry_lookup(pdn->upf_ip,
					&upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: upx context not found %d\n", LOG_VALUE,ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Lookup Stored the session information. */
	if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id %lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *)&cs_resp.header,
			GTP_CREATE_SESSION_RSP, context->s11_mme_gtpc_teid,
			sequence, is_piggybacked);

	if (context->cp_mode == SGWC) {
		if(context->indication_flag.oi == TRUE || pdn->proc == S1_HANDOVER_PROC) {
			cause_value = GTPV2C_CAUSE_REQUEST_ACCEPTED;
		} else {
			cause_value = resp->gtpc_msg.cs_rsp.cause.cause_value;
		}
	} else {
		if (pdn->requested_pdn_type == PDN_IP_TYPE_IPV4V6
				&& (config.ip_type_supported == IP_V4
					|| config.ip_type_supported == IP_V6)) {

			cause_value = GTPV2C_CAUSE_NEW_PDN_TYPE_NETWORK_PREFERENCE;

		} else if (pdn->requested_pdn_type == PDN_IP_TYPE_IPV4V6
			&& (config.ip_type_supported == IPV4V6_PRIORITY
				|| (config.ip_type_supported == IPV4V6_DUAL
					&& !(context->indication_flag.daf)))) {

			cause_value = GTPV2C_CAUSE_NEW_PDN_TYPE_SINGLE_ADDR_BEARER;

		} else {
			cause_value = GTPV2C_CAUSE_REQUEST_ACCEPTED;
		}
	}


	set_csresp_cause(&cs_resp.cause, cause_value, IE_INSTANCE_ZERO);

	if(context->change_report == TRUE && context->cp_mode == SGWC) {
		set_change_reporting_action(&cs_resp.chg_rptng_act,
				IE_INSTANCE_ZERO, context->change_report_action);
	}else if (context->cp_mode == SAEGWC  || context->cp_mode == PGWC) {
		if (config.use_gx) {
			if(((context->event_trigger & (1 << ECGI_EVENT_TRIGGER)) != 0) ||
					((context->event_trigger & (1 << TAI_EVENT_TRIGGER)) != 0))
				set_change_reporting_action(&cs_resp.chg_rptng_act, IE_INSTANCE_ZERO, START_REPORT_TAI_ECGI);
		}

	}

	if (context->cp_mode != PGWC) {

		if ((context->s11_sgw_gtpc_teid != 0) && (context->s11_sgw_gtpc_ip.ipv4_addr != 0
						|| *context->s11_sgw_gtpc_ip.ipv6_addr)) {
			set_gtpc_fteid(&cs_resp.sender_fteid_ctl_plane,
				GTPV2C_IFTYPE_S11S4_SGW_GTPC, IE_INSTANCE_ZERO,
				context->s11_sgw_gtpc_ip, context->s11_sgw_gtpc_teid);
		}
	}


	if (pdn->s5s8_pgw_gtpc_teid == 0) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"S5S8 PGW TEID is NULL\n",
				LOG_VALUE);
	}

	if(pdn->s5s8_pgw_gtpc_ip.ipv4_addr == 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"S5S8 PGW IP is NULL\n",
				LOG_VALUE);

	}

	set_gtpc_fteid(&cs_resp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc,
					GTPV2C_IFTYPE_S5S8_PGW_GTPC, IE_INSTANCE_ONE,
					pdn->s5s8_pgw_gtpc_ip, pdn->s5s8_pgw_gtpc_teid);

	set_paa(&cs_resp.paa, IE_INSTANCE_ZERO, pdn);

	set_apn_restriction(&cs_resp.apn_restriction, IE_INSTANCE_ZERO,
			pdn->apn_restriction);

	if(context->pra_flag){
		set_presence_reporting_area_action_ie(&cs_resp.pres_rptng_area_act, context);
		context->pra_flag = 0;
	}

	cs_resp.bearer_count = 0;
	uint8_t index = 0;

	for(uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = pdn->eps_bearers[i];
		if(bearer == NULL)
			continue;

		cs_resp.bearer_count++;
		set_ie_header(&cs_resp.bearer_contexts_created[index].header, GTP_IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);


		set_ebi(&cs_resp.bearer_contexts_created[index].eps_bearer_id, IE_INSTANCE_ZERO,
				bearer->eps_bearer_id);

		cs_resp.bearer_contexts_created[index].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_csresp_cause(&cs_resp.bearer_contexts_created[index].cause, cause_value, IE_INSTANCE_ZERO);

		cs_resp.bearer_contexts_created[index].header.len += sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

		if (bearer->s11u_mme_gtpu_teid) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"S11U Detect- set_create_session_response-"
					"\n\tbearer->s11u_mme_gtpu_teid= %X;"
					"\n\tGTPV2C_IFTYPE_S11U_MME_GTPU= %X\n", LOG_VALUE,
					htonl(bearer->s11u_mme_gtpu_teid),
					GTPV2C_IFTYPE_S11U_SGW_GTPU);

			/* TODO: set fteid values to create session response member */

		} else {

			if ((bearer->s1u_sgw_gtpu_teid != 0) && (upf_ctx->s1u_ip.ipv4_addr != 0
													|| *upf_ctx->s1u_ip.ipv6_addr)) {
				cs_resp.bearer_contexts_created[index].header.len +=
					set_gtpc_fteid(&cs_resp.bearer_contexts_created[index].s1u_sgw_fteid,
						GTPV2C_IFTYPE_S1U_SGW_GTPU,
						IE_INSTANCE_ZERO, upf_ctx->s1u_ip,
						bearer->s1u_sgw_gtpu_teid);
			}
		}

		if ((bearer->s5s8_pgw_gtpu_teid != 0) && (bearer->s5s8_pgw_gtpu_ip.ipv4_addr != 0
												|| *bearer->s5s8_pgw_gtpu_ip.ipv6_addr)) {
			cs_resp.bearer_contexts_created[index].header.len +=
				set_gtpc_fteid(&cs_resp.bearer_contexts_created[index].s5s8_u_pgw_fteid,
					GTPV2C_IFTYPE_S5S8_PGW_GTPU,
					IE_INSTANCE_TWO, bearer->s5s8_pgw_gtpu_ip,
					bearer->s5s8_pgw_gtpu_teid);
		}

		set_ie_header(&cs_resp.bearer_contexts_created[index].bearer_lvl_qos.header,
				GTP_IE_BEARER_QLTY_OF_SVC, IE_INSTANCE_ZERO,
				sizeof(gtp_bearer_qlty_of_svc_ie_t) - sizeof(ie_header_t));

		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.pvi =
			context->eps_bearers[i]->qos.arp.preemption_vulnerability;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.spare2 = 0;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.pl =
			context->eps_bearers[i]->qos.arp.priority_level;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.pci =
			context->eps_bearers[i]->qos.arp.preemption_capability;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.spare3 = 0;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.qci =
			context->eps_bearers[i]->qos.qci;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_uplnk =
			context->eps_bearers[i]->qos.ul_mbr;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_dnlnk =
			context->eps_bearers[i]->qos.dl_mbr;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_uplnk =
			context->eps_bearers[i]->qos.ul_gbr;
		cs_resp.bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_dnlnk =
			context->eps_bearers[i]->qos.dl_gbr;

		cs_resp.bearer_contexts_created[index].header.len +=
			cs_resp.bearer_contexts_created[index].bearer_lvl_qos.header.len
			+ sizeof(ie_header_t);

		index++;
		if(is_piggybacked){
			break;
		}
	} /* End of for loop */

#ifdef USE_CSID
	if (context->cp_mode != PGWC) {

		fqcsid_t *csid = NULL;
		/* Get peer CSID associated with node */
		csid = get_peer_addr_csids_entry(&pdn->mme_csid.node_addr,
				UPDATE_NODE);
		if ((csid != NULL) && (csid->num_csid)) {
			/* Set the SGW FQ-CSID */
			if (pdn->sgw_csid.num_csid) {
				set_gtpc_fqcsid_t(&cs_resp.sgw_fqcsid, IE_INSTANCE_ONE,
						&pdn->sgw_csid);
			}

			/* Set the PGW FQ-CSID */
			if (context->cp_mode != SAEGWC) {
				if (pdn->pgw_csid.num_csid) {
					set_gtpc_fqcsid_t(&cs_resp.pgw_fqcsid, IE_INSTANCE_ZERO,
							&pdn->pgw_csid);
				}
			}
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Note: Not found associated Local CSID, Peer_Addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(context->s11_mme_gtpc_ip.ipv4_addr));

		}
	} else {
			if (pdn->pgw_csid.num_csid) {
				set_gtpc_fqcsid_t(&cs_resp.pgw_fqcsid, IE_INSTANCE_ZERO,
						&pdn->pgw_csid);
			} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Note: Not found PGW associated CSID\n", LOG_VALUE);
		}
	}

#endif /* USE_CSID */

	uint16_t msg_len = 0;
	msg_len = encode_create_sess_rsp(&cs_resp, (uint8_t *)gtpv2c_tx);
	return msg_len;
}
