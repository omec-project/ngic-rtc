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

#include "ue.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "../pfcp_messages/pfcp_set_ie.h"
#include "cp/cp_app.h"
#include "sm_enum.h"
#include "gw_adapter.h"
#include "pfcp_session.h"

extern int clSystemLog;
/**
 * @brief  : from parameters, populates gtpv2c message 'modify access bearer response' and
 *           populates required information elements as defined by
 *           clause 7.2.8 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify access bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @param  : bearer
 *           bearer data structure to be modified
 * @return : Returns nothing
 */
void
set_modify_access_bearer_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer,
		mod_acc_bearers_req_t *mabr)
{
	uint8_t _ebi = bearer->eps_bearer_id;
	int ebi_index = GET_EBI_INDEX(_ebi), ret = 0;
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	}

	upf_context_t *upf_ctx = NULL;

	/*Retrive bearer id from bearer --> context->pdns[]->upf_ip*/
	if ((upf_context_entry_lookup(context->pdns[ebi_index]->upf_ip,
					&upf_ctx)) < 0) {
		return;
	}

	mod_acc_bearers_rsp_t mb_resp = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *) &mb_resp, GTP_MODIFY_ACCESS_BEARER_RSP,
			context->s11_mme_gtpc_teid, sequence, 0);

	set_cause_accepted(&mb_resp.cause, IE_INSTANCE_ZERO);

	mb_resp.bearer_modify_count =  mabr->bearer_modify_count;

	for (uint8_t uiCnt = 0; uiCnt < mabr->bearer_modify_count; ++uiCnt) {
		int ebi_index = GET_EBI_INDEX(mabr->bearer_contexts_to_be_modified[uiCnt].eps_bearer_id.ebi_ebi);
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

			if(context->indication_flag.s11tf == 1){
				bearer->s11u_sgw_gtpu_teid = bearer->s1u_sgw_gtpu_teid;

				ret = set_address(&bearer->s11u_sgw_gtpu_ip, &bearer->s1u_sgw_gtpu_ip);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}

				mb_resp.bearer_contexts_modified[uiCnt].header.len +=
					set_gtpc_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s11_u_sgw_fteid,
						GTPV2C_IFTYPE_S11U_SGW_GTPU, IE_INSTANCE_ZERO, upf_ctx->s1u_ip,
						bearer->s11u_sgw_gtpu_teid);

			}else{

				mb_resp.bearer_contexts_modified[uiCnt].header.len +=
					set_gtpc_fteid(&mb_resp.bearer_contexts_modified[uiCnt].s1u_sgw_fteid,
						GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, upf_ctx->s1u_ip,
						bearer->s1u_sgw_gtpu_teid);
			}
		}
	}

	/* Update status of mbr processing for ue*/
	context->mabr_info.seq = 0;
	context->mabr_info.status = MABR_PROCESS_DONE;

	encode_mod_acc_bearers_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);

}
