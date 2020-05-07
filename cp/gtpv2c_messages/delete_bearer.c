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

#include <rte_debug.h>

#include "gtpv2c.h"
#include "gtpv2c_set_ie.h"
#include "ue.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "clogger.h"

/**
 * @brief  : Maintatins data from parsed delete bearer response
 */
struct parse_delete_bearer_rsp_t {
	ue_context *context;
	pdn_connection *pdn;
	eps_bearer *ded_bearer;

	gtpv2c_ie *cause_ie;
	gtpv2c_ie *bearer_context_ebi_ie;
	gtpv2c_ie *bearer_context_cause_ie;
};

/**
 * @brief  : parses gtpv2c message and populates parse_delete_bearer_rsp_t structure
 * @param  : gtpv2c_rx
 *           buffer containing delete bearer response message
 * @param  : dbr
 *           data structure to contain required information elements from parsed
 *           delete bearer response
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
static int
parse_delete_bearer_response(gtpv2c_header_t *gtpv2c_rx,
		struct parse_delete_bearer_rsp_t *dbr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid.has_teid.teid,
	    (void **) &dbr->context);

	if (ret < 0 || !dbr->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	/** TODO: we should fully verify mandatory fields within received
	 *  message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == GTP_IE_CAUSE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			dbr->cause_ie = current_ie;
		} else if (current_ie->type == GTP_IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			FOR_EACH_GROUPED_IE(current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == GTP_IE_EPS_BEARER_ID &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					dbr->bearer_context_ebi_ie =
							current_group_ie;
				} else if (current_group_ie->type == GTP_IE_CAUSE &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					dbr->bearer_context_cause_ie =
							current_group_ie;
				}
			}
		}
	}


	if (!dbr->cause_ie || !dbr->bearer_context_ebi_ie
	    || !dbr->bearer_context_cause_ie) {
		clLog(clSystemLog, eCLSeverityCritical, "Received Delete Bearer Response without "
				"mandatory IEs\n");
		return -EPERM;
	}


	if (IE_TYPE_PTR_FROM_GTPV2C_IE(cause_ie,
			dbr->cause_ie)->cause_ie_hdr.cause_value
	    != GTPV2C_CAUSE_REQUEST_ACCEPTED)
		return IE_TYPE_PTR_FROM_GTPV2C_IE(cause_ie,
				dbr->cause_ie)->cause_ie_hdr.cause_value;


	return 0;
}


int
process_delete_bearer_response(gtpv2c_header_t *gtpv2c_rx)
{
	struct parse_delete_bearer_rsp_t delete_bearer_rsp = { 0 };
	int ret = parse_delete_bearer_response(gtpv2c_rx, &delete_bearer_rsp);
	if (ret)
		return ret;

	uint8_t ebi =
	    IE_TYPE_PTR_FROM_GTPV2C_IE(eps_bearer_id_ie,
			    delete_bearer_rsp.bearer_context_ebi_ie)->ebi;
	uint8_t ebi_index = ebi - 5;

	delete_bearer_rsp.ded_bearer =
	    delete_bearer_rsp.context->eps_bearers[ebi_index];

	if (delete_bearer_rsp.ded_bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
		    "Received Delete Bearer Response for"
		    " non-existant EBI: %"PRIu8"\n",
		    ebi);
		return -EPERM;
	}
	delete_bearer_rsp.pdn = delete_bearer_rsp.ded_bearer->pdn;

	if (delete_bearer_rsp.context->eps_bearers[ebi_index]
	    != delete_bearer_rsp.pdn->eps_bearers[ebi_index])
		rte_panic("Incorrect provisioning of bearers\n");


	if (delete_bearer_rsp.ded_bearer->eps_bearer_id
	    ==
	    IE_TYPE_PTR_FROM_GTPV2C_IE(eps_bearer_id_ie,
			    delete_bearer_rsp.bearer_context_ebi_ie)->ebi) {
		delete_bearer_rsp.context->bearer_bitmap &= ~(1
		    << (delete_bearer_rsp.ded_bearer->eps_bearer_id - 5));
		delete_bearer_rsp.context->eps_bearers[ebi_index] = NULL;
		delete_bearer_rsp.pdn->eps_bearers[ebi_index] = NULL;
		uint8_t index = ((0x0f000000
		    & delete_bearer_rsp.ded_bearer->s1u_sgw_gtpu_teid) >> 24);
		delete_bearer_rsp.context->teid_bitmap &= ~(0x01 << index);

		struct dp_id dp_id = { .id = DPN_ID };

		struct session_info si;
		memset(&si, 0, sizeof(si));

		si.ue_addr.u.ipv4_addr =
		     htonl(delete_bearer_rsp.pdn->ipv4.s_addr);
		si.sess_id =
			SESS_ID(delete_bearer_rsp.context->s11_sgw_gtpc_teid,
				delete_bearer_rsp.ded_bearer->eps_bearer_id);
		session_delete(dp_id, si);

		rte_free(delete_bearer_rsp.ded_bearer);
	}

	return 0;
}


void
set_delete_bearer_request(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	ue_context *context, uint8_t linked_eps_bearer_id,
	uint8_t ded_eps_bearer_ids[], uint8_t ded_bearer_counter)
{
	del_bearer_req_t db_req = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *) &db_req, GTP_DELETE_BEARER_REQ,
	    context->s11_mme_gtpc_teid, sequence);

	if (linked_eps_bearer_id > 0) {
		set_ebi(&db_req.lbi, IE_INSTANCE_ZERO, linked_eps_bearer_id);
	} else {
		for (uint8_t iCnt = 0; iCnt < ded_bearer_counter; ++iCnt) {
			set_ebi(&db_req.eps_bearer_ids[iCnt], IE_INSTANCE_ONE,
				ded_eps_bearer_ids[iCnt]);
		}

		db_req.bearer_count = ded_bearer_counter;
	}

	uint16_t msg_len = 0;
	msg_len = encode_del_bearer_req(&db_req, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
}

void
set_delete_bearer_response(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	uint8_t linked_eps_bearer_id, uint8_t ded_eps_bearer_ids[],
	uint8_t ded_bearer_counter, uint32_t s5s8_pgw_gtpc_teid)
{
	del_bearer_rsp_t db_resp = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *) &db_resp, GTP_DELETE_BEARER_RSP,
		s5s8_pgw_gtpc_teid , sequence);

	set_cause_accepted(&db_resp.cause, IE_INSTANCE_ZERO);

	//db_resp..header.gtpc.message_len += db_resp.cause.header.len + sizeof(ie_header_t);
	if (linked_eps_bearer_id > 0) {
		set_ebi(&db_resp.lbi, IE_INSTANCE_ZERO, linked_eps_bearer_id);
	} else {
		for (uint8_t iCnt = 0; iCnt < ded_bearer_counter; ++iCnt) {
			set_ie_header(&db_resp.bearer_contexts[iCnt].header,
				GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);

			set_ebi(&db_resp.bearer_contexts[iCnt].eps_bearer_id,
				IE_INSTANCE_ZERO, ded_eps_bearer_ids[iCnt]);
			db_resp.bearer_contexts[iCnt].header.len +=
				sizeof(uint8_t) + IE_HEADER_SIZE;

			set_cause_accepted(&db_resp.bearer_contexts[iCnt].cause,
				IE_INSTANCE_ZERO);
			db_resp.bearer_contexts[iCnt].header.len +=
				sizeof(uint16_t) + IE_HEADER_SIZE;
	//		db_resp..header.gtpc.message_len += db_resp.bearer_contexts[iCnt].header.len +
	//					sizeof(ie_header_t);

		}

		db_resp.bearer_count = ded_bearer_counter;
	}

	uint16_t msg_len = 0;
	msg_len = encode_del_bearer_rsp(&db_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
}

