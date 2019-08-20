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
#include "pfcp.h"
#include "cp_stats.h"
#include "sm_struct.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

#define size sizeof(pfcp_sess_mod_req_t)

extern int pfcp_fd;

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
int
parse_release_access_bearer_request(gtpv2c_header *gtpv2c_rx,
		rel_acc_ber_req *rel_acc_ber_req_t)
{
	/* VS: Remove this part at integration of libgtpv2 lib*/
	rel_acc_ber_req_t->header = *(gtpv2c_header_t *)gtpv2c_rx;

	uint32_t teid = ntohl(gtpv2c_rx->teid_u.has_teid.teid);

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &teid,
	    (void **) &rel_acc_ber_req_t->context);

	if (ret < 0 || !rel_acc_ber_req_t->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if(gtpv2c_rx != NULL) {
		if(gtpv2c_rx->gtpc.teidFlg == 1) {
			rel_acc_ber_req_t->seq =
				gtpv2c_rx->teid_u.has_teid.seq;
		} else {
			rel_acc_ber_req_t->seq =
				gtpv2c_rx->teid_u.no_teid.seq;
		}
	}

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
/* TODO: Remove #if 0 before rollup */
void
set_release_access_bearer_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, uint32_t s11_mme_gtpc_teid)
{
	set_gtpv2c_teid_header(gtpv2c_tx, GTP_RELEASE_ACCESS_BEARERS_RSP,
	    htonl(s11_mme_gtpc_teid), sequence);

	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);

}

int
process_release_access_bearer_request(rel_acc_ber_req *rel_acc_ber_req_t)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};


	for (int i = 0; i < MAX_BEARERS; ++i) {
		if ((rel_acc_ber_req_t->context)->eps_bearers[i] == NULL)
			continue;

		bearer = (rel_acc_ber_req_t->context)->eps_bearers[ebi_index];
		if (!bearer) {
			fprintf(stderr,
					"Retrive Context for release access bearer is non-existent EBI - "
					"Bitmap Inconsistency - Dropping packet\n");
			return -EPERM;
		}

		bearer->s1u_enb_gtpu_teid = 0;

		pdn = bearer->pdn;

		rel_acc_ber_req_t->context->seid =
			SESS_ID((rel_acc_ber_req_t->context)->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

		fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &rel_acc_ber_req_t->header,
				rel_acc_ber_req_t->context, bearer, pdn);

		pfcp_sess_mod_req.update_far_count = 1;
		if(pfcp_sess_mod_req.update_far_count) {
			pfcp_sess_mod_req.update_far[0].apply_action.forw = 0;
			pfcp_sess_mod_req.update_far[0].apply_action.buff = PRESENT;
			if (pfcp_sess_mod_req.update_far[0].apply_action.buff == PRESENT) {
				pfcp_sess_mod_req.update_far[0].apply_action.nocp = PRESENT;
				pfcp_sess_mod_req.update_far[0].upd_frwdng_parms.outer_hdr_creation.teid = 0;
			}
		}


		if (get_sess_entry((rel_acc_ber_req_t->context)->seid, &resp) != 0) {
			fprintf(stderr, "Failed to add response in entry in SM_HASH\n");
			return -1;
		}

		/* Store s11 struture data into sm_hash for sending delete response back to s11 */
		resp->s11_mme_gtpc_teid = (rel_acc_ber_req_t->context)->s11_mme_gtpc_teid;
		resp->s11_mme_gtpc_ipv4 = (rel_acc_ber_req_t->context)->s11_mme_gtpc_ipv4;
		resp->s11_sgw_gtpc_teid = (rel_acc_ber_req_t->context)->s11_sgw_gtpc_teid;
		resp->sequence = rel_acc_ber_req_t->header.teid.has_teid.seq;
		resp->msg_type = GTP_RELEASE_ACCESS_BEARERS_REQ;
		resp->state = SESS_MOD_REQ_SNT_STATE;

		uint8_t pfcp_msg[size]={0};
		int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

		pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
		header->message_len = htons(encoded - 4);

		if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 )
			printf("Error sending: %i\n",errno);
		else {
			cp_stats.session_modification_req_sent++;
			get_current_time(cp_stats.session_modification_req_sent_time);
		}
		/* Update UE State */
		ret = update_ue_state(resp->s11_sgw_gtpc_teid,
				SESS_MOD_REQ_SNT_STATE);
		if (ret < 0) {
			fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
		}
	}
	return 0;
}
