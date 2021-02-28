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
#include "cp_config.h"
#include "sm_struct.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "cdr.h"
#include "pfcp_enum.h"
#ifdef CP_BUILD
#include "cp_timer.h"
#endif /* CP_BUILD */
#define UPD_PARAM_HEADER_SIZE (4)
#define NR_RAT_TYPE           (10)
#define RESET_TEID            (0)
#define RAT_TYPE_VALUE        (0)

extern int pfcp_fd;

int
process_release_access_bearer_request(rel_acc_ber_req_t *rel_acc_ber_req, uint8_t proc)
{
	pdn_connection *pdn = NULL;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	struct resp_info *resp = NULL;
	uint32_t seq = 0;
	int ret = 0;
	uint8_t pdn_counter = 0;
	int ebi_index = 0;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &rel_acc_ber_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	if(rel_acc_ber_req->indctn_flgs.header.len != 0) {
		context->indication_flag.arrl = rel_acc_ber_req->indctn_flgs.indication_arrl;
	}

	for(int itr_pdn = 0; itr_pdn < MAX_BEARERS; itr_pdn++) {
		pdn = context->pdns[itr_pdn];
		pfcp_sess_mod_req.update_far_count = 0;
		if(pdn) {
			for(int itr_bearer = 0 ; itr_bearer < MAX_BEARERS; itr_bearer++) {
				bearer = pdn->eps_bearers[itr_bearer];
				if(bearer) {
					bearer->s1u_enb_gtpu_teid = RESET_TEID;
					for(uint8_t itr_pdr = 0; itr_pdr < bearer->pdr_count; itr_pdr++) {
						if(bearer->pdrs[itr_pdr] != NULL) {
							if(bearer->pdrs[itr_pdr]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) {
								bearer->pdrs[itr_pdr]->far.actions.buff = TRUE;
								bearer->pdrs[itr_pdr]->far.actions.nocp = TRUE;
								bearer->pdrs[itr_pdr]->far.actions.forw = FALSE;
								set_update_far(&(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count]),
									&bearer->pdrs[itr_pdr]->far);
								uint16_t len = 0;
								len += set_upd_forwarding_param(&(pfcp_sess_mod_req.update_far
											[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms));
								len += UPD_PARAM_HEADER_SIZE;
								pfcp_sess_mod_req.update_far
									[pfcp_sess_mod_req.update_far_count].header.len += len;

								pfcp_sess_mod_req.update_far
									[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
									bearer->s1u_enb_gtpu_teid;
								pfcp_sess_mod_req.update_far
									[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
									bearer->s1u_enb_gtpu_ipv4.s_addr;
								pfcp_sess_mod_req.update_far
									[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
									GTPV2C_IFTYPE_S1U_ENODEB_GTPU;
								pfcp_sess_mod_req.update_far_count++;
								break;
							}
						}
					}
				}
			}
			context->sequence =
				rel_acc_ber_req->header.teid.has_teid.seq;

			set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn->seid, pfcp_config.pfcp_ip.s_addr);

			seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);
			set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header), PFCP_SESSION_MODIFICATION_REQUEST,
					HAS_SEID, seq, context->cp_mode);
			pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

			uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
			int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
			pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
			header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

			if(pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to send"
				"PFCP Session Modification Request %i\n", LOG_VALUE, errno);
			}
			else {
				if (get_sess_entry(pdn->seid, &resp) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
					return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
				}

				reset_resp_info_structure(resp);

				ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}

				add_pfcp_if_timer_entry(rel_acc_ber_req->header.teid.has_teid.teid,
						&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);

				resp->msg_type = GTP_RELEASE_ACCESS_BEARERS_REQ;
				resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
				resp->proc = proc;
				memcpy(&resp->gtpc_msg.rel_acc_ber_req, rel_acc_ber_req, sizeof(rel_acc_ber_req_t));
				resp->cp_mode = context->cp_mode;
				pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
				context->pfcp_sess_count++;
			}
			pdn_counter++;
			if(pdn_counter == context->num_pdns) {
				for(uint8_t i =0; i< rel_acc_ber_req->second_rat_count; i++) {

					if(rel_acc_ber_req->secdry_rat_usage_data_rpt[i].irpgw == PRESENT) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IRPGW Flag is SET in the"
								" release access bearer request not expected from MME\n", LOG_VALUE);
					}
					if(rel_acc_ber_req->secdry_rat_usage_data_rpt[i].irsgw == PRESENT) {

						uint8_t trigg_buff[] = "secondary_rat_usage";
						cdr second_rat_data = {0};
						struct timeval unix_start_time;
						struct timeval unix_end_time;

						second_rat_data.cdr_type = CDR_BY_SEC_RAT;
						second_rat_data.change_rat_type_flag = PRESENT;
						/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
						second_rat_data.rat_type = (rel_acc_ber_req->secdry_rat_usage_data_rpt[i].secdry_rat_type ==
								RAT_TYPE_VALUE) ? NR_RAT_TYPE : RAT_TYPE_VALUE;
						second_rat_data.bearer_id = rel_acc_ber_req->secdry_rat_usage_data_rpt[i].ebi;
						second_rat_data.seid = pdn->seid;
						second_rat_data.imsi = pdn->context->imsi;
						second_rat_data.start_time = rel_acc_ber_req->secdry_rat_usage_data_rpt[i].start_timestamp;
						second_rat_data.end_time = rel_acc_ber_req->secdry_rat_usage_data_rpt[i].end_timestamp;
						second_rat_data.data_volume_uplink = rel_acc_ber_req->secdry_rat_usage_data_rpt[i].usage_data_ul;
						second_rat_data.data_volume_downlink = rel_acc_ber_req->secdry_rat_usage_data_rpt[i].usage_data_dl;

						ntp_to_unix_time(&second_rat_data.start_time, &unix_start_time);
						ntp_to_unix_time(&second_rat_data.end_time, &unix_end_time);

						second_rat_data.sgw_addr.s_addr = pfcp_config.pfcp_ip.s_addr;
						second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
						second_rat_data.data_start_time = 0;
						second_rat_data.data_end_time = 0;
						second_rat_data.total_data_volume = second_rat_data.data_volume_uplink + second_rat_data.data_volume_downlink;

						memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));
						if(generate_cdr_info(&second_rat_data) != 0) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT" failed to generate CDR\n",
									LOG_VALUE);
						}
					}
				}
				break;
			}
		}
	}
	return 0;
}
void
set_release_access_bearer_response(gtpv2c_header_t *gtpv2c_tx, pdn_connection *pdn) {

	release_access_bearer_resp_t rel_acc_ber_rsp = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *) &rel_acc_ber_rsp, GTP_RELEASE_ACCESS_BEARERS_RSP,
				 pdn->context->s11_mme_gtpc_teid, pdn->context->sequence, NOT_PIGGYBACKED);

	set_cause_accepted(&rel_acc_ber_rsp.cause, IE_INSTANCE_ZERO);

	uint16_t msg_len = 0;
	msg_len = encode_release_access_bearers_rsp(&rel_acc_ber_rsp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

}
