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
#include "debug_str.h"
#include "dp_ipc_api.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include"cp_config.h"
#include "cp_timer.h"

extern int pfcp_fd;
extern int pfcp_fd_v6;
extern struct cp_stats_t cp_stats;
extern pfcp_config_t config;
extern int clSystemLog;

/**
 * @brief  : callback to handle downlink data notification messages from the
 *           data plane
 * @param  : msg_payload
 *           message payload received by control plane from the data plane
 * @return : 0 inicates success, error otherwise
 */
int
cb_ddn(struct msgbuf *msg_payload)
{
	int ret = ddn_by_session_id(msg_payload->msg_union.sess_entry.sess_id, NULL);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error on DDN Handling %s: (%d) %s\n", LOG_VALUE,
				gtp_type_str(ret), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
	}
	return ret;
}

int
ddn_by_session_id(uint64_t session_id, pdr_ids *pfcp_pdr_id )
{
	uint8_t tx_buf[MAX_GTPV2C_UDP_LEN] = { 0 };
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *) tx_buf;
	uint32_t sgw_s11_gtpc_teid = UE_SESS_ID(session_id);
	ue_context *context = NULL;
	pdr_ids *pfcp_pdr = NULL;
	uint32_t sequence = 0;
	int ebi = 0;
	int ebi_index = 0;
	int ret = 0;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"sgw_s11_gtpc_teid:%u\n",
			LOG_VALUE, sgw_s11_gtpc_teid);

	ret = rte_hash_lookup_data(buffered_ddn_req_hash,
				(const void *) &session_id,
				(void **) &pfcp_pdr);

	if(ret < 0){
		ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				(const void *) &sgw_s11_gtpc_teid,
				(void **) &context);

		if (ret < 0 || !context)
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

		sequence = generate_seq_number();


		ret = create_downlink_data_notification(context,
				UE_BEAR_ID(session_id),
				sequence,
				gtpv2c_tx, pfcp_pdr_id);

		if (ret)
			return ret;

		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
		}

		uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
									+ sizeof(gtpv2c_tx->gtpc);

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr, SENT);

		ebi = UE_BEAR_ID(session_id);
		ebi_index = GET_EBI_INDEX(ebi);

		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI Index\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		add_gtpv2c_if_timer_entry(sgw_s11_gtpc_teid, &s11_mme_sockaddr, tx_buf,
				payload_length, ebi_index, S11_IFACE,
				context->cp_mode);

		++cp_stats.ddn;

		/* Allocate memory*/

		pfcp_pdr = rte_zmalloc_socket(NULL, sizeof(thrtle_count),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(pfcp_pdr  == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for pfcp_pdr_id structure, Error: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));

			return -1;
		}

		if(pfcp_pdr_id != NULL) {
			memcpy(pfcp_pdr, pfcp_pdr_id, sizeof(pdr_ids));

		if(pfcp_pdr_id->ddn_buffered_count == 0)
			pfcp_pdr->ddn_buffered_count = 0;
		}
		/*Add session ids and pdr ids into buffered ddn request hash */
		ret = rte_hash_add_key_data(buffered_ddn_req_hash,
				(const void *)&session_id, pfcp_pdr);

		if(ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"Unable to add entry in buffered ddn request hash\n",
					LOG_VALUE);
			rte_free(pfcp_pdr);
			pfcp_pdr = NULL;
			return -1;
		}
	} else {
		pfcp_pdr->ddn_buffered_count += 1;
	}
	return 0;
}

int
create_downlink_data_notification(ue_context *context, uint8_t eps_bearer_id,
		uint32_t sequence, gtpv2c_header_t *gtpv2c_tx, pdr_ids *pdr)
{
	uint8_t i = 1;
	uint8_t j = 0;
	pdn_connection *pdn = NULL;
	dnlnk_data_notif_t dnl_data_notify = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *)&dnl_data_notify, GTP_DOWNLINK_DATA_NOTIFICATION,
				context->s11_mme_gtpc_teid, sequence, 0);
	int ebi_index = GET_EBI_INDEX(eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}
	eps_bearer *bearer = context->eps_bearers[ebi_index];
	if (bearer == NULL)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	pdn = bearer->pdn;

	if(pdr == NULL){
		set_ebi(&dnl_data_notify.eps_bearer_id, IE_INSTANCE_ZERO, bearer->eps_bearer_id);
		set_ar_priority(&dnl_data_notify.alloc_reten_priority, IE_INSTANCE_ZERO, bearer);

	}else {
		for(uint8_t itr = 0; itr <MAX_BEARERS; itr++){
			if(pdn->eps_bearers[itr] != NULL){
				bearer = pdn->eps_bearers[itr];
				if(bearer->pdrs[i]->rule_id == pdr->pdr_id[j]){
					set_ebi(&dnl_data_notify.eps_bearer_id, IE_INSTANCE_ZERO, bearer->eps_bearer_id);
					set_ar_priority(&dnl_data_notify.alloc_reten_priority, IE_INSTANCE_ZERO, bearer);
					j++;
					pdr->pdr_count--;
				}
			}
		}
	}
	uint16_t msg_len = 0;
	msg_len = encode_dnlnk_data_notif(&dnl_data_notify, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

	return 0;
}

void
fill_send_pfcp_sess_report_resp(ue_context *context, uint8_t sequence,
		pdn_connection *pdn, uint16_t dl_buf_sugg_pkt_cnt, bool dldr_flag)
{
	int encoded = 0, ret = 0;
	pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};

	/*Fill and send pfcp session report response. */
	fill_pfcp_sess_report_resp(&pfcp_sess_rep_resp,
			sequence, context->cp_mode);

	if (dldr_flag) {
		/* Send Default DL Buffering Suggested Packet Count */
		if (NOT_PRESENT == pdn->is_default_dl_sugg_pkt_cnt_sent) {

			pdn->is_default_dl_sugg_pkt_cnt_sent = PRESENT;
			dl_buf_sugg_pkt_cnt = config.dl_buf_suggested_pkt_cnt;
		}

		/* Send Update BAR IE */
		if ((NOT_PRESENT != dl_buf_sugg_pkt_cnt) && (pdn != NULL)) {


			pdn->bar.dl_buf_suggstd_pckts_cnt.pckt_cnt_val = dl_buf_sugg_pkt_cnt;
			set_update_bar_sess_rpt_rsp(&(pfcp_sess_rep_resp.update_bar), &pdn->bar);

		}

	}
	pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	encoded =  encode_pfcp_sess_rpt_rsp_t(&pfcp_sess_rep_resp, pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	/* UPF ip address  */
	ret = set_dest_address(pdn->upf_ip, &upf_pfcp_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr,ACC) < 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in REPORT REPONSE "
			"message: %i\n", LOG_VALUE, errno);
		return;
	}

}

pdr_ids *
delete_buff_ddn_req(uint64_t sess_id)
{
	int ret = 0;
	pdr_ids *pfcp_pdr_id = NULL;
	ret = rte_hash_lookup_data(buffered_ddn_req_hash,
				(const void *) &sess_id,
				(void **) &pfcp_pdr_id);

	if(ret >= 0){
		ret = rte_hash_del_key(buffered_ddn_req_hash, (const void *)&sess_id);
		if(ret < 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete Entry"
					"from buffered ddn request hash\n", LOG_VALUE);
			return pfcp_pdr_id;
		}
	}else{
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"No session entry buffered"
			    "\n", LOG_VALUE);
		return NULL;
	}
	return pfcp_pdr_id;
}

int
process_ddn_ack(dnlnk_data_notif_ack_t *ddn_ack)
{
	int ebi_index = 0;
	int dl_delay_value = 0;
	uint16_t dl_buf_sugg_pkt_cnt = 0;
	int delay_value = 0;
	struct resp_info *resp = NULL;
	pdn_connection *pdn = NULL;
	ue_context *context = NULL;
	pdr_ids *pfcp_pdr_id = NULL;

	if (get_ue_context(ddn_ack->header.teid.has_teid.teid, &context) != 0){

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error:ue context not found\n", LOG_VALUE);
		return -1;
	}
	/* Lookup entry in hash table on the basis of session id*/
	for (uint32_t idx=0; idx <MAX_BEARERS; idx++) {
		pdn = context->pdns[idx];
		if(pdn != NULL) {
			ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
			break;
		}
	}

	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	/* Remove session Entry from buffered ddn request hash */
	pfcp_pdr_id = delete_buff_ddn_req(pdn->seid);
	if(pfcp_pdr_id != NULL) {
			if(pfcp_pdr_id->ddn_buffered_count > 0) {
				pfcp_pdr_id->ddn_buffered_count -= 1;
				ddn_by_session_id(pdn->seid, pfcp_pdr_id);
			}
		rte_free(pfcp_pdr_id);
		pfcp_pdr_id = NULL;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
			return -1;
	}

	/* Update the session state */
	resp->msg_type = GTP_DOWNLINK_DATA_NOTIFICATION_ACK;
	resp->state = IDEL_STATE;

	/* Delete the timer entry for UE Level timer if already present */
	ddn_ack->data_notif_delay.delay_value +=
			delete_ddn_timer_entry(timer_by_teid_hash, ddn_ack->header.teid.has_teid.teid, ddn_by_seid_hash);

	if(ddn_ack->data_notif_delay.header.len){
		if(ddn_ack->data_notif_delay.delay_value > 0){
			/* Start UE Level Timer with the assgined delay*/
			start_ddn_timer_entry(timer_by_teid_hash, pdn->seid,
					(ddn_ack->data_notif_delay.delay_value * 50),
										ddn_timer_callback);
		}
	}

	/* Set dl buffering timer */
	if(ddn_ack->dl_buffering_dur.timer_value){

		/* REVIEW: Extend the timer if timer entry is present. */
		/* Delete the timer entry for UE level timer if already present */
		delete_ddn_timer_entry(dl_timer_by_teid_hash,
				ddn_ack->header.teid.has_teid.teid,
				pfcp_rep_by_seid_hash);

		dl_delay_value = ddn_ack->dl_buffering_dur.timer_value;

		/* Depending upon timer uint value DL Buffering Duration Timer value needs to be multiplied */
		if(ddn_ack->dl_buffering_dur.timer_unit == ZERO){
			dl_delay_value = dl_delay_value * TWOSEC;
		} else if(ddn_ack->dl_buffering_dur.timer_unit == ONE){
			dl_delay_value = dl_delay_value * ONEMINUTE;
		} else if(ddn_ack->dl_buffering_dur.timer_unit == TWO){
			dl_delay_value = dl_delay_value * TENMINUTE;
		} else if(ddn_ack->dl_buffering_dur.timer_unit == THREE){
			dl_delay_value = dl_delay_value * ONEHOUR;
		} else if(ddn_ack->dl_buffering_dur.timer_unit == FOUR){
			dl_delay_value = dl_delay_value * TENHOUR;
		} else if(ddn_ack->dl_buffering_dur.timer_unit == SEVEN){
			dl_delay_value = dl_delay_value * ONEMINUTE;
		} else {
			/* Here the value zero is for infinity*/
			dl_delay_value = ddn_ack->dl_buffering_dur.timer_value * 0;
		}

		/* Starts the timer to buffer the pfcp_session_report_request */
		start_ddn_timer_entry(dl_timer_by_teid_hash, pdn->seid, dl_delay_value, dl_buffer_timer_callback);

		/* Set suggested buffered packet count*/
		if(ddn_ack->dl_buffering_suggested_pckt_cnt.header.len){
			dl_buf_sugg_pkt_cnt = ddn_ack->dl_buffering_suggested_pckt_cnt.int_nbr_val;
		} else {
			dl_buf_sugg_pkt_cnt = config.dl_buf_suggested_pkt_cnt;
		}
	}

	/* Set throttling factor timer */
	if(ddn_ack->dl_low_priority_traffic_thrtlng.header.len){
		/* Delete the timer entry if already present */
		set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_val +=
				delete_thrtle_timer(&context->s11_mme_gtpc_ip);

		delay_value = ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_val;

		/* Depending upon timer uint value throttling timer value needs to be multiplied */
		if(ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_unit == ZERO){
			delay_value = delay_value * TWOSEC;
		} else if(ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_unit == ONE){
			delay_value = delay_value * ONEMINUTE;
		} else if(ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_unit == TWO){
			delay_value = delay_value * TENMINUTE;
		} else if(ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_unit == THREE){
			delay_value = delay_value * ONEHOUR;
		} else if(ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_unit == FOUR){
			delay_value = delay_value * TENHOUR;
		} else if(ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_delay_unit == SEVEN){

			/* Here the value zero is used to indicated timer deactivation */
			delay_value = delay_value * 0;
		} else {
			delay_value = delay_value * ONEMINUTE;
		}

		/*spec 29.274,  8.85.1 Throttling information element */

		if((ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_factor) > 100){

			ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_factor = 0;
		}
		if(delay_value != 0){
			/* Start timer for throttling and also save throttling factor */
			start_throttle_timer(&context->s11_mme_gtpc_ip, delay_value,
									ddn_ack->dl_low_priority_traffic_thrtlng.thrtlng_factor);
		}
	}

	pdn->state = IDEL_STATE;
	if((context->pfcp_rept_resp_sent_flag == 0) || dl_buf_sugg_pkt_cnt ){
		fill_send_pfcp_sess_report_resp(context, resp->pfcp_seq, pdn, dl_buf_sugg_pkt_cnt, TRUE);
	}

	return 0;

}

int
send_pfcp_sess_mod_with_drop(ue_context *context)
{

	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	pdr_ids *pfcp_pdr_id = NULL;
	uint32_t seq = 0;
	int ret = 0;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	node_address_t node_value = {0};


	for(uint8_t itr_pdn = 0; itr_pdn < MAX_BEARERS; itr_pdn++){
		if(context->pdns[itr_pdn] != NULL) {
			pdn = context->pdns[itr_pdn];
				for(int itr_bearer = 0 ; itr_bearer < MAX_BEARERS; itr_bearer++) {
					bearer = pdn->eps_bearers[itr_bearer];
					if(bearer) {
						for(uint8_t itr_pdr = 0; itr_pdr < bearer->pdr_count; itr_pdr++) {
							if(bearer->pdrs[itr_pdr] != NULL) {
								if(bearer->pdrs[itr_pdr]->pdi.src_intfc.interface_value
										== SOURCE_INTERFACE_VALUE_CORE) {

									bearer->pdrs[itr_pdr]->far.actions.forw = FALSE;
									bearer->pdrs[itr_pdr]->far.actions.dupl = FALSE;
									bearer->pdrs[itr_pdr]->far.actions.nocp = FALSE;
									bearer->pdrs[itr_pdr]->far.actions.buff = FALSE;
									bearer->pdrs[itr_pdr]->far.actions.drop = TRUE;
									set_update_far(
											&(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count]),
											&bearer->pdrs[itr_pdr]->far);

									uint16_t len = 0;
									len += set_upd_forwarding_param(&(pfcp_sess_mod_req.update_far
												[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms),
												bearer->s1u_enb_gtpu_ip);

									len += UPD_PARAM_HEADER_SIZE;
									pfcp_sess_mod_req.update_far
										[pfcp_sess_mod_req.update_far_count].header.len += len;

									pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].\
										upd_frwdng_parms.outer_hdr_creation.teid =
										bearer->s1u_enb_gtpu_teid;

									ret = set_node_address(&pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].\
														upd_frwdng_parms.outer_hdr_creation.ipv4_address,
														pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.\
														update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv6_address,
														bearer->s1u_enb_gtpu_ip);
									if (ret < 0) {
										clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
											"IP address", LOG_VALUE);
									}

									pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].\
										upd_frwdng_parms.dst_intfc.interface_value =
										GTPV2C_IFTYPE_S1U_ENODEB_GTPU;
									pfcp_sess_mod_req.update_far_count++;
								}
							}
						}
					}
				}
			}
	}
	set_pfcpsmreqflags(&(pfcp_sess_mod_req.pfcpsmreq_flags));
	pfcp_sess_mod_req.pfcpsmreq_flags.drobu = TRUE;

	/*Filling Node ID for F-SEID*/
	if (pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV4) {
		uint8_t temp[IPV6_ADDRESS_LEN] = {0};
		ret = fill_ip_addr(config.pfcp_ip.s_addr, temp, &node_value);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

	} else if (pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV6) {

		ret = fill_ip_addr(0, config.pfcp_ip_v6.s6_addr, &node_value);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

	}
	/* Remove session Entry from buffered ddn request hash */
	pfcp_pdr_id = delete_buff_ddn_req(pdn->seid);
	if(pfcp_pdr_id != NULL) {
		rte_free(pfcp_pdr_id);
		pfcp_pdr_id = NULL;
	}
	set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn->seid, node_value);

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq, context->cp_mode);
	pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if(pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, SENT) < 0) {

		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to send"
				"PFCP Session Modification Request %i\n", LOG_VALUE, errno);

		return -1;
	}

	return 0;
}

int
process_ddn_failure(dnlnk_data_notif_fail_indctn_t *ddn_fail_ind)
{

	ue_context *context = NULL;
	int ret = 0;

	if(ddn_fail_ind->header.teid.has_teid.teid != 0){
		if (get_ue_context(ddn_fail_ind->header.teid.has_teid.teid, &context) != 0){

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error:ue context not found\n", LOG_VALUE);
			return -1;
		}

	} else {
		if(ddn_fail_ind->imsi.header.len){
			ret = rte_hash_lookup_data(ue_context_by_imsi_hash,
					&ddn_fail_ind->imsi.imsi_number_digits,
					(void **) &context);
			if(ret < 0){
				clLog(clSystemLog, eCLSeverityCritical,  LOG_FORMAT"Failed to get UE Context"
						"for imsi: %ld\n",LOG_VALUE, ddn_fail_ind->imsi.imsi_number_digits);
				return -1;
			}
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"There is no teid and no imsi present \n",
					LOG_VALUE);
			return -1;
		}
	}
	ret = send_pfcp_sess_mod_with_drop(context);
	if (ret){

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: while processing"
				" pfcp session modification request\n", LOG_VALUE);
	}

	return 0;
}
