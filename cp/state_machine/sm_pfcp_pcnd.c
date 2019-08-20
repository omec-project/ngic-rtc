/*
 * Copyright (c) 2019 Sprint
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

#include "cp.h"
#include "gtpv2c.h"
#include "sm_pcnd.h"
#include "cp_stats.h"
#include "debug_str.h"
#include "pfcp_util.h"
#include "pfcp_messages_decoder.h"

#ifdef C3PO_OSS
#include "cp_config.h"
#endif /* C3PO_OSS */

extern struct cp_stats_t cp_stats;
extern struct sockaddr_in upf_pfcp_sockaddr;

static uint8_t
pcnd_check(pfcp_header_t *pfcp_header, int bytes_rx)
{
	RTE_SET_USED(pfcp_header);
	RTE_SET_USED(bytes_rx);
	/* int ret = 0; */
	/* TODO: Precondition of PFCP message need to handle later on. ]*/

	return 0;

}

uint8_t
pfcp_pcnd_check(uint8_t *pfcp_rx, msg_info *msg, int bytes_rx)
{
	int ret = 0;
	int decoded = 0;

	pfcp_header_t *pfcp_header = (pfcp_header_t *) pfcp_rx;

	if ((ret = pcnd_check(pfcp_header, bytes_rx)) != 0)
		return ret;

	msg->msg_type = pfcp_header->message_type;

	switch(msg->msg_type) {
	case PFCP_ASSOCIATION_SETUP_RESPONSE: {
			/*Decode the received msg and stored into the struct. */
			decoded = decode_pfcp_assn_setup_rsp_t(pfcp_rx,
						&msg->pfcp_msg.pfcp_ass_resp);

			clLog(sxlogger, eCLSeverityDebug, "Decoded bytes [%d]\n", decoded);

			if(msg->pfcp_msg.pfcp_ass_resp.cause.cause_value != REQUESTACCEPTED){

				clLog(sxlogger, eCLSeverityDebug,
						"Cause received  Association response is %d\n",
						msg->pfcp_msg.pfcp_ass_resp.cause.cause_value);

				/* TODO: Add handling to send association to next upf
				 * for each buffered CSR */
				return -1;
			}

			cp_stats.sgwu_status = 1;
			cp_stats.pgwu_status = 1;
			cp_stats.association_setup_resp_acc_rcvd++;
			get_current_time(cp_stats.association_setup_resp_acc_rcvd_time);

			memcpy(&msg->upf_ipv4.s_addr,
					&msg->pfcp_msg.pfcp_ass_resp.node_id.node_id_value,
					IPV4_SIZE);

			/* Init rule tables of user-plane */
			upf_pfcp_sockaddr.sin_addr.s_addr = msg->upf_ipv4.s_addr;
			init_dp_rule_tables();

			upf_context_t *upf_context = NULL;

			/*Retrive association state based on UPF IP. */
			ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));
			if (ret == 0) {
				msg->state = upf_context->state;
			} else {
				fprintf(stderr, "%s: Entry not Found Msg_Type:%u, UPF IP:%u, Error_no:%d\n",
						__func__, msg->msg_type, msg->upf_ipv4.s_addr, ret);
				return -1;
			}

			/*Set the appropriate event type.*/
			msg->event = PFCP_ASSOC_SETUP_RESP_RCVD_EVNT;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:PFCP_ASSOCIATION_SETUP_RESPONSE[%u], UPF_IP:%u, "
					"State:%s, Event:%s\n",
					__func__, msg->msg_type, msg->upf_ipv4.s_addr,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case PFCP_SESSION_ESTABLISHMENT_RESPONSE: {
			/*Decode the received msg and stored into the struct. */
			decoded = decode_pfcp_sess_estab_rsp_t(pfcp_rx,
											&msg->pfcp_msg.pfcp_sess_est_resp);
			clLog(sxlogger, eCLSeverityDebug, "DEOCED bytes in Sess Estab Resp is %d\n",
					 decoded);

			if(msg->pfcp_msg.pfcp_sess_est_resp.cause.cause_value !=
					REQUESTACCEPTED){

				clLog(sxlogger, eCLSeverityDebug, "Cause received Est response is %d\n",
						msg->pfcp_msg.pfcp_sess_est_resp.cause.cause_value);
			}
			cp_stats.session_establishment_resp_acc_rcvd++;
			get_current_time(cp_stats.session_establishment_resp_acc_rcvd_time);

			/*Retrive Session state. */
			if ((ret = get_sess_state(msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid)) > 0) {
				msg->state = ret;
			} else {
				fprintf(stderr, "%s: Session entry not found Msg_Type:%u, Sess ID:%lu, Error_no:%d\n",
						__func__, msg->msg_type,
						msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid, ret);
				return -1;
			}

			/*Set the appropriate event type.*/
			msg->event = PFCP_SESS_EST_RESP_RCVD_EVNT;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:PFCP_SESSION_ESTABLISHMENT_RESPONSE[%u], Seid:%lu, "
					"State:%s, Event:%s\n",
					__func__, msg->msg_type, msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case PFCP_SESSION_MODIFICATION_RESPONSE: {
			/*Decode the received msg and stored into the struct. */
			decoded = decode_pfcp_sess_mod_rsp_t(pfcp_rx,
					&msg->pfcp_msg.pfcp_sess_mod_resp);

			clLog(sxlogger, eCLSeverityDebug, "DECODED bytes in Sess Modify Resp is %d\n",
					decoded);

			/*Validate the modification is accepted or not. */
			if(msg->pfcp_msg.pfcp_sess_mod_resp.cause.cause_value !=
					REQUESTACCEPTED){
				clLog(sxlogger, eCLSeverityDebug, "Cause received Modify response is %d\n",
						msg->pfcp_msg.pfcp_sess_mod_resp.cause.cause_value);
				return -1;
			}
			cp_stats.session_modification_resp_acc_rcvd++;
			get_current_time(cp_stats.session_modification_resp_acc_rcvd_time);

			/*Retrive Session state. */
			if ((ret = get_sess_state(
							msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid)) > 0) {
				msg->state = ret;
			} else {
				fprintf(stderr, "%s: Session entry not found Msg_Type:%u,"
						"Sess ID:%lu, Error_no:%d\n",
						__func__, msg->msg_type,
						msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, ret);
				return -1;
			}

			/*Set the appropriate event type.*/
			msg->event = PFCP_SESS_MOD_RESP_RCVD_EVNT;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:PFCP_SESSION_MODIFICATION_RESPONSE[%u], Seid:%lu, "
					"State:%s, Event:%s\n",
					__func__, msg->msg_type,
					msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case PFCP_SESSION_DELETION_RESPONSE: {
			/* Decode pfcp session delete response*/
			decoded = decode_pfcp_sess_del_rsp_t(pfcp_rx, &msg->pfcp_msg.pfcp_sess_del_resp);

					clLog(sxlogger, eCLSeverityDebug, "DECODED bytes in Sess Del Resp is %d\n",
					decoded);

			if(msg->pfcp_msg.pfcp_sess_del_resp.cause.cause_value != REQUESTACCEPTED){

				clLog(sxlogger, eCLSeverityCritical, "Cause received Del response is %d\n",
						msg->pfcp_msg.pfcp_sess_del_resp.cause.cause_value);

			}

			cp_stats.session_deletion_resp_acc_rcvd++;
			get_current_time(cp_stats.session_deletion_resp_acc_rcvd_time);

			/*Retrive Session state. */
			if ((ret = get_sess_state(
							msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid)) > 0) {
				msg->state = ret;
			} else {
				fprintf(stderr, "%s: Session entry not found Msg_Type:%u, "
						"Sess ID:%lu, Error_no:%d\n",
						__func__, msg->msg_type,
						msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid, ret);
				return -1;
			}

			/*Set the appropriate event type.*/
			msg->event = PFCP_SESS_DEL_RESP_RCVD_EVNT ;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:PFCP_SESSION_DELETION_RESPONSE[%u], Seid:%lu, "
					"State:%s, Event:%s\n",
					__func__, msg->msg_type,
					msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case PFCP_SESSION_REPORT_REQUEST: {
			/*Decode the received msg and stored into the struct. */
			decoded = decode_pfcp_sess_rpt_req_t(pfcp_rx,
							&msg->pfcp_msg.pfcp_sess_rep_req);

			clLog(sxlogger, eCLSeverityDebug, "DEOCED bytes in Sess Report Request is %d\n",
					decoded);

			/*Retrive Session state. */
			if ((ret = get_sess_state(
							msg->pfcp_msg.pfcp_sess_rep_req.header.seid_seqno.has_seid.seid)) > 0) {
				msg->state = ret;
			} else {
				fprintf(stderr, "%s: Session entry not found Msg_Type:%u, Sess ID:%lu, Error_no:%d\n",
						__func__, msg->msg_type,
						msg->pfcp_msg.pfcp_sess_rep_req.header.seid_seqno.has_seid.seid, ret);
				return -1;
			}

			/*Set the appropriate event type.*/
			msg->event = PFCP_SESS_RPT_REQ_RCVD_EVNT;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:PFCP_SESSION_REPORT_REQUEST[%u], Seid:%lu, "
					"State:%s, Event:%s\n",
					__func__, msg->msg_type,
					msg->pfcp_msg.pfcp_sess_rep_req.header.seid_seqno.has_seid.seid,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	default:
			/* Retrive Session state. */
			if ((ret = get_sess_state(pfcp_header->seid_seqno.has_seid.seid)) > 0) {
				msg->state = ret;
			} else {
				msg->state = NONE_STATE;
			}

			msg->event = NONE_EVNT;

			fprintf(stderr, "%s::process_msgs-"
					"\n\tcase: spgw_cfg= %d;"
					"\n\tReceived unprocessed PFCP Message_Type:%u"
					"... Discarding\n", __func__, spgw_cfg, msg->msg_type);
			return -1;
	}

	return 0;
}
