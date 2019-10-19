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

#include "gtpv2c.h"
#include "sm_pcnd.h"
#include "cp_stats.h"
#include "debug_str.h"
#include "pfcp_util.h"
#include "gtpv2c_error_rsp.h"

#ifdef C3PO_OSS
#include "cp_config.h"
#endif /* C3PO_OSS */

#ifdef USE_REST
#include "main.h"
#endif

pfcp_config_t pfcp_config;
extern struct cp_stats_t cp_stats;

uint8_t
gtpc_s5s8_pcnd_check(gtpv2c_header_t *gtpv2c_rx, msg_info *msg, int bytes_rx)
{
	int ret = 0;
	ue_context *context = NULL;

	msg->msg_type = gtpv2c_rx->gtpc.message_type;

	switch(msg->msg_type) {
	case GTP_CREATE_SESSION_REQ: {
			if ((ret = decode_check_csr(gtpv2c_rx, &msg->gtpc_msg.csr)) != 0)
				return ret;
			}
			break;

		/*case GTP_MODIFY_BEARER_REQ:
			if((ret = decode_mod_bearer_req((uint8_t *) gtpv2c_rx,
							&msg->s11_msg.mbr) == 0)) {
				return ret;
			}
			break;

		case GTP_DELETE_SESSION_REQ:
			ret = decode_del_sess_req((uint8_t *) gtpv2c_rx, &msg->s11_msg.dsr);
			if (ret == 0){
				return -1;
			}*/
	}

	if ((ret = gtpv2c_pcnd_check(gtpv2c_rx, bytes_rx)) != 0){
		switch(msg->msg_type){

			case GTP_CREATE_SESSION_REQ:
				cs_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				break;

			case GTP_DELETE_SESSION_REQ:
				ds_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			    break;
			case GTP_MODIFY_BEARER_REQ:
				mbr_error_response(msg, ret, spgw_cfg != PGWC? S11_IFACE : S5S8_IFACE);
				break;
		}
		return ret;
	}

	switch(msg->msg_type) {

	case GTP_CREATE_SESSION_REQ: {

			msg->proc = get_procedure(msg);
			if (INITIAL_PDN_ATTACH_PROC == msg->proc) {
				/* VS: Set the initial state for initial PDN connection */
#ifdef GX_BUILD
				msg->state = PGWC_NONE_STATE;
#else
				msg->state = SGWC_NONE_STATE;
#endif /* GX_BUILD */
			} else if (SGW_RELOCATION_PROC == msg->proc) {
				/* SGW Relocation */
				msg->state = CONNECTED_STATE;
			} else {
				/* S1 handover  */
			}

			msg->event = CS_REQ_RCVD_EVNT;

			/*cli_logic --> when CSR received from SGWC add it as a peer*/
			add_node_conn_entry(ntohl(msg->gtpc_msg.csr.sender_fteid_ctl_plane.ipv4_address),
								S5S8_PGWC_PORT_ID);

			clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_CREATE_SESSION_RSP: {
			/*TODO: This part will remove after getting libgtpv2c support on S5S8.*/
			/*Parse the CS Resp received msg from PGWC and stored into the struct. */
			/*ret = parse_sgwc_s5s8_create_session_response(gtpv2c_rx,
			 *		&msg->s5s8_msg.csr_resp);
			 *if (ret)
			 *	return ret;*/

			/* Remove after libgtpv2 support */
			/* VG: msg->s5s8_msg.gtpv2c_rx = *gtpv2c_rx; */

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			/* Retrive UE Context */
			if (get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				cs_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
																		  S5S8_IFACE);
				return -1;
			}

			msg->state = context->state;
			msg->proc = context->proc;

			/*Set the appropriate event type.*/
			msg->event = CS_RESP_RCVD_EVNT;

			clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_DELETE_SESSION_REQ: {
			/* Decode delete session request */
			//ret = decode_delete_session_request_t((uint8_t *) gtpv2c_rx,
			//		&msg->gtpc_msg.dsr);
			//if (ret < 0)
			//	return -1;

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			msg->proc = get_procedure(msg);
			if (DETACH_PROC == msg->proc) {
				if (update_ue_proc(gtpv2c_rx->teid.has_teid.teid,
							msg->proc) != 0) {
					return -1;
				}

				/* Retrive ue context and set state and proc */
				if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
					ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, S5S8_IFACE);
					return -1;
				}

				msg->state = context->state;
			}

			/*Set the appropriate event type.*/
			msg->event = DS_REQ_RCVD_EVNT;

			clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_DELETE_SESSION_RSP: {
			/* Decode delete session response */
			//ret = decode_delete_session_response_t((uint8_t *) gtpv2c_rx,
			//		&msg->gtpc_msg.dsr);
			//if (ret < 0)
			//	return -1;
			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);
			/* Retrive ue context and set state and proc */
			if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, S11_IFACE);
				return -1;
			}

			msg->state = context->state;
			msg->proc = context->proc;

			/*Set the appropriate event type.*/
			msg->event = DS_RESP_RCVD_EVNT;

			clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_MODIFY_BEARER_REQ: {

			/* Decode MBR request
			Get UE Context to set state and proc
			and set event to MB_REQ_RCVD_EVNT; */

			if((ret = decode_mod_bearer_req((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.mbr) == 0)) {
					return ret;
			}

			msg->proc = get_procedure(msg);
			if (update_ue_proc(gtpv2c_rx->teid.has_teid.teid,
							msg->proc) != 0) {
					return -1;
			}
			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);//0xd0ffee;

			if(SGW_RELOCATION_PROC == msg->proc) {
				if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
					return -1;
				}
				msg->state = context->state;
	       // msg->proc = context->proc;
			}

	        msg->event = MB_REQ_RCVD_EVNT;

		break;

	}

	case GTP_MODIFY_BEARER_RSP: {

			/* Received MBR response from PGWC
			Get UE Context and set state and proc
			Set event to MB_RESP_RCVD_EVNT; */

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
			                 return -1;
			}

			msg->state = context->state;
			msg->proc = context->proc;
			msg->event = MB_RESP_RCVD_EVNT;

		break;
	}

	default:
			/*If Event is not supported then we will called default handler. */
			/*Retrive UE state. */
			if ((get_ue_context(ntohl(gtpv2c_rx->teid.has_teid.teid), &context)) != 0) {
			     msg->proc = NONE_PROC;
#ifdef GX_BUILD
			     msg->state = PGWC_NONE_STATE;
#else
			     msg->state = SGWC_NONE_STATE;
#endif /* GX_BUILD */
			} else {
				msg->state = context->state;
				msg->proc = context->proc;
			}

			msg->event = NONE_EVNT;

			fprintf(stderr, "%s::process_msgs-"
					"\n\tcase: SAEGWC::spgw_cfg= %d;"
					"\n\tReceived unprocessed GTPv2c Message Type: "
					"%s (%u 0x%x)... Discarding\n", __func__,
					spgw_cfg, gtp_type_str(gtpv2c_rx->gtpc.message_type),
					gtpv2c_rx->gtpc.message_type,
					gtpv2c_rx->gtpc.message_type);
			return -1;
	}

	return 0;
}
