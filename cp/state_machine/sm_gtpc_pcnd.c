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
#include "gtp_messages_decoder.h"
#include "gtpv2c_error_rsp.h"


#ifdef USE_REST
#include "main.h"
#endif

#ifdef C3PO_OSS
#include "cp_config.h"
#include "cp_adapter.h"
#endif /* C3PO_OSS */

pfcp_config_t pfcp_config;
extern struct cp_stats_t cp_stats;

uint8_t
gtpv2c_pcnd_check(gtpv2c_header_t *gtpv2c_rx, int bytes_rx)
{
	int ret = 0;

	if ((unsigned)bytes_rx !=
		 (ntohs(gtpv2c_rx->gtpc.message_len)
		 + sizeof(gtpv2c_rx->gtpc))
		) {
		ret = GTPV2C_CAUSE_INVALID_LENGTH;
		/* According to 29.274 7.7.7, if message is request,
		 * reply with cause = GTPV2C_CAUSE_INVALID_LENGTH
		 *  should be sent - ignoring packet for now
		 */
		fprintf(stderr, "GTPv2C Received UDP Payload:"
				"\n\t(%d bytes) with gtpv2c + "
				"header (%u + %lu) = %lu bytes\n",
				bytes_rx, ntohs(gtpv2c_rx->gtpc.message_len),
				sizeof(gtpv2c_rx->gtpc),
				ntohs(gtpv2c_rx->gtpc.message_len)
				+ sizeof(gtpv2c_rx->gtpc));
		return ret;
	}

	if(bytes_rx > 0){
		if(gtpv2c_rx->gtpc.version < GTP_VERSION_GTPV2C) {
			fprintf(stderr, "Discarding packet due to gtp version is not supported..");
			return GTPV2C_CAUSE_VERSION_NOT_SUPPORTED;
		}else if(gtpv2c_rx->gtpc.version > GTP_VERSION_GTPV2C){
			send_version_not_supported(spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE,
					gtpv2c_rx->teid.has_teid.seq);
			fprintf(stderr, "Discarding packet due to gtp version is not supported..");
			return GTPV2C_CAUSE_VERSION_NOT_SUPPORTED;
		}
	}
	return 0;

}

uint8_t
gtpc_pcnd_check(gtpv2c_header_t *gtpv2c_rx, msg_info *msg, int bytes_rx)
{
	int ret = 0;
	ue_context *context = NULL;
	msg->msg_type = gtpv2c_rx->gtpc.message_type;


	if ((ret = gtpv2c_pcnd_check(gtpv2c_rx, bytes_rx)) != 0){

		if (ret == GTPV2C_CAUSE_VERSION_NOT_SUPPORTED)
			return ret;

		switch(msg->msg_type) {

			case GTP_CREATE_SESSION_REQ:

				if(decode_create_sess_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.csr) != 0){
					cs_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
					process_error_occured_handler(&msg, NULL);
				}
				break;

			case GTP_CREATE_SESSION_RSP:

				if( decode_create_sess_rsp((uint8_t *)gtpv2c_rx,&msg->gtpc_msg.cs_rsp) != 0){
					cs_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
					process_error_occured_handler(&msg, NULL);
				}
				break;

			case GTP_DELETE_SESSION_REQ:

				if( decode_del_sess_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.dsr) != 0){
					ds_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				}
				break;

			case GTP_DELETE_SESSION_RSP:

				if( decode_del_sess_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.ds_rsp) != 0){
					ds_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				}
				break;

			case GTP_MODIFY_BEARER_REQ:

				if( decode_mod_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.mbr) != 0) {
					mbr_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				}
				break;
			case GTP_MODIFY_BEARER_RSP:

				if( decode_mod_bearer_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.mb_rsp) != 0) {
					mbr_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				}
				break;
			case GTP_CREATE_BEARER_REQ:

				if( decode_create_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.cb_req) != 0) {
					/* TODO for create bearer request error response */
				}
				break;
			case GTP_CREATE_BEARER_RSP:

				if( decode_create_bearer_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.cb_rsp) != 0) {
					/* TODO for create bearer response error response */
				}
				break;

		}
		return -1;

	}

	switch(msg->msg_type) {

		case GTP_CREATE_SESSION_REQ: {

			if ((ret = decode_check_csr(gtpv2c_rx, &msg->gtpc_msg.csr)) != 0){
				if(ret != -1)
					cs_error_response(msg, ret,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}

			/*CLI*/
			/*add entry of MME(if cp is SGWC) and SGWC (if cp PGWC)*/
			add_node_conn_entry(ntohl(msg->gtpc_msg.csr.sender_fteid_ctl_plane.ipv4_address),
										spgw_cfg != PGWC ? S11_SGW_PORT_ID : S5S8_PGWC_PORT_ID);
			msg->proc = get_procedure(msg);
			if (INITIAL_PDN_ATTACH_PROC == msg->proc) {
				/* VS: Set the initial state for initial PDN connection */
				/* VS: Make single state for all combination */
				if (pfcp_config.cp_type == SGWC) {
					/*Set the appropriate state for the SGWC */
					msg->state = SGWC_NONE_STATE;
				} else {
					/*Set the appropriate state for the SAEGWC and PGWC*/
#ifdef GX_BUILD
					msg->state = PGWC_NONE_STATE;
#else
					msg->state = SGWC_NONE_STATE;
#endif
				}
			} else if (SGW_RELOCATION_PROC == msg->proc) {
				/* SGW Relocation */
			} else {
				/* S1 handover  */
			}

			/*Set the appropriate event type.*/
			msg->event = CS_REQ_RCVD_EVNT;

			clLog(s11logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_CREATE_SESSION_RSP: {

			ret = decode_create_sess_rsp((uint8_t *)gtpv2c_rx, &msg->gtpc_msg.cs_rsp);
			if(!ret)
				return -1;
			if(msg->gtpc_msg.cs_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
				cs_error_response(msg, msg->gtpc_msg.cs_rsp.cause.cause_value,
						        spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}
			if (get_ue_context(msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid, &context) != 0)
			{
				cs_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}

			msg->state = context->state;
			msg->proc = context->proc;

			/*Set the appropriate event type.*/
			msg->event = CS_RESP_RCVD_EVNT;

			clLog(s11logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_MODIFY_BEARER_REQ: {
			/*Decode the received msg and stored into the struct. */
			if((ret = decode_mod_bearer_req((uint8_t *) gtpv2c_rx,
							&msg->gtpc_msg.mbr) == 0)) {
				return -1;
			}
			if(pfcp_config.cp_type == PGWC) {
				msg->proc = get_procedure(msg);

				gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);//0xd0ffee;


				if (update_ue_proc(gtpv2c_rx->teid.has_teid.teid,
							msg->proc) != 0) {
					mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							    spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}

				if(get_ue_context(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context) != 0) {
					mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							    spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}
				msg->state = context->state;
				msg->event = MB_REQ_RCVD_EVNT;
				context->proc = msg->proc;

			} else {
			/*Retrive UE state. */
			if(get_ue_context(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context) != 0) {

				mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							    spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}

			msg->state = context->state;
			msg->proc = context->proc;

			/*Set the appropriate event type.*/
			msg->event = MB_REQ_RCVD_EVNT;

			clLog(s11logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
			}
			break;
	}

	case GTP_MODIFY_BEARER_RSP: {
		if((ret = decode_mod_bearer_rsp((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.mb_rsp) == 0)) {
			return -1;
		}

		gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

		if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
			cs_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(&msg, NULL);

			return -1;
		}
		msg->state = context->state;
		msg->proc = context->proc;
		msg->event = MB_RESP_RCVD_EVNT;
		break;
	}

	case GTP_DELETE_SESSION_REQ: {
			/* Decode delete session request */

			ret = decode_del_sess_req((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.dsr);
			if (ret == 0)
				return -1;

			/* Retrive ue state and set in msg state and event */
			if(get_ue_context(msg->gtpc_msg.dsr.header.teid.has_teid.teid,
						&context) != 0) {
				ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}

			msg->proc = get_procedure(msg);
			if (DETACH_PROC == msg->proc) {
				if (update_ue_proc(msg->gtpc_msg.dsr.header.teid.has_teid.teid,
							msg->proc) != 0) {
				ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}


				msg->state = context->state;
			}

			/*Set the appropriate event type.*/
			msg->event = DS_REQ_RCVD_EVNT;

			clLog(s11logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));

		break;
	}

	case GTP_DELETE_SESSION_RSP: {

		ret = decode_del_sess_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.ds_rsp);
		if(ret == 0)
			return -1;
		if(get_ue_context(msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid, &context) != 0) {

			ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}

		if(msg->gtpc_msg.ds_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
			fprintf(stderr, "Cause Req Error : (%s:%d)msg type :%u, cause ie : %u \n", __func__, __LINE__,
					msg->msg_type, msg->gtpc_msg.ds_rsp.cause.cause_value);

			 ds_error_response(msg, msg->gtpc_msg.ds_rsp.cause.cause_value,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}

		/*Set the appropriate procedure and state.*/
		msg->state = context->state;
		msg->proc = context->proc;
		/*Set the appropriate event type.*/
		msg->event = DS_RESP_RCVD_EVNT;

		clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
			"Msg_Type:%s[%u], Teid:%u, "
			"Procedure:%s, State:%s, Event:%s\n",
			__func__, gtp_type_str(msg->msg_type), msg->msg_type,
			msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid,
			get_proc_string(msg->proc),
			get_state_string(msg->state), get_event_string(msg->event));
		break;
		}
	case GTP_RELEASE_ACCESS_BEARERS_REQ: {
			/* Parse the Relaese access bearer request message and update State and Event */
			/* TODO: Revisit after libgtpv2c support */
			ret = parse_release_access_bearer_request(gtpv2c_rx,
					&msg->gtpc_msg.rel_acc_ber_req_t);
			if (ret)
				return ret;

			msg->proc = get_procedure(msg);
			if (CONN_SUSPEND_PROC == msg->proc) {
				if (update_ue_proc((msg->gtpc_msg.rel_acc_ber_req_t.context)->s11_sgw_gtpc_teid,
							msg->proc) != 0) {
					fprintf(stderr, "%s failed\n", __func__);
					return -1;
				}

				/*Retrive UE state. */
				if(get_ue_context((msg->gtpc_msg.rel_acc_ber_req_t.context)->s11_sgw_gtpc_teid,
							&context) != 0) {
					return -1;
				}

				msg->state = context->state;
			}

			/*Set the appropriate event type.*/
			msg->event = REL_ACC_BER_REQ_RCVD_EVNT;

			clLog(s11logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_DOWNLINK_DATA_NOTIFICATION_ACK: {
			/* TODO: Revisit after libgtpv2c support */
			ret = parse_downlink_data_notification_ack(gtpv2c_rx,
				&msg->gtpc_msg.ddn_ack);
			if (ret)
				return ret;

			/*Retrive UE state. */
			if (get_ue_context(ntohl(gtpv2c_rx->teid.has_teid.teid), &context) != 0) {
				return -1;
			}

			msg->state = context->state;
			msg->proc = context->proc;

			/*Set the appropriate event type.*/
			msg->event = DDN_ACK_RESP_RCVD_EVNT;

			clLog(s11logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_CREATE_BEARER_REQ:{

			if((ret = decode_create_bearer_req((uint8_t *) gtpv2c_rx,
							&msg->gtpc_msg.cb_req) == 0))
					return -1;

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if((ret = get_ue_state(gtpv2c_rx->teid.has_teid.teid)) > 0){
				msg->state = ret;
			}else{
				return -1;
			}

			msg->proc = get_procedure(msg);
			msg->event = CREATE_BER_REQ_RCVD_EVNT;

			clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_state_string(msg->state), get_event_string(msg->event));

	   break;
	}

	case GTP_CREATE_BEARER_RSP:{
			if((ret = decode_create_bearer_rsp((uint8_t *) gtpv2c_rx,
						&msg->gtpc_msg.cb_rsp) == 0))
				return -1;

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if((ret = get_ue_state(gtpv2c_rx->teid.has_teid.teid)) > 0){
				msg->state = ret;
			}else{
				return -1;
			}

			msg->proc = get_procedure(msg);
			msg->event = CREATE_BER_RESP_RCVD_EVNT;

			clLog(s5s8logger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"State:%s, Event:%s\n",
					__func__, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_state_string(msg->state), get_event_string(msg->event));

	   break;
	}

	default:
			/*If Event is not supported then we will called default handler. */
			/* Retrive UE state. */
			if (get_ue_context(ntohl(gtpv2c_rx->teid.has_teid.teid), &context) != 0) {
				msg->proc =  NONE_PROC;
				if (SGWC == pfcp_config.cp_type)
					msg->state = SGWC_NONE_STATE;
				else {
#ifdef GX_BUILD
					msg->state = PGWC_NONE_STATE;
#else
					msg->state = SGWC_NONE_STATE;
#endif /* GX_BUILD */
					}
			} else {
				msg->state = context->state;
				msg->proc = context->proc;
			}

			msg->event = NONE_EVNT;
			/* HP: Remove extra print DONE */
			fprintf(stderr, "%s::process_msgs-"
					"\n\tcase: SAEGWC::spgw_cfg= %d;"
					"\n\tReceived GTPv2c Message Type: "
					"%s (%u) not supported... Discarding\n", __func__,
					spgw_cfg, gtp_type_str(gtpv2c_rx->gtpc.message_type),
					gtpv2c_rx->gtpc.message_type);
			return -1;
	}

	return 0;
}
