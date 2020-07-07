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
#include "cp_timer.h"
#include "pfcp.h"

#ifdef USE_REST
#include "main.h"
#endif

#include "cp_config.h"
#include "gw_adapter.h"

pfcp_config_t pfcp_config;
extern struct cp_stats_t cp_stats;

uint8_t
gtpv2c_pcnd_check(gtpv2c_header_t *gtpv2c_rx, int bytes_rx,
		struct sockaddr_in *peer_addr, uint8_t iface)
{
	int ret = 0;

	if ((unsigned)bytes_rx !=
		 (ntohs(gtpv2c_rx->gtpc.message_len)
		 + sizeof(gtpv2c_rx->gtpc)) && gtpv2c_rx->gtpc.piggyback == 0
		) {
		ret = GTPV2C_CAUSE_INVALID_LENGTH;
		/* According to 29.274 7.7.7, if message is request,
		 * reply with cause = GTPV2C_CAUSE_INVALID_LENGTH
		 *  should be sent - ignoring packet for now
		 */
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"GTPv2C Received UDP Payload:"
				"\n\t(%d bytes) with gtpv2c + "
				"header (%u + %lu) = %lu bytes\n", LOG_VALUE,
				bytes_rx, ntohs(gtpv2c_rx->gtpc.message_len),
				sizeof(gtpv2c_rx->gtpc),
				ntohs(gtpv2c_rx->gtpc.message_len)
				+ sizeof(gtpv2c_rx->gtpc));
		return ret;
	}

	if(bytes_rx > 0){
		if (gtpv2c_rx->gtpc.version < GTP_VERSION_GTPV2C) {
			if (peer_addr != NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ERROR: Discarding packet from "IPV4_ADDR" due to gtp version %u not supported..\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(peer_addr->sin_addr.s_addr)), gtpv2c_rx->gtpc.version);
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ERROR: Discarding packet due to gtp version %u not supported..\n",
						LOG_VALUE, gtpv2c_rx->gtpc.version);
			}
			return GTPV2C_CAUSE_VERSION_NOT_SUPPORTED;
		}else if (gtpv2c_rx->gtpc.version > GTP_VERSION_GTPV2C){
			send_version_not_supported(iface, gtpv2c_rx->teid.has_teid.seq);
			if (peer_addr != NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ERROR: Discarding packet from "IPV4_ADDR" due to gtp version %u not supported..\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(peer_addr->sin_addr.s_addr)), gtpv2c_rx->gtpc.version);
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ERROR: Discarding packet due to gtp version %u not supported..\n",
						LOG_VALUE, gtpv2c_rx->gtpc.version);
			}
			return GTPV2C_CAUSE_VERSION_NOT_SUPPORTED;
		}
	}
	return 0;

}

uint8_t
gtpc_pcnd_check(gtpv2c_header_t *gtpv2c_rx, msg_info *msg, int bytes_rx,
		struct sockaddr_in *peer_addr, uint8_t interface_type)
{
	int ret = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	msg->msg_type = gtpv2c_rx->gtpc.message_type;
	int ebi_index = 0;
	int i = 0;

	/*Below check is for GTPV2C version Check and GTPV2C MSG INVALID LENGTH CHECK */
	if ((ret = gtpv2c_pcnd_check(gtpv2c_rx, bytes_rx, peer_addr, interface_type)) != 0 ){

		if(ret == GTPV2C_CAUSE_VERSION_NOT_SUPPORTED) {
			return ret;
		}

		switch(msg->msg_type) {

			case GTP_CREATE_SESSION_REQ:

				if(decode_create_sess_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.csr) != 0){
					msg->cp_mode = 0;
					cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
					process_error_occured_handler(&msg, NULL);
				}
				break;

			case GTP_CREATE_SESSION_RSP:

				if( decode_create_sess_rsp((uint8_t *)gtpv2c_rx,&msg->gtpc_msg.cs_rsp) != 0){
					msg->cp_mode = 0;
					cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
					process_error_occured_handler(&msg, NULL);
				}
				break;

			case GTP_DELETE_SESSION_REQ:

				if( decode_del_sess_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.dsr) != 0){
					ds_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
				}
				break;

			case GTP_DELETE_SESSION_RSP:

				if( decode_del_sess_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.ds_rsp) != 0){
					ds_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
				}
				break;


			case GTP_MODIFY_BEARER_REQ:

				if( decode_mod_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.mbr) != 0) {
					mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
				}
				break;

			case GTP_MODIFY_BEARER_RSP:

				if( decode_mod_bearer_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.mb_rsp) != 0) {
					mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
				}
				break;

			case GTP_CREATE_BEARER_REQ:

				if( decode_create_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.cb_req) != 0) {
					cbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
				}
				break;

			case GTP_CREATE_BEARER_RSP:

				if( decode_create_bearer_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.cb_rsp) != 0) {
					cbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type == S5S8_IFACE ? GX_IFACE : S5S8_IFACE);
				}
				break;

			case GTP_DELETE_BEARER_REQ:

				if( decode_del_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.db_req) != 0) {
					delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
				}
				break;

			case GTP_DELETE_BEARER_RSP:

				if( decode_del_bearer_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.db_rsp) != 0) {
					delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type == S5S8_IFACE ? GX_IFACE : S5S8_IFACE);
				}
				break;

			case GTP_UPDATE_BEARER_REQ:

				if((decode_upd_bearer_req((uint8_t *) gtpv2c_rx,
											&msg->gtpc_msg.ub_req) != 0)){
					ubr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);

				}
				break;

			case GTP_UPDATE_BEARER_RSP:

				if((decode_upd_bearer_rsp((uint8_t *) gtpv2c_rx,
											&msg->gtpc_msg.ub_rsp) != 0)){
					/*TODO : Need to change interface condition*/
					ubr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);

				}
				break;

			case GTP_DELETE_PDN_CONNECTION_SET_REQ:
				if( decode_del_pdn_conn_set_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.del_pdn_req) != 0) {
					/* TODO for delete pdn connection set request error response */
				}
				break;

			case GTP_DELETE_PDN_CONNECTION_SET_RSP:
				if( decode_del_pdn_conn_set_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.del_pdn_rsp) != 0) {
					/* TODO for delete pdn connection set response error response */
				}
				break;

			case GTP_UPDATE_PDN_CONNECTION_SET_REQ:
				if( decode_upd_pdn_conn_set_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.upd_pdn_req) != 0) {
					update_pdn_connection_set_error_response(msg, CAUSE_SOURCE_SET_TO_0, ret);
				}
				break;

			case GTP_UPDATE_PDN_CONNECTION_SET_RSP:
				if( decode_upd_pdn_conn_set_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.upd_pdn_rsp) != 0) {
					/* TODO for update pdn connection set response error response */
					mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, interface_type);
				}
				break;

			case GTP_PGW_RESTART_NOTIFICATION_ACK:
				if( decode_pgw_rstrt_notif_ack((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.pgw_rstrt_notif_ack) != 0) {
					/* TODO for PGW restart notification response error response */
				}
				break;

			case GTP_DELETE_BEARER_CMD:
				if(decode_del_bearer_cmd((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.del_ber_cmd) != 0) {
					delete_bearer_cmd_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type);
					}
				break;

			case GTP_DELETE_BEARER_FAILURE_IND:
				if(decode_del_bearer_fail_indctn((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.del_fail_ind) != 0) {
					delete_bearer_cmd_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type);
					}
				break;

			case GTP_CHANGE_NOTIFICATION_REQ:
				if(decode_change_noti_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.change_not_req) != 0) {
					change_notification_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type);
					}
				break;

			case GTP_RELEASE_ACCESS_BEARERS_REQ:

				if(decode_release_access_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.rel_acc_ber_req) != 0){
					release_access_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type);
				}
				break;

			case GTP_BEARER_RESOURCE_CMD :
				if(decode_bearer_rsrc_cmd((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.bearer_rsrc_cmd) != 0) {
					send_bearer_resource_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type);
				}
				break;

			case GTP_BEARER_RESOURCE_FAILURE_IND:
				if(decode_bearer_rsrc_fail_indctn((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.ber_rsrc_fail_ind) != 0) {
					send_bearer_resource_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
							interface_type);
					}
				break;

			case GTP_IDENTIFICATION_RSP:
				break;
		}
		return -1;

	}

	switch(msg->msg_type) {

		case GTP_CREATE_SESSION_REQ: {

			uint8_t cp_type= 0;
			if ((ret = decode_check_csr(gtpv2c_rx, &msg->gtpc_msg.csr, &cp_type)) != 0) {
				if(ret != -1) {
					if (cp_type != 0) {
						msg->cp_mode = cp_type;
						cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
								cp_type != PGWC ? S11_IFACE : S5S8_IFACE);
					} else {
						/* Send CS error response if failed to select gateway type */
						msg->cp_mode = 0;
						cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
								interface_type);
					}
				}
				return -1;
			}
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Selected mode for Gateway: %s\n",
					LOG_VALUE, cp_type == SGWC ? "SGW-C" : cp_type == PGWC ? "PGW-C" :
					cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");

			msg->cp_mode = cp_type;
			msg->interface_type = interface_type;
			/*CLI*/
			/*add entry of MME(if cp is SGWC) and SGWC (if cp PGWC)*/
			if (msg->gtpc_msg.csr.sender_fteid_ctl_plane.ipv4_address != 0) {
				add_cli_peer(htonl(msg->gtpc_msg.csr.sender_fteid_ctl_plane.ipv4_address), S5S8);
				add_node_conn_entry(msg->gtpc_msg.csr.sender_fteid_ctl_plane.ipv4_address,
											msg->cp_mode != PGWC ? S11_SGW_PORT_ID : S5S8_PGWC_PORT_ID,
											msg->cp_mode);
			}
			msg->proc = get_procedure(msg);
			if (INITIAL_PDN_ATTACH_PROC == msg->proc) {
				/* VS: Set the initial state for initial PDN connection */
				/* VS: Make single state for all combination */
				if (cp_type == SGWC) {
					/*Set the appropriate state for the SGWC */
					msg->state = SGWC_NONE_STATE;
				} else {
					/*Set the appropriate state for the SAEGWC and PGWC*/
					if (pfcp_config.use_gx) {
						msg->state = PGWC_NONE_STATE;
					} else {
						msg->state = SGWC_NONE_STATE;
					}
				}
			}

			/*Set the appropriate event type.*/
			msg->event = CS_REQ_RCVD_EVNT;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
			break;
		}

		case GTP_CREATE_SESSION_RSP: {
			struct resp_info *resp = NULL;
			ret = decode_create_sess_rsp((uint8_t *)gtpv2c_rx, &msg->gtpc_msg.cs_rsp);
			if(!ret)
				return -1;

			delete_timer_entry(msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid);

			msg->interface_type = interface_type;
			if(msg->gtpc_msg.cs_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
				msg->cp_mode = 0;
				cs_error_response(msg, msg->gtpc_msg.cs_rsp.cause.cause_value,
					CAUSE_SOURCE_SET_TO_1, S11_IFACE);
				return -1;
			}

			if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid, &context) != 0)
			{
				if(msg->gtpc_msg.cs_rsp.sender_fteid_ctl_plane.interface_type == S5_S8_PGW_GTP_C) {
					msg->cp_mode = 0;
					cs_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
							S11_IFACE);
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
							"UE context for teid: %d\n \n", LOG_VALUE, msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid);
					return -1;
				}
			}

			msg->cp_mode = context->cp_mode;
			/*extract ebi_id from array as all the ebi's will be of same pdn.*/
			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.cs_rsp.bearer_contexts_created[0].eps_bearer_id.ebi_ebi);
			if (ebi_index == -1) {

				cs_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
						msg->cp_mode!= PGWC ? S11_IFACE : S5S8_IFACE);
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI "
					"ID\n", LOG_VALUE);
				return -1;
			}

			pdn = GET_PDN(context, ebi_index);
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
				return -1;
			}

			msg->state = pdn->state;

			if(msg->gtpc_msg.csr.header.gtpc.piggyback) {

				msg->proc = ATTACH_DEDICATED_PROC;
				pdn->proc = ATTACH_DEDICATED_PROC;

				if(get_sess_entry(pdn->seid, &resp) == 0)
					memcpy(&resp->gtpc_msg.cs_rsp, &msg->gtpc_msg.cs_rsp, sizeof(create_sess_rsp_t));

				gtpv2c_rx = (gtpv2c_header_t *)((uint8_t *)gtpv2c_rx + ntohs(gtpv2c_rx->gtpc.message_len)
						+ sizeof(gtpv2c_rx->gtpc));
				msg->msg_type =  gtpv2c_rx->gtpc.message_type;

			} else {
				msg->proc = pdn->proc;

				/*Set the appropriate event type.*/
				msg->event = CS_RESP_RCVD_EVNT;

				update_sys_stat(number_of_users, INCREMENT);
				update_sys_stat(number_of_active_session, INCREMENT);

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
						"Msg_Type:%s[%u], Teid:%u, "
						"Procedure:%s, State:%s, Event:%s\n",
						LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
						gtpv2c_rx->teid.has_teid.teid,
						get_proc_string(msg->proc),
						get_state_string(msg->state), get_event_string(msg->event));
			}
		break;
	}

	case GTP_CREATE_BEARER_REQ:{

			if((ret = decode_create_bearer_req((uint8_t *) gtpv2c_rx,
							&msg->gtpc_msg.cb_req) == 0))
					return -1;

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);
			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.cb_req.lbi.ebi_ebi);


			if(get_ue_context_by_sgw_s5s8_teid(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);

				cbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						S5S8_IFACE);
				return -1;
			}

			/*Delete timer entry for bearer resource command*/
			if (context->ue_initiated_seq_no == msg->gtpc_msg.cb_req.header.teid.has_teid.seq) {
				delete_timer_entry(gtpv2c_rx->teid.has_teid.teid);
			}

			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				cbr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
						S5S8_IFACE);
				return -1;
			}

			msg->cp_mode = context->cp_mode;
			msg->interface_type = interface_type;
			msg->state = context->eps_bearers[ebi_index]->pdn->state;
			if(context->eps_bearers[ebi_index]->pdn->proc == ATTACH_DEDICATED_PROC){
				msg->proc = context->eps_bearers[ebi_index]->pdn->proc;
			}else {
				msg->proc = get_procedure(msg);
			}

			msg->event = CREATE_BER_REQ_RCVD_EVNT;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_state_string(msg->state), get_event_string(msg->event));

	   break;
	}


	case GTP_MODIFY_BEARER_RSP: {
		teid_key_t teid_key = {0};

		if((ret = decode_mod_bearer_rsp((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.mb_rsp) == 0)) {
			return -1;
		}

		msg->proc = get_procedure(msg);

		snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
			msg->gtpc_msg.mb_rsp.header.teid.has_teid.seq);

		/* If Received Error Modify Bearer Resp form peer node with 0 teid */
		if ((!(msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid)) &&
				(msg->gtpc_msg.mb_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {


			struct teid_value_t *teid_value = NULL;

			teid_value = get_teid_for_seq_number(teid_key);
			if (teid_value == NULL) {
				/* TODO: Add the appropriate handling */
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get TEID value for Sequence "
					"Number key : %s \n", LOG_VALUE,
					teid_key.teid_key);
				return -1;
			}

			/* Delete the timer entry for  MBREQ */
			delete_timer_entry(teid_value->teid);

			/* Copy local stored TEID in the MBResp header */
			msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid = teid_value->teid;

			/* Fill the response struct and sending peer node */
			mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						S11_IFACE);

			/* Delete the TEID entry for MB REQ */
			delete_teid_entry_for_seq(teid_key);

			process_error_occured_handler(&msg, NULL);
			/* Set the return value to skip SM */
			return GTPC_ZERO_TEID_FOUND;
		}

		delete_timer_entry(msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);

		/* Delete the TEID entry for MB REQ */
		delete_teid_entry_for_seq(teid_key);

		if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid, &context) != 0)
		{
			if(msg->gtpc_msg.mb_rsp.bearer_count != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
						"UE context for teid: %d\n", LOG_VALUE,
						msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);
				msg->cp_mode = 0;
				cs_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						S11_IFACE);
				process_error_occured_handler(&msg, NULL);
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
						"UE context for teid: %d\n", LOG_VALUE,
						msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);
				mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						S11_IFACE);
				process_error_occured_handler(&msg, NULL);
			}
			return -1;
		}

		msg->cp_mode = context->cp_mode;
		msg->interface_type = interface_type;

		if(msg->gtpc_msg.mb_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED) {
			if(context->procedure == SGW_RELOCATION_PROC) {
				cs_error_response(msg, msg->gtpc_msg.mb_rsp.cause.cause_value,
						CAUSE_SOURCE_SET_TO_1,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			} else {
				mbr_error_response(msg, msg->gtpc_msg.mb_rsp.cause.cause_value,
						CAUSE_SOURCE_SET_TO_1, context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			}
			return -1;
		}

		if (msg->gtpc_msg.mb_rsp.linked_eps_bearer_id.ebi_ebi == 0) {
			if (msg->gtpc_msg.mb_rsp.bearer_contexts_modified[0].header.len != 0) {
				/*extract ebi_id from array as all the ebi's will be of same pdn.*/
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.mb_rsp.bearer_contexts_modified[0].eps_bearer_id.ebi_ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);

					mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
							CAUSE_SOURCE_SET_TO_0,
							msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}

			}else{
				struct eps_bearer_t *bearer_temp = NULL;
				ret = get_bearer_by_teid(msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid, &bearer_temp);
				if(ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Bearer found "
							"for teid: %x\n", LOG_VALUE, msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);
						mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
								CAUSE_SOURCE_SET_TO_0,
								msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}
				int ebi = UE_BEAR_ID(bearer_temp->pdn->seid);
				ebi_index = GET_EBI_INDEX(ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
							msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}

			}
		} else {
			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.mb_rsp.linked_eps_bearer_id.ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}
		}

		pdn = GET_PDN(context, ebi_index);
		if(pdn == NULL){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}

		msg->cp_mode = context->cp_mode;
		msg->state = pdn->state;
		msg->proc = pdn->proc;
		msg->event = MB_RESP_RCVD_EVNT;

		break;
	}

	case GTP_DELETE_SESSION_REQ: {
			/* Decode delete session request */
			ret = decode_del_sess_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.dsr);
			if (ret == 0){
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to Decode GTP_DELETE_SESSION_REQ \n",LOG_VALUE);
				return -1;
			}

			if(get_ue_context(msg->gtpc_msg.dsr.header.teid.has_teid.teid,
						&context) != 0) {

				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get UE context for teid: %d\n",LOG_VALUE,
						msg->gtpc_msg.dsr.header.teid.has_teid.teid);

				if(msg->gtpc_msg.dsr.indctn_flgs.header.len != 0) {
					ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
							S11_IFACE);
				} else {
					ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
							S5S8_IFACE);
				}

				return -1;
			}

			msg->cp_mode = context->cp_mode;
			msg->interface_type = interface_type;
			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.dsr.lbi.ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				ds_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
							msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
				return -1;
			}

			msg->proc = get_procedure(msg);
			if (DETACH_PROC == msg->proc) {
				if (update_ue_proc(context, msg->proc, ebi_index) != 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to Update Procedure for"
							" GTP_DELETE_SESSION_REQ \n",LOG_VALUE);
					ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
							context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					return -1;
				}
			}

			/*Set the appropriate event type and state.*/
			msg->state = CONNECTED_STATE;
			msg->event = DS_REQ_RCVD_EVNT;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid, get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));

		break;
	}

	case GTP_DELETE_SESSION_RSP: {

		teid_key_t teid_key = {0};

		ret = decode_del_sess_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.ds_rsp);
		if (ret == 0){
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to Decode GTP_DELETE_SESSION_RSP \n",LOG_VALUE);
			return -1;
		}

		msg->proc = get_procedure(msg);

		snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
			msg->gtpc_msg.ds_rsp.header.teid.has_teid.seq);

		/* If Received Error DSResp form peer node with 0 teid */
		if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid, &context) != 0) {

			struct teid_value_t *teid_value = NULL;

			teid_value = get_teid_for_seq_number(teid_key);
			if (teid_value == NULL) {
				/* TODO: Add the appropriate handling */
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get TEID value for Sequence "
					"Number key: %s \n", LOG_VALUE,
					teid_key.teid_key);
				ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0, S11_IFACE);
				return -1;
			}

			/* Delete the timer entry for DS REQ */
			delete_timer_entry(teid_value->teid);

			/* Copy local stored TEID in the DSResp header */
			msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid = teid_value->teid;

			/* Delete the TEID entry for DS REQ */
			delete_teid_entry_for_seq(teid_key);

			if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid, &context) != 0) {
				ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0, S11_IFACE);
				return -1;
			}
		}

		delete_timer_entry(msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid);

		/* Delete the TEID entry for DS REQ */
		delete_teid_entry_for_seq(teid_key);

		if(context != NULL){
			msg->cp_mode = context->cp_mode;
		}

		msg->interface_type = interface_type;

		/* Here we are considering GTPV2C_CAUSE_CONTEXT_NOT_FOUND as success
		 * Beacuse purpose of DSReq is to cleanup that session
		 * and if the node don't have the session data
		 * that means purpose of Request is achived so no need to send error and
		 * Terminate process here
		 */

		/*Set the appropriate procedure, state and event type.*/
		msg->state = DS_REQ_SNT_STATE;
		/*Set the appropriate event type.*/
		msg->event = DS_RESP_RCVD_EVNT;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
			"Msg_Type:%s[%u], Teid:%u, "
			"Procedure:%s, State:%s, Event:%s\n",
			LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
			msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid,
			get_proc_string(msg->proc),
			get_state_string(msg->state), get_event_string(msg->event));
		break;
	}
	case GTP_RELEASE_ACCESS_BEARERS_REQ: {

		if(decode_release_access_bearer_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.rel_acc_ber_req) == 0){
			return -1;
		}

		gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

		if(get_ue_context(msg->gtpc_msg.rel_acc_ber_req.header.teid.has_teid.teid, &context)) {
			clLog(clSystemLog, eCLSeverityCritical,  LOG_FORMAT"Failed to get UE Context"
				"for teid: %d\n",LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
			release_access_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
					CAUSE_SOURCE_SET_TO_0, S11_IFACE);
			return -1;
		}

		msg->cp_mode = context->cp_mode;
		msg->interface_type = interface_type;
		msg->proc = get_procedure(msg);
		msg->event = REL_ACC_BER_REQ_RCVD_EVNT;

		for(i=0; i < MAX_BEARERS; i++){
			if(context->pdns[i] == NULL){
				continue;
			}
			else {
				context->pdns[i]->proc = msg->proc;
				msg->state = context->pdns[i]->state;
			}
		}

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
				"Msg_Type:%s[%u], Teid:%u, "
				"State:%s, Event:%s\n",
				LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
				gtpv2c_rx->teid.has_teid.teid,
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
					clLog(clSystemLog, eCLSeverityCritical,  LOG_FORMAT"Failed to get UE Context"
						"for teid: %d\n",LOG_VALUE, ntohl(gtpv2c_rx->teid.has_teid.teid));
				return -1;
			}

			for(i=0; i < MAX_BEARERS; i++){
				if(context->pdns[i] == NULL){
					continue;
				}
				else{
					msg->state = context->pdns[i]->state;
					msg->proc = context->pdns[i]->proc;
				}
			}

			msg->cp_mode = context->cp_mode;
			msg->interface_type = interface_type;
			/*Set the appropriate event type.*/
			msg->event = DDN_ACK_RESP_RCVD_EVNT;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}


	case GTP_CREATE_BEARER_RSP:{
			struct resp_info *resp = NULL;
			teid_key_t teid_key = {0};

			if((ret = decode_create_bearer_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.cb_rsp) == 0))
				return -1;

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			ebi_index = GET_EBI_INDEX((MAX_BEARERS + NUM_EBI_RESERVED));
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				cbr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
						context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
				return -1;
			}

			msg->proc = get_procedure(msg);

			snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
				msg->gtpc_msg.cb_rsp.header.teid.has_teid.seq);

			/* If Received Error CBResp form peer node with 0 teid */
			if ((!(msg->gtpc_msg.cb_rsp.header.teid.has_teid.teid)) &&
					(msg->gtpc_msg.cb_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

				struct teid_value_t *teid_value = NULL;

				teid_value = get_teid_for_seq_number(teid_key);
				if (teid_value == NULL) {
					/* TODO: Add the appropriate handling */
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get TEID value for Sequence "
						"Number key: %s \n", LOG_VALUE,
						teid_key.teid_key);
					return -1;
				}

				/* Delete the timer entry for CB REQ */
				delete_pfcp_if_timer_entry(teid_value->teid, ebi_index);

				/* Copy local stored TEID in the CBResp header */
				msg->gtpc_msg.cb_rsp.header.teid.has_teid.teid = teid_value->teid;

				/* Fill the response struct and sending peer node */
				cbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						interface_type);

				/* Delete the TEID entry for CB REQ */
				delete_teid_entry_for_seq(teid_key);
				/* Set the return value to skip SM */
				return GTPC_ZERO_TEID_FOUND;
			}

			if (get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
						" UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);

				return -1;
			}

			if(msg->gtpc_msg.cb_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
				cbr_error_response(msg, msg->gtpc_msg.cb_rsp.cause.cause_value,
						CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
				return -1;
			}

			delete_pfcp_if_timer_entry(gtpv2c_rx->teid.has_teid.teid, ebi_index);

			/* Delete the TEID entry for CB REQ */
			delete_teid_entry_for_seq(teid_key);

			if((ret = get_ue_state(gtpv2c_rx->teid.has_teid.teid ,ebi_index)) > 0){
				msg->state = ret;
			}else{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
						" Ue state for tied: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
				cbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
								interface_type);
				return -1;
			}


			msg->cp_mode = context->cp_mode;
			msg->interface_type = interface_type;

			if(msg->gtpc_msg.cb_rsp.header.gtpc.piggyback){

				msg->proc = ATTACH_DEDICATED_PROC;
				pdn->proc = ATTACH_DEDICATED_PROC;

				context->piggback = TRUE;
				if(get_sess_entry(pdn->seid, &resp) == 0)
					memcpy(&resp->gtpc_msg.cb_rsp, &msg->gtpc_msg.cb_rsp, sizeof(create_bearer_rsp_t));

				gtpv2c_rx = (gtpv2c_header_t *)((uint8_t *)gtpv2c_rx + ntohs(gtpv2c_rx->gtpc.message_len)
						+ sizeof(gtpv2c_rx->gtpc));
				msg->msg_type =  gtpv2c_rx->gtpc.message_type;

			} else {
				msg->proc = get_procedure(msg);
				msg->event = CREATE_BER_RESP_RCVD_EVNT;

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
						"Msg_Type:%s[%u], Teid:%u, "
						"State:%s, Event:%s\n",
						LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
						gtpv2c_rx->teid.has_teid.teid,
						get_state_string(msg->state), get_event_string(msg->event));

				break;
			}
	}

	case GTP_MODIFY_BEARER_REQ: {

			/*Decode the received msg and stored into the struct. */
			if((ret = decode_mod_bearer_req((uint8_t *) gtpv2c_rx,
							&msg->gtpc_msg.mbr) == 0)) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Erorr in decoding MBR Req\n", LOG_VALUE);
				return -1;
			}

			uint8_t cp_mode = 0;
			/* Dynamically Set the gateway modes */
			if ((msg->gtpc_msg.mbr.sender_fteid_ctl_plane.header.len != 0) &&
				(msg->gtpc_msg.mbr.sender_fteid_ctl_plane.interface_type == S5_S8_SGW_GTP_C)
				&& (interface_type == S5S8_IFACE)) {
				/* Selection/Demotion Criteria for Combined GW to PGWC */
				if (pfcp_config.cp_type == SAEGWC) {
					cp_mode = PGWC;
				} else if (pfcp_config.cp_type == PGWC) {
					cp_mode = PGWC;
				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Not Valid MBR Request for configured GW, Gateway Mode:%s\n",
							LOG_VALUE, pfcp_config.cp_type == SGWC ? "SGW-C" :
							pfcp_config.cp_type == PGWC ? "PGW-C" :
							pfcp_config.cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Demoted Gateway Mode: %s\n",
						LOG_VALUE, cp_mode == SGWC ? "SGW-C" : cp_mode == PGWC ? "PGW-C" :
						cp_mode == SAEGWC ? "SAEGW-C" : "UNKNOWN");
			}

			msg->proc = get_procedure(msg);
			msg->state = CONNECTED_STATE;
			msg->event = MB_REQ_RCVD_EVNT;

			/*Retrive UE state. */
			if(get_ue_context(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.mbr.header.teid.has_teid.teid);
				mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						interface_type);
				return -1;
			}

			/* Reset the CP Mode Flag */
			context->cp_mode_flag = FALSE;
			if ((cp_mode != 0) && (cp_mode != context->cp_mode)) {
				/* Replicat/Assign in the Context CP Mode */
				context->cp_mode = cp_mode;
				/* Set the CP Mode Flag */
				context->cp_mode_flag = TRUE;
			}

			/*extract ebi_id from array as all the ebi's will be of same pdn.*/
			if(msg->gtpc_msg.mbr.bearer_count != 0) {
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.mbr.bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi);

				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					mbr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
						interface_type);
					return -1;
				}

				pdn = GET_PDN(context, ebi_index);
				if(pdn == NULL){
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to get pdn for ebi_index : %d \n", LOG_VALUE, ebi_index);
					mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						interface_type);
					return -1;
				}

				pdn->proc = msg->proc;
			}

			/* Set CP mode in Msg struct for STATE MACHINE */
			msg->cp_mode = context->cp_mode;
			msg->interface_type = interface_type;
			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if(cp_mode == PGWC) {
				if (msg->gtpc_msg.mbr.sender_fteid_ctl_plane.ipv4_address != 0) {
					/* add cli peer in case of sgw handover */
					add_cli_peer(htonl(msg->gtpc_msg.mbr.sender_fteid_ctl_plane.ipv4_address), S5S8);

					add_node_conn_entry(msg->gtpc_msg.mbr.sender_fteid_ctl_plane.ipv4_address,
							S5S8_PGWC_PORT_ID, cp_mode);
				}

				msg->cp_mode = cp_mode;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"Procedure:%s, State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_proc_string(msg->proc),
					get_state_string(msg->state), get_event_string(msg->event));
			break;

	}
	case GTP_DELETE_BEARER_REQ:{

			if((ret = decode_del_bearer_req((uint8_t *) gtpv2c_rx,
							&msg->gtpc_msg.db_req) == 0)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
					"while decoding Delete Bearer Request\n", LOG_VALUE);
				return -1;
			}

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if(get_ue_context_by_sgw_s5s8_teid(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get "
					"UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
				delete_bearer_error_response(msg,GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
						CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
				return -1;
			}

			/*Delete timer entry for bearer resource command*/
			if (context->ue_initiated_seq_no == msg->gtpc_msg.db_req.header.teid.has_teid.seq) {
				delete_timer_entry(gtpv2c_rx->teid.has_teid.teid);
			}

			if (msg->gtpc_msg.db_req.lbi.header.len) {
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.db_req.lbi.ebi_ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
							S5S8_IFACE);
					return -1;
				}

			} else {
				/*extract ebi_id from array as all the ebi's will be of same pdn.*/
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.db_req.eps_bearer_ids[0].ebi_ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
							S5S8_IFACE);
					return -1;
				}
			}

			if(context->eps_bearers[ebi_index]->pdn->proc == MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC){
				msg->proc = context->eps_bearers[ebi_index]->pdn->proc;
			}else{
				msg->proc = get_procedure(msg);
				context->eps_bearers[ebi_index]->pdn->proc = msg->proc;
			}

			msg->state = context->eps_bearers[ebi_index]->pdn->state;
			msg->event = DELETE_BER_REQ_RCVD_EVNT;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;
			context->eps_bearers[ebi_index]->pdn->proc = msg->proc;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_state_string(msg->state), get_event_string(msg->event));

	   break;
	}

	case GTP_DELETE_BEARER_RSP:{
			teid_key_t teid_key = {0};

			if((ret = decode_del_bearer_rsp((uint8_t *) gtpv2c_rx,
						&msg->gtpc_msg.db_rsp) == 0)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
					"while decoding Delete Bearer Response\n", LOG_VALUE);
				return -1;
			}

			/* Here we are considering GTPV2C_CAUSE_CONTEXT_NOT_FOUND as success
			 * Beacuse purpose of DBReq is to cleanup that bearer data
			 * and if the node don't have the bearer data
			 * that means purpose of Request is achived so no need to send error and
			 * Terminate process here
			 */

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if (msg->gtpc_msg.db_rsp.lbi.header.len) {
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.db_rsp.lbi.ebi_ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
							CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
					return -1;
				}

			} else {
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.db_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
							CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
					return -1;
				}

			}

			msg->proc = get_procedure(msg);

			snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
				msg->gtpc_msg.db_rsp.header.teid.has_teid.seq);

			/* If Received Error DBResp form peer node with 0 teid */
			if ((!(msg->gtpc_msg.db_rsp.header.teid.has_teid.teid)) &&
					(msg->gtpc_msg.db_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

				struct teid_value_t *teid_value = NULL;

				teid_value = get_teid_for_seq_number(teid_key);
				if (teid_value == NULL) {
					/* TODO: Add the appropriate handling */
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get TEID value for Sequence "
						"Number key : %s \n", LOG_VALUE,
						teid_key.teid_key);
					return -1;
				}

				/* Delete the timer entry for DB REQ */
				delete_pfcp_if_timer_entry(teid_value->teid, ebi_index);

				/* Copy local stored TEID in the DBResp header */
				msg->gtpc_msg.db_rsp.header.teid.has_teid.teid = teid_value->teid;

				/* Fill the response struct and sending peer node */
				delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
							CAUSE_SOURCE_SET_TO_0, interface_type);

				/* Delete the TEID entry for DB REQ */
				delete_teid_entry_for_seq(teid_key);
				/* Set the return value to skip SM */
				return GTPC_ZERO_TEID_FOUND;
			}

			if (get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);

				return -1;
			}


			if (msg->gtpc_msg.db_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED
				&& msg->gtpc_msg.db_rsp.cause.cause_value != GTPV2C_CAUSE_CONTEXT_NOT_FOUND) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error cause "
					"received Delete Bearer Response.Cause : %s\n", LOG_VALUE,
					cause_str(msg->gtpc_msg.db_rsp.cause.cause_value));
				delete_bearer_error_response(msg, msg->gtpc_msg.db_rsp.cause.cause_value,
						CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);

				delete_pfcp_if_timer_entry(gtpv2c_rx->teid.has_teid.teid, ebi_index);
				return -1;
			}

			delete_pfcp_if_timer_entry(gtpv2c_rx->teid.has_teid.teid, ebi_index);

			/* Delete the TEID entry for DB REQ */
			delete_teid_entry_for_seq(teid_key);

			if ((ret = get_ue_state(gtpv2c_rx->teid.has_teid.teid, ebi_index)) > 0) {
				msg->state = ret;
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" Ue state for tied: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
				return -1;
			}

			if(context->eps_bearers[ebi_index]->pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
				msg->proc = get_procedure(msg);
			} else {
				msg->proc = context->eps_bearers[ebi_index]->pdn->proc;
			}

			msg->event = DELETE_BER_RESP_RCVD_EVNT;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					"Msg_Type:%s[%u], Teid:%u, "
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					gtpv2c_rx->teid.has_teid.teid,
					get_state_string(msg->state), get_event_string(msg->event));

			break;
	}
	case GTP_DELETE_BEARER_FAILURE_IND:{
			if((ret = decode_del_bearer_fail_indctn((uint8_t *) gtpv2c_rx,
						&msg->gtpc_msg.del_fail_ind) == 0)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
				"while decoding Delete Bearer Failure Indication\n", LOG_VALUE);
				return -1;
			}

			msg->interface_type = interface_type;
			if(msg->gtpc_msg.del_fail_ind.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
				delete_bearer_cmd_failure_indication(msg, msg->gtpc_msg.del_fail_ind.cause.cause_value,
						CAUSE_SOURCE_SET_TO_1, S11_IFACE);
						return -1;
			}
			break;
		}

	case GTP_BEARER_RESOURCE_FAILURE_IND:{
			if((ret = decode_bearer_rsrc_fail_indctn((uint8_t *) gtpv2c_rx,
							&msg->gtpc_msg.ber_rsrc_fail_ind) == 0)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
						"while decoding Bearer Resource "
						"Failure Indication msg\n", LOG_VALUE);
				return -1;
			}

				send_bearer_resource_failure_indication(msg,
							msg->gtpc_msg.ber_rsrc_fail_ind.cause.cause_value,
							CAUSE_SOURCE_SET_TO_0, S11_IFACE);
						return -1;
			break;
		}

	case GTP_UPDATE_BEARER_REQ:{

		if((ret = decode_upd_bearer_req((uint8_t *) gtpv2c_rx,
						&msg->gtpc_msg.ub_req) == 0))
			return -1;


		gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

		if(get_ue_context_by_sgw_s5s8_teid(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
			ubr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
			return -1;
		}

		/*Delete timer entry for bearer resource command*/
		if (context->ue_initiated_seq_no == msg->gtpc_msg.ub_req.header.teid.has_teid.seq) {
			delete_timer_entry(gtpv2c_rx->teid.has_teid.teid);
		}

		/*Which ebi to be selected as multiple bearer in request*/
		/*extract ebi_id from array as all the ebi's will be of same pdn.*/
		ebi_index = GET_EBI_INDEX(msg->gtpc_msg.ub_req.bearer_contexts[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			ubr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
					CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
			return -1;
		}

		msg->interface_type = interface_type;

		msg->state = context->eps_bearers[ebi_index]->pdn->state;
		msg->proc = get_procedure(msg);
		msg->event = UPDATE_BEARER_REQ_RCVD_EVNT;
		msg->cp_mode = context->cp_mode;

		break;

	}

	case GTP_UPDATE_BEARER_RSP:{

		teid_key_t teid_key = {0};

		if((ret = decode_upd_bearer_rsp((uint8_t *) gtpv2c_rx,
						&msg->gtpc_msg.ub_rsp) == 0))
				return -1;

		gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

		ebi_index = GET_EBI_INDEX(msg->gtpc_msg.ub_rsp.bearer_contexts[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			ubr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
					CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
			return -1;
		}

		msg->proc = get_procedure(msg);

		snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
			msg->gtpc_msg.ub_rsp.header.teid.has_teid.seq);

		/* If Received Error UBResp form peer node with 0 teid */
		if ((!(msg->gtpc_msg.ub_rsp.header.teid.has_teid.teid)) &&
				(msg->gtpc_msg.ub_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

			struct teid_value_t *teid_value = NULL;

			teid_value = get_teid_for_seq_number(teid_key);
			if (teid_value == NULL) {
				/* TODO: Add the appropriate handling */
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get TEID value for Sequence "
					"Number key: %s \n", LOG_VALUE,
					teid_key.teid_key);
				return -1;
			}

			/* Delete the timer entry for UB REQ */
			delete_pfcp_if_timer_entry(teid_value->teid, ebi_index);

			/* Copy local stored TEID in the UBResp header */
			msg->gtpc_msg.ub_rsp.header.teid.has_teid.teid = teid_value->teid;

			/* Fill the response struct and sending peer node */
			ubr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
					interface_type);

			/* Delete the TEID entry for UB REQ */
			delete_teid_entry_for_seq(teid_key);
			/* Set the return value to skip SM */
			return GTPC_ZERO_TEID_FOUND;
		}

		if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
			return -1;
		}

		if(context->is_sent_bearer_rsc_failure_indc != PRESENT) {
			if(msg->gtpc_msg.ub_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
				ubr_error_response(msg, msg->gtpc_msg.ub_rsp.cause.cause_value,
						CAUSE_SOURCE_SET_TO_1, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
				return -1;
			}
		}

		delete_pfcp_if_timer_entry(gtpv2c_rx->teid.has_teid.teid, ebi_index);

		/* Delete the TEID entry for UB REQ */
		delete_teid_entry_for_seq(teid_key);

		/*TODO: Which ebi to be selected as multiple bearer in request*/
		if((ret = get_ue_state(gtpv2c_rx->teid.has_teid.teid ,ebi_index)) > 0){
				msg->state = ret;
		}else{
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" Ue state for tied: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);
			return -1;
		}

		msg->proc = get_procedure(msg);
		msg->event = UPDATE_BEARER_RSP_RCVD_EVNT;
		msg->interface_type = interface_type;


		msg->cp_mode = context->cp_mode;
		break;
	}

	case GTP_DELETE_PDN_CONNECTION_SET_REQ: {
			if ((ret = decode_del_pdn_conn_set_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.del_pdn_req) == 0))
			    return -1;

			msg->state = DEL_PDN_CONN_SET_REQ_RCVD_STATE;
			msg->proc = get_procedure(msg);
			msg->event = DEL_PDN_CONN_SET_REQ_RCVD_EVNT;
			msg->interface_type = interface_type;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					" Msg_Type:%s[%u],"
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}

	case GTP_DELETE_PDN_CONNECTION_SET_RSP: {
			if ((ret = decode_del_pdn_conn_set_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.del_pdn_rsp) == 0))
			    return -1;

			msg->state = DEL_PDN_CONN_SET_REQ_SNT_STATE;
			msg->proc = get_procedure(msg);
			msg->event = DEL_PDN_CONN_SET_RESP_RCVD_EVNT;
			msg->interface_type = interface_type;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					" Msg_Type:%s[%u],"
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}
	case GTP_UPDATE_PDN_CONNECTION_SET_REQ: {
			if ((ret = decode_upd_pdn_conn_set_req((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.upd_pdn_req) == 0))
			    return -1;

			msg->state = CONNECTED_STATE;
			msg->proc = get_procedure(msg);
			msg->event = UPD_PDN_CONN_SET_REQ_RCVD_EVNT;
			msg->interface_type = interface_type;

			/*Retrive UE state. */
			if(get_ue_context(msg->gtpc_msg.upd_pdn_req.header.teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE,
					msg->gtpc_msg.upd_pdn_req.header.teid.has_teid.teid);
				update_pdn_connection_set_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
						CAUSE_SOURCE_SET_TO_0);
				return -1;
			}

			msg->cp_mode = context->cp_mode;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					" Msg_Type:%s[%u],"
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					get_state_string(msg->state), get_event_string(msg->event));
	   break;
	 }
	case GTP_DELETE_BEARER_CMD: {

			if((ret = decode_del_bearer_cmd((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.del_ber_cmd) == 0)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
						"while decoding Delete Bearer Command\n", LOG_VALUE);
					return -1;
			}
			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			/*extract ebi_id from array as all the ebi's will be of same pdn.*/
			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.del_ber_cmd.bearer_contexts[0].eps_bearer_id.ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				delete_bearer_cmd_failure_indication(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
						CAUSE_SOURCE_SET_TO_0, interface_type);
				return -1;
			}

			if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);

				delete_bearer_cmd_failure_indication(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
						CAUSE_SOURCE_SET_TO_0, interface_type);
				return -1;
			}
			msg->proc = get_procedure(msg);
			if (update_ue_proc(context, msg->proc, ebi_index) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
					"update Procedure\n", LOG_VALUE);
				return -1;
			}
			msg->state = CONNECTED_STATE;
			msg->event = DELETE_BER_CMD_RCVD_EVNT;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;

		break;
	}

	case GTP_BEARER_RESOURCE_CMD : {

			if((ret = decode_bearer_rsrc_cmd((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.bearer_rsrc_cmd) == 0)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
						"while decoding Bearer Resource Command\n", LOG_VALUE);
					return -1;
			}

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			if(get_ue_context(gtpv2c_rx->teid.has_teid.teid, &context) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n for Bearer"
					"Resource Command", LOG_VALUE, gtpv2c_rx->teid.has_teid.teid);

				send_bearer_resource_failure_indication(msg,
						GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
						interface_type);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/*Get default bearer id i.e. lbi from BRC */
			/*Check for mandatory IE LBI,PTI,TAD*/
			if(msg->gtpc_msg.bearer_rsrc_cmd.lbi.header.len != 0 &&
					msg->gtpc_msg.bearer_rsrc_cmd.pti.header.len != 0 &&
					msg->gtpc_msg.bearer_rsrc_cmd.tad.header.len != 0) {
				ebi_index = GET_EBI_INDEX(msg->gtpc_msg.bearer_rsrc_cmd.lbi.ebi_ebi);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID for"
							"Bearer Resource Command\n ", LOG_VALUE);
					send_bearer_resource_failure_indication(msg,
							GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
							interface_type);
					return -1;
				}
			} else {
				send_bearer_resource_failure_indication(msg,
						GTPV2C_CAUSE_MANDATORY_IE_MISSING, CAUSE_SOURCE_SET_TO_0,
						interface_type);

				return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
			}

			/*Check LBI (pdn connection) for UE is exist or not*/
			ret = check_default_bearer_id_presence_in_ue(msg->gtpc_msg.bearer_rsrc_cmd.lbi.ebi_ebi,
															context);
			if(ret != 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Invalid LBI,pdn connection not found"
						"for ebi : %d\n,for Bearer Resource Command",
						LOG_VALUE, msg->gtpc_msg.bearer_rsrc_cmd.lbi.ebi_ebi);
				send_bearer_resource_failure_indication(msg,
						GTPV2C_CAUSE_MANDATORY_IE_INCORRECT, CAUSE_SOURCE_SET_TO_0,
						interface_type);
				return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
			}

			msg->proc = get_procedure(msg);
			if (update_ue_proc(context,msg->proc ,ebi_index) != 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"failed to update procedure\n",LOG_VALUE);
				return -1;
			}

			msg->state = CONNECTED_STATE;
			msg->cp_mode = context->cp_mode;
			msg->event = BEARER_RSRC_CMD_RCVD_EVNT;

		break;
	}

	case GTP_UPDATE_PDN_CONNECTION_SET_RSP: {
			teid_key_t teid_key = {0};

			if ((ret = decode_upd_pdn_conn_set_rsp((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.upd_pdn_rsp) == 0))
		        return -1;

			msg->proc = get_procedure(msg);

			snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
				msg->gtpc_msg.mb_rsp.header.teid.has_teid.seq);

		    /* If Received Error UP PDN Resp form peer node with 0 teid */
			if ((!(msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid)) &&
				(msg->gtpc_msg.upd_pdn_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

				struct teid_value_t *teid_value = NULL;

				teid_value = get_teid_for_seq_number(teid_key);
				if (teid_value == NULL) {
					/* TODO: Add the appropriate handling */
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get TEID value for Sequence "
						"Number key: %s \n", LOG_VALUE,
						teid_key.teid_key);
					return -1;
				}

				/* Delete the timer entry for  UP PDN REQ */
				delete_timer_entry(teid_value->teid);

				/* Copy local stored TEID in the MBResp header */
				msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid = teid_value->teid;

				/* Fill the response struct and sending peer node */
				mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
							S11_IFACE);
				process_error_occured_handler(&msg, NULL);

				/* Delete the TEID entry for UP PDN REQ */
				delete_teid_entry_for_seq(teid_key);
				/* Set the return value to skip SM */
				return GTPC_ZERO_TEID_FOUND;
			}

			delete_timer_entry(msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid);

			/* Delete the TEID entry for UP PDN REQ */
			delete_teid_entry_for_seq(teid_key);

			if(msg->gtpc_msg.upd_pdn_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED){
				mbr_error_response(msg, msg->gtpc_msg.upd_pdn_rsp.cause.cause_value,
						CAUSE_SOURCE_SET_TO_1, interface_type);
				return -1;
			}

			if(get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid, &context) != 0)
			{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE,
					msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid);
				mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
						CAUSE_SOURCE_SET_TO_0, interface_type);
				process_error_occured_handler(&msg, NULL);

				return -1;
			}


			msg->state = UPD_PDN_CONN_SET_REQ_SNT_STATE;
			msg->proc = get_procedure(msg);
			msg->event = UPD_PDN_CONN_SET_RESP_RCVD_EVNT;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
				" Msg_Type:%s[%u],"
					"State:%s, Event:%s\n",
				LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					get_state_string(msg->state), get_event_string(msg->event));

		break;
	}
	case GTP_PGW_RESTART_NOTIFICATION_ACK: {
			if ((ret = decode_pgw_rstrt_notif_ack((uint8_t *) gtpv2c_rx, &msg->gtpc_msg.pgw_rstrt_notif_ack) == 0))
			    return -1;

			msg->state = PGW_RSTRT_NOTIF_REQ_SNT_STATE;
			msg->proc = get_procedure(msg);
			msg->event = PGW_RSTRT_NOTIF_ACK_RCVD_EVNT;
			msg->interface_type = interface_type;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
					" Msg_Type:%s[%u],"
					"State:%s, Event:%s\n",
					LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
					get_state_string(msg->state), get_event_string(msg->event));
		break;
	}
	case GTP_IDENTIFICATION_RSP:{
		clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"Warning: Received GTP IDENTIFICATION RSP Message, i.e. Simulator"
					" Not support Delete PDN connection Set request feature.\n", LOG_VALUE);

			/* TODO: Need to handle this message in state m/c*/
			msg->state = END_STATE;
			msg->proc = END_PROC;
			msg->event = END_EVNT;
			msg->interface_type = interface_type;

		break;
	}

	case GTP_CHANGE_NOTIFICATION_REQ: {

			if((ret = decode_change_noti_req((uint8_t *) gtpv2c_rx,
				  &msg->gtpc_msg.change_not_req) == 0))
				    return -1;

			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);


			ebi_index = GET_EBI_INDEX(msg->gtpc_msg.change_not_req.lbi.ebi_ebi);
			if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);

					change_notification_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
							CAUSE_SOURCE_SET_TO_0, interface_type);
					return -1;
			}



			if(get_ue_context(msg->gtpc_msg.change_not_req.header.teid.has_teid.teid, &context)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE,
					msg->gtpc_msg.change_not_req.header.teid.has_teid.teid);

				change_notification_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
						CAUSE_SOURCE_SET_TO_0, interface_type);

					return -1;
			}

			msg->proc = get_procedure(msg);
			msg->state = context->eps_bearers[ebi_index]->pdn->state;
			msg->event = CHANGE_NOTIFICATION_REQ_RCVD_EVNT;
			context->eps_bearers[ebi_index]->pdn->proc = msg->proc;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Callback called for"
						  "Msg_Type:%s[%u], Teid:%u, "
						  "State:%s, Event:%s\n",
						  LOG_VALUE, gtp_type_str(msg->msg_type), msg->msg_type,
						  gtpv2c_rx->teid.has_teid.teid,
						  get_state_string(msg->state), get_event_string(msg->event));

			 break;
	}

	case GTP_CHANGE_NOTIFICATION_RSP: {
			teid_key_t teid_key = {0};

			if((ret = decode_change_noti_rsp((uint8_t *) gtpv2c_rx,
					&msg->gtpc_msg.change_not_rsp) == 0)) {
					return -1;
			}
			gtpv2c_rx->teid.has_teid.teid = ntohl(gtpv2c_rx->teid.has_teid.teid);

			msg->proc = get_procedure(msg);

			snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(msg->proc),
				msg->gtpc_msg.change_not_rsp.header.teid.has_teid.seq);

			/* If Received Error Change Notification Rsp  from peer node with 0 teid */
			if((!msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid) &&
					(msg->gtpc_msg.change_not_rsp.cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED)) {

				struct teid_value_t *teid_value = NULL;

				teid_value = get_teid_for_seq_number(teid_key);
				if (teid_value == NULL) {
					/* TODO: Add the appropriate handling */
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get TEID value for Sequence "
						"Number key : %s \n", LOG_VALUE,
						msg->gtpc_msg.change_not_rsp.header.teid.has_teid.seq);
					return -1;
				}

				/* Delete the timer entry for Change Notification REQ */
				delete_timer_entry(teid_value->teid);

				/* Copy local stored TEID in the Change Notification header */
				msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid = teid_value->teid;

				/* Fill the response struct and sending peer node */
				change_notification_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
						CAUSE_SOURCE_SET_TO_0, interface_type);

				/* Delete the TEID entry for Change Notification Req */
				delete_teid_entry_for_seq(teid_key);

				/* Set the return value to skip SM */
				return GTPC_ZERO_TEID_FOUND;
			}

			delete_timer_entry(msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid);

			/* Delete the TEID entry for Change Notification Req */
			delete_teid_entry_for_seq(teid_key);

			ret = get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid, &context);
			if(ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
					" UE context for teid: %d\n", LOG_VALUE,
					msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid);
				change_notification_error_response(msg, ret,
						CAUSE_SOURCE_SET_TO_0, interface_type);
				return -1;
			}

			msg->proc = get_procedure(msg);
			msg->state = CONNECTED_STATE;
			msg->event = CHANGE_NOTIFICATION_RSP_RCVD_EVNT;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;

		break;
	}

	default:
			/*If Event is not supported then we will called default handler. */
			/* Retrive UE state. */
			if (get_ue_context(ntohl(gtpv2c_rx->teid.has_teid.teid), &context) != 0) {
				msg->proc =  NONE_PROC;
				if (SGWC == context->cp_mode)
					msg->state = SGWC_NONE_STATE;
				else {
						if (pfcp_config.use_gx) {
							msg->state = PGWC_NONE_STATE;
						} else {
							msg->state = SGWC_NONE_STATE;
						}
					}
			} else {
					pdn = GET_PDN(context, ebi_index);
					if(pdn == NULL){
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
							"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
						return -1;
					}

					msg->state = pdn->state;
					msg->proc = pdn->proc;
			}

			msg->event = NONE_EVNT;
			msg->interface_type = interface_type;
			msg->cp_mode = context->cp_mode;

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"process_msgs-"
					"\n\tcase: SAEGWC::gw_cfg= %d;"
					"\n\tReceived GTPv2c Message Type: "
					"%s (%u) not supported... Discarding\n", LOG_VALUE,
					context->cp_mode, gtp_type_str(gtpv2c_rx->gtpc.message_type),
					gtpv2c_rx->gtpc.message_type);
			return -1;
	}

	/* copy packet for user level packet copying or li */
	if ((NULL != context) && (S11_IFACE == interface_type) && (GTP_CREATE_SESSION_REQ != msg->msg_type)) {
		int bytes_rx_li = bytes_rx;
		uint8_t gtpv2c_rx_li[MAX_GTPV2C_UDP_LEN] = {0};
		memcpy(gtpv2c_rx_li, gtpv2c_rx, bytes_rx);

		if (PRESENT == context->dupl) {
			process_pkt_for_li(context, S11_INTFC_IN, (uint8_t *)gtpv2c_rx_li,
					bytes_rx_li, ntohl(peer_addr->sin_addr.s_addr), ntohl(pfcp_config.s11_ip.s_addr),
					ntohs(peer_addr->sin_port), pfcp_config.s11_port);
		}
	}

	if ((NULL != context) && (S5S8_IFACE == interface_type)) {
		int bytes_rx_li = bytes_rx;
		uint8_t gtpv2c_rx_li[MAX_GTPV2C_UDP_LEN] = {0};
		memcpy(gtpv2c_rx_li, gtpv2c_rx, bytes_rx);

		if (PRESENT == context->dupl) {
			process_pkt_for_li(context, S5S8_C_INTFC_IN, (uint8_t *)gtpv2c_rx_li,
					bytes_rx_li, ntohl(peer_addr->sin_addr.s_addr), ntohl(pfcp_config.s5s8_ip.s_addr),
					ntohs(peer_addr->sin_port), pfcp_config.s5s8_port);
		}
	}

	RTE_SET_USED(peer_addr);
	RTE_SET_USED(interface_type);

	return 0;
}
