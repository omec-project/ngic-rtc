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
#include <stdio.h>
#include <getopt.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cfgfile.h>

#include "cp.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "debug_str.h"
#include "dp_ipc_api.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_messages_encoder.h"

#include "sm_arr.h"
#include "sm_pcnd.h"
#include "sm_struct.h"

#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

#include "cdnshelper.h"

extern int s11_fd;
extern socklen_t s11_mme_sockaddr_len;
extern pfcp_config_t pfcp_config;

uint32_t start_time;

/* S5S8 */
extern int s5s8_fd;
struct sockaddr_in s5s8_recv_sockaddr;
extern socklen_t s5s8_sockaddr_len;

struct cp_params cp_params;
extern struct cp_stats_t cp_stats;


uint16_t payload_length;

/*teid_info list pointer for upf*/
teid_info *upf_teid_info_head = NULL;

/**
 * @brief  : Process echo request
 * @param  : gtpv2c_rx, holds data from incoming request
 * @param  : gtpv2c_tx, structure to be filled with response
 * @param  : iface, interfcae from which request is received
 * @return : Returns 0 in case of success , -1 otherwise
 */
static uint8_t
process_echo_req(gtpv2c_header_t *gtpv2c_rx, gtpv2c_header_t *gtpv2c_tx, int iface)
{
	int ret = 0;
	uint16_t payload_length = 0;
	echo_request_t *echo_rx = (echo_request_t *) gtpv2c_rx;
	echo_request_t *echo_tx = (echo_request_t *) gtpv2c_tx;

	if((iface != S11_IFACE) && (iface != S5S8_IFACE)){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid interface %d \n", LOG_VALUE, iface);
		return -1;
	}

	ret = process_echo_request(gtpv2c_rx, gtpv2c_tx);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"main.c::control_plane()::Error"
				"\n\tprocess_echo_req "
				"%s: %s\n", LOG_VALUE,
				gtp_type_str(gtpv2c_rx->gtpc.message_type),
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
	}

	if ((iface == S11_IFACE) && ((echo_rx)->sending_node_feat).header.len) {
		if (((echo_rx)->sending_node_feat).sup_feat == PRN) {
			set_node_feature_ie((gtp_node_features_ie_t *) echo_tx, GTP_IE_NODE_FEATURES,
					sizeof(uint8_t), IE_INSTANCE_ZERO, PRN);
		}
	}
#ifdef USE_REST
	/* Reset ECHO Timers */
	if(iface == S11_IFACE){
		ret = process_response(s11_mme_sockaddr.sin_addr.s_addr);
		if (ret) {
			/* TODO: Error handling not implemented */
		}
	}else {
		ret = process_response(s5s8_recv_sockaddr.sin_addr.s_addr);
		if (ret) {
			/*TODO: Error handling not implemented */
		}
	}
#endif /* USE_REST */

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if(iface == S11_IFACE){
		gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len,SENT);
		cp_stats.echo++;
	}else{
		gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len,SENT);
		cp_stats.echo++;
	}
	return 0;
}

#ifdef USE_REST
/**
 * @brief  : Process echo response
 * @param  : gtpv2c_rx, holds data from incoming message
 * @param  : iface, interfcae from which response is received
 * @return : Returns 0 in case of success , -1 otherwise
 */
static uint8_t
process_echo_resp(gtpv2c_header_t *gtpv2c_rx, int iface)
{
	int ret = 0;

	if((iface != S11_IFACE) && (iface != S5S8_IFACE)){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid interface %d \n", LOG_VALUE, iface);
		return -1;
	}

	if(iface == S11_IFACE){
		ret = process_response(s11_mme_sockaddr.sin_addr.s_addr);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"main.c::control_plane()::Error"
					"\n\tprocess_echo_resp "
					"%s: %s\n", LOG_VALUE,
					gtp_type_str(gtpv2c_rx->gtpc.message_type),
					(ret < 0 ? strerror(-ret) : cause_str(ret)));
			/* Error handling not implemented */
			return -1;
		}
	}else{
		ret = process_response(s5s8_recv_sockaddr.sin_addr.s_addr);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane()::Error"
					"\n\tprocess_echo_resp "
					"%s: (%d) %s\n",
					gtp_type_str(gtpv2c_rx->gtpc.message_type), ret,
					(ret < 0 ? strerror(-ret) : cause_str(ret)));
			/* Error handling not implemented */
			return -1;
		}
	}
	return 0;
}
#endif /* USE_REST */


void
msg_handler_s11(void)
{
	int ret = 0, bytes_s11_rx = 0;
	msg_info msg = {0};
	bzero(&s11_rx_buf, sizeof(s11_rx_buf));
	bzero(&s11_tx_buf, sizeof(s11_tx_buf));
	gtpv2c_header_t *gtpv2c_s11_rx = (gtpv2c_header_t *) s11_rx_buf;
	gtpv2c_header_t *gtpv2c_s11_tx = (gtpv2c_header_t *) s11_tx_buf;

	bytes_s11_rx = recvfrom(s11_fd,
			s11_rx_buf, MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
			(struct sockaddr *) &s11_mme_sockaddr,
			&s11_mme_sockaddr_len);
	s11_mme_sockaddr.sin_addr.s_addr = ntohl(s11_mme_sockaddr.sin_addr.s_addr);
	if (bytes_s11_rx == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "SGWC|SAEGWC_s11 recvfrom error:"
				"\n\ton %s:%u - %s\n",
				inet_ntoa(s11_mme_sockaddr.sin_addr),
				s11_mme_sockaddr.sin_port,
				strerror(errno));
		return;
	}

	if ((bytes_s11_rx < 0) &&
		(errno == EAGAIN  || errno == EWOULDBLOCK))
		return;

	if (!gtpv2c_s11_rx->gtpc.message_type) {
		return;
	}

	if (bytes_s11_rx > 0)
		++cp_stats.rx;

	/* Reset periodic timers */
	process_response(s11_mme_sockaddr.sin_addr.s_addr);

	/*CLI: update counter for any req rcvd on s11 interface */
	if(gtpv2c_s11_rx->gtpc.message_type != GTP_DOWNLINK_DATA_NOTIFICATION_ACK &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_CREATE_BEARER_RSP &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_UPDATE_BEARER_RSP &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_DELETE_BEARER_RSP &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_PGW_RESTART_NOTIFICATION_ACK) {

			update_cli_stats(htonl((uint32_t)s11_mme_sockaddr.sin_addr.s_addr),
							gtpv2c_s11_rx->gtpc.message_type,RCVD,S11);
	}

	if (gtpv2c_s11_rx->gtpc.message_type == GTP_ECHO_REQ){
		if (bytes_s11_rx > 0) {

			/* this call will handle echo request for boh PGWC and SGWC */
			ret = process_echo_req(gtpv2c_s11_rx, gtpv2c_s11_tx, S11_IFACE);
			if(ret != 0){
				return;
			}
			++cp_stats.tx;
		}
		return;
	}else if(gtpv2c_s11_rx->gtpc.message_type == GTP_ECHO_RSP){
		if (bytes_s11_rx > 0) {

#ifdef USE_REST
			/* this call will handle echo responce for boh PGWC and SGWC */
			ret = process_echo_resp(gtpv2c_s11_rx, S11_IFACE);
			if(ret != 0){
				return;
			}
#endif /* USE_REST */
			++cp_stats.tx;
		}
		return;
	}else {

		if ((ret = gtpc_pcnd_check(gtpv2c_s11_rx, &msg, bytes_s11_rx,
						&s11_mme_sockaddr, S11_IFACE)) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT" Failure in gtpc_pcnd_check for s11 interface messages",
					LOG_VALUE);
			return;
		}

		if(gtpv2c_s11_rx->gtpc.message_type == GTP_DOWNLINK_DATA_NOTIFICATION_ACK ||
				gtpv2c_s11_rx->gtpc.message_type == GTP_CREATE_BEARER_RSP ||
				gtpv2c_s11_rx->gtpc.message_type == GTP_UPDATE_BEARER_RSP ||
				gtpv2c_s11_rx->gtpc.message_type == GTP_DELETE_BEARER_RSP ||
				gtpv2c_s11_rx->gtpc.message_type == GTP_PGW_RESTART_NOTIFICATION_ACK ) {
				update_cli_stats(htonl((uint32_t)s11_mme_sockaddr.sin_addr.s_addr),
								gtpv2c_s11_rx->gtpc.message_type,ACC,S11);
			}

		/* State Machine execute on session level, but following messages are NODE level */
		if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_REQ) {
			/* Process RCVD Delete PDN Connection Set request */
			ret = process_del_pdn_conn_set_req(&msg, NULL);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_del_pdn_conn_set_req() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;
		} else if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_RSP) {
			/* Process RCVD Delete PDN Connection Set response */
			ret = process_del_pdn_conn_set_rsp(&msg, NULL);
			if (ret) {
				/* DsTool sending Mandetory IE Missing */
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"process_del_pdn_conn_set_rsp() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;

		} else if (msg.msg_type == GTP_PGW_RESTART_NOTIFICATION_ACK) {
			/* Process RCVD PGW Restart Notification Ack */
			ret = process_pgw_rstrt_notif_ack(&msg, NULL);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_pgw_rstrt_notif_ack() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;

		} else {
			if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
				if (SGWC == msg.cp_mode) {
				    ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
				} else if (PGWC == msg.cp_mode) {
				    ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
				} else if (SAEGWC == msg.cp_mode) {
				    ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, NULL);
				} else {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
							"Invalid Control Plane Type: %d \n",
							LOG_VALUE, msg.cp_mode);
					return;
				}

				if(ret == GTPC_RE_TRANSMITTED_REQ) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Discarding re-transmitted %s Error: %d \n",
							LOG_VALUE, gtp_type_str(gtpv2c_s11_rx->gtpc.message_type), ret);
					return;
				}
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"State_Machine Callback failed with Error: %d \n",
							LOG_VALUE, ret);
					return;
				}
			} else {
				if ((msg.proc == END_PROC) &&
						(msg.state == END_STATE) &&
						(msg.event == END_EVNT)) {
					return;
				}

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Invalid Procedure or State or Event \n",
							LOG_VALUE);
				return;
			}
		}
	}

	switch (msg.cp_mode) {
	case SGWC:
	case PGWC:
	case SAEGWC:
		if (bytes_s11_rx > 0) {
			++cp_stats.tx;
			switch (gtpv2c_s11_rx->gtpc.message_type) {
			case GTP_CREATE_SESSION_REQ:
				cp_stats.create_session++;
				break;
			case GTP_DELETE_SESSION_REQ:
					cp_stats.delete_session++;
				break;
			case GTP_MODIFY_BEARER_REQ:
				cp_stats.modify_bearer++;
				break;
			case GTP_RELEASE_ACCESS_BEARERS_REQ:
				cp_stats.rel_access_bearer++;

				break;
			case GTP_BEARER_RESOURCE_CMD:
				cp_stats.bearer_resource++;
				break;
			case GTP_CREATE_BEARER_RSP:
				cp_stats.create_bearer++;
				return;
			case GTP_DELETE_BEARER_RSP:
				cp_stats.delete_bearer++;
				return;
			case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
				cp_stats.ddn_ack++;
			}
		}
		break;
	default:
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"cp_stats: Unknown msg.cp_mode= %u\n", LOG_VALUE, msg.cp_mode);
		break;
	}

}

void
msg_handler_s5s8(void)
{
	int ret = 0;
	int bytes_s5s8_rx = 0;
	msg_info msg = {0};
	uint32_t s5s8_cli_addr;
	bzero(&s5s8_rx_buf, sizeof(s5s8_rx_buf));
	gtpv2c_header_t *gtpv2c_s5s8_rx = (gtpv2c_header_t *) s5s8_rx_buf;

#ifdef USE_REST
	bzero(&s5s8_tx_buf, sizeof(s5s8_tx_buf));
	gtpv2c_header_t *gtpv2c_s5s8_tx = (gtpv2c_header_t *) s5s8_tx_buf;
#endif /* USE_REST */

	bytes_s5s8_rx = recvfrom(s5s8_fd, s5s8_rx_buf,
			MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
			(struct sockaddr *) &s5s8_recv_sockaddr,
			&s5s8_sockaddr_len);
	s5s8_cli_addr = s5s8_recv_sockaddr.sin_addr.s_addr;
	s5s8_recv_sockaddr.sin_addr.s_addr = ntohl(s5s8_recv_sockaddr.sin_addr.s_addr);

	if(cli_node.s5s8_selection == NOT_PRESENT) {
		cli_node.s5s8_selection = OSS_S5S8_RECEIVER;
	}

	if (bytes_s5s8_rx == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"s5s8 recvfrom error:"
				"\n\ton %s:%u - %s\n", LOG_VALUE,
				inet_ntoa(s5s8_recv_sockaddr.sin_addr),
				s5s8_recv_sockaddr.sin_port,
				strerror(errno));
	}

	if (
			(bytes_s5s8_rx < 0) &&
			(errno == EAGAIN  || errno == EWOULDBLOCK)
	   )
		return;

	if (!gtpv2c_s5s8_rx->gtpc.message_type) {
		return;
	}

	if (bytes_s5s8_rx > 0)
		++cp_stats.rx;

	/* Reset periodic timers */
	process_response(s5s8_recv_sockaddr.sin_addr.s_addr);

	if(gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_REQ) {
		if (bytes_s5s8_rx > 0) {
#ifdef USE_REST
			ret = process_echo_req(gtpv2c_s5s8_rx, gtpv2c_s5s8_tx, S5S8_IFACE);
			if(ret != 0){
				return;
			}
			update_cli_stats(s5s8_cli_addr,
					gtpv2c_s5s8_rx->gtpc.message_type, RCVD, S5S8);
#endif /* USE_REST */
			++cp_stats.tx;
		}
		return;
	}else if(gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_RSP){
		if (bytes_s5s8_rx > 0) {
#ifdef USE_REST
			ret = process_echo_resp(gtpv2c_s5s8_rx, S5S8_IFACE);
			if(ret != 0){
				return;
			}
			update_cli_stats(s5s8_cli_addr,
					gtpv2c_s5s8_rx->gtpc.message_type, RCVD, S5S8);
#endif /* USE_REST */
			++cp_stats.tx;
		}

		return;
	}else {

		if ((ret = gtpc_pcnd_check(gtpv2c_s5s8_rx, &msg, bytes_s5s8_rx,
						&s5s8_recv_sockaddr, S5S8_IFACE)) != 0)
		{
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT" Failure in gtpc_pcnd_check for s5s8 interface messages\n",
					LOG_VALUE);
			/*CLI: update csr, dsr, mbr rej response*/
			update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,REJ,S5S8);
			return;
		}

		/*TODO:CLI handler should be done in handlers;*/
		if((msg.cp_mode == PGWC) && (gtpv2c_s5s8_rx->gtpc.message_type != GTP_CREATE_BEARER_RSP &&
					gtpv2c_s5s8_rx->gtpc.message_type != GTP_DELETE_BEARER_RSP &&
					gtpv2c_s5s8_rx->gtpc.message_type != GTP_UPDATE_BEARER_RSP ))
			update_cli_stats(s5s8_cli_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,RCVD,S5S8);

		if ((msg.cp_mode == SGWC) && (gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_REQ ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_RSP ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_CREATE_BEARER_REQ ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_DELETE_BEARER_REQ ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_UPDATE_BEARER_REQ ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_DELETE_PDN_CONNECTION_SET_RSP ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_DELETE_PDN_CONNECTION_SET_REQ)) {

			update_cli_stats(s5s8_cli_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,RCVD,S5S8);
		}

		if ((msg.cp_mode == SGWC) &&
				(gtpv2c_s5s8_rx->gtpc.message_type != GTP_DELETE_PDN_CONNECTION_SET_RSP &&
				 gtpv2c_s5s8_rx->gtpc.message_type != GTP_DELETE_PDN_CONNECTION_SET_REQ &&
				 gtpv2c_s5s8_rx->gtpc.message_type != GTP_CREATE_BEARER_REQ &&
				 gtpv2c_s5s8_rx->gtpc.message_type != GTP_DELETE_BEARER_REQ &&
				 gtpv2c_s5s8_rx->gtpc.message_type != GTP_UPDATE_BEARER_REQ &&
				 gtpv2c_s5s8_rx->gtpc.message_type != GTP_DELETE_PDN_CONNECTION_SET_REQ))
			update_cli_stats(s5s8_cli_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,ACC,S5S8);

		if (msg.cp_mode == SGWC)
		{
			if (gtpv2c_s5s8_rx->gtpc.message_type == GTP_CREATE_SESSION_RSP )
			{
				if (s5s8_recv_sockaddr.sin_addr.s_addr != 0) {
					add_node_conn_entry(s5s8_recv_sockaddr.sin_addr.s_addr, S5S8_SGWC_PORT_ID,
							msg.cp_mode);
				}
			}
			if (gtpv2c_s5s8_rx->gtpc.message_type == GTP_MODIFY_BEARER_RSP)
			{
				if (s5s8_recv_sockaddr.sin_addr.s_addr != 0) {
					add_node_conn_entry(s5s8_recv_sockaddr.sin_addr.s_addr, S5S8_SGWC_PORT_ID,
							msg.cp_mode);
				}
			}
		}

		if (msg.cp_mode == PGWC && (gtpv2c_s5s8_rx->gtpc.message_type == GTP_CREATE_BEARER_RSP ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_DELETE_BEARER_RSP ||
					gtpv2c_s5s8_rx->gtpc.message_type == GTP_UPDATE_BEARER_RSP ))

			update_cli_stats(s5s8_cli_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,ACC,S5S8);

		/* State Machine execute on session level, but following messages are NODE level */
		if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_REQ) {
			/* Process RCVD Delete PDN Connection Set request */
			ret = process_del_pdn_conn_set_req(&msg, NULL);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_del_pdn_conn_set_req() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;
		} else if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_RSP) {
			/* Process RCVD Delete PDN Connection Set response */
			ret = process_del_pdn_conn_set_rsp(&msg, NULL);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_del_pdn_conn_set_rsp() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;
		} else {
			if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
				if (SGWC == msg.cp_mode) {
					ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
				} else if (PGWC == msg.cp_mode) {
					ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
				} else if (SAEGWC == msg.cp_mode) {
					ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, NULL);
				} else {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Invalid Control Plane Type: %d \n",
							LOG_VALUE, msg.cp_mode);
					return;
				}

				if(ret == GTPC_RE_TRANSMITTED_REQ) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Discarding re-transmitted %s Error: %d \n",
							LOG_VALUE, gtp_type_str(gtpv2c_s5s8_rx->gtpc.message_type), ret);
					return;
				}

				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"State_Machine Callback failed with Error: %d \n",
							LOG_VALUE, ret);
					return;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Invalid Procedure or State or Event \n",
							LOG_VALUE);
				return;
			}
		}
	}

	if (bytes_s5s8_rx > 0)
		++cp_stats.tx;

	switch (msg.cp_mode) {
		case SGWC:
			break; //do not update console stats for SGWC
		case PGWC:
			if (bytes_s5s8_rx > 0) {
				switch (gtpv2c_s5s8_rx->gtpc.message_type) {
					case GTP_CREATE_SESSION_REQ:
						cp_stats.create_session++;
						break;
					case GTP_MODIFY_BEARER_REQ:
						cp_stats.modify_bearer++;
						break;
					case GTP_DELETE_SESSION_REQ:
						cp_stats.delete_session++;
						break;
					case GTP_BEARER_RESOURCE_CMD:
						cp_stats.bearer_resource++;
						break;
					case GTP_CREATE_BEARER_RSP:
						cp_stats.create_bearer++;
						break;
				}
			}
			break;
		default:
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"cp_stats: Unknown msg.cp_mode= %u\n", LOG_VALUE, msg.cp_mode);
			break;
	}
}

const char *
get_cc_string(uint16_t cc_value){

	switch(cc_value){
		case HOME:
			return "HOME";
		case VISITING:
			return "VISITING";
		case ROAMING:
			return "ROAMING";
		default:
			return "Unknown";
	}
	return "";
}
