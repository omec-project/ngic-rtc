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
#include "ngic_timer.h"
#endif /* USE_REST */

#include "cdnshelper.h"

extern int s11_fd;
extern int s11_fd_v6;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s11_mme_sockaddr_ipv6_len;
extern pfcp_config_t config;
extern peer_addr_t s11_mme_sockaddr;
extern int clSystemLog;
uint32_t start_time;
extern struct rte_hash *conn_hash_handle;

/* S5S8 */
extern int s5s8_fd;
extern int s5s8_fd_v6;
struct peer_addr_t s5s8_recv_sockaddr;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s5s8_sockaddr_ipv6_len;

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
	node_address_t node_addr = {0};
	/* Reset ECHO Timers */
	if(iface == S11_IFACE){
		get_peer_node_addr(&s11_mme_sockaddr, &node_addr);
		ret = process_response(&node_addr);
		if (ret) {
			/* TODO: Error handling not implemented */
		}
	}else {
		get_peer_node_addr(&s5s8_recv_sockaddr, &node_addr);
		ret = process_response(&node_addr);
		if (ret) {
			/*TODO: Error handling not implemented */
		}
	}
#endif /* USE_REST */

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if(iface == S11_IFACE){
		gtpv2c_send(s11_fd, s11_fd_v6, s11_tx_buf, payload_length,
				s11_mme_sockaddr, SENT);
		cp_stats.echo++;
	} else{
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, s5s8_tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);
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
	node_address_t node_addr = {0};

	if((iface != S11_IFACE) && (iface != S5S8_IFACE)){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid interface %d \n", LOG_VALUE, iface);
		return -1;
	}

	if(iface == S11_IFACE){
		get_peer_node_addr(&s11_mme_sockaddr, &node_addr);
		ret = process_response(&node_addr);
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
		get_peer_node_addr(&s5s8_recv_sockaddr, &node_addr);
		ret = process_response(&node_addr);
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
msg_handler_s11(bool is_ipv6)
{
	int ret = 0, bytes_s11_rx = 0;
	msg_info msg = {0};
	bzero(&s11_rx_buf, sizeof(s11_rx_buf));
	bzero(&s11_tx_buf, sizeof(s11_tx_buf));
	gtpv2c_header_t *gtpv2c_s11_rx = (gtpv2c_header_t *) s11_rx_buf;
	gtpv2c_header_t *gtpv2c_s11_tx = (gtpv2c_header_t *) s11_tx_buf;
	gtpv2c_header_t *piggy_backed;
	memset(&s11_mme_sockaddr, 0, sizeof(s11_mme_sockaddr));

	if (!is_ipv6) {
		bytes_s11_rx = recvfrom(s11_fd, s11_rx_buf, MAX_GTPV2C_UDP_LEN,
					MSG_DONTWAIT, (struct sockaddr *) &s11_mme_sockaddr.ipv4,
					&s11_mme_sockaddr_len);

		s11_mme_sockaddr.type |= PDN_TYPE_IPV4;
		clLog(clSystemLog, eCLSeverityDebug, "SGWC|SAEGWC_s11 received %d bytes "
			"with IPv4 Address for message %d", bytes_s11_rx,
			gtpv2c_s11_rx->gtpc.message_type);

	} else {

		bytes_s11_rx = recvfrom(s11_fd_v6, s11_rx_buf, MAX_GTPV2C_UDP_LEN,
						MSG_DONTWAIT, (struct sockaddr *) &s11_mme_sockaddr.ipv6,
						&s11_mme_sockaddr_ipv6_len);

		s11_mme_sockaddr.type |= PDN_TYPE_IPV6;
		clLog(clSystemLog, eCLSeverityDebug, "SGWC|SAEGWC_s11 received  %d bytes "
			"with IPv6 Address for message %d", bytes_s11_rx,
			gtpv2c_s11_rx->gtpc.message_type);

	}

	if (bytes_s11_rx == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "SGWC|SAEGWC_s11 recvfrom error:"
				"\n\t on %s "IPv6_FMT" :%u - %s\n",
				inet_ntoa(s11_mme_sockaddr.ipv4.sin_addr),
				IPv6_PRINT(s11_mme_sockaddr.ipv6.sin6_addr),
				s11_mme_sockaddr.ipv4.sin_port,
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

#ifdef USE_REST
	/* Reset periodic timers */
	node_address_t node_addr = {0};
	get_peer_node_addr(&s11_mme_sockaddr, &node_addr);
	process_response(&node_addr);
#endif /* USE_REST */

	/*CLI: update counter for any req rcvd on s11 interface */
	if(gtpv2c_s11_rx->gtpc.message_type != GTP_DOWNLINK_DATA_NOTIFICATION_ACK &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_CREATE_BEARER_RSP &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_UPDATE_BEARER_RSP &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_DELETE_BEARER_RSP &&
			gtpv2c_s11_rx->gtpc.message_type != GTP_PGW_RESTART_NOTIFICATION_ACK) {

			update_cli_stats((peer_address_t *)&s11_mme_sockaddr,
							gtpv2c_s11_rx->gtpc.message_type,RCVD,S11);
	}

	if(gtpv2c_s11_rx->gtpc.piggyback) {
		piggy_backed = (gtpv2c_header_t*) ((uint8_t *)gtpv2c_s11_rx +
				sizeof(gtpv2c_s11_rx->gtpc) + ntohs(gtpv2c_s11_rx->gtpc.message_len));

		update_cli_stats((peer_address_t *)&s11_mme_sockaddr,
				piggy_backed->gtpc.message_type, RCVD, S11);
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

				update_cli_stats((peer_address_t *)&s11_mme_sockaddr,
								gtpv2c_s11_rx->gtpc.message_type,ACC,S11);
			}

		/* State Machine execute on session level, but following messages are NODE level */
		if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_REQ) {
			/* Process RCVD Delete PDN Connection Set request */
			ret = process_del_pdn_conn_set_req(&msg, &s11_mme_sockaddr);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_del_pdn_conn_set_req() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;
		} else if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_RSP) {
			/* Process RCVD Delete PDN Connection Set response */
			ret = process_del_pdn_conn_set_rsp(&msg, &s11_mme_sockaddr);
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
msg_handler_s5s8(bool is_ipv6)
{
	int ret = 0;
	int bytes_s5s8_rx = 0;
	msg_info msg = {0};
	node_address_t s5s8_cli_addr = {0};

	bzero(&s5s8_rx_buf, sizeof(s5s8_rx_buf));
	gtpv2c_header_t *gtpv2c_s5s8_rx = (gtpv2c_header_t *) s5s8_rx_buf;
	gtpv2c_header_t *piggy_backed;
#ifdef USE_REST
	bzero(&s5s8_tx_buf, sizeof(s5s8_tx_buf));
	gtpv2c_header_t *gtpv2c_s5s8_tx = (gtpv2c_header_t *) s5s8_tx_buf;
#endif /* USE_REST */

	s5s8_recv_sockaddr.type = 0;
	if (!is_ipv6){

		bytes_s5s8_rx = recvfrom(s5s8_fd, s5s8_rx_buf, MAX_GTPV2C_UDP_LEN,
					MSG_DONTWAIT, (struct sockaddr *) &s5s8_recv_sockaddr.ipv4,
					&s5s8_sockaddr_len);

		s5s8_recv_sockaddr.type |= PDN_TYPE_IPV4;
		clLog(clSystemLog, eCLSeverityDebug, "s5s8 received %d bytes "
			"with IPv4 Address for message %d", bytes_s5s8_rx,
			gtpv2c_s5s8_rx->gtpc.message_type);

	} else {

		bytes_s5s8_rx = recvfrom(s5s8_fd_v6, s5s8_rx_buf, MAX_GTPV2C_UDP_LEN,
						MSG_DONTWAIT, (struct sockaddr *) &s5s8_recv_sockaddr.ipv6,
						&s5s8_sockaddr_ipv6_len);

		s5s8_recv_sockaddr.type |= PDN_TYPE_IPV6;
		clLog(clSystemLog, eCLSeverityDebug, "s5s8 received %d bytes "
			"with IPv6 Address for message %d", bytes_s5s8_rx,
			gtpv2c_s5s8_rx->gtpc.message_type);

	}

	if (bytes_s5s8_rx == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "s5s8 recvfrom error:"
				"\n\ton %s "IPv6_FMT" :%u - %s\n",
				inet_ntoa(s5s8_recv_sockaddr.ipv4.sin_addr),
				IPv6_PRINT(s5s8_recv_sockaddr.ipv6.sin6_addr),
				s5s8_recv_sockaddr.ipv4.sin_port,
				strerror(errno));
		return;
	}

	ret = fill_ip_addr(s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
				s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr,
				&s5s8_cli_addr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"S5S8 IP", LOG_VALUE);
	}

	add_cli_peer((peer_address_t *) &s5s8_recv_sockaddr, S5S8);

	if(cli_node.s5s8_selection == NOT_PRESENT) {
		cli_node.s5s8_selection = OSS_S5S8_RECEIVER;
	}

	if (bytes_s5s8_rx == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"s5s8 recvfrom error:"
				"\n\ton %s:%u - %s\n", LOG_VALUE,
				inet_ntoa(s5s8_recv_sockaddr.ipv4.sin_addr),
				s5s8_recv_sockaddr.ipv4.sin_port,
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
	node_address_t node_addr = {0};
	get_peer_node_addr(&s5s8_recv_sockaddr, &node_addr);
	process_response(&node_addr);

	if(gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_REQ) {
		if (bytes_s5s8_rx > 0) {
#ifdef USE_REST
			ret = process_echo_req(gtpv2c_s5s8_rx, gtpv2c_s5s8_tx, S5S8_IFACE);
			if(ret != 0){
				return;
			}

			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
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

			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
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
			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
					gtpv2c_s5s8_rx->gtpc.message_type, REJ, S5S8);
			return;
		}

		if ((msg.cp_mode == SGWC) &&
			(dRespRcvd == ossS5s8MessageDefs[s5s8MessageTypes[gtpv2c_s5s8_rx->gtpc.message_type]].dir)) {
			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
					gtpv2c_s5s8_rx->gtpc.message_type, ACC, S5S8);
		} else if(msg.cp_mode == SGWC) {
			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
				gtpv2c_s5s8_rx->gtpc.message_type, RCVD, S5S8);
		} else if((msg.cp_mode == PGWC) &&
			(dRespRcvd == ossS5s8MessageDefs[s5s8MessageTypes[gtpv2c_s5s8_rx->gtpc.message_type]].pgwc_dir))
			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
				gtpv2c_s5s8_rx->gtpc.message_type, ACC, S5S8);
		else {
			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
				gtpv2c_s5s8_rx->gtpc.message_type, RCVD, S5S8);
		}

		if(gtpv2c_s5s8_rx->gtpc.piggyback) {

			piggy_backed = (gtpv2c_header_t*) ((uint8_t *)gtpv2c_s5s8_rx +
					sizeof(gtpv2c_s5s8_rx->gtpc) + ntohs(gtpv2c_s5s8_rx->gtpc.message_len));
			update_cli_stats((peer_address_t *) &s5s8_recv_sockaddr,
					piggy_backed->gtpc.message_type, RCVD, S5S8);
		}

		if (msg.cp_mode == SGWC)
		{
			if (gtpv2c_s5s8_rx->gtpc.message_type == GTP_CREATE_SESSION_RSP )
			{
				if ((s5s8_recv_sockaddr.ipv4.sin_addr.s_addr != 0)
						|| (s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr)) {
					node_address_t node_addr = {0};
					get_peer_node_addr(&s5s8_recv_sockaddr, &node_addr);
					add_node_conn_entry(&node_addr, S5S8_SGWC_PORT_ID,
							msg.cp_mode);
				}
			}
			if (gtpv2c_s5s8_rx->gtpc.message_type == GTP_MODIFY_BEARER_RSP)
			{
				if ((s5s8_recv_sockaddr.ipv4.sin_addr.s_addr != 0)
						|| (s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr)) {
					node_address_t node_addr = {0};
					get_peer_node_addr(&s5s8_recv_sockaddr, &node_addr);
					add_node_conn_entry(&node_addr, S5S8_SGWC_PORT_ID,
							msg.cp_mode);
				}
			}
		}

		/* State Machine execute on session level, but following messages are NODE level */
		if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_REQ) {
			/* Process RCVD Delete PDN Connection Set request */
			ret = process_del_pdn_conn_set_req(&msg, &s5s8_recv_sockaddr);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_del_pdn_conn_set_req() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return;
		} else if (msg.msg_type == GTP_DELETE_PDN_CONNECTION_SET_RSP) {
			/* Process RCVD Delete PDN Connection Set response */
			ret = process_del_pdn_conn_set_rsp(&msg, &s5s8_recv_sockaddr);
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
			break;
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

static int update_periodic_timer_value(const int periodic_timer_value) {
	peerData *conn_data = NULL;
	const void *key;
	uint32_t iter = 0;
	config.periodic_timer = periodic_timer_value;
	if(conn_hash_handle != NULL) {
		while (rte_hash_iterate(conn_hash_handle, &key, (void **)&conn_data, &iter) >= 0) {

			/* If Initial timer value was set to 0, then start the timer */
			if (!conn_data->pt.ti_ms) {
					conn_data->pt.ti_ms = (periodic_timer_value * 1000);
					if (startTimer( &conn_data->pt ) < 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Periodic Timer failed to start...\n", LOG_VALUE);
					}
			} else {
					conn_data->pt.ti_ms = (periodic_timer_value * 1000);
			}
		}
	}
	return 0;
}

static int update_transmit_timer_value(const int transmit_timer_value) {
	peerData *conn_data = NULL;
	const void *key;
	uint32_t iter = 0;
	config.transmit_timer = transmit_timer_value;
	if(conn_hash_handle != NULL) {
		while (rte_hash_iterate(conn_hash_handle, &key, (void **)&conn_data, &iter) >= 0) {
			/* If Initial timer value was set to 0, then start the timer */
			if (!conn_data->tt.ti_ms) {
					conn_data->tt.ti_ms = (transmit_timer_value * 1000);
					if (startTimer( &conn_data->tt ) < 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Transmit Timer failed to start...\n", LOG_VALUE);
					}
			} else {
					conn_data->tt.ti_ms = (transmit_timer_value * 1000);
			}
		}
	}
	return 0;
}

int8_t fill_cp_configuration(cp_configuration_t *cp_configuration)
{
	cp_configuration->cp_type = OSS_CONTROL_PLANE;
	cp_configuration->s11_port = config.s11_port;
	cp_configuration->s5s8_port = config.s5s8_port;
	cp_configuration->pfcp_port = config.pfcp_port;
	cp_configuration->dadmf_port = config.dadmf_port;
	strncpy(cp_configuration->dadmf_ip, config.dadmf_ip, IPV6_STR_LEN);
	cp_configuration->upf_pfcp_port = config.upf_pfcp_port;
	cp_configuration->upf_pfcp_ip.s_addr = config.upf_pfcp_ip.s_addr;
	cp_configuration->redis_port = config.redis_port;
	strncpy(cp_configuration->redis_ip_buff, config.redis_ip_buff,
			IPV6_STR_LEN);
	cp_configuration->request_tries = config.request_tries;
	cp_configuration->request_timeout = config.request_timeout;
	cp_configuration->use_dns = config.use_dns;
	cp_configuration->trigger_type = config.trigger_type;
	cp_configuration->uplink_volume_th = config.uplink_volume_th;
	cp_configuration->downlink_volume_th = config.downlink_volume_th;
	cp_configuration->time_th = config.time_th;
	cp_configuration->ip_pool_ip.s_addr = config.ip_pool_ip.s_addr;
	cp_configuration->generate_cdr = config.generate_cdr;
	cp_configuration->generate_sgw_cdr = config.generate_sgw_cdr;
	cp_configuration->sgw_cc = config.sgw_cc;
	cp_configuration->ip_pool_mask.s_addr = config.ip_pool_mask.s_addr;
	cp_configuration->num_apn = config.num_apn;
	cp_configuration->restoration_params.transmit_cnt = config.transmit_cnt;
	cp_configuration->restoration_params.transmit_timer = config.transmit_timer;
	cp_configuration->restoration_params.periodic_timer = config.periodic_timer;
	strncpy(cp_configuration->cp_redis_ip_buff, config.cp_redis_ip_buff,
			IPV6_STR_LEN);
	strncpy(cp_configuration->ddf2_ip, config.ddf2_ip, IPV6_STR_LEN);
	cp_configuration->add_default_rule = config.add_default_rule;
	cp_configuration->ddf2_port = config.ddf2_port;
	strncpy(cp_configuration->redis_cert_path, config.redis_cert_path, REDIS_CERT_PATH_LEN);
	strncpy(cp_configuration->ddf2_local_ip, config.ddf2_local_ip, IPV6_STR_LEN);
	strncpy(cp_configuration->dadmf_local_addr, config.dadmf_local_addr, IPV6_STR_LEN);
	cp_configuration->use_gx = config.use_gx;
	cp_configuration->generate_sgw_cdr = config.generate_sgw_cdr;
	cp_configuration->sgw_cc = config.sgw_cc;

	if(config.cp_type != SGWC)
	{
		cp_configuration->is_gx_interface = PRESENT;
	}

	cp_configuration->s11_ip.s_addr = config.s11_ip.s_addr;
	cp_configuration->s5s8_ip.s_addr = config.s5s8_ip.s_addr;
	cp_configuration->pfcp_ip.s_addr = config.pfcp_ip.s_addr;

	for(uint8_t itr_apn = 0; itr_apn < cp_configuration->num_apn; itr_apn++)
	{
		cp_configuration->apn_list[itr_apn].apn_usage_type = apn_list[itr_apn].apn_usage_type;
		cp_configuration->apn_list[itr_apn].trigger_type = apn_list[itr_apn].trigger_type;
		cp_configuration->apn_list[itr_apn].uplink_volume_th = apn_list[itr_apn].uplink_volume_th;
		cp_configuration->apn_list[itr_apn].downlink_volume_th = apn_list[itr_apn].downlink_volume_th;
		cp_configuration->apn_list[itr_apn].time_th = apn_list[itr_apn].time_th;
		strncpy(cp_configuration->apn_list[itr_apn].apn_name_label,
				apn_list[itr_apn].apn_name_label+1, APN_NAME_LEN);
		strncpy(cp_configuration->apn_list[itr_apn].apn_net_cap, apn_list[itr_apn].apn_net_cap, MAX_NETCAP_LEN);
		cp_configuration->apn_list[itr_apn].ip_pool_ip.s_addr =
			apn_list[itr_apn].ip_pool_ip.s_addr;
		cp_configuration->apn_list[itr_apn].ip_pool_mask.s_addr =
			apn_list[itr_apn].ip_pool_mask.s_addr;
		cp_configuration->apn_list[itr_apn].ipv6_prefix_len =
			apn_list[itr_apn].ipv6_prefix_len;
		cp_configuration->apn_list[itr_apn].ipv6_network_id =
			apn_list[itr_apn].ipv6_network_id;
	}

	cp_configuration->dns_cache.concurrent = config.dns_cache.concurrent;
	cp_configuration->dns_cache.sec = (config.dns_cache.sec / 1000);
	cp_configuration->dns_cache.percent = config.dns_cache.percent;
	cp_configuration->dns_cache.timeoutms = config.dns_cache.timeoutms;
	cp_configuration->dns_cache.tries = config.dns_cache.tries;

	cp_configuration->app_dns.freq_sec = config.app_dns.freq_sec;
	cp_configuration->app_dns.nameserver_cnt = config.app_dns.nameserver_cnt;
	strncpy(cp_configuration->app_dns.filename, config.app_dns.filename, PATH_LEN);
	strncpy(cp_configuration->app_dns.nameserver_ip[config.app_dns.nameserver_cnt-DNS_IP_INDEX],
			config.app_dns.nameserver_ip[config.app_dns.nameserver_cnt-DNS_IP_INDEX], IPV6_STR_LEN);

	cp_configuration->ops_dns.freq_sec = config.ops_dns.freq_sec;
	cp_configuration->ops_dns.nameserver_cnt = config.ops_dns.nameserver_cnt;
	strncpy(cp_configuration->ops_dns.filename, config.ops_dns.filename, PATH_LEN);
	strncpy(cp_configuration->ops_dns.nameserver_ip[config.ops_dns.nameserver_cnt-DNS_IP_INDEX],
		config.ops_dns.nameserver_ip[config.ops_dns.nameserver_cnt-DNS_IP_INDEX], IPV6_STR_LEN);

	cp_configuration->dl_buf_suggested_pkt_cnt = config.dl_buf_suggested_pkt_cnt;
	cp_configuration->low_lvl_arp_priority = config.low_lvl_arp_priority;
	cp_configuration->ipv6_network_id = config.ipv6_network_id;
	cp_configuration->ipv6_prefix_len = config.ipv6_prefix_len;
	cp_configuration->ip_allocation_mode = config.ip_allocation_mode;
	cp_configuration->ip_type_supported = config.ip_type_supported;
	cp_configuration->ip_type_priority = config.ip_type_priority;
	strncpy(cp_configuration->cp_dns_ip_buff,
		config.cp_dns_ip_buff, IPV6_STR_LEN);
	cp_configuration->s5s8_ip_v6 = config.s5s8_ip_v6;
	cp_configuration->pfcp_ip_v6 = config.pfcp_ip_v6;
	cp_configuration->upf_pfcp_ip_v6 = config.upf_pfcp_ip_v6;
	cp_configuration->s11_ip_v6 = config.s11_ip_v6;
	strncpy(cp_configuration->cli_rest_ip_buff, config.cli_rest_ip_buff, IPV6_STR_LEN);
	cp_configuration->cli_rest_port = config.cli_rest_port;

	return 0;
}

int8_t	post_request_timeout(const int request_timeout_value) {
	config.request_timeout = request_timeout_value;
	return 0;
}

int8_t	post_request_tries(const int number_of_request_tries) {
	config.request_tries = number_of_request_tries;
	return 0;
}

int8_t	post_periodic_timer(const int periodic_timer_value) {
	update_periodic_timer_value(periodic_timer_value);
	return 0;
}

int8_t	post_transmit_timer(const int transmit_timer_value) {
	update_transmit_timer_value(transmit_timer_value);
	return 0;
}

int8_t	post_transmit_count(const int transmit_count) {
	config.transmit_cnt = transmit_count;
	return 0;
}

int	get_request_timeout(void) {
	return config.request_timeout;
}

int	get_request_tries(void) {
	return config.request_tries;
}

int	get_periodic_timer(void) {
	return config.periodic_timer;
}

int	get_transmit_timer(void) {
	return config.transmit_timer;
}

int	get_transmit_count(void) {
	return config.transmit_cnt;
}
