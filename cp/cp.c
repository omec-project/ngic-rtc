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

#ifdef USE_DNS_QUERY
#include "cdnshelper.h"
#endif /* USE_DNS_QUERY */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

extern int s11_fd;
extern socklen_t s11_mme_sockaddr_len;
extern pfcp_config_t pfcp_config;

uint32_t start_time;
enum cp_config spgw_cfg;

/* S5S8 */
extern int s5s8_fd;
struct sockaddr_in s5s8_recv_sockaddr;
extern socklen_t s5s8_sockaddr_len;

struct cp_params cp_params;
extern struct cp_stats_t cp_stats;


uint16_t payload_length;

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
	uint16_t payload_length = 0;
	int ret = 0;

	if((iface != S11_IFACE) && (iface != S5S8_IFACE)){
		clLog(clSystemLog, eCLSeverityCritical, "%s: Invalid interface %d \n", __func__, iface);
		return -1;
	}

	ret = process_echo_request(gtpv2c_rx, gtpv2c_tx);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane()::Error"
				"\n\tprocess_echo_req "
				"%s: (%d) %s\n",
				gtp_type_str(gtpv2c_rx->gtpc.message_type), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
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
				s11_mme_sockaddr_len);
		cp_stats.echo++;
		update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
					gtpv2c_tx->gtpc.message_type,SENT,S11);
	}else{
		gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);
		cp_stats.echo++;
		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
					gtpv2c_tx->gtpc.message_type,SENT,S5S8);
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
		clLog(clSystemLog, eCLSeverityCritical, "%s: Invalid interface %d \n", __func__, iface);
		return -1;
	}

	if(iface == S11_IFACE){
		ret = process_response(s11_mme_sockaddr.sin_addr.s_addr);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane()::Error"
					"\n\tprocess_echo_resp "
					"%s: (%d) %s\n",
					gtp_type_str(gtpv2c_rx->gtpc.message_type), ret,
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
	if(gtpv2c_s11_rx->gtpc.message_type != GTP_DOWNLINK_DATA_NOTIFICATION_ACK) {

			update_cli_stats((uint32_t)s11_mme_sockaddr.sin_addr.s_addr,
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

		if ((ret = gtpc_pcnd_check(gtpv2c_s11_rx, &msg, bytes_s11_rx)) != 0)
			return;

		if(gtpv2c_s11_rx->gtpc.message_type == GTP_DOWNLINK_DATA_NOTIFICATION_ACK) {
				update_cli_stats((uint32_t)s11_mme_sockaddr.sin_addr.s_addr,
								gtpv2c_s11_rx->gtpc.message_type,ACC,S11);
			}

		if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
			if (SGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
			} else if (PGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
			} else if (SAEGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, NULL);
			} else {
				clLog(s11logger, eCLSeverityCritical, "%s : "
						"Invalid Control Plane Type: %d \n",
						__func__, pfcp_config.cp_type);
				return;
			}

			if(ret == -2) {
				clLog(s11logger, eCLSeverityCritical, "%s : "
						"Discarding re-transmitted csr Error: %d \n",
						__func__, ret);
				return;
			}
			if (ret) {
				clLog(s11logger, eCLSeverityCritical, "%s : "
						"State_Machine Callback failed with Error: %d \n",
						__func__, ret);
				return;
			}
		} else {
			if ((msg.proc == END_PROC) &&
					(msg.state == END_STATE) &&
					(msg.event == END_EVNT)) {
				return;
			}

			clLog(s11logger, eCLSeverityCritical, "%s : "
						"Invalid Procedure or State or Event \n",
						__func__);
			return;
		}
	}

#if 0
	if (bytes_s11_rx > 0) {
		if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
			switch (gtpv2c_s11_rx->gtpc.type) {
			case GTP_BEARER_RESOURCE_CMD:
				ret = process_bearer_resource_command(
						gtpv2c_s11_rx, gtpv2c_s11_tx);

				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_bearer_resource_command "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);
				break;

			case GTP_CREATE_BEARER_RSP:
				ret = process_create_bearer_response(gtpv2c_s11_rx);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_create_bearer_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
				break;

			case GTP_DELETE_BEARER_RSP:
				ret = process_delete_bearer_response(gtpv2c_s11_rx);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_delete_bearer_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
				break;

			default:
				//clLog(clSystemLog, eCLSeverityCritical, "main.c::control_plane::process_msgs-"
				//		"\n\tcase: SAEGWC::spgw_cfg= %d;"
				//		"\n\tReceived unprocessed s11 GTPv2c Message Type: "
				//		"%s (%u 0x%x)... Discarding\n",
				//		spgw_cfg, gtp_type_str(gtpv2c_s11_rx->gtpc.type),
				//		gtpv2c_s11_rx->gtpc.type,
				//		gtpv2c_s11_rx->gtpc.type);
				//return;
				break;
			}
		}
	}
#endif

	switch (spgw_cfg) {
	case SGWC:
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
				//clLog(clSystemLog, eCLSeverityDebug,"VS:MBR[%u]:cnt: %u\n", gtpv2c_s11_rx->gtpc.type, ++cnt);
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
		rte_panic("main.c::control_plane::cp_stats-"
				"Unknown spgw_cfg= %u.", spgw_cfg);
		break;
	}

}

void
msg_handler_s5s8(void)
{
	int ret = 0;
	int bytes_s5s8_rx = 0;
	msg_info msg = {0};

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

	if (bytes_s5s8_rx == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "s5s8 recvfrom error:"
				"\n\ton %s:%u - %s\n",
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

#if 0
	if ((spgw_cfg == SGWC) || (spgw_cfg == PGWC)) {
		if ((bytes_s5s8_rx > 0) &&
			 (unsigned)bytes_s5s8_rx != (
			 ntohs(gtpv2c_s5s8_rx->gtpc.message_len)
			 + sizeof(gtpv2c_s5s8_rx->gtpc))
			) {
			ret = GTPV2C_CAUSE_INVALID_LENGTH;
			/* According to 29.274 7.7.7, if message is request,
			 * reply with cause = GTPV2C_CAUSE_INVALID_LENGTH
			 *  should be sent - ignoring packet for now
			 */
			clLog(clSystemLog, eCLSeverityCritical, "SGWC|PGWC_s5s8 Received UDP Payload:"
					"\n\t(%d bytes) with gtpv2c + "
					"header (%u + %lu) = %lu bytes\n",
					bytes_s5s8_rx, ntohs(gtpv2c_s5s8_rx->gtpc.message_len),
					sizeof(gtpv2c_s5s8_rx->gtpc),
					ntohs(gtpv2c_s5s8_rx->gtpc.message_len)
					+ sizeof(gtpv2c_s5s8_rx->gtpc));
		}
	}
#endif
	if (bytes_s5s8_rx > 0)
		++cp_stats.rx;

	/* Reset periodic timers */
	process_response(s5s8_recv_sockaddr.sin_addr.s_addr);

	if (spgw_cfg == PGWC)
		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,RCVD,S5S8);

	if (spgw_cfg == SGWC && (gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_REQ ||
		gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_RSP ||
		gtpv2c_s5s8_rx->gtpc.message_type == GTP_CREATE_BEARER_REQ))

		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,RCVD,S5S8);
#if 0
	if (((spgw_cfg == PGWC) && (bytes_s5s8_rx > 0)) &&
		  (gtpv2c_s5s8_rx->gtpc.version != GTP_VERSION_GTPV2C)
		) {
		clLog(clSystemLog, eCLSeverityCritical, "PFCP Discarding packet from %s:%u - "
				"Expected S5S8_IP = %s\n",
				inet_ntoa(s5s8_recv_sockaddr.sin_addr),
				ntohs(s5s8_recv_sockaddr.sin_port),
				inet_ntoa(pfcp_config.s5s8_ip));
		return;
		}
#endif
	if(gtpv2c_s5s8_rx->gtpc.message_type == GTP_ECHO_REQ){
		if (bytes_s5s8_rx > 0) {
#ifdef USE_REST
			ret = process_echo_req(gtpv2c_s5s8_rx, gtpv2c_s5s8_tx, S5S8_IFACE);
			if(ret != 0){
				return;
			}
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
#endif /* USE_REST */
			++cp_stats.tx;
		}
		return;
	}else {

		if ((ret = gtpc_pcnd_check(gtpv2c_s5s8_rx, &msg, bytes_s5s8_rx)) != 0)
		{
			/*CLI: update csr, dsr, mbr rej response*/
			if(spgw_cfg == SGWC)
				update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
							gtpv2c_s5s8_rx->gtpc.message_type,REJ,S5S8);
			return;
		}

	if (spgw_cfg == SGWC)
		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
					gtpv2c_s5s8_rx->gtpc.message_type,ACC,S5S8);

	if (spgw_cfg == SGWC)
	{
		if (gtpv2c_s5s8_rx->gtpc.message_type == GTP_CREATE_SESSION_RSP )
		{
			add_node_conn_entry(s5s8_recv_sockaddr.sin_addr.s_addr, S5S8_SGWC_PORT_ID);
		}
		if (gtpv2c_s5s8_rx->gtpc.message_type == GTP_MODIFY_BEARER_RSP)
		{
			add_node_conn_entry(s5s8_recv_sockaddr.sin_addr.s_addr, S5S8_SGWC_PORT_ID);
		}
	}

		if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
			if (SGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
			} else if (PGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, NULL);
			} else if (SAEGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, NULL);
			} else {
				clLog(s5s8logger, eCLSeverityCritical, "%s : "
						"Invalid Control Plane Type: %d \n",
						__func__, pfcp_config.cp_type);
				return;
			}
			if(ret == -2) {
				clLog(s11logger, eCLSeverityCritical, "%s : "
						"Discarding re-transmitted csr Error: %d \n",
						__func__, ret);
				return;
			}

			if (ret) {
				clLog(s5s8logger, eCLSeverityCritical, "%s : "
						"State_Machine Callback failed with Error: %d \n",
						__func__, ret);
				return;
			}
		} else {
			clLog(s11logger, eCLSeverityCritical, "%s : "
						"Invalid Procedure or State or Event \n",
						__func__);
			return;
		}
	}

	if (bytes_s5s8_rx > 0)
		++cp_stats.tx;

	switch (spgw_cfg) {
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
			}
		}
		break;
	default:
		rte_panic("main.c::control_plane::cp_stats-"
				"Unknown spgw_cfg= %u.", spgw_cfg);
		break;
	}
}


