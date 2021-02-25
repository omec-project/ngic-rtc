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

#include <byteswap.h>

#include "pfcp_util.h"
#include "dp_ipc_api.h"
#include "pfcp_set_ie.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "gw_adapter.h"
#include "clogger.h"

#ifdef CP_BUILD
#include "pfcp.h"
#include "sm_arr.h"
#include "sm_pcnd.h"
#include "cp_stats.h"
#include "sm_struct.h"
#include "cp_config.h"
#else
#include "up_main.h"
#include "pfcp_up_sess.h"
#include "pfcp_up_struct.h"
#endif /* CP_BUILD */

uint16_t dp_comm_port;
uint16_t cp_comm_port;

struct in_addr dp_comm_ip;

/*
 * UDP Socket
 */
extern udp_sock_t my_sock;

extern struct rte_hash *heartbeat_recovery_hash;

extern struct sockaddr_in upf_pfcp_sockaddr;

#ifdef CP_BUILD
extern pfcp_config_t pfcp_config;
extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;
#else
extern struct rte_hash *node_id_hash;
#endif /* CP_BUILD */

#if defined(CP_BUILD) || defined(DP_BUILD)

/**
 * @brief  : Process incoming heartbeat request and send response
 * @param  : buf_rx holds data from incoming request
 * @param  : peer_addr used to pass address of peer node
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
process_heartbeat_request(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{
	int encoded = 0;
	int decoded = 0;
	uint8_t pfcp_msg[PFCP_MSG_LEN]= {0};

	RTE_SET_USED(decoded);

	memset(pfcp_msg, 0, PFCP_MSG_LEN);
	pfcp_hrtbeat_req_t *pfcp_heartbeat_req = malloc(sizeof(pfcp_hrtbeat_req_t));
	pfcp_hrtbeat_rsp_t  pfcp_heartbeat_resp = {0};
	decoded = decode_pfcp_hrtbeat_req_t(buf_rx, pfcp_heartbeat_req);
	fill_pfcp_heartbeat_resp(&pfcp_heartbeat_resp);
	pfcp_heartbeat_resp.header.seid_seqno.no_seid.seq_no = pfcp_heartbeat_req->header.seid_seqno.no_seid.seq_no;

	encoded = encode_pfcp_hrtbeat_rsp_t(&pfcp_heartbeat_resp,  pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

#ifdef USE_REST
	/* Reset the periodic timers */
	process_response((uint32_t)peer_addr->sin_addr.s_addr);
#endif /* USE_REST */

#ifdef CP_BUILD
	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr,SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":Error sending in "
			"heartbeat request: %i\n", LOG_VALUE, errno);
	}
#endif /* CP_BUILD */
	free(pfcp_heartbeat_req);

#ifdef DP_BUILD
	if (encoded != 0) {
		if (sendto(my_sock.sock_fd,
					(char *)pfcp_msg,
					encoded,
					MSG_DONTWAIT,
					(struct sockaddr *)peer_addr,
					sizeof(struct sockaddr_in)) < 0) {

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error sending in "
				"heartbeat request: %i\n", LOG_VALUE, errno);
		} else {

		update_cli_stats(peer_addr->sin_addr.s_addr,
				PFCP_HEARTBEAT_RESPONSE,SENT,SX);
		}
	}
#endif /* DP_BUILD */
	return 0;
}

/**
 * @brief  : Process hearbeat response message
 * @param  : buf_rx holds data from incoming request
 * @param  : peer_addr used to pass address of peer node
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
process_heartbeat_response(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{

#ifdef USE_REST
	process_response((uint32_t)peer_addr->sin_addr.s_addr);
#endif /*USE_REST*/

	int ret = 0;
	uint32_t *recov_time;
	uint32_t update_recov_time = 0;
	pfcp_hrtbeat_rsp_t pfcp_hearbeat_resp = {0};

	ret = decode_pfcp_hrtbeat_rsp_t(buf_rx, &pfcp_hearbeat_resp);
	if (ret <= 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to decode PFCP Heartbeat Resp\n\n", LOG_VALUE);
	}

	ret = rte_hash_lookup_data(heartbeat_recovery_hash , &peer_addr->sin_addr.s_addr ,
			(void **) &(recov_time));

	if (ret == -ENOENT) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"No entry found for the heartbeat!!\n", LOG_VALUE);

	} else {
		/*Restoration part to be added if recovery time is found greater*/
		update_recov_time = (pfcp_hearbeat_resp.rcvry_time_stmp.rcvry_time_stmp_val);

		if(update_recov_time > *recov_time) {
			/* Updated time stamp of user-plane */
			*recov_time = update_recov_time;

#ifdef CP_BUILD
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"WARNING : DP Restart Detected and INITIATED RECOVERY MODE\n",
								LOG_VALUE);
			/* SET recovery initiated flag */
			recovery_flag = 1;

			/* Send association request to peer node */
			if(process_aasociation_setup_req(peer_addr->sin_addr.s_addr) < 0) {
				/* Severity level*/
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error in sending "
					"PFCP Association Setup Request\n", LOG_VALUE);
				return -1;
			}

#endif /* CP_BUILD */
		}
	}

	return 0;
}


/* Parse byte_rx to process_pfcp_msg */
int
process_pfcp_msg(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{
	int ret = 0, bytes_rx = 0;
	pfcp_header_t *pfcp_header = (pfcp_header_t *) buf_rx;


#ifdef CP_BUILD

	/* TODO: Move this rx */
	if ((bytes_rx = pfcp_recv(pfcp_rx, PFCP_RX_BUFF_SIZE,
					peer_addr)) < 0) {
		perror("msgrecv");
		return -1;
	}

	msg_info msg = {0};
	if(pfcp_header->message_type == PFCP_HEARTBEAT_REQUEST){

		update_cli_stats(peer_addr->sin_addr.s_addr,
				pfcp_header->message_type,RCVD,SX);

		ret = process_heartbeat_request(buf_rx, peer_addr);
		if(ret != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to process "
				"pfcp heartbeat request\n", LOG_VALUE);
			return -1;
		}
		return 0;
	}else if(pfcp_header->message_type == PFCP_HEARTBEAT_RESPONSE){
		ret = process_heartbeat_response(buf_rx, peer_addr);
		if (ret != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT":Failed to process "
				"pfcp heartbeat response\n", LOG_VALUE);
			return -1;
		} else {

			update_cli_stats(peer_addr->sin_addr.s_addr,
					PFCP_HEARTBEAT_RESPONSE,RCVD,SX);

		}
		return 0;
	}else {
		/*Reset periodic timers*/
		process_response(peer_addr->sin_addr.s_addr);

		if ((ret = pfcp_pcnd_check(buf_rx, &msg, bytes_rx, peer_addr)) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT":Failed to process "
				"pfcp precondition check\n", LOG_VALUE);

			if(msg.pfcp_msg.pfcp_sess_del_resp.cause.cause_value != REQUESTACCEPTED){
				update_cli_stats(peer_addr->sin_addr.s_addr,
						pfcp_header->message_type, REJ,SX);
			}
			else {
				update_cli_stats(peer_addr->sin_addr.s_addr,
						pfcp_header->message_type, ACC,SX);
			}
			return -1;
		}

		if(pfcp_header->message_type == PFCP_SESSION_REPORT_REQUEST ||
		   pfcp_header->message_type == PFCP_SESSION_SET_DELETION_REQUEST ||
		   pfcp_header->message_type == PFCP_SESSION_SET_DELETION_RESPONSE)
			update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type, RCVD,SX);
		else
			update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type, ACC,SX);

		/* State Machine execute on session level, but following messages are NODE level */
		if (msg.msg_type == PFCP_SESSION_SET_DELETION_REQUEST) {
			/* Process RCVD PFCP Session Set Deletion Request */
			ret = process_pfcp_sess_set_del_req(&msg, NULL);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_pfcp_sess_set_del_req() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return 0;
		} else if (msg.msg_type == PFCP_SESSION_SET_DELETION_RESPONSE) {
			/* Process RCVD PFCP Session Set Deletion Response */
			ret = process_pfcp_sess_set_del_rsp(&msg, NULL);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"process_del_pdn_conn_set_rsp() failed with Error: %d \n",
						LOG_VALUE, ret);
			}
			return 0;
		} else {
			if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
				if (SGWC == msg.cp_mode) {
				    ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, peer_addr);
				} else if (PGWC == msg.cp_mode) {
				    ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, peer_addr);
				} else if (SAEGWC == msg.cp_mode) {
				    ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, peer_addr);
				} else {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Invalid "
						"Control Plane Type: %d \n", LOG_VALUE, msg.cp_mode);
					return -1;
				}

				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"State"
						"Machine Callback failed with Error: %d \n", LOG_VALUE, ret);
					return -1;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Invalid Procedure "
					"or State or Event \n", LOG_VALUE);
				return -1;
			}
		}
	}
#else /* End CP_BUILD , Start DP_BUILD */

	pfcp_session_t *sess = NULL;
	pfcp_session_t *tmp_sess = NULL;
	tmp_sess = malloc(sizeof(pfcp_session_t));

	memset(tmp_sess, 0, sizeof(pfcp_session_t));
	/* TODO: Move this rx */
	if ((bytes_rx = udp_recv(pfcp_rx, 2048,
					peer_addr)) < 0) {
		perror("msgrecv");
		return -1;
	}

	int encoded = 0;
	int decoded = 0;
	uint8_t pfcp_msg[2048]= {0};
	struct msgbuf rule_msg = {0} ;

	uint8_t cli_cause = 0;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Bytes received is %d\n", LOG_VALUE, bytes_rx);
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"IPADDR [%u]\n", LOG_VALUE, peer_addr->sin_addr.s_addr);


	if( pfcp_header->message_type != PFCP_SESSION_REPORT_RESPONSE)
	{
		update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type,RCVD,SX);
	}


	/*Reset periodic timers*/
	process_response(peer_addr->sin_addr.s_addr);

	switch (pfcp_header->message_type)
	{

		case PFCP_HEARTBEAT_REQUEST:
			ret = process_heartbeat_request(buf_rx, peer_addr);
			if(ret != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to process "
					"pfcp heartbeat request\n", LOG_VALUE);
				return -1;
			}
			break;
		case PFCP_HEARTBEAT_RESPONSE:
			ret = process_heartbeat_response(buf_rx, peer_addr);
			if(ret != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to process "
					"pfcp heartbeat response\n", LOG_VALUE);
				return -1;

			}
			break;
		case PFCP_ASSOCIATION_SETUP_REQUEST:
			{
				memset(pfcp_msg, 0, 2048);
				pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};
				pfcp_assn_setup_rsp_t pfcp_ass_setup_resp = {0} ;

				/* TODO: Error Handling */
				decoded = decode_pfcp_assn_setup_req_t(buf_rx, &pfcp_ass_setup_req);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"[DP] Decoded bytes [%d]\n", LOG_VALUE, decoded);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"recover_time[%d],cpf[%d] from CP \n\n",
						LOG_VALUE, (pfcp_ass_setup_req.rcvry_time_stmp.rcvry_time_stmp_val),
						(pfcp_ass_setup_req.cp_func_feat.sup_feat));

				uint8_t cause_id = 0;
				uint32_t value = 0;
				int offend_id = 0;
				cause_check_association(&pfcp_ass_setup_req, &cause_id, &offend_id);

				cli_cause = cause_id;

				if (cause_id == REQUESTACCEPTED)
				{
					//Adding NODE ID into nodeid hash in DP
					uint64_t *data = rte_zmalloc_socket(NULL, sizeof(uint8_t),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
					if (data == NULL)
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
							"memory for node id hash, Error : %s\n", LOG_VALUE,
							rte_strerror(rte_errno));
					*data = NODE_ID_TYPE_TYPE_IPV4ADDRESS;
					memcpy(&value, &pfcp_ass_setup_req.node_id.node_id_value_ipv4_address,IPV4_SIZE);

					uint32_t nodeid =(ntohl(value));
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NODEID in INTERRFACE [%u]\n", LOG_VALUE, nodeid);
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DATA[%lu]\n", LOG_VALUE, *data);
					add_node_id_hash(&nodeid, data);
					/*Data was not being in use , Doing rte free */
					if (data != NULL) {
						rte_free(data);
						data = NULL;
					}
				}

				add_ip_to_heartbeat_hash(peer_addr,
						pfcp_ass_setup_req.rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST
				if (peer_addr->sin_addr.s_addr != 0) {
					if ((add_node_conn_entry((uint32_t)peer_addr->sin_addr.s_addr, 0, SX_PORT_ID)) != 0) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
							"add connection entry for SGWU/SAEGWU", LOG_VALUE);
					}
				}
#endif

				fill_pfcp_association_setup_resp(&pfcp_ass_setup_resp, cause_id, value);

				pfcp_ass_setup_resp.header.seid_seqno.no_seid.seq_no =
					pfcp_ass_setup_req.header.seid_seqno.no_seid.seq_no;

				memcpy(&(pfcp_ass_setup_resp.node_id.node_id_value_ipv4_address), &(dp_comm_ip.s_addr), IPV4_SIZE);
				encoded =  encode_pfcp_assn_setup_rsp_t(&pfcp_ass_setup_resp, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "sending response "
					"of sess [%d] from dp\n",LOG_VALUE, pfcp_hdr->message_type);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "length[%d]\n",
					LOG_VALUE, htons(pfcp_hdr->message_len));

				break;
			}
		case PFCP_PFD_MGMT_REQUEST:
			{
				int offend_id = 0;
				uint8_t cause_id = 0;
				memset(pfcp_msg, 0, 2048);
				memset(&rule_msg, 0, sizeof(struct msgbuf));
				pfcp_pfd_mgmt_rsp_t pfcp_pfd_mgmt_resp = {0};

				pfcp_pfd_mgmt_req_t *pfcp_pfd_mgmt_req = malloc(sizeof(pfcp_pfd_mgmt_req_t));
				memset(pfcp_pfd_mgmt_req, 0, sizeof(pfcp_pfd_mgmt_req_t));

				/* Decode pfcp pfd mgmt req */
				decoded = decode_pfcp_pfd_mgmt_req_t(buf_rx, pfcp_pfd_mgmt_req);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"[DP] Decoded bytes [%d]\n",
						LOG_VALUE, decoded);

				process_up_pfd_mgmt_request(pfcp_pfd_mgmt_req, &cause_id,
						&offend_id, peer_addr->sin_addr.s_addr);

				/* Fill pfcp pfd mgmt response */
				fill_pfcp_pfd_mgmt_resp(&pfcp_pfd_mgmt_resp, cause_id, offend_id);

				if(pfcp_pfd_mgmt_req->header.s) {
					pfcp_pfd_mgmt_resp.header.seid_seqno.no_seid.seq_no =
						pfcp_pfd_mgmt_req->header.seid_seqno.has_seid.seq_no;
				} else {
					pfcp_pfd_mgmt_resp.header.seid_seqno.no_seid.seq_no =
						pfcp_pfd_mgmt_req->header.seid_seqno.no_seid.seq_no;
				}

				cli_cause = cause_id;
				encoded = encode_pfcp_pfd_mgmt_rsp_t(&pfcp_pfd_mgmt_resp, pfcp_msg);

				RTE_SET_USED(encoded);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);
				RTE_LOG_DP(DEBUG, DP, "length[%d]\n",htons(pfcp_hdr->message_len));
				break;


			}
		case PFCP_SESSION_ESTABLISHMENT_REQUEST:
			{
				memset(pfcp_msg, 0, 2048);
				pfcp_sess_estab_req_t *pfcp_session_request = malloc(sizeof(pfcp_sess_estab_req_t));
				memset(pfcp_session_request, 0, sizeof(pfcp_sess_estab_req_t));
				pfcp_sess_estab_rsp_t pfcp_session_response = {0};

				decoded = decode_pfcp_sess_estab_req_t(buf_rx, pfcp_session_request);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DECOED bytes in sesson "
					"is %d\n", LOG_VALUE, decoded);

				if (process_up_session_estab_req(pfcp_session_request,
							&pfcp_session_response, ntohl(peer_addr->sin_addr.s_addr))) {
					return -1;
				}

				uint8_t cause_id = 0;
				int offend_id = 0 ;
				cause_check_sess_estab(pfcp_session_request, &cause_id, &offend_id);

				cli_cause = cause_id;

				fill_pfcp_session_est_resp(&pfcp_session_response, cause_id,
						offend_id, dp_comm_ip, pfcp_session_request);

				pfcp_session_response.header.seid_seqno.has_seid.seq_no =
					pfcp_session_request->header.seid_seqno.has_seid.seq_no;

				memcpy(&(pfcp_session_response.up_fseid.ipv4_address),
						&(dp_comm_ip.s_addr), IPV4_SIZE);

				/*CLI:increment active-session count*/
				if (cause_id == REQUESTACCEPTED)
					update_sys_stat(number_of_active_session,INCREMENT);

				encoded = encode_pfcp_sess_estab_rsp_t(&pfcp_session_response, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

				pfcp_hdr->seid_seqno.has_seid.seid =
						bswap_64(pfcp_session_request->cp_fseid.seid);

				sess = get_sess_info_entry(pfcp_session_response.up_fseid.seid, SESS_MODIFY);
				if (sess != NULL ) {
					memcpy(tmp_sess, sess, sizeof(pfcp_session_t));
				}
				if (pfcp_session_request != NULL) {
					free(pfcp_session_request);
				}
				break;
			}
		case PFCP_SESSION_MODIFICATION_REQUEST:
			{

				int offend_id = 0;
				uint8_t cause_id = REQUESTACCEPTED;
				memset(pfcp_msg, 0, 2048);

				pfcp_sess_mod_req_t pfcp_session_mod_req = {0};

				pfcp_sess_mod_rsp_t pfcp_sess_mod_res = {0};

				decoded = decode_pfcp_sess_mod_req_t(buf_rx, &pfcp_session_mod_req);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "DECODED bytes in "
					"sesson modification is %d\n",LOG_VALUE, decoded);

				cli_cause = cause_id;

				fill_pfcp_session_modify_resp(&pfcp_sess_mod_res,
					&pfcp_session_mod_req, cause_id, offend_id);

				pfcp_sess_mod_res.header.seid_seqno.has_seid.seid =
						pfcp_session_mod_req.cp_fseid.seid;

				sess = get_sess_info_entry(pfcp_session_mod_req.header.seid_seqno.has_seid.seid, SESS_MODIFY);
				if (sess != NULL ) {
					memcpy(tmp_sess, sess, sizeof(pfcp_session_t));
				}
				pfcp_sess_mod_res.header.seid_seqno.has_seid.seq_no =
					pfcp_session_mod_req.header.seid_seqno.has_seid.seq_no;

				if (process_up_session_modification_req(&pfcp_session_mod_req,
						&pfcp_sess_mod_res, ntohl(peer_addr->sin_addr.s_addr))) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failure in proces "
						"up session modification_req function\n", LOG_VALUE);
					return -1;
				}

				/*cause_check_sess_modification(&pfcp_session_mod_req, &cause_id, &offend_id);
				 * if (ret == SESSIONCONTEXTNOTFOUND ){
					cause_id = SESSIONCONTEXTNOTFOUND;
				} */


				encoded = encode_pfcp_sess_mod_rsp_t(&pfcp_sess_mod_res, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "sending response of "
					"sess [%d] from dp\n", LOG_VALUE, pfcp_hdr->message_type);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "length[%d]\n",
					LOG_VALUE, htons(pfcp_hdr->message_len));

				break;
			}
		case PFCP_SESSION_DELETION_REQUEST:
			{
				int ret = 0;
				int offend_id = 0;
				uint8_t cause_id = 0;
				uint64_t cp_seid = 0;
				memset(pfcp_msg, 0, 2048);

				pfcp_sess_del_req_t *pfcp_session_del_req =
						malloc(sizeof(pfcp_sess_del_req_t));

				pfcp_sess_del_rsp_t  pfcp_sess_del_res = {0};
				decoded = decode_pfcp_sess_del_req_t(buf_rx, pfcp_session_del_req);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DECODE bytes in sesson deletion is %d\n\n",
					LOG_VALUE, decoded);

				sess = get_sess_info_entry(pfcp_session_del_req->header.seid_seqno.has_seid.seid, SESS_MODIFY);
				if (sess != NULL) {
					memcpy(tmp_sess, sess, sizeof(pfcp_session_t));
				}
				if (process_up_session_deletion_req(pfcp_session_del_req,
						&pfcp_sess_del_res, ntohl(peer_addr->sin_addr.s_addr))) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failure in "
						"process_up_session_deletion_req function\n",LOG_VALUE);
					return -1;
				}

				cause_check_delete_session(pfcp_session_del_req, &cause_id, &offend_id);
				if (ret == SESSIONCONTEXTNOTFOUND ){
					cause_id = SESSIONCONTEXTNOTFOUND;
				}

				cp_seid = pfcp_sess_del_res.header.seid_seqno.has_seid.seid;

				cli_cause = cause_id;

				fill_pfcp_sess_del_resp(&pfcp_sess_del_res, cause_id, offend_id);

				pfcp_sess_del_res.header.seid_seqno.has_seid.seid = cp_seid;

				pfcp_sess_del_res.header.seid_seqno.has_seid.seq_no =
					pfcp_session_del_req->header.seid_seqno.has_seid.seq_no;

				encoded = encode_pfcp_sess_del_rsp_t(&pfcp_sess_del_res,  pfcp_msg);


				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"sending response "
					"of sess [%d] from dp\n", LOG_VALUE, pfcp_hdr->message_type);

				if (pfcp_session_del_req != NULL) {
					free(pfcp_session_del_req);
				}
				break;

			}

		case PFCP_SESSION_REPORT_RESPONSE:
			{
				/*DDN Response Handle*/
				pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};

				decoded = decode_pfcp_sess_rpt_rsp_t(buf_rx,
						&pfcp_sess_rep_resp);

				update_cli_stats(peer_addr->sin_addr.s_addr,
						pfcp_header->message_type,
						(pfcp_sess_rep_resp.cause.cause_value = REQUESTACCEPTED) ? ACC:REJ, SX);

				if (pfcp_sess_rep_resp.cause.cause_value != REQUESTACCEPTED) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Cause received "
							"Report response is %d\n", LOG_VALUE,
							pfcp_sess_rep_resp.cause.cause_value);

					/* Add handling to send association to next upf
					 * for each buffered CSR */
					return -1;
				}

				sess = get_sess_info_entry(pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid, SESS_MODIFY);
				if (sess != NULL) {
					memcpy(tmp_sess, sess, sizeof(pfcp_session_t));
				}

				remove_cdr_entry(pfcp_sess_rep_resp.header.seid_seqno.has_seid.seq_no,
						pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid);

				clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "Received Report "
					"Response for sess_id:%lu\n\n", LOG_VALUE,
					pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid);

				break;
			}
		case PFCP_SESSION_SET_DELETION_REQUEST:
			{
#ifdef USE_CSID
				int offend_id = 0;
				uint8_t cause_id = 0;
				memset(pfcp_msg, 0, 2048);

				/* Handle PFCP Session SET Deletion Response */
				pfcp_sess_set_del_req_t pfcp_sess_set_del_req = {0};

				pfcp_sess_set_del_rsp_t pfcp_sess_set_del_rsp = {0};

				/* Type : 0 --> DP */
				/*Decode the received msg and stored into the struct. */
				decoded = decode_pfcp_sess_set_del_req_t(buf_rx,
						&pfcp_sess_set_del_req);

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DECODE bytes in "
					"session set deletion req is %d\n", LOG_VALUE, decoded);

				if (process_up_sess_set_del_req(&pfcp_sess_set_del_req)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in "
						"process up Session Set Deletion Request function\n",
						LOG_VALUE);
					return -1;
				}

				/* Fill PFCP SESS SET DEL RESP */
				cause_id = REQUESTACCEPTED;
				fill_pfcp_sess_set_del_resp(&pfcp_sess_set_del_rsp,
						cause_id, offend_id);

				if (pfcp_sess_set_del_req.header.s) {
					pfcp_sess_set_del_rsp.header.seid_seqno.no_seid.seq_no =
						pfcp_sess_set_del_req.header.seid_seqno.has_seid.seq_no;
				} else {
					pfcp_sess_set_del_rsp.header.seid_seqno.no_seid.seq_no =
						pfcp_sess_set_del_req.header.seid_seqno.no_seid.seq_no;
				}

				encoded = encode_pfcp_sess_set_del_rsp_t(&pfcp_sess_set_del_rsp, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Sending response "
					"for [%d] from dp\n", LOG_VALUE, pfcp_hdr->message_type);

#endif /* USE_CSID */
				break;
			}
		case PFCP_SESSION_SET_DELETION_RESPONSE:
			{
				/* Handle PFCP Session SET Deletion Response */
				pfcp_sess_set_del_rsp_t pfcp_sess_set_del_rsp = {0};

				/*Decode the received msg and stored into the struct. */
				decoded = decode_pfcp_sess_set_del_rsp_t(buf_rx,
						&pfcp_sess_set_del_rsp);

				if (pfcp_sess_set_del_rsp.cause.cause_value != REQUESTACCEPTED) {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Cause received pfcp session set deletion "
						"response is %d\n", LOG_VALUE,
						pfcp_sess_set_del_rsp.cause.cause_value);

					/* Add handling to send association to next upf
					 * for each buffered CSR */
							return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Received PFCP "
					"Session Set Deletion Response\n", LOG_VALUE);
				break;
			}
		default:
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"No Data received\n", LOG_VALUE);
			break;
		}
		if (encoded != 0) {
			if (sendto(my_sock.sock_fd,
				(char *)pfcp_msg,
				encoded,
				MSG_DONTWAIT,
				(struct sockaddr *)peer_addr,
				sizeof(struct sockaddr_in)) < 0) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Error in sending "
					"PFCP Set Deletion Response: %i\n", LOG_VALUE, errno);
			} else {
				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				if(pfcp_header->message_type != PFCP_SESSION_SET_DELETION_REQUEST &&
						pfcp_header->message_type != PFCP_SESSION_SET_DELETION_RESPONSE)
				update_cli_stats(peer_addr->sin_addr.s_addr,
						pfcp_hdr->message_type,
				(cli_cause == REQUESTACCEPTED) ? ACC:REJ, SX);
				else
					update_cli_stats(peer_addr->sin_addr.s_addr,pfcp_hdr->message_type,SENT,SX);
			}
		}

		if ((tmp_sess != NULL) && (tmp_sess->li_sx_config_cnt > 0)) {

			process_event_li(tmp_sess, buf_rx, bytes_rx, pfcp_msg, encoded,
				peer_addr->sin_addr.s_addr, peer_addr->sin_port);
			free(tmp_sess);
			tmp_sess = NULL;
		}
#endif /* DP_BUILD */
		return 0;
	}
#endif

