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
#include "interface.h"

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

static int
process_heartbeat_request(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{
	int encoded = 0;
	int decoded = 0;
	uint8_t pfcp_msg[1024]= {0};

	RTE_SET_USED(decoded);

	memset(pfcp_msg, 0, 1024);
	pfcp_hrtbeat_req_t *pfcp_heartbeat_req = malloc(sizeof(pfcp_hrtbeat_req_t));
	pfcp_hrtbeat_rsp_t  pfcp_heartbeat_resp = {0};
	decoded = decode_pfcp_hrtbeat_req_t(buf_rx, pfcp_heartbeat_req);
	fill_pfcp_heartbeat_resp(&pfcp_heartbeat_resp);
	pfcp_heartbeat_resp.header.seid_seqno.no_seid.seq_no = pfcp_heartbeat_req->header.seid_seqno.no_seid.seq_no;

	encoded = encode_pfcp_hrtbeat_rsp_t(&pfcp_heartbeat_resp,  pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - 4);

#ifdef USE_REST
	/* Reset the periodic timers */
	process_response((uint32_t)peer_addr->sin_addr.s_addr);
#endif /* USE_REST */

#ifdef CP_BUILD
	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
		RTE_LOG_DP(DEBUG, DP, "Error sending in heartbeat request: %i\n",errno);
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
					sizeof(struct sockaddr_in)) < 0)
			RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
	}
#endif /* DP_BUILD */
	return 0;
}

static int
process_heartbeat_response(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{

#ifdef USE_REST
	process_response((uint32_t)peer_addr->sin_addr.s_addr);
#endif /*USE_REST*/

	pfcp_hrtbeat_rsp_t pfcp_hearbeat_resp = {0};
	decode_pfcp_hrtbeat_rsp_t(buf_rx, &pfcp_hearbeat_resp);
	uint32_t *recov_time ;

	int ret = rte_hash_lookup_data(heartbeat_recovery_hash , &peer_addr->sin_addr.s_addr ,
			(void **) &(recov_time));

	if (ret == -ENOENT) {
		RTE_LOG_DP(DEBUG, DP, "No entry found for the heartbeat!!\n");

	} else {
		/*TODO: Restoration part to be added if recovery time is found greater*/
		uint32_t update_recov_time = 0;
		update_recov_time =  (pfcp_hearbeat_resp.rcvry_time_stmp.rcvry_time_stmp_val);

		if(update_recov_time > *recov_time) {

			ret = rte_hash_add_key_data (heartbeat_recovery_hash,
					&peer_addr->sin_addr.s_addr, &update_recov_time);

			ret = rte_hash_lookup_data(heartbeat_recovery_hash , &peer_addr->sin_addr.s_addr,
					(void **) &(recov_time));
		}
	}

	return 0;
}


/* TODO: Parse byte_rx to process_pfcp_msg */
int
process_pfcp_msg(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{
	int ret = 0, bytes_rx = 0;
	pfcp_header_t *pfcp_header = (pfcp_header_t *) buf_rx;

#ifdef CP_BUILD

	/*CLI*/
	EInterfaceType it;

	if (pfcp_config.cp_type == SGWC)
	{
		it = itSxa;

	} else if (pfcp_config.cp_type == PGWC)
	{
		it = itSxb;
	} else
	{
		it = itSxaSxb;
	}


	/* TODO: Move this rx */
	if ((bytes_rx = pfcp_recv(pfcp_rx, 512,
					peer_addr)) < 0) {
		perror("msgrecv");
		return -1;
	}

	msg_info msg = {0};
	if(pfcp_header->message_type == PFCP_HEARTBEAT_REQUEST){

		/*CLI:add DP as a peer,status FALSE*/
		add_cli_peer(peer_addr->sin_addr.s_addr,it);
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(peer_addr->sin_addr.s_addr,
				pfcp_header->message_type,RCVD,
				cp_stats.stat_timestamp);

		update_last_activity(peer_addr->sin_addr.s_addr, cp_stats.stat_timestamp);


		ret = process_heartbeat_request(buf_rx, peer_addr);
		if(ret != 0){
			fprintf(stderr, "%s: Failed to process pfcp heartbeat request\n", __func__);
			return -1;
		} else {

		/*CLI:pfcp_hrtb_resp sent count*/
		add_cli_peer(peer_addr->sin_addr.s_addr,it);
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(peer_addr->sin_addr.s_addr,
				PFCP_HEARTBEAT_RESPONSE,SENT,
				cp_stats.stat_timestamp);

		}
		return 0;
	}else if(pfcp_header->message_type == PFCP_HEARTBEAT_RESPONSE){
		ret = process_heartbeat_response(buf_rx, peer_addr);
		if(ret != 0){
			fprintf(stderr, "%s: Failed to process pfcp heartbeat response\n", __func__);
			return -1;
		} else {

			/*CLI:pfcp hrtbt response rcvd count*/
			add_cli_peer(peer_addr->sin_addr.s_addr,it);
			get_current_time(cp_stats.stat_timestamp);
			update_cli_stats(peer_addr->sin_addr.s_addr,
					PFCP_HEARTBEAT_RESPONSE,RCVD,
					cp_stats.stat_timestamp);

			update_last_activity(peer_addr->sin_addr.s_addr, cp_stats.stat_timestamp);

		}
		return 0;
	}else {
		/*Reset periodic timers*/
		process_response(peer_addr->sin_addr.s_addr);
		get_current_time(cp_stats.stat_timestamp);
		update_last_activity(peer_addr->sin_addr.s_addr, cp_stats.stat_timestamp);

		if ((ret = pfcp_pcnd_check(buf_rx, &msg, bytes_rx)) != 0) {
			fprintf(stderr, "%s: Failed to process pfcp precondition check\n", __func__);

		get_current_time(cp_stats.stat_timestamp);

		if(pfcp_header->message_type == PFCP_SESSION_REPORT_REQUEST)
			update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type, REJ,
							cp_stats.stat_timestamp);
		else
			update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type, REJ,
							cp_stats.stat_timestamp);
			return -1;
		}

		if(pfcp_header->message_type == PFCP_SESSION_REPORT_REQUEST)
			update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type, REQ,
							cp_stats.stat_timestamp);
		else
			update_cli_stats(peer_addr->sin_addr.s_addr,
							pfcp_header->message_type, ACC,
							cp_stats.stat_timestamp);

		switch(pfcp_header->message_type)
		{
			case PFCP_ASSOCIATION_SETUP_RESPONSE :
				/*CLI:add DP as a peer when ASSTN resp is rcvd,status:TRUE*/
				update_peer_status(peer_addr->sin_addr.s_addr, TRUE);

				break;
			default :
				break;
		}

		if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
			if (SGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, peer_addr);
			} else if (PGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, peer_addr);
			} else if (SAEGWC == pfcp_config.cp_type) {
			    ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, peer_addr);
			} else {
				clLog(sxlogger, eCLSeverityCritical, "%s : "
						"Invalid Control Plane Type: %d \n",
						__func__, pfcp_config.cp_type);
				return -1;
			}

			if (ret) {
				clLog(sxlogger, eCLSeverityCritical, "%s : "
						"State_Machine Callback failed with Error: %d \n",
						__func__, ret);
				return -1;
			}
		} else {
			clLog(s11logger, eCLSeverityCritical, "%s : "
						"Invalid Procedure or State or Event \n",
						__func__);
			return -1;
		}
	}
#else /* End CP_BUILD , Start DP_BUILD */

	/* TODO: Move this rx */
	if ((bytes_rx = udp_recv(pfcp_rx, 1024,
					peer_addr)) < 0) {
		perror("msgrecv");
		return -1;
	}

	int encoded = 0;
	int decoded = 0;
	uint8_t pfcp_msg[1024]= {0};
	struct msgbuf rule_msg = {0} ;

	RTE_LOG_DP(DEBUG, DP, "Bytes received is %d\n", bytes_rx);
	RTE_LOG_DP(DEBUG, DP, "IPADDR [%u]\n", peer_addr->sin_addr.s_addr);

	/*Reset periodic timers*/
	process_response(peer_addr->sin_addr.s_addr);

	switch (pfcp_header->message_type)
	{

		case PFCP_HEARTBEAT_REQUEST:
			ret = process_heartbeat_request(buf_rx, peer_addr);
			if(ret != 0){
				fprintf(stderr, "%s: Failed to process pfcp heartbeat request\n", __func__);
				return -1;
			}
			break;
		case PFCP_HEARTBEAT_RESPONSE:
			ret = process_heartbeat_response(buf_rx, peer_addr);
			if(ret != 0){
				fprintf(stderr, "%s: Failed to process pfcp heartbeat response\n", __func__);
				return -1;
			}
			break;
		case PFCP_ASSOCIATION_SETUP_REQUEST:
			{
				memset(pfcp_msg, 0, 1024);
				pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};
				pfcp_assn_setup_rsp_t pfcp_ass_setup_resp = {0} ;

				/* TODO: Error Handling */
				decoded = decode_pfcp_assn_setup_req_t(buf_rx, &pfcp_ass_setup_req);
				RTE_LOG_DP(DEBUG, DP, "[DP] Decoded bytes [%d]\n", decoded);
				RTE_LOG_DP(DEBUG, DP, "recover_time[%d],cpf[%d] from CP \n\n",
						(pfcp_ass_setup_req.rcvry_time_stmp.rcvry_time_stmp_val),
						(pfcp_ass_setup_req.cp_func_feat.sup_feat));

				//if (process_up_assoc_req(pfcp_ass_setup_req, &pfcp_ass_setup_resp)) {
				//	/* TODO: ERROR Handling */
				//	return -1;
				//}

				uint8_t cause_id = 0;
				int offend_id = 0;
				cause_check_association(&pfcp_ass_setup_req, &cause_id, &offend_id);
				// TODO: /handle hash error handling
				//fill_pfcp_association_setup_resp(&pfcp_ass_setup_resp);
				if (cause_id == REQUESTACCEPTED)
				{
					//Adding NODE ID into nodeid hash in DP
					int ret ;
					uint32_t value;
					uint64_t *data = rte_zmalloc_socket(NULL, sizeof(uint8_t),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
					if (data == NULL)
						rte_panic("Failure to allocate node id hash: "
								"%s (%s:%d)\n",
								rte_strerror(rte_errno),
								__FILE__,
								__LINE__);
					*data = NODE_ID_TYPE_TYPE_IPV4ADDRESS;
					memcpy(&value, &pfcp_ass_setup_req.node_id.node_id_value,IPV4_SIZE);
					uint32_t nodeid =(ntohl(value));
					RTE_LOG_DP(DEBUG, DP, "NODEID in INTERRFACE [%u]\n",nodeid);
					RTE_LOG_DP(DEBUG, DP, "DATA[%lu]\n",*data);

					ret = rte_hash_lookup_data(node_id_hash,(const void*) &(nodeid),
							(void **) &(data));
					if (ret == -ENOENT) {
						ret = add_node_id_hash(&nodeid, data);
					}

				}

				add_ip_to_heartbeat_hash(peer_addr,
						pfcp_ass_setup_req.rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST
				if ((add_node_conn_entry((uint32_t)peer_addr->sin_addr.s_addr, 0, SX_PORT_ID)) != 0) {
					RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGWU/SAEGWU");
				}
#endif

				fill_pfcp_association_setup_resp(&pfcp_ass_setup_resp, cause_id);

				pfcp_ass_setup_resp.header.seid_seqno.no_seid.seq_no =
					pfcp_ass_setup_req.header.seid_seqno.no_seid.seq_no;

				memcpy(&(pfcp_ass_setup_resp.node_id.node_id_value), &(dp_comm_ip.s_addr), NODE_ID_VALUE_LEN);

				encoded =  encode_pfcp_assn_setup_rsp_t(&pfcp_ass_setup_resp, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);
				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n", pfcp_hdr->message_type);
				RTE_LOG_DP(DEBUG, DP, "length[%d]\n", htons(pfcp_hdr->message_len));

				break;
			}
		case PFCP_PFD_MGMT_REQUEST:
			{
				memset(pfcp_msg, 0, 1024);
				memset(&rule_msg, 0, sizeof(struct msgbuf));
				int offend_id = 0;
				uint8_t cause_id = 0;
				uint16_t idx=0;
				pfcp_pfd_mgmt_req_t *pfcp_pfd_mgmt_req = malloc(sizeof(pfcp_pfd_mgmt_req_t));
				memset(pfcp_pfd_mgmt_req, 0, sizeof(pfcp_pfd_mgmt_req_t));
				pfcp_pfd_mgmt_rsp_t pfcp_pfd_mgmt_resp = {0};
				/* Decode pfcp pfd mgmt req */
				decoded = decode_pfcp_pfd_mgmt_req_t(buf_rx, pfcp_pfd_mgmt_req);
				/* Check for custom ie data is present and extract rule string  */
				for (int itr = 0; itr < pfcp_pfd_mgmt_req->app_ids_pfds_count; itr++) {
					for (int itr1 = 0; itr1 < pfcp_pfd_mgmt_req->app_ids_pfds[itr].pfd_context_count; itr1++) {
						for (int itr2 = 0; itr2 < pfcp_pfd_mgmt_req->app_ids_pfds[itr].pfd_context[itr1].pfd_contents_count; itr2++) {
							if(pfcp_pfd_mgmt_req->app_ids_pfds[itr].pfd_context[itr1].pfd_contents[itr2].header.len){
								if((pfcp_pfd_mgmt_req->app_ids_pfds[itr].pfd_context[itr1].pfd_contents[itr2].pfd_contents_cp)                                               && (pfcp_pfd_mgmt_req->app_ids_pfds[itr].pfd_context[itr1].pfd_contents[itr2].len_of_cstm_pfd_cntnt)){

									cause_id = REQUESTACCEPTED;
								}
							} else{
								cause_id = MANDATORYIEMISSING;
								offend_id= PFCP_IE_PFD_CONTENTS;
							}

							if(cause_id == REQUESTACCEPTED){
								/* extract msg type from cstm string */
								rule_msg.mtype = get_rule_type(&pfcp_pfd_mgmt_req->app_ids_pfds[itr].pfd_context[itr1].
										pfd_contents[itr2], &idx);
								if (rule_msg.mtype == MSG_ADC_TBL_ADD) {
									rule_msg.msg_union.adc_filter_entry =
										*(struct adc_rules *)(pfcp_pfd_mgmt_req->app_ids_pfds[itr].
												pfd_context[itr1].pfd_contents[itr2].cstm_pfd_cntnt + idx);
#ifdef PRINT_NEW_RULE_ENTRY
									print_adc_val(&rule_msg.msg_union.adc_filter_entry);
#endif /* PRINT_NEW_RULE_ENTRY */
								}else if (rule_msg.mtype == MSG_PCC_TBL_ADD) {
									rule_msg.msg_union.pcc_entry =
										*(struct pcc_rules *)(pfcp_pfd_mgmt_req->app_ids_pfds[itr].
												pfd_context[itr1].pfd_contents[itr2].cstm_pfd_cntnt + idx);
#ifdef PRINT_NEW_RULE_ENTRY
									print_pcc_val(&rule_msg.msg_union.pcc_entry);
#endif /* PRINT_NEW_RULE_ENTRY */
								}else if (rule_msg.mtype == MSG_MTR_ADD) {
									rule_msg.msg_union.mtr_entry =
										*(struct mtr_entry *)(pfcp_pfd_mgmt_req->app_ids_pfds[itr].
												pfd_context[itr1].pfd_contents[itr2].cstm_pfd_cntnt + idx);
#ifdef PRINT_NEW_RULE_ENTRY
									print_mtr_val(&rule_msg.msg_union.mtr_entry);
#endif /* PRINT_NEW_RULE_ENTRY */
								}else if (rule_msg.mtype == MSG_SDF_ADD) {
									rule_msg.msg_union.pkt_filter_entry =
										*(struct pkt_filter *)(pfcp_pfd_mgmt_req->app_ids_pfds[itr].
												pfd_context[itr1].pfd_contents[itr2].cstm_pfd_cntnt + idx);
#ifdef PRINT_NEW_RULE_ENTRY
									print_sdf_val(&rule_msg.msg_union.pkt_filter_entry);
#endif /* PRINT_NEW_RULE_ENTRY */
								}else {
									RTE_LOG_DP(DEBUG, DP, "No rules received\n");
								}
							}
						}
					}
				}
				/* Fill pfcp pfd mgmt response */
				fill_pfcp_pfd_mgmt_resp(&pfcp_pfd_mgmt_resp, cause_id, offend_id);

				if(pfcp_pfd_mgmt_req->header.s) {
					pfcp_pfd_mgmt_resp.header.seid_seqno.no_seid.seq_no =
						pfcp_pfd_mgmt_req->header.seid_seqno.has_seid.seq_no;
				} else {
					pfcp_pfd_mgmt_resp.header.seid_seqno.no_seid.seq_no =
						pfcp_pfd_mgmt_req->header.seid_seqno.no_seid.seq_no;
				}

				encoded = encode_pfcp_pfd_mgmt_rsp_t(&pfcp_pfd_mgmt_resp, pfcp_msg);

				RTE_SET_USED(encoded);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);

				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);
				RTE_LOG_DP(DEBUG, DP, "length[%d]\n",htons(pfcp_hdr->message_len));
				/* Free the allocated memory  */
				free(pfcp_pfd_mgmt_req);
				for (int itr_1 = 0; itr_1 < pfcp_pfd_mgmt_req->app_ids_pfds_count; itr_1++) {
					for (int itr_2 = 0; itr_2 < pfcp_pfd_mgmt_req->app_ids_pfds[itr_1].pfd_context_count; itr_2++) {
						for (int itr_3 = 0; itr_3 < pfcp_pfd_mgmt_req->app_ids_pfds[itr_1].pfd_context[itr_2].pfd_contents_count;
								itr_3++) {
							free(pfcp_pfd_mgmt_req->app_ids_pfds[itr_1].pfd_context[itr_2].pfd_contents[itr_3].cstm_pfd_cntnt);
						}
					}
				}
				break;
			}

		case PFCP_SESSION_ESTABLISHMENT_REQUEST:
			{
				memset(pfcp_msg, 0, 1024);
				pfcp_sess_estab_req_t *pfcp_session_request = malloc(sizeof(pfcp_sess_estab_req_t));
				memset(pfcp_session_request, 0, sizeof(pfcp_sess_estab_req_t));
				pfcp_sess_estab_rsp_t pfcp_session_response = {0};

				decoded = decode_pfcp_sess_estab_req_t(buf_rx, pfcp_session_request);
				RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson is %d\n\n", decoded);

				if (process_up_session_estab_req(pfcp_session_request, &pfcp_session_response)) {
					/* TODO: ERROR HANDLING */
					return -1;
				}

				uint8_t cause_id = 0;
				int offend_id = 0 ;
				cause_check_sess_estab(pfcp_session_request, &cause_id, &offend_id);

				fill_pfcp_session_est_resp(&pfcp_session_response, cause_id,
						offend_id, dp_comm_ip, pfcp_session_request);


				pfcp_session_response.header.seid_seqno.has_seid.seq_no =
					pfcp_session_request->header.seid_seqno.has_seid.seq_no;


				memcpy(&(pfcp_session_response.up_fseid.ipv4_address),
						&(dp_comm_ip.s_addr), IPV4_SIZE);


				encoded = encode_pfcp_sess_estab_rsp_t(&pfcp_session_response,
						pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);

				/* TODO: Need to be remove */
				pfcp_hdr->seid_seqno.has_seid.seid =
						bswap_64(pfcp_session_request->cp_fseid.seid);

				free(pfcp_session_request);
				break;
			}
		case PFCP_SESSION_MODIFICATION_REQUEST:
			{

				int offend_id = 0;
				uint8_t cause_id = REQUESTACCEPTED;
				memset(pfcp_msg, 0, 1024);

				pfcp_sess_mod_req_t pfcp_session_mod_req = {0};

				pfcp_sess_mod_rsp_t pfcp_sess_mod_res = {0};

				decoded = decode_pfcp_sess_mod_req_t(buf_rx, &pfcp_session_mod_req);
				RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson modification is %d\n\n", decoded);

				if (process_up_session_modification_req(&pfcp_session_mod_req,
						&pfcp_sess_mod_res)) {
					/* TODO: ERROR HANDLING */
					return -1;
				}

				/*cause_check_sess_modification(&pfcp_session_mod_req, &cause_id, &offend_id);
	      			if (ret == SESSIONCONTEXTNOTFOUND ){
					cause_id = SESSIONCONTEXTNOTFOUND;
				} */

				fill_pfcp_session_modify_resp(&pfcp_sess_mod_res,
					&pfcp_session_mod_req, cause_id, offend_id);

				/* TODO: Need to be remove */
				pfcp_sess_mod_res.header.seid_seqno.has_seid.seid =
						pfcp_session_mod_req.cp_fseid.seid;

				pfcp_sess_mod_res.header.seid_seqno.has_seid.seq_no =
					pfcp_session_mod_req.header.seid_seqno.has_seid.seq_no;

				encoded = encode_pfcp_sess_mod_rsp_t(&pfcp_sess_mod_res, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);
				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",
							pfcp_hdr->message_type);
				RTE_LOG_DP(DEBUG, DP, "length[%d]\n",
							htons(pfcp_hdr->message_len));

				break;
			}
		case PFCP_SESSION_DELETION_REQUEST:
			{
				int ret = 0;
				int offend_id = 0;
				uint8_t cause_id = 0;
				uint64_t cp_seid = 0;
				memset(pfcp_msg, 0, 1024);

				pfcp_sess_del_req_t *pfcp_session_del_req =
						malloc(sizeof(pfcp_sess_del_req_t));

				//memset(pfcp_session_del_req, 0, sizeof(pfcp_sess_del_req_t));
				pfcp_sess_del_rsp_t  pfcp_sess_del_res = {0};
				decoded = decode_pfcp_sess_del_req_t(buf_rx, pfcp_session_del_req);
				RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson deletion is %d\n\n", decoded);

				if (process_up_session_deletion_req(pfcp_session_del_req,
						&pfcp_sess_del_res)) {
					/* TODO: ERROR HANDLING */
					return -1;
				}

				cause_check_delete_session(pfcp_session_del_req, &cause_id, &offend_id);
				if (ret == SESSIONCONTEXTNOTFOUND ){
					cause_id = SESSIONCONTEXTNOTFOUND;
				}

				/* TODO: Need to be remove */
				cp_seid = pfcp_sess_del_res.header.seid_seqno.has_seid.seid;

				fill_pfcp_sess_del_resp(&pfcp_sess_del_res, cause_id, offend_id);

				/* TODO: Need to be remove */
				pfcp_sess_del_res.header.seid_seqno.has_seid.seid = cp_seid;

				pfcp_sess_del_res.header.seid_seqno.has_seid.seq_no =
					pfcp_session_del_req->header.seid_seqno.has_seid.seq_no;

				encoded = encode_pfcp_sess_del_rsp_t(&pfcp_sess_del_res,  pfcp_msg);


				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);
				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);

				free(pfcp_session_del_req);
				break;

			}

		case PFCP_SESSION_REPORT_RESPONSE:
			{
				/*DDN Response Handle*/
				pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};

				decoded = decode_pfcp_sess_rpt_rsp_t(buf_rx,
						&pfcp_sess_rep_resp);

				if(pfcp_sess_rep_resp.cause.cause_value !=
						REQUESTACCEPTED){
							fprintf(stderr, "Cause received Report response is %d\n",
							pfcp_sess_rep_resp.cause.cause_value);

					/* TODO: Add handling to send association to next upf
					 * for each buffered CSR */
					return -1;
				}

				RTE_LOG_DP(DEBUG, DP, "Received Report Response for sess_id:%lu\n\n",
						pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid);

				break;
			}

		default:
				RTE_LOG_DP(DEBUG, DP, "No Data received\n");
			break;
		}
		if (encoded != 0) {
			if (sendto(my_sock.sock_fd,
				(char *)pfcp_msg,
				encoded,
				MSG_DONTWAIT,
				(struct sockaddr *)peer_addr,
				sizeof(struct sockaddr_in)) < 0)
				RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
		}
#endif /* DP_BUILD */
		return 0;
	}
#endif

