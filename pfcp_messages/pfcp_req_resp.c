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

#include "main.h"
#include "meter.h"
#include "acl_dp.h"
#include "cp_stats.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_enum.h"

#ifdef CP_BUILD
#include "sm_arr.h"
#include "sm_pcnd.h"
#include "sm_struct.h"
#include "cp_config.h"
#endif /* CP_BUILD */

uint16_t dp_comm_port;
uint16_t cp_comm_port;

struct in_addr dp_comm_ip;
struct rte_hash *node_id_hash;

/*
 * UDP Socket
 */
extern udp_sock_t my_sock;

extern struct rte_hash *heartbeat_recovery_hash;

extern pfcp_config_t pfcp_config;
extern struct sockaddr_in upf_pfcp_sockaddr;

extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

#if defined(CP_BUILD) || defined(DP_BUILD)

static int
process_heartbeat_request(uint8_t *buf_rx, struct sockaddr_in *peer_addr)
{
	int encoded = 0;
	int decoded = 0;
	uint8_t pfcp_msg[1024]= {0};

	RTE_SET_USED(decoded);
#ifdef CP_BUILD
	cp_stats.nbr_of_sgwu_to_sgwc_echo_req_rcvd++;
	cp_stats.nbr_of_pgwu_to_pgwc_echo_req_rcvd++;
	cp_stats.sgwu_status = 1;
	cp_stats.pgwu_status = 1;
#endif /* CP_BUILD */

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
	}  else {
		cp_stats.nbr_of_sgwc_to_sgwu_echo_resp_sent++;
		cp_stats.nbr_of_pgwc_to_pgwu_echo_resp_sent++;
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
#ifdef CP_BUILD
	cp_stats.nbr_of_sgwu_to_sgwc_echo_resp_rcvd++;
	cp_stats.nbr_of_pgwu_to_pgwc_echo_resp_rcvd++;
	cp_stats.sgwu_status = 1;
	cp_stats.pgwu_status = 1;
#endif /*CP_BUILD*/
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
	/* TODO: Move this rx */
	if ((bytes_rx = pfcp_recv(pfcp_rx, 512,
					peer_addr)) < 0) {
		perror("msgrecv");
		return -1;
	}

	msg_info msg = {0};
	get_current_time(cp_stats.sx_peer_timestamp);
	if(pfcp_header->message_type == PFCP_HEARTBEAT_REQUEST){
		ret = process_heartbeat_request(buf_rx, peer_addr);
		if(ret != 0){
			fprintf(stderr, "%s: Failed to process pfcp heartbeat request\n", __func__);
			return -1;
		}
		return 0;
	}else if(pfcp_header->message_type == PFCP_HEARTBEAT_RESPONSE){
		ret = process_heartbeat_response(buf_rx, peer_addr);
		if(ret != 0){
			fprintf(stderr, "%s: Failed to process pfcp heartbeat response\n", __func__);
			return -1;
		}
		return 0;
	}else {
		/*Reset periodic timers*/
		process_response(peer_addr->sin_addr.s_addr);

		if ((ret = pfcp_pcnd_check(buf_rx, &msg, bytes_rx)) != 0) {
			fprintf(stderr, "%s: Failed to process pfcp precondition check\n", __func__);
			return -1;
		}

		if ((msg.state < END_STATE) && (msg.event < END_EVNT)) {
			/* Called register callback */
			ret = (*State_Machine[msg.state][msg.event])(&msg, peer_addr);
			if (ret) {

				clLog(sxlogger, eCLSeverityCritical, "%s : "
						"State_Machine Callback failed with Error: %d \n",
						__func__, ret);
				return -1;
			}
		}
	}
#else /* End CP_BUILD , Start DP_BUILD */

	/* TODO: Move this rx */
	if ((bytes_rx = udp_recv(pfcp_rx, 512,
					peer_addr)) < 0) {
		perror("msgrecv");
		return -1;
	}

	int encoded = 0;
	int decoded = 0;
	uint8_t pfcp_msg[1024]= {0};
	struct msgbuf *rule_msg = NULL;

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
				pfcp_assn_setup_req_t *pfcp_ass_setup_req = malloc(sizeof(pfcp_assn_setup_req_t));
				pfcp_assn_setup_rsp_t pfcp_ass_setup_resp = {0} ;

				decoded = decode_pfcp_assn_setup_req_t(buf_rx,pfcp_ass_setup_req);
				RTE_LOG_DP(DEBUG, DP, "[DP] Decoded bytes [%d]\n",decoded);
				RTE_LOG_DP(DEBUG, DP, "recover_time[%d],cpf[%d] from CP \n",
						(pfcp_ass_setup_req->rcvry_time_stmp.rcvry_time_stmp_val),
						(pfcp_ass_setup_req->cp_func_feat.sup_feat));

				uint8_t cause_id = 0;
				int offend_id = 0;
				cause_check_association(pfcp_ass_setup_req, &cause_id, &offend_id);
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
					memcpy(&value,pfcp_ass_setup_req->node_id.node_id_value,IPV4_SIZE);
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
						pfcp_ass_setup_req->rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST

				if ((add_node_conn_entry((uint32_t)peer_addr->sin_addr.s_addr, 0, SX_PORT_ID)) != 0) {
					RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGWU/SAEGWU");
				}
#endif

				fill_pfcp_association_setup_resp(&pfcp_ass_setup_resp, cause_id);

				pfcp_ass_setup_resp.header.seid_seqno.no_seid.seq_no =
					pfcp_ass_setup_req->header.seid_seqno.no_seid.seq_no;
				memcpy(&(pfcp_ass_setup_resp.node_id.node_id_value),&(dp_comm_ip.s_addr), NODE_ID_VALUE_LEN);

				encoded =  encode_pfcp_assn_setup_rsp_t(&pfcp_ass_setup_resp, pfcp_msg);

				RTE_SET_USED(encoded);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);
				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);
				RTE_LOG_DP(DEBUG, DP, "length[%d]\n",htons(pfcp_hdr->message_len));
				free(pfcp_ass_setup_req);
				break;
			}
		case PFCP_SESSION_ESTABLISHMENT_REQUEST:
			{
				memset(pfcp_msg, 0, 1024);
				pfcp_sess_estab_req_t *pfcp_session_request = malloc(sizeof(pfcp_sess_estab_req_t));
				pfcp_sess_estab_rsp_t pfcp_session_response = {0};
				struct session_info sess_info = {0};;
				struct dp_id dp = {0};

				decoded = decode_pfcp_sess_estab_req_t(buf_rx, pfcp_session_request);
				RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson is %d\n", decoded);

				uint8_t cause_id = 0;
				int offend_id = 0 ;
				cause_check_sess_estab(pfcp_session_request, &cause_id, &offend_id);

				switch (app.spgw_cfg)
				{
					case SGWU:
						/*Filling s1u f-teid in sess info*/
						sess_info.ul_s1_info.sgw_teid =
							ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.teid);
						sess_info.ul_s1_info.sgw_addr.u.ipv4_addr =
							ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.ipv4_address);
						sess_info.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;

						/*Filling s5s8 sgwu f-teid in sess info*/
						sess_info.dl_s1_info.s5s8_sgwu_addr.iptype  = IPTYPE_IPV4;
						sess_info.dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr =
							ntohl(pfcp_session_request->create_pdr[1].pdi.local_fteid.ipv4_address);

						break;

					case PGWU:
						sess_info.ul_s1_info.sgw_teid =
							pfcp_session_request->create_pdr[0].pdi.local_fteid.teid;
						sess_info.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
						sess_info.ul_s1_info.sgw_addr.u.ipv4_addr =
							ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.ipv4_address);

						sess_info.dl_s1_info.enb_teid =
							ntohl(pfcp_session_request->create_far[0].frwdng_parms.outer_hdr_creation.teid);
						sess_info.dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
						sess_info.dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr =
							ntohl(pfcp_session_request->create_far[0].frwdng_parms.outer_hdr_creation.ipv4_address);

					case SAEGWU:

						sess_info.ul_s1_info.sgw_teid =
							ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.teid);
						sess_info.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
						sess_info.ul_s1_info.sgw_addr.u.ipv4_addr =
							ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.ipv4_address);

						break;
					default:
					     RTE_LOG_DP(DEBUG, DP, "Default %d\n", app.spgw_cfg);
				}

				sess_info.sess_id = pfcp_session_request->cp_fseid.seid;
				sess_info.num_ul_pcc_rules = 1;
				sess_info.num_dl_pcc_rules = 1;
				sess_info.ul_pcc_rule_id[0] = 1;
				sess_info.dl_pcc_rule_id[0] = 1;
				sess_info.ue_addr.iptype = IPTYPE_IPV4;
				sess_info.ue_addr.u.ipv4_addr =
					ntohl(pfcp_session_request->create_pdr[0].pdi.ue_ip_address.ipv4_address);
				RTE_LOG_DP(DEBUG, DP, "SESS ID in DP %lu\n", sess_info.sess_id);
				dp_session_create(dp,&sess_info);
				fill_pfcp_session_est_resp(&pfcp_session_response, cause_id,
						offend_id, dp_comm_ip, pfcp_session_request);

				pfcp_session_response.up_fseid.seid =
					pfcp_session_request->header.seid_seqno.has_seid.seid;
				pfcp_session_response.header.seid_seqno.has_seid.seq_no =
					pfcp_session_request->header.seid_seqno.has_seid.seq_no;

				/* memcpy(&(pfcp_session_response.node_id.node_id_value),
						&(dp_comm_ip.s_addr), NODE_ID_VALUE_LEN); */

				memcpy(&(pfcp_session_response.up_fseid.ipv4_address),
						&(dp_comm_ip.s_addr), IPV4_SIZE);

				/* TODO: Revisit this for change in yang */
				/*
				memcpy(&(pfcp_session_response.sgwu_fqcsid.node_address.ipv4_address),
						&(dp_comm_ip.s_addr), IPV4_SIZE);
				*/

				encoded = encode_pfcp_sess_estab_rsp_t(&pfcp_session_response,
						pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);

				pfcp_hdr->seid_seqno.has_seid.seid =
							bswap_64(pfcp_session_response.up_fseid.seid);

				free(pfcp_session_request);
				break;
			}
		case PFCP_SESSION_MODIFICATION_REQUEST:
			{

				uint8_t cause_id = 0;
				int offend_id = 0;
				memset(pfcp_msg, 0, 1024);

				RTE_LOG_DP(DEBUG, DP, "In the Session Modifiation Request\n");

				pfcp_sess_mod_req_t *pfcp_session_mod_req =
							malloc(sizeof(pfcp_sess_mod_req_t));

				pfcp_sess_mod_rsp_t  pfcp_sess_mod_res = {0};
				struct session_info sess_info = {0};
				struct dp_id dp = {0};

				decoded = decode_pfcp_sess_mod_req_t(buf_rx, pfcp_session_mod_req);
				RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson modification  is %d\n", decoded);


				/* SOURCE_INTERFACE_VALUE_CORE   = DL packet
				   SOURCE_INTERFACE_VALUE_ACCESS = UL packet
				   Access <-> SGWU <-> core -s5s8- Access <-> PGWU <-> Core */

				if(pfcp_session_mod_req->create_pdr_count){
					if(pfcp_session_mod_req->create_pdr[0].pdi.src_intfc.interface_value ==
							SOURCE_INTERFACE_VALUE_CORE ){
						/*Filling of Enodeb F-TEID*/
						sess_info.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
						/* TODO: Revisit this for change in yang */
						sess_info.dl_s1_info.enb_teid =
							ntohl(pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.teid);
						/* TODO: Revisit this for change in yang */
						sess_info.dl_s1_info.enb_addr.u.ipv4_addr =
							ntohl(pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ipv4_address);
					}else{
						/*Filling of s5s8 pgwu F-TEID*/
						//sess_info.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
						/*TODO :Here it should be pgw teid ?*/
						/*sess_info.ul_s1_info.sgw_teid =
						  pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.teid;*/
						sess_info.ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
						/* TODO: Revisit this for change in yang */
						sess_info.ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr =
							ntohl(pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ipv4_address);
					}
				} else if(pfcp_session_mod_req->update_far_count){
					if(pfcp_session_mod_req->update_far[0].upd_frwdng_parms.dst_intfc.interface_value ==
							SOURCE_INTERFACE_VALUE_ACCESS ){
						/*Filling of Enodeb F-TEID*/
						sess_info.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
						/* TODO: Revisit this for change in yang */
						sess_info.dl_s1_info.enb_teid =
							(pfcp_session_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.teid);
						/* TODO: Revisit this for change in yang */
						sess_info.dl_s1_info.enb_addr.u.ipv4_addr =
							(pfcp_session_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.ipv4_address);
					}else{
						sess_info.ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
						/* TODO: Revisit this for change in yang */
						sess_info.ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr =
							(pfcp_session_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.ipv4_address);
					}
				}
				sess_info.sess_id = pfcp_session_mod_req->cp_fseid.seid;
				sess_info.ue_addr.iptype = IPTYPE_IPV4;
				/* TODO: Revisit this for change in yang */

				/* Removing this code, taking car of this in copy_sess_info function */
				/*
				   sess_info.ue_addr.u.ipv4_addr =
				   ntohl(pfcp_session_mod_req->create_pdr[0].pdi.ue_ip_address.ipv4_address);
				*/

				sess_info.num_ul_pcc_rules = 1;
				sess_info.num_dl_pcc_rules = 1;
				sess_info.ul_pcc_rule_id[0] = 1;
				sess_info.dl_pcc_rule_id[0] = 1;
				RTE_LOG_DP(DEBUG, DP, "In MODIFY ENB TEID[%u] ENDIP[%u]\n",
						sess_info.dl_s1_info.enb_teid,sess_info.dl_s1_info.enb_addr.u.ipv4_addr);
				dp_session_modify(dp, &sess_info);
				cause_check_sess_modification(pfcp_session_mod_req, &cause_id, &offend_id);

				fill_pfcp_session_modify_resp(&pfcp_sess_mod_res, pfcp_session_mod_req, cause_id, offend_id);
				/* SOURCE_INTERFACE_VALUE_CORE   = DL packet
				   SOURCE_INTERFACE_VALUE_ACCESS = UL packet*/

				if(pfcp_sess_mod_res.created_pdr.header.len){
					if(pfcp_session_mod_req->create_pdr[0].pdi.src_intfc.interface_value ==
							SOURCE_INTERFACE_VALUE_CORE ){
						pfcp_sess_mod_res.created_pdr.local_fteid.teid =
							sess_info.ul_s1_info.sgw_teid;
						pfcp_sess_mod_res.created_pdr.local_fteid.ipv4_address =
							htonl(sess_info.ul_s1_info.sgw_addr.u.ipv4_addr);
					} else {
						pfcp_sess_mod_res.created_pdr.local_fteid.teid =
							pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.teid;
						pfcp_sess_mod_res.created_pdr.local_fteid.ipv4_address =
							htonl(pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ipv4_address);
					}
				}

				RTE_LOG_DP(DEBUG, DP, "In MODIFY S1U TEID[%u]\n",
						pfcp_sess_mod_res.created_pdr.local_fteid.teid);

				pfcp_sess_mod_res.header.seid_seqno.has_seid.seid =
					pfcp_session_mod_req->header.seid_seqno.has_seid.seid;
				pfcp_sess_mod_res.header.seid_seqno.has_seid.seq_no =
					pfcp_session_mod_req->header.seid_seqno.has_seid.seq_no;

				encoded = encode_pfcp_sess_mod_rsp_t(&pfcp_sess_mod_res, pfcp_msg);

				pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
				pfcp_hdr->message_len = htons(encoded - 4);
				RTE_LOG_DP(DEBUG, DP, "sending response of sess [%d] from dp\n",pfcp_hdr->message_type);
				RTE_LOG_DP(DEBUG, DP, "length[%d]\n",htons(pfcp_hdr->message_len));

				free(pfcp_session_mod_req);
				break;
			}
		case PFCP_SESSION_DELETION_REQUEST:
			{

				memset(pfcp_msg, 0, 1024);
				struct session_info sess_info = {0};
				struct dp_id dp = {0};
				uint8_t cause_id = 0;
				int offend_id = 0;

				pfcp_sess_del_req_t *pfcp_session_del_req =
						malloc(sizeof(pfcp_sess_del_req_t));

				pfcp_sess_del_rsp_t  pfcp_sess_del_res = {0};
				decoded = decode_pfcp_sess_del_req_t(buf_rx, pfcp_session_del_req);
				RTE_LOG_DP(DEBUG, DP, "DECOED bytes in sesson deletion  is %d\n", decoded);

				sess_info.sess_id = pfcp_session_del_req->header.seid_seqno.has_seid.seid;
				dp_session_delete(dp,&sess_info);

				cause_check_delete_session(pfcp_session_del_req, &cause_id, &offend_id);

				fill_pfcp_sess_del_resp(&pfcp_sess_del_res, cause_id, offend_id);
				pfcp_sess_del_res.header.seid_seqno.has_seid.seid =
					pfcp_session_del_req->header.seid_seqno.has_seid.seid;
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

				RTE_LOG_DP(DEBUG, DP, "Received Report Response for sess_id:%lu\n",
						pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid);

				break;
			}

		default:
			rule_msg = (struct msgbuf *) buf_rx;

			if (rule_msg->mtype == MSG_ADC_TBL_ADD) {
				cb_adc_entry_add(rule_msg);
			} else if (rule_msg->mtype == MSG_PCC_TBL_ADD) {
				cb_pcc_entry_add(rule_msg);
			} else if (rule_msg->mtype == MSG_MTR_ADD) {
				cb_meter_profile_entry_add(rule_msg);
			} else if (rule_msg->mtype == MSG_SDF_ADD) {
				cb_sdf_filter_entry_add(rule_msg);
			} else {
				RTE_LOG_DP(DEBUG, DP, "No rules received\n");
			}
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

