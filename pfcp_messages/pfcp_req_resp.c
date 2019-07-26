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

uint8_t tx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t tx_s5s8_buf[MAX_GTPV2C_UDP_LEN];

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
int
process_pfcp_msg(uint8_t *buf_rx, int bytes_rx,
		struct sockaddr_in *peer_addr)
{
	pfcp_header_t *pfcp_header = (pfcp_header_t *) buf_rx;
	uint8_t pfcp_msg[1024]= {0};
	int encoded = 0 ;
	int decoded = 0;

#ifdef DP_BUILD
	struct msgbuf *rule_msg = NULL;
#else
	uint16_t payload_length;
	bzero(&tx_buf, sizeof(tx_buf));
	bzero(&tx_s5s8_buf, sizeof(tx_s5s8_buf));
	gtpv2c_header *gtpv2c_s11_tx = (gtpv2c_header *) tx_buf;
	gtpv2c_header *gtpv2c_s5s8_tx = (gtpv2c_header *) tx_s5s8_buf;
#endif

	RTE_LOG_DP(DEBUG, DP, "Bytes received is %d\n", bytes_rx);
	RTE_LOG_DP(DEBUG, DP, "IPADDR [%u]\n",peer_addr->sin_addr.s_addr);

	switch (pfcp_header->message_type)
	{

		case PFCP_HEARTBEAT_REQUEST:
			{

#ifdef CP_BUILD
				cp_stats.nbr_of_sgwu_to_sgwc_echo_req_rcvd++;
				cp_stats.nbr_of_pgwu_to_pgwc_echo_req_rcvd++;
				cp_stats.sgwu_status = 1;
				cp_stats.pgwu_status = 1;
#endif

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
#endif

#ifdef CP_BUILD
				if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
					RTE_LOG_DP(DEBUG, DP, "Error sending in heartbeat request: %i\n",errno);
				}  else {
					cp_stats.nbr_of_sgwc_to_sgwu_echo_resp_sent++;
					cp_stats.nbr_of_pgwc_to_pgwu_echo_resp_sent++;
				}
#endif
				free(pfcp_heartbeat_req);

				break;
			}

		case PFCP_HEARTBEAT_RESPONSE:
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

				break;
			}

#ifdef DP_BUILD
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
							ntohl(pfcp_session_request->create_pdr[1].pdi.local_fteid.teid);
						sess_info.dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
						sess_info.dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr =
							ntohl(pfcp_session_request->create_pdr[1].pdi.local_fteid.ipv4_address);

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
				fill_pfcp_session_est_resp(&pfcp_session_response, cause_id, offend_id);

				pfcp_session_response.up_fseid.seid =
					pfcp_session_request->header.seid_seqno.has_seid.seid;
				pfcp_session_response.header.seid_seqno.has_seid.seq_no =
					pfcp_session_request->header.seid_seqno.has_seid.seq_no;
				switch (app.spgw_cfg)
				{
				 case SGWU:
					/* TODO: Revisit this for change in yang */
					pfcp_session_response.created_pdr.local_fteid.teid =
						ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.teid);
					/* TODO: Revisit this for change in yang */
					pfcp_session_response.created_pdr.local_fteid.ipv4_address =
						ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.ipv4_address);

					/*
					pfcp_session_response.created_pdr[1].local_fteid.teid =
						(pfcp_session_request->create_pdr[1].pdi.local_fteid.teid);
					pfcp_session_response.created_pdr[1].local_fteid.ipv4_address =
						ntohl(pfcp_session_request->create_pdr[1].pdi.local_fteid.ipv4_address);
					*/
					break;
				 case PGWU:
					/* TODO: Revisit this for change in yang */
					pfcp_session_response.created_pdr.local_fteid.teid =
						pfcp_session_request->create_pdr[0].pdi.local_fteid.teid;
					/* TODO: Revisit this for change in yang */
					pfcp_session_response.created_pdr.local_fteid.ipv4_address =
						(pfcp_session_request->create_pdr[0].pdi.local_fteid.ipv4_address);

					/*
					pfcp_session_response.created_pdr[1].local_fteid.teid =
						(pfcp_session_request->create_pdr[1].pdi.local_fteid.teid);
					pfcp_session_response.created_pdr[1].local_fteid.ipv4_address =
						ntohl(pfcp_session_request->create_pdr[1].pdi.local_fteid.ipv4_address);
					*/

					break;

				 case SAEGWU:
					/* TODO: Revisit this for change in yang */
					pfcp_session_response.created_pdr.local_fteid.teid =
						ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.teid);
					/* TODO: Revisit this for change in yang */
					pfcp_session_response.created_pdr.local_fteid.ipv4_address =
						ntohl(pfcp_session_request->create_pdr[0].pdi.local_fteid.ipv4_address);
					break;
				}

				memcpy(&(pfcp_session_response.node_id.node_id_value),
						&(dp_comm_ip.s_addr), NODE_ID_VALUE_LEN);

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
				} else{
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
				sess_info.sess_id = pfcp_session_mod_req->cp_fseid.seid;
				sess_info.ue_addr.iptype = IPTYPE_IPV4;
				/* TODO: Revisit this for change in yang */
				sess_info.ue_addr.u.ipv4_addr =
					ntohl(pfcp_session_mod_req->create_pdr[0].pdi.ue_ip_address.ipv4_address);

				sess_info.num_ul_pcc_rules = 1;
				sess_info.num_dl_pcc_rules = 1;
				sess_info.ul_pcc_rule_id[0] = 1;
				sess_info.dl_pcc_rule_id[0] = 1;
				RTE_LOG_DP(DEBUG, DP, "In MODIFY ENB TEID[%u] ENDIP[%u]\n",
						sess_info.dl_s1_info.enb_teid,sess_info.dl_s1_info.enb_addr.u.ipv4_addr);
				dp_session_modify(dp, &sess_info);
				cause_check_sess_modification(pfcp_session_mod_req, &cause_id, &offend_id);

				fill_pfcp_session_modify_resp(&pfcp_sess_mod_res, cause_id, offend_id);
				/* SOURCE_INTERFACE_VALUE_CORE   = DL packet
				   SOURCE_INTERFACE_VALUE_ACCESS = UL packet*/

				if(pfcp_session_mod_req->create_pdr[0].pdi.src_intfc.interface_value ==
						SOURCE_INTERFACE_VALUE_CORE ){
					pfcp_sess_mod_res.created_pdr.local_fteid.teid =
						sess_info.ul_s1_info.sgw_teid;
					pfcp_sess_mod_res.created_pdr.local_fteid.ipv4_address =
						htonl(sess_info.ul_s1_info.sgw_addr.u.ipv4_addr);
				} else {
					pfcp_sess_mod_res.created_pdr.local_fteid.teid =
						htonl(pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.teid);
					pfcp_sess_mod_res.created_pdr.local_fteid.ipv4_address =
						pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ipv4_address;
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
				/*VS: DDN Response Handle*/
				pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};

				decoded = decode_pfcp_sess_rpt_rsp_t(buf_rx,
						&pfcp_sess_rep_resp);

				if(pfcp_sess_rep_resp.cause.cause_value !=
						REQUESTACCEPTED){
							fprintf(stderr, "Cause received  Association response is %d\n",
							pfcp_sess_rep_resp.cause.cause_value);

					/* TODO: Add handling to send association to next upf
					 * for each buffered CSR */
					return -1;
				}

				RTE_LOG_DP(DEBUG, DP, "Received Report Response for sess_id:%lu\n",
						pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid);

				break;
			}
#else
		case PFCP_ASSOCIATION_SETUP_RESPONSE:
			{
				int ret =0;
				uint32_t upf_ip = 0;

				pfcp_assn_setup_rsp_t resp = {0};
				decoded = decode_pfcp_assn_setup_rsp_t(buf_rx,
							&resp);

				if(resp.cause.cause_value != REQUESTACCEPTED){
					RTE_LOG_DP(DEBUG, DP,
							"Cause received  Association response is %d\n",
							resp.cause.cause_value);

					/* TODO: Add handling to send association to next upf
					 * for each buffered CSR */
					return -1;
				}

				cp_stats.sgwu_status = 1;
				cp_stats.pgwu_status = 1;
				cp_stats.association_setup_resp_acc_rcvd++;

				memcpy(&upf_ip, &resp.node_id.node_id_value,
						IPV4_SIZE);

				/* Init rule tables of user-plane */
				upf_pfcp_sockaddr.sin_addr.s_addr = upf_ip;
				init_dp_rule_tables();

				upf_context_t *upf_context = NULL;
				ret = rte_hash_lookup_data(upf_context_by_ip_hash,
						(const void*) &(upf_ip), (void **) &(upf_context));

				if (ret < 0) {
					RTE_LOG_DP(DEBUG, DP, "NO ENTRY FOUND IN UPF HASH [%u]\n", upf_ip);
					return 0;
				}

				upf_context->assoc_status = ASSOC_ESTABLISHED;

				upf_context->up_supp_features =
						resp.up_func_feat.sup_feat;

				switch (pfcp_config.cp_type)
				{
					case SGWC :
						if (resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
								resp.user_plane_ip_rsrc_info[0].src_intfc ==
								SOURCE_INTERFACE_VALUE_ACCESS )
							upf_context->s1u_ip =
									resp.user_plane_ip_rsrc_info[0].ipv4_address;

						if( resp.user_plane_ip_rsrc_info[1].assosi == 1 &&
								resp.user_plane_ip_rsrc_info[1].src_intfc ==
								SOURCE_INTERFACE_VALUE_CORE )
							upf_context->s5s8_sgwu_ip =
									resp.user_plane_ip_rsrc_info[1].ipv4_address;
						break;

					case PGWC :
						if (resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
								resp.user_plane_ip_rsrc_info[0].src_intfc ==
								SOURCE_INTERFACE_VALUE_ACCESS )
							upf_context->s5s8_pgwu_ip =
									resp.user_plane_ip_rsrc_info[0].ipv4_address;
						break;

					case SAEGWC :
						if( resp.user_plane_ip_rsrc_info[0].assosi == 1 &&
								resp.user_plane_ip_rsrc_info[0].src_intfc ==
								SOURCE_INTERFACE_VALUE_ACCESS )
							upf_context->s1u_ip =
									resp.user_plane_ip_rsrc_info[0].ipv4_address;
						break;

				}

				if (pfcp_config.cp_type == SGWC ||
						pfcp_config.cp_type == SAEGWC) {
					/* TODO: Remove gtpv2c_rx, once change in
					 * process_pfcp_sess_est_request signature
					 */
					struct in_addr upf_ipv4 = {0};
					upf_ipv4.s_addr = upf_ip;

					for (uint8_t i = 0; i < upf_context->csr_cnt; i++) {

						uint8_t encoded_msg[512];
						uint16_t msg_len = 0;

						encode_create_session_request_t(
								(create_session_request_t *)(upf_context->pending_csr[i]),
								encoded_msg, &msg_len);

						ret = process_pfcp_sess_est_request(
								(gtpv2c_header *)encoded_msg,
								(create_session_request_t *)(upf_context->pending_csr[i]),
								gtpv2c_s11_tx, gtpv2c_s5s8_tx,
								upf_context->fqdn, &upf_ipv4);

						if (ret) {
								RTE_LOG_DP(ERR, CP, "%s : Error: %d \n", __func__, ret);
						}

						if (spgw_cfg == SAEGWC) {
							payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
								+ sizeof(gtpv2c_s11_tx->gtpc);

							gtpv2c_send(s11_fd, tx_buf, payload_length,
									(struct sockaddr *) &s11_mme_sockaddr,
									s11_mme_sockaddr_len);
						}

						if (spgw_cfg == SGWC) {
							/* Forward s11 create_session_request on s5s8 */
							payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
								+ sizeof(gtpv2c_s5s8_tx->gtpc);

							RTE_LOG_DP(DEBUG, CP, "SEND REQ TO PGWC :%s\n",
										inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr)));

							gtpv2c_send(s5s8_fd, tx_s5s8_buf, payload_length,
									(struct sockaddr *) &s5s8_recv_sockaddr,
									s5s8_sockaddr_len);

							cp_stats.sm_create_session_req_sent++;
							//s5s8_sgwc_msgcnt++;
						}

						gtpv2c_header *msg = (gtpv2c_header *) encoded_msg;
						stats_update(msg->gtpc.type);

						rte_free(upf_context->pending_csr[i]);
						upf_context->csr_cnt--;
					}
				} else if (pfcp_config.cp_type == PGWC) {

					struct in_addr upf_ipv4 = {0};
					upf_ipv4.s_addr = upf_ip;

					for (uint8_t i = 0; i < upf_context->csr_cnt; i++) {

						uint8_t encoded_msg[512];
						uint16_t msg_len = 0;

						encode_create_session_request_t(
								(create_session_request_t *)(upf_context->pending_csr[i]),
								encoded_msg, &msg_len);

						ret = process_pgwc_s5s8_create_session_request(
								(gtpv2c_header *)encoded_msg,
								gtpv2c_s5s8_tx, &upf_ipv4);

						payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
							+ sizeof(gtpv2c_s5s8_tx->gtpc);

						gtpv2c_send(s5s8_fd, tx_s5s8_buf, payload_length,
								(struct sockaddr *) &s5s8_recv_sockaddr,
								s5s8_sockaddr_len);

						cp_stats.sm_create_session_req_rcvd++;

						gtpv2c_header *msg = (gtpv2c_header *) encoded_msg;
						stats_update(msg->gtpc.type);

						rte_free(upf_context->pending_csr[i]);
						upf_context->csr_cnt--;
					}
				}

				/*adding ip to cp  heartbeat when dp returns the association response*/
				add_ip_to_heartbeat_hash(peer_addr,
						resp.rcvry_time_stmp.rcvry_time_stmp_val);

#ifdef USE_REST
				if ((add_node_conn_entry((uint32_t)peer_addr->sin_addr.s_addr,
								SX_PORT_ID)) != 0) {

					RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGWU/SAEGWU");
				}

#endif/* USE_REST */

				break;
				}

				case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
				{
					pfcp_sess_estab_rsp_t pfcp_sess_est_resp = {0};
					decoded = decode_pfcp_sess_estab_rsp_t(buf_rx,
													&pfcp_sess_est_resp);

					RTE_LOG_DP(DEBUG, DP, "DEOCED bytes in Sess Estab Resp is %d\n",
							decoded);

					if(pfcp_sess_est_resp.cause.cause_value !=
							REQUESTACCEPTED){
						//rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
						//rte_panic("cause received[%d] \n", pfcp_sess_est_resp.cause.cause_value);
						RTE_LOG_DP(DEBUG, DP, "Cause received Est response is %d\n",
								pfcp_sess_est_resp.cause.cause_value);
					}
					cp_stats.session_establishment_resp_acc_rcvd++;

					break;
				}

				case PFCP_SESSION_MODIFICATION_RESPONSE:
				{
					pfcp_sess_mod_rsp_t  pfcp_sess_mod_resp = {0};
					decoded = decode_pfcp_sess_mod_rsp_t(buf_rx,
							&pfcp_sess_mod_resp);
					RTE_LOG_DP(DEBUG, DP, "DEOCED bytes in Sess Modif Resp is %d\n",
							decoded);

					if(pfcp_sess_mod_resp.cause.cause_value !=
							REQUESTACCEPTED){
						//rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
						//rte_panic("cause received[%d] \n", pfcp_sess_mod_resp.cause.cause_value);
						RTE_LOG_DP(DEBUG, DP, "Cause received Mod response is %d\n",
								pfcp_sess_mod_resp.cause.cause_value);
					}
					cp_stats.session_modification_resp_acc_rcvd++;

					break;
				}

				case PFCP_SESSION_DELETION_RESPONSE:
				{
					pfcp_sess_del_rsp_t pfcp_sess_del_resp = {0};
					decoded = decode_pfcp_sess_del_rsp_t(buf_rx, &pfcp_sess_del_resp);
					RTE_LOG_DP(DEBUG, DP, "DEOCED bytes in Sess  Delete Resp is %d\n", decoded );
					if(pfcp_sess_del_resp.cause.cause_value !=
							REQUESTACCEPTED){
						//rte_exit( EXIT_FAILURE,"cause received[%d]\n",pfcp_ass_setup_resp->cause.cause_value);
						//rte_panic("cause received[%d] \n", pfcp_sess_del_resp.cause.cause_value);
						RTE_LOG_DP(DEBUG, DP, "Cause received Del response is %d\n",
								pfcp_sess_del_resp.cause.cause_value);
					}
					cp_stats.session_deletion_resp_acc_rcvd++;
					break;
				}

				case PFCP_SESSION_REPORT_REQUEST:
				{
					/*VS: DDN Handling */
					int ret = 0;
					pfcp_sess_rpt_req_t pfcp_sess_rep_req = {0};
					pfcp_sess_rpt_rsp_t pfcp_sess_rep_resp = {0};
					decoded = decode_pfcp_sess_rpt_req_t(buf_rx, &pfcp_sess_rep_req);

					RTE_LOG_DP(DEBUG, CP, "DDN Request recv from DP for sess:%lu\n",
							pfcp_sess_rep_req.header.seid_seqno.has_seid.seid);

					if (pfcp_sess_rep_req.report_type.dldr == 1) {
						ret = ddn_by_session_id(pfcp_sess_rep_req.header.seid_seqno.has_seid.seid);
						if (ret) {
							fprintf(stderr, "DDN %s: (%d) \n", __func__, ret);
							return -1;
						}
					}

					fill_pfcp_sess_report_resp(&pfcp_sess_rep_resp,
							pfcp_sess_rep_req.header.seid_seqno.has_seid.seq_no);

					pfcp_sess_rep_resp.header.seid_seqno.has_seid.seid =
							pfcp_sess_rep_req.header.seid_seqno.has_seid.seid;

					encoded =  encode_pfcp_sess_rpt_rsp_t(&pfcp_sess_rep_resp, pfcp_msg);
					pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
					pfcp_hdr->message_len = htons(encoded - 4);

					if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
						RTE_LOG_DP(ERR, CP, "Error REPORT REPONSE message: %i\n", errno);
						return -1;
					}
					break;
				}
#endif
				default:
#ifdef DP_BUILD
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
#endif
				break;
			}
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
#endif
			return 0;
	}
#endif

