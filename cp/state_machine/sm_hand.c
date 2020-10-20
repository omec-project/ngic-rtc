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
#include "pfcp.h"
#include "cp_app.h"
#include "sm_enum.h"
#include "sm_hand.h"
#include "cp_stats.h"
#include "pfcp_util.h"
#include "debug_str.h"
#include "sm_struct.h"
#include "ipc_api.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "gtpv2c_error_rsp.h"
#include "gtpc_session.h"
#include "cp_timer.h"
#include "cp_config.h"
#include "gw_adapter.h"
#include "cdr.h"
#include "teid.h"
#include "cp.h"

#ifdef USE_REST
#include "main.h"
#endif


int ret = 0;

extern pfcp_config_t config;
extern int clSystemLog;
extern int s5s8_fd;
extern int s5s8_fd_v6;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s5s8_sockaddr_ipv6_len;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s11_mme_sockaddr_ipv6_len;
extern peer_addr_t s5s8_recv_sockaddr;

extern struct rte_hash *bearer_by_fteid_hash;
extern struct cp_stats_t cp_stats;
extern int gx_app_sock;

int
gx_setup_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;

	ret = process_create_sess_req(&msg->gtpc_msg.csr,
			&context, msg->upf_ip, msg->cp_mode);
	if (ret != 0 && ret != GTPC_RE_TRANSMITTED_REQ) {

		if (ret == GTPC_CONTEXT_REPLACEMENT) {
			/* return success value for context replacement case */
			return 0;
		}

		if (ret != -1){

			cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Create Session Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	if(ret == GTPC_RE_TRANSMITTED_REQ ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Discarding Retransmitted "
			"CSR Request\n", LOG_VALUE);
		return ret;
	}

	if (PGWC == context->cp_mode) {
		/*extract ebi_id from array as all the ebi's will be of same pdn.*/
		int ebi_index = GET_EBI_INDEX(msg->gtpc_msg.csr.bearer_contexts_to_be_created[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			cs_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}

		pdn = GET_PDN(context, ebi_index);
		if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			return -1;
		}
		process_msg_for_li(context, S5S8_C_INTFC_IN, msg,
				fill_ip_info(s5s8_recv_sockaddr.type,
						pdn->s5s8_sgw_gtpc_ip.ipv4_addr,
						pdn->s5s8_sgw_gtpc_ip.ipv6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				pdn->s5s8_sgw_gtpc_teid, config.s5s8_port);
	} else {
		process_msg_for_li(context, S11_INTFC_IN, msg,
				fill_ip_info(s11_mme_sockaddr.type,
						context->s11_mme_gtpc_ip.ipv4_addr,
						context->s11_mme_gtpc_ip.ipv6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						config.s11_ip.s_addr,
						config.s11_ip_v6.s6_addr),
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)),
				config.s11_port);
	}

	RTE_SET_USED(unused_param);
	return ret;
}

int
association_setup_handler(void *data, void *unused_param)
{
	int ebi_index = 0;
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint8_t cp_mode = 0;

	/* Populate the UE context, PDN and Bearer information */
	ret = process_create_sess_req(&msg->gtpc_msg.csr,
			&context, msg->upf_ip, msg->cp_mode);
	if (ret) {
		if(ret != -1) {
			if (ret == GTPC_CONTEXT_REPLACEMENT)
				return 0;
			if(ret == GTPC_RE_TRANSMITTED_REQ)
				return ret;
			if(context == NULL)
				cp_mode = msg->cp_mode;
			else
				cp_mode = context->cp_mode;
			cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
					" processing Create Session Request with cause: %s \n",
					LOG_VALUE, cause_str(ret));
		}
		return -1;
	}

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	ebi_index = GET_EBI_INDEX(msg->gtpc_msg.csr.bearer_contexts_to_be_created[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		msg->cp_mode = context->cp_mode;
		cs_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	pdn =  GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return -1;
	}

	if (PGWC == context->cp_mode) {
		process_msg_for_li(context, S5S8_C_INTFC_IN, msg,
				fill_ip_info(s5s8_recv_sockaddr.type,
						pdn->s5s8_sgw_gtpc_ip.ipv4_addr,
						pdn->s5s8_sgw_gtpc_ip.ipv6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				pdn->s5s8_sgw_gtpc_teid, config.s5s8_port);
	} else {
		process_msg_for_li(context, S11_INTFC_IN, msg,
				fill_ip_info(s11_mme_sockaddr.type,
						context->s11_mme_gtpc_ip.ipv4_addr,
						context->s11_mme_gtpc_ip.ipv6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						config.s11_ip.s_addr,
						config.s11_ip_v6.s6_addr),
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)),
				config.s11_port);
	}

	if (pdn->upf_ip.ip_type == 0) {
		if (config.use_dns) {
			push_dns_query(pdn);
			return 0;
		} else {

			if ((config.pfcp_ip_type == PDN_TYPE_IPV6
					|| config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6)
				&& (config.upf_pfcp_ip_type == PDN_TYPE_IPV6
					|| config.upf_pfcp_ip_type == PDN_TYPE_IPV4_IPV6)) {

				memcpy(pdn->upf_ip.ipv6_addr, config.upf_pfcp_ip_v6.s6_addr, IPV6_ADDRESS_LEN);
				pdn->upf_ip.ip_type = PDN_TYPE_IPV6;

			} else if ((config.pfcp_ip_type == PDN_TYPE_IPV4
					|| config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6)
				&& (config.upf_pfcp_ip_type == PDN_TYPE_IPV4
					|| config.upf_pfcp_ip_type == PDN_TYPE_IPV4_IPV6)) {

				pdn->upf_ip.ipv4_addr = config.upf_pfcp_ip.s_addr;
				pdn->upf_ip.ip_type = PDN_TYPE_IPV4;
			}
		}
	}

	if (!context->promotion_flag) {
		process_pfcp_sess_setup(pdn);
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_assoc_resp_handler(void *data, void *addr)
{
	msg_info *msg = (msg_info *)data;
	peer_addr_t *peer_addr = (peer_addr_t *)addr;

	ret = process_pfcp_ass_resp(msg, peer_addr);
	if(ret) {
		cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		process_error_occured_handler(data, addr);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Association Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}
	return 0;
}

int process_recov_asso_resp_handler(void *data, void *addr) {

	int ret = 0;
	peer_addr_t *peer_addr = (peer_addr_t *)addr;
	msg_info *msg = (msg_info *)data;

	ret = process_asso_resp(msg, peer_addr);
	if(ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Association Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}
	return 0;
}

int process_recov_est_resp_handler(void *data, void *unused_param) {

	int ret = 0;
	msg_info *msg = (msg_info *)data;

	ret = process_sess_est_resp(&msg->pfcp_msg.pfcp_sess_est_resp);
	if(ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Establishment Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_cs_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_sgwc_s5s8_create_sess_rsp(&msg->gtpc_msg.cs_rsp);
	if (ret) {
		if(ret != -1){
			msg->cp_mode = 0;
			cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S11_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
		" processing Create Session Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_est_resp_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	uint8_t cp_mode = 0;
	int ret = 0;
	msg_info *msg = (msg_info *)data;
	int ebi = UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		cs_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
						msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	ue_context *context  = NULL;
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
				"Context for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}


	ret = process_pfcp_sess_est_resp(
			&msg->pfcp_msg.pfcp_sess_est_resp, gtpv2c_tx, NOT_PIGGYBACKED);

	if (ret) {
		if(ret != -1){
			cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
								msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing PFCP Session Establishment Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	cp_mode = msg->cp_mode;

	if ((msg->cp_mode == SGWC) || (msg->cp_mode == PGWC)) {

		if(((context->indirect_tunnel_flag == 1) && context->cp_mode == SGWC) ||
				context->procedure == S1_HANDOVER_PROC) {

			ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
					s11_mme_sockaddr, ACC);
			return 0;
		} else {
			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);
		}

		if (SGWC == context->cp_mode) {
			add_gtpv2c_if_timer_entry(
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid),
				&s5s8_recv_sockaddr, tx_buf, payload_length,
				ebi_index, S5S8_IFACE, cp_mode);
		}

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	} else {
		/* Send response on s11 interface */
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr, ACC);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
						config.s11_ip.s_addr,
						config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						s11_mme_sockaddr.ipv4.sin_addr.s_addr,
						s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_mb_req_handler(void *data, void *unused_param)
{

	ue_context *context = NULL;
	msg_info *msg = (msg_info *)data;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn = NULL;
	int pre_check = 0;
	int ebi_index = 0, ret = 0;

	/*Retrive UE state. */
	if(get_ue_context(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context) != 0) {

		mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
					    msg->interface_type);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			" UE context for teid: %d \n", LOG_VALUE,
			msg->gtpc_msg.mbr.header.teid.has_teid.teid);
		return -1;
	}

	if(context->cp_mode != PGWC) {

		pre_check = mbr_req_pre_check(&msg->gtpc_msg.mbr);
		if(pre_check != 0) {

			mbr_error_response(msg, pre_check, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"Conditional IE missing MBR Request",
					LOG_VALUE);

			return -1;
		}
	}

	ret = update_ue_context(&msg->gtpc_msg.mbr, context, bearer, pdn);
	if(ret != 0) {
		if(ret == GTPC_RE_TRANSMITTED_REQ){
			return ret;
		}else{
			mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
					" processing Modify Bearer Request with cause: %s \n",
					LOG_VALUE, cause_str(ret));
			return -1;
		}
	}

	if(msg->gtpc_msg.mbr.pres_rptng_area_info.header.len){
		store_presc_reporting_area_info_to_ue_context(&msg->gtpc_msg.mbr.pres_rptng_area_info,
																						context);
	}

	if(msg->gtpc_msg.mbr.bearer_count != 0) {
		ebi_index =
			GET_EBI_INDEX(msg->gtpc_msg.mbr.bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi);

		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			mbr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}
		delete_gtpv2c_if_timer_entry(msg->gtpc_msg.mbr.header.teid.has_teid.teid,
				ebi_index);
	}

	/*add entry for New MME if MME get change */
	if (((context->mme_changed_flag == TRUE) && ((s11_mme_sockaddr.ipv4.sin_addr.s_addr != 0)
					|| (s11_mme_sockaddr.ipv6.sin6_addr.s6_addr)))) {
		node_address_t node_addr = {0};
		get_peer_node_addr(&s11_mme_sockaddr, &node_addr);
		add_node_conn_entry(&node_addr, S11_SGW_PORT_ID, msg->cp_mode);
	}

	if(context->cp_mode == SGWC) {
		if(pre_check != FORWARD_MBR_REQUEST) {
			ret = process_pfcp_sess_mod_request(&msg->gtpc_msg.mbr, context);
		} else {

			bzero(&tx_buf, sizeof(tx_buf));
			gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
			set_modify_bearer_request(gtpv2c_tx, pdn, bearer);
			ret = set_dest_address(bearer->pdn->s5s8_pgw_gtpc_ip, &s5s8_recv_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", LOG_VALUE,
					inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.ipv4.sin_addr.s_addr)));

			uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);

			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
					s5s8_recv_sockaddr, SENT);

			uint8_t  cp_mode = pdn->context->cp_mode;
			add_gtpv2c_if_timer_entry(
					pdn->context->s11_sgw_gtpc_teid,
					&s5s8_recv_sockaddr, tx_buf, payload_length,
					ebi_index,
					S5S8_IFACE, cp_mode);

			/* copy packet for user level packet copying or li */
			if (context->dupl) {
				process_pkt_for_li(
						context, S5S8_C_INTFC_OUT, s5s8_tx_buf, payload_length,
						fill_ip_info(s5s8_recv_sockaddr.type,
								config.s5s8_ip.s_addr,
								config.s5s8_ip_v6.s6_addr),
						fill_ip_info(s5s8_recv_sockaddr.type,
								s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
								s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
						config.s5s8_port,
						((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
							ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
							ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
			}

			//resp->state =  MBR_REQ_SNT_STATE;
			pdn->state =  MBR_REQ_SNT_STATE;
			return 0;
		}
	} else {
		ret = process_pfcp_sess_mod_req_for_saegwc_pgwc(&msg->gtpc_msg.mbr, context);
	}

	if (ret != 0) {
		if(ret != -1)
			mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode = PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Modify Bearer Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_mb_req_for_mod_proc_handler(void *data, void *unused_param)
{
	RTE_SET_USED(unused_param);
	RTE_SET_USED(data);
	return 0;
}

int
process_sess_mod_resp_handler(void *data, void *unused_param)
{
	struct resp_info *resp = NULL;
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	if (get_sess_entry(sess_id, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, sess_id);
		return -1;
	}

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret) {
		pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"context for teid: %u\n", LOG_VALUE, teid);
		return -1;
	}

	int ebi = UE_BEAR_ID(sess_id);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_SYSTEM_FAILURE);
		return -1;
	}

	bearer = context->eps_bearers[ebi_index];
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND);
		return -1;
	}

	if(resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		uint8_t mbr_procedure = check_mbr_procedure(pdn);

		if(context->cp_mode == SGWC){

			ret = process_pfcp_sess_mod_resp_mbr_req(&msg->pfcp_msg.pfcp_sess_mod_resp,
					gtpv2c_tx, pdn, resp, bearer, &mbr_procedure);
			if (ret != 0) {
				if(ret != -1)
					pfcp_modification_error_response(resp, msg, ret);
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
						" processing PFCP Session Modification Response with cause: %s \n",
						LOG_VALUE, cause_str(ret));

				return -1;
			}
			return 0;

		} else if((context->cp_mode == SAEGWC) || (context->cp_mode == PGWC)) {
#ifdef USE_CSID
			{
				update_peer_node_csid(&msg->pfcp_msg.pfcp_sess_mod_resp, pdn);
			}
#endif /* USE_CSID */

			set_modify_bearer_response(gtpv2c_tx,
					context->sequence, context, bearer, &resp->gtpc_msg.mbr);
			resp->state = CONNECTED_STATE;
			/* Update the UE state */
			pdn->state = CONNECTED_STATE;
		}
	} else {

		ret = process_pfcp_sess_mod_resp(&msg->pfcp_msg.pfcp_sess_mod_resp,
													gtpv2c_tx, context, resp);

		if (ret != 0) {
			if(ret != -1)
				pfcp_modification_error_response(resp, msg, ret);
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
						" processing PFCP Session Modification Response with cause: %s \n",
						LOG_VALUE, cause_str(ret));

			return -1;
		}
	}

	if(context->cp_mode != PGWC &&
			       resp->proc == CONN_SUSPEND_PROC) {
			resp = NULL;
		    RTE_SET_USED(unused_param);
			return 0;
	}

	if(resp->msg_type == GTP_MODIFY_ACCESS_BEARER_REQ) {
			resp = NULL;
		    RTE_SET_USED(unused_param);
			return 0;
	}
	uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if(context->cp_mode != PGWC) {

		ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr, ACC);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));

	} else {

		ret = set_dest_address(bearer->pdn->s5s8_sgw_gtpc_ip, &s5s8_recv_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, s5s8_tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

		}
	}

	RTE_SET_USED(unused_param);
	return 0;
}


/**
 * @brief  : This handler will be called after receiving pfcp_sess_mod_resp in
			 case of mod_proc procedure
 * @param  : data( message received on the sx interface)
 * @param  : unused_param
 * @retrun : Returns 0 in case of success
 */

int
process_mod_resp_for_mod_proc_handler(void *data, void *unused_param)
{
	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);

	return 0;
}

int
process_rel_access_ber_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	/* TODO: Check return type and do further processing */
	ret = process_release_access_bearer_request(&msg->gtpc_msg.rel_acc_ber_req,
			msg->proc);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Release Access Bearer Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		release_access_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				S11_IFACE);
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_change_noti_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	pdn_connection *pdn = NULL;
	ue_context *context = NULL;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &msg->gtpc_msg.change_not_req.header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context) {

		clLog(clSystemLog, eCLSeverityCritical,
				"%s : Error: Failed to process Change Notification Request %d \n",
				__func__, ret);

		change_notification_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

		return -1;
	}

	if(msg->gtpc_msg.change_not_req.pres_rptng_area_info.header.len){
		store_presc_reporting_area_info_to_ue_context(&msg->gtpc_msg.change_not_req.pres_rptng_area_info,
													                                            context);
	}

	if(context->cp_mode == PGWC || context->cp_mode == SAEGWC) {

		ret = process_change_noti_request(&msg->gtpc_msg.change_not_req, context);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Change Notification Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			change_notification_error_response(msg, ret,
					CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

			return -1;
		}

	} else if(context->cp_mode == SGWC) {

		bzero(&tx_buf, sizeof(tx_buf));
		gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

		ret = set_change_notification_request(gtpv2c_tx, &msg->gtpc_msg.change_not_req, &pdn);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Change Notification Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			change_notification_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);

	return 0;
}


int
process_change_noti_resp_handler(void *data, void *unused_param)
{
	ue_context *context = NULL;
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_change_noti_response(&msg->gtpc_msg.change_not_rsp, gtpv2c_tx);
	if(ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Change Notification Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		change_notification_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				msg->interface_type);
		return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, SENT);

	ret = get_ue_context_by_sgw_s5s8_teid(
			msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid,
			&context);
	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"UE Context for teid: %d\n",
			LOG_VALUE, msg->gtpc_msg.change_not_rsp.header.teid.has_teid.teid);
		change_notification_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
			msg->interface_type);
		return -1;
	}

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S11_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s11_mme_sockaddr.type,
							config.s11_ip.s_addr,
							config.s11_ip_v6.s6_addr),
					fill_ip_info(s11_mme_sockaddr.type,
							s11_mme_sockaddr.ipv4.sin_addr.s_addr,
							s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);

	return 0;
}

int
process_ds_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	int ebi_index = 0;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &msg->gtpc_msg.dsr.header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context){

		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Context not found for "
			"given Dropping packet\n", LOG_VALUE);
		ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0,
				msg->interface_type);

		return -1;

	}

	if(context != NULL ) {
		if(context->dsr_info.seq ==  msg->gtpc_msg.dsr.header.teid.has_teid.seq) {
			if(context->dsr_info.status == DSR_IN_PROGRESS) {
				/* Discarding re-transmitted dsr */
				return GTPC_RE_TRANSMITTED_REQ;
			}else{
				/* Restransmitted DSR but processing already done for previous req */
				context->dsr_info.status = DSR_IN_PROGRESS;
			}
		} else {
			context->dsr_info.seq = msg->gtpc_msg.dsr.header.teid.has_teid.seq;
			context->dsr_info.status = DSR_IN_PROGRESS;
		}
	}

	ebi_index = GET_EBI_INDEX(msg->gtpc_msg.dsr.lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		ds_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE :S5S8_IFACE);
		return -1;
	}

	delete_gtpv2c_if_timer_entry(msg->gtpc_msg.dsr.header.teid.has_teid.teid,
		ebi_index);

	/* Handling the case of Demotion */
	if((msg->interface_type == S11_IFACE) && (context->cp_mode == PGWC)) {
		ret = cleanup_sgw_context(&msg->gtpc_msg.dsr, context);
		if (ret) {
			return ret;
		}
		return 0;
	}

	if (context->cp_mode == SGWC && msg->gtpc_msg.dsr.indctn_flgs.indication_oi == 1) {
		/* Indication flag 1 mean dsr needs to be sent to PGW otherwise dont send it to PGW */
		ret = process_sgwc_delete_session_request(&msg->gtpc_msg.dsr, context);
	} else {
		ret = process_pfcp_sess_del_request(&msg->gtpc_msg.dsr, context);
	}

	if (ret){
		 if(ret != -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete Session Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			ds_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE :S5S8_IFACE);
			return -1;
		 }
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_del_resp_handler(void *data, void *unused_param)
{
	uint8_t dupl = 0;
	uint64_t imsi = 0;
	uint8_t cp_mode = 0;
	uint8_t li_data_cntr = 0;
	uint8_t cleanup_status = 0;
	ue_context *context = NULL;
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;
	li_data_t li_data[MAX_LI_ENTRIES_PER_UE] = {0};

	uint16_t msglen = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	uint64_t seid = msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid;

	if (msg->pfcp_msg.pfcp_sess_del_resp.usage_report_count != 0) {
		for(int i=0 ; i< msg->pfcp_msg.pfcp_sess_del_resp.usage_report_count; i++)
			fill_cdr_info_sess_del_resp(seid,
					&msg->pfcp_msg.pfcp_sess_del_resp.usage_report[i]);
	}

	ret = get_ue_context(UE_SESS_ID(seid), &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to retrieve UE context",
				LOG_VALUE);
		ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
				msg->interface_type != PGWC ? S11_IFACE :S5S8_IFACE);
		return -1;
	}
	/*cleanup activity for HSS initiated flow*/
	cleanup_status = context->mbc_cleanup_status;
	/* copy data for LI */
	imsi = context->imsi;
	dupl = context->dupl;
	li_data_cntr = context->li_data_cntr;
	memcpy(li_data, context->li_data, (sizeof(li_data_t) * context->li_data_cntr));

	cp_mode = context->cp_mode;

	if(context->cp_mode != SGWC ) {
		/* Lookup value in hash using session id and fill pfcp response and delete entry from hash*/
		if (config.use_gx) {

			ret = process_pfcp_sess_del_resp(seid, gtpv2c_tx, &ccr_request, &msglen,
					context);

			buffer = rte_zmalloc_socket(NULL, msglen + GX_HEADER_LEN,
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (buffer == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
										"Memory for Buffer, Error: %s \n", LOG_VALUE,
																rte_strerror(rte_errno));
				ds_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
									cp_mode != PGWC ? S11_IFACE :S5S8_IFACE);
				return -1;
			}

			memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
			memcpy(buffer + sizeof(ccr_request.msg_type),
									&ccr_request.msg_len,
							sizeof(ccr_request.msg_len));

			if (gx_ccr_pack(&(ccr_request.data.ccr),
						(unsigned char *)(buffer + GX_HEADER_LEN), msglen) == 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Packing "
					"CCR Buffer\n", LOG_VALUE);
				rte_free(buffer);
				return -1;
			}
		} else {
			ret = process_pfcp_sess_del_resp(
					msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
					gtpv2c_tx, NULL, NULL, context);
		}
	}  else {
		ret = process_pfcp_sess_del_resp(
				msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
				gtpv2c_tx, NULL, NULL, context);
	}

	if (ret) {
		ds_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				cp_mode != PGWC ? S11_IFACE :S5S8_IFACE);

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing PFCP Session Deletion Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return -1;
	}

	if(cleanup_status != PRESENT) {

		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		if ((cp_mode == PGWC) ) {
			/*Send response on s5s8 interface */
			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
					s5s8_recv_sockaddr, SENT);

			update_sys_stat(number_of_users, DECREMENT);
			update_sys_stat(number_of_active_session, DECREMENT);

			if (PRESENT == dupl) {
				process_cp_li_msg_for_cleanup(
						li_data, li_data_cntr, S5S8_C_INTFC_OUT, tx_buf, payload_length,
						fill_ip_info(s5s8_recv_sockaddr.type,
								config.s5s8_ip.s_addr,
								config.s5s8_ip_v6.s6_addr),
						fill_ip_info(s5s8_recv_sockaddr.type,
								s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
								s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
						config.s5s8_port,
						((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
							ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
							ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)),
						cp_mode, imsi);
			}
		} else {
			/* Send response on s11 interface */
			gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
					s11_mme_sockaddr, ACC);

			update_sys_stat(number_of_users, DECREMENT);
			update_sys_stat(number_of_active_session, DECREMENT);

			if (PRESENT == dupl) {
				process_cp_li_msg_for_cleanup(
						li_data, li_data_cntr, S11_INTFC_OUT, tx_buf, payload_length,
						fill_ip_info(s11_mme_sockaddr.type,
								config.s11_ip.s_addr,
								config.s11_ip_v6.s6_addr),
						fill_ip_info(s11_mme_sockaddr.type,
								s11_mme_sockaddr.ipv4.sin_addr.s_addr,
								s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
						config.s11_port,
						((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
							ntohs(s11_mme_sockaddr.ipv4.sin_port) :
							ntohs(s11_mme_sockaddr.ipv6.sin6_port)),
						cp_mode, imsi);
			}
		}
	}
	if (config.use_gx) {
		/* Write or Send CCR -T msg to Gx_App */
		if (cp_mode != SGWC) {
			send_to_ipc_channel(gx_app_sock, buffer,
					msglen + GX_HEADER_LEN);
		}

		if (buffer != NULL) {
			rte_free(buffer);
			buffer = NULL;
		}

		free_dynamically_alloc_memory(&ccr_request);

		update_cli_stats((peer_address_t *) &config.gx_ip, OSS_CCR_TERMINATE, SENT, GX);
		rte_free(buffer);
	}

	RTE_SET_USED(unused_param);
	return 0;
}


int
process_ds_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_delete_session_response(&msg->gtpc_msg.ds_rsp);
	if (ret) {
		if(ret  != -1)
			ds_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->interface_type);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete Session Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_rpt_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_pfcp_report_req(&msg->pfcp_msg.pfcp_sess_rep_req);
	if (ret)
		return ret;

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_ddn_ack_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	int ret = process_ddn_ack(&msg->gtpc_msg.ddn_ack);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Downlink Datat Notification Ack with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return ret;
	}


	RTE_SET_USED(unused_param);
	return 0;
}

int
process_ddn_failure_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	int ret = process_ddn_failure(&msg->gtpc_msg.ddn_fail_ind);
	if(ret){

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Downlink Datat Notification Failure with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return ret;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int process_sess_mod_resp_dl_buf_dur_handler(void *data, void *unused_param)
{
	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int process_sess_mod_resp_ddn_fail_handler(void *data, void *unused_param)
{
	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_est_resp_sgw_reloc_handler(void *data, void *unused_param)
{
	/* SGW Relocation
	 * Handle pfcp session establishment response
	 * and send mbr request to PGWC
	 * Update proper state in hash as MBR_REQ_SNT_STATE
	 */

	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;
	uint8_t cp_mode = 0;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	uint8_t ebi = UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);

	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
				"for seid: %lu", LOG_VALUE,
				msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);
		return -1;
	}

	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_SYSTEM_FAILURE);
		return -1;
	}

	ret = process_pfcp_sess_est_resp(
			&msg->pfcp_msg.pfcp_sess_est_resp, gtpv2c_tx, NOT_PIGGYBACKED);

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing PFCP Session Establishment Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return -1;
	}
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);


	gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

	cp_mode = msg->cp_mode;

	if (SGWC == msg->cp_mode) {
		add_gtpv2c_if_timer_entry(
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid),
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			ebi_index, S5S8_IFACE, cp_mode);
	}

	process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

	RTE_SET_USED(unused_param);
	return 0;
}

/*
This function Handles the CCA-T received from PCEF
*/
int
cca_t_msg_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	gx_context_t *gx_context = NULL;

	RTE_SET_USED(unused_param);

	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(msg->gx_msg.cca.session_id.val),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"hash table for session id: %lu\n", LOG_VALUE, msg->gx_msg.cca.session_id.val);
		return -1;
	}

	if(rte_hash_del_key(gx_context_by_sess_id_hash, msg->gx_msg.cca.session_id.val) < 0){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to delete "
			"hash key for session id: %lu\n", LOG_VALUE, gx_context_by_sess_id_hash);
	}

	if (gx_context != NULL) {
		rte_free(gx_context);
		gx_context = NULL;
	}
	return 0;
}

int cca_u_msg_handler(void *data, void *unused)
{
	msg_info *msg = (msg_info *)data;
	int ret = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	int ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	mod_bearer_req_t *mb_req = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&msg->gx_msg.cca.session_id.val, &call_id);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id found for "
			"session id: %s\n", LOG_VALUE,
			(char*) &msg->gx_msg.cca.session_id.val);
		return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn = get_pdn_conn_entry(call_id);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"PDN for CALL_ID:%u\n", LOG_VALUE, call_id);
		return -1;
	}

	if(msg->gx_msg.cca.presence.presence_reporting_area_information)
		store_presence_reporting_area_info(pdn, &msg->gx_msg.cca.presence_reporting_area_information);

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return -1;
	}
	int ebi = UE_BEAR_ID(pdn->seid);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	if (!(pdn->context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n", LOG_VALUE);
		return -EPERM;
	}

	bearer = pdn->eps_bearers[ebi_index];
	context = pdn->context;
	mb_req = &resp->gtpc_msg.mbr;

	if((context->cp_mode == PGWC) &&(context->sgwu_changed == FALSE) && (mb_req->sgw_fqcsid.header.len == 0 )) {
		set_modify_bearer_response_handover(gtpv2c_tx, mb_req->header.teid.has_teid.seq, context,
				bearer, mb_req);

		int payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		ret = set_dest_address(pdn->s5s8_sgw_gtpc_ip, &s5s8_recv_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
						fill_ip_info(s5s8_recv_sockaddr.type,
								config.s5s8_ip.s_addr,
								config.s5s8_ip_v6.s6_addr),
						fill_ip_info(s5s8_recv_sockaddr.type,
								s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
								s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

		}

		pdn->state =  CONNECTED_STATE;

		return 0;
	} else {

		if (resp->msg_type != GTP_CREATE_SESSION_REQ) {
			ret = send_pfcp_sess_mod_req(pdn, bearer, &resp->gtpc_msg.mbr);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to send"
					" PFCP Session Modification Request%d \n", LOG_VALUE, ret);
				return ret;
			}
		} else {
			if ((ret = send_pfcp_modification_req(context, pdn, bearer, &resp->gtpc_msg.csr, ebi_index)) < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to send"
					" PFCP Session Modification Request%d \n", LOG_VALUE, ret);
				return ret;
			}
		}
	}

	RTE_SET_USED(unused);

	return 0;
}

/*
This function Handles the msgs received from PCEF
*/
int
cca_msg_handler(void *data, void *unused_param)
{
	pdn_connection *pdn = NULL;

	msg_info *msg = (msg_info *)data;

	RTE_SET_USED(msg);

	if (config.use_gx) {
		/* Handle the CCR-T Message */
		if (msg->gx_msg.cca.cc_request_type == TERMINATION_REQUEST) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Received GX CCR-T Response..!! \n",
					LOG_VALUE);
			return 0;
		}

		/* Retrive the ebi index */
		ret = parse_gx_cca_msg(&msg->gx_msg.cca, &pdn);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Credit Control Answer with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			gx_cca_error_response(ret, msg);
			return -1;
		}

		if (pdn->proc == UE_REQ_BER_RSRC_MOD_PROC ||
				pdn->proc == HSS_INITIATED_SUB_QOS_MOD)
			return 0;

		/*update proc if there are two rules*/
		if(pdn->policy.num_charg_rule_install > 1)
			pdn->proc = ATTACH_DEDICATED_PROC;

		if (msg->gx_msg.cca.cc_request_type == UPDATE_REQUEST && pdn->proc == CHANGE_NOTIFICATION_PROC) {

			bzero(&tx_buf, sizeof(tx_buf));
			gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
			set_change_notification_response(gtpv2c_tx, pdn);

			uint8_t payload_length = 0;
			payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);

			if(pdn->context->cp_mode == PGWC) {
				gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
						s5s8_recv_sockaddr, SENT);

				/* copy packet for user level packet copying or li */
				if (pdn->context->dupl) {
					process_pkt_for_li(
							pdn->context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
								fill_ip_info(s5s8_recv_sockaddr.type,
										config.s5s8_ip.s_addr,
										config.s5s8_ip_v6.s6_addr),
								fill_ip_info(s5s8_recv_sockaddr.type,
										s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
										s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
							config.s5s8_port,
							((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
								ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
								ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
				}

			} else if (pdn->context->cp_mode == SAEGWC) {
				gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
						s11_mme_sockaddr, SENT);

				/* copy packet for user level packet copying or li */
				if (pdn->context->dupl) {
					process_pkt_for_li(
							pdn->context, S11_INTFC_OUT, tx_buf, payload_length,
							fill_ip_info(s11_mme_sockaddr.type,
									config.s11_ip.s_addr,
									config.s11_ip_v6.s6_addr),
							fill_ip_info(s11_mme_sockaddr.type,
									s11_mme_sockaddr.ipv4.sin_addr.s_addr,
									s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
							config.s11_port,
							((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
								ntohs(s11_mme_sockaddr.ipv4.sin_port) :
								ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
				}

			}
			pdn->state = CONNECTED_STATE;
			return 0;
		}

	}

	if (pdn->upf_ip.ip_type == 0) {
		if(config.use_dns) {
			push_dns_query(pdn);
			return 0;
		} else {
			if ((config.pfcp_ip_type == PDN_TYPE_IPV6
					|| config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6)
				&& (config.upf_pfcp_ip_type == PDN_TYPE_IPV6
					|| config.upf_pfcp_ip_type == PDN_TYPE_IPV4_IPV6)) {

				memcpy(pdn->upf_ip.ipv6_addr, config.upf_pfcp_ip_v6.s6_addr, IPV6_ADDRESS_LEN);
				pdn->upf_ip.ip_type = PDN_TYPE_IPV6;

			} else if ((config.pfcp_ip_type == PDN_TYPE_IPV4
					|| config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6)
				&& (config.upf_pfcp_ip_type == PDN_TYPE_IPV4
					|| config.upf_pfcp_ip_type == PDN_TYPE_IPV4_IPV6)) {

				pdn->upf_ip.ipv4_addr = config.upf_pfcp_ip.s_addr;
				pdn->upf_ip.ip_type = PDN_TYPE_IPV4;
			}
		}
	}

	process_pfcp_sess_setup(pdn);
	RTE_SET_USED(unused_param);
	return 0;
}


int
process_mb_req_sgw_reloc_handler(void *data, void *unused_param)
{
	RTE_SET_USED(unused_param);
	RTE_SET_USED(data);
	return 0;
}

int
process_sess_mod_resp_sgw_reloc_handler(void *data, void *unused_param)
{

	uint8_t cp_mode = 0;
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	int ebi = UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);

	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	}

	ret = get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid), &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to retrieve UE context",
				LOG_VALUE);
		mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

		return -1;
	}

	ret = process_pfcp_sess_mod_resp_handover(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx, context);
	if (ret) {
		if(ret != -1)
			mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Modification Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
		       s5s8_recv_sockaddr, SENT);

	cp_mode = context->cp_mode;

	if (SGWC == context->cp_mode) {
		add_gtpv2c_if_timer_entry(
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			ebi_index, S5S8_IFACE, cp_mode);
	}

	process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_sess_mod_resp_cbr_handler(void *data, void *unused_param)
{
	uint8_t cp_mode = 0;
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	int ret = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	int ebi = UE_BEAR_ID(sess_id);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		cbr_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
				CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);

		return -1;
	}

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				"UE Context for teid: %u\n", LOG_VALUE, teid);
		cbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0,
					msg->interface_type);
		return -1;
	}

	cp_mode = context->cp_mode;

	ret = get_sess_entry(sess_id, &resp);
	if (ret){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
				"for seid: %lu", LOG_VALUE, sess_id);
		cbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);

		return -1;
	}

	ret = process_pfcp_sess_mod_resp(&msg->pfcp_msg.pfcp_sess_mod_resp, gtpv2c_tx, context, resp);
	if (ret != 0) {
		if(ret != -1)
			cbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Modification Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}


	/* Dedicated Activation Procedure */
	if(context->piggyback == TRUE) {
		context->piggyback = FALSE;
		return 0;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((SAEGWC != context->cp_mode) && ((resp->msg_type == GTP_CREATE_BEARER_RSP) ||
			(resp->msg_type == GX_RAR_MSG) || (resp->msg_type == GTP_BEARER_RESOURCE_CMD))){
	    gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
	           s5s8_recv_sockaddr, SENT);
		if(resp->msg_type != GTP_CREATE_BEARER_RSP){
			add_gtpv2c_if_timer_entry(
					UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
					&s5s8_recv_sockaddr, tx_buf, payload_length,
					ebi_index, S5S8_IFACE, cp_mode);
		}

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	} else {
		if(resp->msg_type != GX_RAA_MSG && resp->msg_type != GX_CCR_MSG) {
		    gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
		            s11_mme_sockaddr, SENT);

			add_gtpv2c_if_timer_entry(
					UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
					&s11_mme_sockaddr, tx_buf, payload_length,
					ebi_index, S11_IFACE, cp_mode);

			process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
		}
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_sess_mod_resp_brc_handler(void *data, void *unused_param)
{

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"BRC HANDLER IS CALLED\n",
			LOG_VALUE);

	int ebi_index = 0;
	uint8_t ebi = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	int ret = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));

	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, sess_id);
		return -1;
	}

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get"
				"UE context for teid: %d\n", LOG_VALUE, teid);
		send_bearer_resource_failure_indication(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode !=  PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	ebi = UE_BEAR_ID(sess_id);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		send_bearer_resource_failure_indication(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
				CAUSE_SOURCE_SET_TO_0, context->cp_mode !=  PGWC ? S11_IFACE : S5S8_IFACE);

		return -1;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		send_bearer_resource_failure_indication(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
			CAUSE_SOURCE_SET_TO_0, context->cp_mode !=  PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	if(pdn->policy.num_charg_rule_install ||
			resp->msg_type == GTP_CREATE_BEARER_REQ ||
			resp->msg_type == GTP_CREATE_BEARER_RSP) {

		process_pfcp_sess_mod_resp_cbr_handler(data, unused_param);

	} else if (pdn->policy.num_charg_rule_modify) {

		process_pfcp_sess_mod_resp_ubr_handler(data, unused_param);

	} else if (pdn->policy.num_charg_rule_delete ||
			resp->msg_type == GTP_DELETE_BEARER_REQ ||
			resp->msg_type == GTP_DELETE_BEARER_RSP) {

		process_pfcp_sess_mod_resp_dbr_handler(data, unused_param);

	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Invalid bearer operation \n", LOG_VALUE);
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
provision_ack_ccau_handler(void *data, void *unused_param) {

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CCA-U for Provsion Ack "
			"is received from PCRF successfully.\n", LOG_VALUE);

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int process_mbr_resp_handover_handler(void *data, void *rx_buf)
{
	ue_context *context = NULL;
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	ret = process_sgwc_s5s8_modify_bearer_response(&(msg->gtpc_msg.mb_rsp),
			gtpv2c_tx, &context);

	if (ret) {
		cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Modify Bearer Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return -1;
	}

	update_sys_stat(number_of_users, INCREMENT);
	update_sys_stat(number_of_active_session, INCREMENT);

	if (NOT_PRESENT == ntohs(gtpv2c_tx->gtpc.message_len)) {
		return 0;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, ACC);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
						config.s11_ip.s_addr,
						config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						s11_mme_sockaddr.ipv4.sin_addr.s_addr,
						s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}

	RTE_SET_USED(rx_buf);

	return 0;
}

int process_mbr_resp_for_mod_proc_handler(void *data, void *rx_buf)
{
	RTE_SET_USED(data);
	RTE_SET_USED(rx_buf);

	return 0;
}

int
process_create_bearer_response_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_create_bearer_response(&msg->gtpc_msg.cb_rsp);
	if (ret) {
		if(ret != -1)
			cbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Create Bearer Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_create_bearer_request_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_create_bearer_request(&msg->gtpc_msg.cb_req);
	if (ret) {
		if(ret != -1)
			cbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Create Bearer Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_rar_request_handler(void *data, void *unused_param)
{
	int16_t ret_temp = 0;
	msg_info *msg = (msg_info *)data;
	uint32_t call_id = 0;
	pdn_connection *pdn_cntxt = NULL;

	ret = retrieve_call_id((char *)&msg->gx_msg.rar.session_id.val, &call_id);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id found for "
			"session id: %s\n", LOG_VALUE, msg->gx_msg.rar.session_id.val);
		return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn_cntxt = get_pdn_conn_entry(call_id);
	if (pdn_cntxt == NULL)
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"PDN for CALL_ID:%u\n", LOG_VALUE, call_id);
		return -1;
	}

	ret_temp = parse_gx_rar_msg(&msg->gx_msg.rar, pdn_cntxt);
	if (ret_temp) {
		if(ret_temp != -1){
			gen_reauth_error_response(pdn_cntxt, ret_temp);
		}
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Re-Auth Request with cause: %s \n",
			LOG_VALUE, cause_str(ret_temp));
		return -1;
	}

	RTE_SET_USED(unused_param);

	return 0;
}

int
pfd_management_handler(void *data, void *unused_param)
{
	clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
		"Pfcp Pfd Management Response Recived Successfully \n", LOG_VALUE);

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_mod_resp_delete_handler(void *data, void *unused_param)
{
	uint8_t cp_mode = 0;
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;

	msg_info *msg = (msg_info *)data;

	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	int ebi = UE_BEAR_ID(sess_id);
	int ebi_index = GET_EBI_INDEX(ebi);

	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		ds_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				"UE context for teid: %u\n", LOG_VALUE, teid);
		ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0,
				msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

		return -1;
	}

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, sess_id);
		ds_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_mod_resp(&msg->pfcp_msg.pfcp_sess_mod_resp,
			gtpv2c_tx, context, resp);
	if (ret) {
		ds_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing PFCP Session Deletion Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		return -1;
	}


	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	cp_mode = context->cp_mode;
	if (context->cp_mode== SGWC) {
		/* Forward s11 delete_session_request on s5s8 */
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		add_gtpv2c_if_timer_entry(
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
			&s5s8_recv_sockaddr, tx_buf, payload_length, ebi_index, S5S8_IFACE,
			cp_mode);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	} else {
		/*Code should not reach here since this handler is only for SGWC*/
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_sess_mod_resp_dbr_handler(void *data, void *unused_param)
{
	uint8_t cp_mode = 0;
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	uint64_t seid = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(seid);
	int ebi  = UE_BEAR_ID(seid);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
				CAUSE_SOURCE_SET_TO_0, msg->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get"
				"UE context for teid: %d\n",LOG_VALUE, teid);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, msg->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	if (get_sess_entry( msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
			"for seid: %lu", LOG_VALUE,
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	if (msg->pfcp_msg.pfcp_sess_mod_resp.usage_report_count != 0) {
		for(int iCnt=0 ; iCnt< msg->pfcp_msg.pfcp_sess_mod_resp.usage_report_count; iCnt++)
			fill_cdr_info_sess_mod_resp(seid,
					&msg->pfcp_msg.pfcp_sess_mod_resp.usage_report[iCnt]);
	}

	cp_mode = context->cp_mode;

	ret = process_delete_bearer_pfcp_sess_response(
		msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
		context, gtpv2c_tx, resp);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing PFCP Session Modification Response with cause: %s \n",
			LOG_VALUE, cause_str(ret));
			delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((SAEGWC != context->cp_mode) &&
		(  resp->msg_type == GTP_DELETE_BEARER_RSP
		|| resp->msg_type == GX_RAR_MSG
		|| resp->msg_type == GTP_DELETE_BEARER_CMD
		|| resp->msg_type == GTP_BEARER_RESOURCE_CMD) ) {

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
	            s5s8_recv_sockaddr, SENT);

		if (resp->msg_type != GTP_DELETE_BEARER_RSP) {
			add_gtpv2c_if_timer_entry(
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
				&s5s8_recv_sockaddr, tx_buf, payload_length,
				ebi_index, S5S8_IFACE, cp_mode);
		}

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	} else if(resp->msg_type != GX_RAA_MSG && resp->msg_type != GX_CCR_MSG) {

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr,SENT);

		add_gtpv2c_if_timer_entry(
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
				&s11_mme_sockaddr, tx_buf, payload_length,
				ebi_index, S11_IFACE, cp_mode);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.
				seid, S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}

	RTE_SET_USED(unused_param);

	return 0;
}

int
process_delete_bearer_request_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;

	ret = get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.db_req.header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"UE context for teid: %d\n", LOG_VALUE, msg->gtpc_msg.db_req.header.teid.has_teid.teid);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, msg->interface_type);
		return -1;
	}

	ret = process_delete_bearer_request(&msg->gtpc_msg.db_req, context, msg->proc);
	if (ret && ret != -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete Bearer Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	RTE_SET_USED(unused_param);

	return 0;
}

int
process_delete_bearer_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;

	if (msg->gtpc_msg.db_rsp.lbi.header.len != 0) {

		/* Delete Default Bearer. Send PFCP Session Deletion Request */
		ret = process_pfcp_sess_del_request_delete_bearer_rsp(&msg->gtpc_msg.db_rsp);
		if (ret && (ret != -1)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete Bearer Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->interface_type);
			return -1;
		}
	} else {

		ret = get_ue_context(msg->gtpc_msg.db_rsp.header.teid.has_teid.teid, &context);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				"UE Context for teid", LOG_VALUE, msg->gtpc_msg.db_rsp.header.teid.has_teid.teid);
			delete_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
					CAUSE_SOURCE_SET_TO_0, msg->interface_type);
			return -1;
		}

		/* Delete Dedicated Bearer. Send PFCP Session Modification Request */
		ret = process_delete_bearer_resp(&msg->gtpc_msg.db_rsp, context, msg->proc);
		if (ret && ret!=-1)
			{
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete Bearer Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
				delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
				return -1;
			}
	}

	RTE_SET_USED(unused_param);

	return 0;
}


int
process_pfcp_sess_del_resp_dbr_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	msg_info *msg = (msg_info *)data;
	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	int ebi = UE_BEAR_ID(sess_id);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_SYSTEM_FAILURE,
				CAUSE_SOURCE_SET_TO_0, msg->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get"
				"UE context for teid: %d\n", LOG_VALUE, teid);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, msg->interface_type);
		return -1;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get PDN for "
			"ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"No Session entry"
				" Found for session id: %lu\n",LOG_VALUE,
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		delete_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	ret = process_delete_bearer_pfcp_sess_response(sess_id, context, gtpv2c_tx, resp);
	if (ret && ret!=-1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Modification Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		delete_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != SGWC ? GX_IFACE : S5S8_IFACE);
		return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((SAEGWC != context->cp_mode) &&
		((resp->msg_type == GTP_DELETE_BEARER_RSP))) {
			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
		    s5s8_recv_sockaddr,SENT);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	}

	delete_sess_context(context, pdn);

	RTE_SET_USED(unused_param);

	return 0;
}

/*UPDATE bearer */
int process_update_bearer_response_handler(void *data, void *unused_param)
{
	int ret = 0;
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;

	if(get_ue_context(msg->gtpc_msg.ub_rsp.header.teid.has_teid.teid, &context) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
				" UE context for teid: %d\n", LOG_VALUE,
				msg->gtpc_msg.ub_rsp.header.teid.has_teid.teid);
		ubr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, msg->interface_type);
		return -1;
	}

	if(msg->gtpc_msg.ub_rsp.pres_rptng_area_info.header.len){
		store_presc_reporting_area_info_to_ue_context(&msg->gtpc_msg.ub_rsp.pres_rptng_area_info,
																						context);
	}

	if (SGWC == context->cp_mode) {

		ret = process_s11_upd_bearer_response(&msg->gtpc_msg.ub_rsp, context);
		if(ret && (ret != -1))
				ubr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
	} else {

		ret = process_s5s8_upd_bearer_response(&msg->gtpc_msg.ub_rsp, context);
		if(ret && ret != -1)
				ubr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, GX_IFACE);
	}

	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Update Bearer Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int process_update_bearer_request_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_update_bearer_request(&msg->gtpc_msg.ub_req);
	if (ret) {
		if(ret != -1)
			ubr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Update Bearer Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;

}

/*Bearer resource command handler*/

/*
 * The Function handles Bearer resource CMD when send from MME to SGWC and
 * also when SGWC sends the same to PGWC
*/
int
process_bearer_resource_command_handler(void *data, void *unused_param)
{
	ue_context *context = NULL;
	uint16_t payload_length = 0;
	uint8_t ret = 0;
	msg_info *msg = (msg_info *)data;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = get_ue_context(msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.teid,
							&context);
	if (ret) {

		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get"
				" UE context for teid: %u\n",LOG_VALUE,
				msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.teid);
		send_bearer_resource_failure_indication(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, msg->interface_type);
		return -1;
	}

	context->is_sent_bearer_rsc_failure_indc = NOT_PRESENT;

	ret = process_bearer_rsrc_cmd(&msg->gtpc_msg.bearer_rsrc_cmd,
												gtpv2c_tx, context);

	if(ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Bearer Resource Command with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		send_bearer_resource_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	if (SGWC == context->cp_mode ) {

		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		add_gtpv2c_if_timer_entry(
				msg->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.teid,
				&s5s8_recv_sockaddr, tx_buf, payload_length,
				GET_EBI_INDEX(msg->gtpc_msg.bearer_rsrc_cmd.lbi.ebi_ebi), S5S8_IFACE, SGWC);


		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

		}
	}

	RTE_SET_USED(unused_param);

	return 0;
}
/*Modify Bearer Command handler*/

/*
 * The Function handles Modify bearer CMD when send from MME to SGWC and
 * also when SGWC sends the same to PGWC
*/
int
process_modify_bearer_command_handler(void *data, void *unused_param)
{
	ue_context *context = NULL;
	uint16_t payload_length = 0;
	uint8_t ret = 0;
	msg_info *msg = (msg_info *)data;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = get_ue_context(msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.teid,
			&context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get"
				" UE context for teid: %u\n", LOG_VALUE,
	                  msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.teid);
		modify_bearer_failure_indication(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
											CAUSE_SOURCE_SET_TO_0, msg->interface_type);
		return -1;
	}

	ret = process_modify_bearer_cmd(&msg->gtpc_msg.mod_bearer_cmd, gtpv2c_tx, context);

	if(ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Modify Bearer Command with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		modify_bearer_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
				context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		return -1;
	}

	if (SGWC == context->cp_mode) {
		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		add_gtpv2c_if_timer_entry(
			msg->gtpc_msg.mod_bearer_cmd.header.teid.has_teid.teid,
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			GET_EBI_INDEX(msg->gtpc_msg.mod_bearer_cmd.bearer_context.eps_bearer_id.ebi_ebi), S5S8_IFACE, SGWC);

		/* copy packet for user level packet copying or li */
		if (context != NULL && context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						s5s8_recv_sockaddr.ipv4.sin_port :
						s5s8_recv_sockaddr.ipv6.sin6_port));
		}
	}

	RTE_SET_USED(unused_param);

	return 0;
}

/*DELETE bearer commaand deactivation*/

/*
 * The Function handles when MME sends Delete Bearer CMD to SGWC and
 * also when SGWC sends the same to PGWC
*/
int
process_delete_bearer_command_handler(void *data, void *unused_param)
{
	ue_context *context = NULL;
	uint16_t payload_length = 0;
	uint8_t ret = 0;
	msg_info *msg = (msg_info *)data;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = get_ue_context(msg->gtpc_msg.del_ber_cmd.header.teid.has_teid.teid,
			&context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get"
				" UE context for teid: %u\n", LOG_VALUE,
				msg->gtpc_msg.del_ber_cmd.header.teid.has_teid.teid);
		delete_bearer_cmd_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
				msg->interface_type);
		return -1;
	}

	ret = process_delete_bearer_cmd_request(&msg->gtpc_msg.del_ber_cmd, gtpv2c_tx, context);

	if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete Bearer Command with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		delete_bearer_cmd_failure_indication(msg, ret, CAUSE_SOURCE_SET_TO_0,
				msg->interface_type);
		return -1;
	}

	if (SGWC == context->cp_mode ) {
		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

		}
	}

	RTE_SET_USED(unused_param);

	return 0;
}

int del_bearer_cmd_ccau_handler(void *data, void *unused_param)
{

	msg_info *msg = (msg_info *)data;
	int ret = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn = NULL;

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&msg->gx_msg.cca.session_id.val, &call_id);
	if (ret < 0) {
	        clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Call Id found "
				"for session id: %s\n", LOG_VALUE,
				(char*) &msg->gx_msg.cca.session_id.val);
	        return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn = get_pdn_conn_entry(call_id);
	if (pdn == NULL)
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"PDN for CALL_ID : %u\n",LOG_VALUE, call_id);
	      return -1;
	}

	ret = process_sess_mod_req_del_cmd(pdn);

	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Modification Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}
	RTE_SET_USED(unused_param);
	return 0;
}

/*Attach with  Dedicated bearer flow*/
int  process_sess_est_resp_dedicated_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;
	gtpv2c_header_t *gtpv2c_cbr_t = NULL;;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_est_resp(
			&msg->pfcp_msg.pfcp_sess_est_resp, gtpv2c_tx, true);

	if (ret) {
		if(ret != -1){
			cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Establishment Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc));

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + ntohs(gtpv2c_cbr_t->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc) + sizeof(gtpv2c_cbr_t->gtpc);


	if (msg->cp_mode == PGWC) {
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
				s5s8_recv_sockaddr, SENT);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	} else {
		/* Send response on s11 interface */
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr, ACC);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));

	}
	RTE_SET_USED(unused_param);
	return 0;
}

/* handles create session response with create bearer request on
 * SGWC and sends pfcp modification request*/

int
process_cs_resp_dedicated_handler(void *data, void *unused)
{

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Handler"
			"process_cs_resp_dedicated_handler is called", LOG_VALUE);

	msg_info *msg = (msg_info *)data;

	ret = process_cs_resp_cb_request(&msg->gtpc_msg.cb_req);
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Create Session Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			return -1;
	}

	RTE_SET_USED(unused);
	RTE_SET_USED(data);
	return 0;
}

/*handles modification response from up side for attach with dedicated flow*/
int
process_pfcp_sess_mod_resp_cs_dedicated_handler(void *data, void *unused)
{

	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	uint32_t teid = 0;

	gtpv2c_header_t *gtpv2c_cbr_t = NULL;

	msg_info *msg = (msg_info *)data;
	uint64_t sess_id  = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	if (get_sess_entry(sess_id , &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"NO Session Entry Found "
			"for session ID : %lu\n", LOG_VALUE, sess_id);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);

	ret = get_ue_context(teid, &context);
	if (ret) {
		if(ret != -1)
			pfcp_modification_error_response(resp, msg, ret);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
				"context for teid: %u\n", LOG_VALUE, teid);
		return -1;
	}

	context->piggyback = TRUE;
	ret =  process_pfcp_sess_mod_resp_cs_cbr_request(sess_id, gtpv2c_tx, resp);
	if (ret != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Session Modification Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return ret;
	}

	if(resp->msg_type == GTP_MODIFY_BEARER_REQ) {

		if(context->cp_mode == SGWC) {

			uint8_t buf1[MAX_GTPV2C_UDP_LEN] = {0};

			gtpv2c_cbr_t = (gtpv2c_header_t *)buf1;

			if (resp->gtpc_msg.mbr.header.teid.has_teid.teid) {
				payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);

				gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
						s11_mme_sockaddr, ACC);
			}

			uint16_t payload_length_s11 = payload_length;

			if (!resp->gtpc_msg.mbr.header.teid.has_teid.teid) {
				payload_length = 0;
				payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);
				gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
						s5s8_recv_sockaddr, SENT);

			} else {
				gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx +
						ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc));

				payload_length = 0;
				payload_length = ntohs(gtpv2c_cbr_t->gtpc.message_len) + sizeof(gtpv2c_cbr_t->gtpc);
				gtpv2c_send(s5s8_fd, s5s8_fd_v6, (uint8_t *)gtpv2c_cbr_t, payload_length,
						s5s8_recv_sockaddr, SENT);

			}


			context->piggyback = FALSE;

			uint8_t tx_buf_temp[MAX_GTPV2C_UDP_LEN] = {0};
			memcpy(tx_buf_temp, tx_buf, payload_length);

			process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length_s11,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));

			process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S5S8_C_INTFC_OUT, tx_buf_temp, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

		} else if (context->cp_mode == SAEGWC){

			context->piggyback = FALSE;
			payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);

			gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
					s11_mme_sockaddr, ACC);

			process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));

		}

	} else {


		gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc));

		payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + ntohs(gtpv2c_cbr_t->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc) + sizeof(gtpv2c_cbr_t->gtpc);

		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
					s11_mme_sockaddr, ACC);

		process_cp_li_msg(
				msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
				S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
					config.s11_ip.s_addr,
					config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
					s11_mme_sockaddr.ipv4.sin_addr.s_addr,
					s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));

	}
	RTE_SET_USED(unused);
	return 0;
}

/*Handles mbr request and cbr response
 * in ATTACH with DEDICATED flow
 */
int
process_mb_request_cb_resp_handler(void *data, void *unused)
{

	msg_info *msg = (msg_info *)data;

	ret = process_mb_request_cb_response(&msg->gtpc_msg.mbr, &msg->cb_rsp);
	if(ret != 0) {
		if(ret == GTPC_RE_TRANSMITTED_REQ){
			return ret;
		}
		else {
				mbr_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0, S11_IFACE);
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
					" processing Modify Bearer Request with cause: %s \n",
					LOG_VALUE, cause_str(ret));
				return -1;
		}
	}
	RTE_SET_USED(unused);
	return 0;
}

/* Function */
int
process_del_pdn_conn_set_req(void *data, void *peer_addr)
{
#ifdef USE_CSID
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;
	peer_addr_t peer_ip = {0};

	memcpy(&peer_ip, peer_addr, sizeof(peer_addr_t));

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_del_pdn_conn_set_req_t(&msg->gtpc_msg.del_pdn_req);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete PDN Connection Set Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	/* Send Response back to peer node */
	ret = fill_gtpc_del_set_pdn_conn_rsp(gtpv2c_tx,
			msg->gtpc_msg.del_pdn_req.header.teid.has_teid.seq,
			GTPV2C_CAUSE_REQUEST_ACCEPTED);
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" Filling Delete PDN Connection Set Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((msg->gtpc_msg.del_pdn_req.pgw_fqcsid.number_of_csids) ||
			(msg->gtpc_msg.del_pdn_req.sgw_fqcsid.number_of_csids)) {
		/* Send response to PGW */
		gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			peer_ip, ACC);
	}

	if (msg->gtpc_msg.del_pdn_req.mme_fqcsid.number_of_csids) {
		/* Send the delete PDN set request to MME */
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				peer_ip, ACC);
	}
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"Send GTPv2C Delete PDN Connection Set Response..!!!\n",
			LOG_VALUE);
#else
	RTE_SET_USED(data);
	RTE_SET_USED(peer_addr);
#endif /* USE_CSID */

	return 0;
}

/* Function */
int
process_del_pdn_conn_set_rsp(void *data, void *unused_param)
{
#ifdef USE_CSID
	msg_info *msg = (msg_info *)data;

	ret = process_del_pdn_conn_set_rsp_t(&msg->gtpc_msg.del_pdn_rsp);
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing Delete PDN Connection Set Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			return -1;
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */

	RTE_SET_USED(unused_param);
	return 0;
}

/* Function */
int
process_pgw_rstrt_notif_ack(void *data, void *unused_param)
{
#ifdef USE_CSID
	msg_info *msg = (msg_info *)data;

	if (msg->gtpc_msg.pgw_rstrt_notif_ack.cause.cause_value !=
			GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PGW Restart Notification Ack with cause: %s \n",
				LOG_VALUE, cause_str(msg->gtpc_msg.pgw_rstrt_notif_ack.cause.cause_value));
		return -1;
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */
	RTE_SET_USED(unused_param);
	return 0;
}

/* Function */
int process_pfcp_sess_set_del_req(void *data, void *peer_addr)
{
#ifdef USE_CSID
	msg_info *msg = (msg_info *)data;
	peer_addr_t *peer_ip = (peer_addr_t *)peer_addr;

	ret = process_pfcp_sess_set_del_req_t(&msg->pfcp_msg.pfcp_sess_set_del_req, peer_ip);
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Set Deletion Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			return -1;
	}

#else
	RTE_SET_USED(data);
	RTE_SET_USED(peer_addr);
#endif /* USE_CSID */
	return 0;
}

/* Function */
int process_pfcp_sess_set_del_rsp(void *data, void *unused_param)
{
#ifdef USE_CSID
	msg_info *msg = (msg_info *)data;

	ret = process_pfcp_sess_set_del_rsp_t(&msg->pfcp_msg.pfcp_sess_set_del_rsp);
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
				" processing PFCP Set Deletion Response with cause: %s \n",
				LOG_VALUE, cause_str(ret));
			return -1;
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */
	RTE_SET_USED(unused_param);
	return 0;
}


int
process_mb_resp_handler(void *data, void *unused_param)
{
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Modify Bearer Response RCVD \n",
			LOG_VALUE);

	msg_info *msg = (msg_info *)data;

	int ret = 0;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	/*Retrive UE state. */
	ret = get_ue_context_by_sgw_s5s8_teid(
			msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid, &context);
	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"UE Context for teid %d\n",
			LOG_VALUE, msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);
		return -1;
	}

	if(msg->gtpc_msg.mb_rsp.pres_rptng_area_act.header.len){
		store_presc_reporting_area_act_to_ue_context(&msg->gtpc_msg.mb_rsp.pres_rptng_area_act,
																						context);
	}

	ret = get_bearer_by_teid(msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid,
				&bearer);

	if(ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Bearer found for "
			"teid:%x \n", LOG_VALUE, msg->gtpc_msg.mb_rsp.header.teid.has_teid.teid);

		mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, S11_IFACE);

		return -1;
	}

	 pdn = bearer->pdn;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
			"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	set_modify_bearer_response(gtpv2c_tx,
			context->sequence, context, bearer, &resp->gtpc_msg.mbr);

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	int payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, ACC);

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Modify Bearer Response SNT \n",
			LOG_VALUE);

	process_cp_li_msg(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			S11_INTFC_OUT, tx_buf, payload_length,
			fill_ip_info(s11_mme_sockaddr.type,
				config.s11_ip.s_addr,
				config.s11_ip_v6.s6_addr),
			fill_ip_info(s11_mme_sockaddr.type,
				s11_mme_sockaddr.ipv4.sin_addr.s_addr,
				s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
			config.s11_port,
			((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
				ntohs(s11_mme_sockaddr.ipv4.sin_port) :
				ntohs(s11_mme_sockaddr.ipv6.sin6_port)));

	RTE_SET_USED(unused_param);

	resp->state = CONNECTED_STATE;
	pdn->state =  CONNECTED_STATE;
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_error_occured_handler(void *data, void *unused_param)
{
	int ret = 0;
	msg_info *msg = (msg_info *)data;

	err_rsp_info info_resp = {0};
	uint8_t count = 1;
	upf_context_t *upf_ctx = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(msg->upf_ip), (void **) &(upf_ctx));

	if(ret >= 0 && (msg->msg_type == PFCP_ASSOCIATION_SETUP_RESPONSE)
			&& (msg->pfcp_msg.pfcp_ass_resp.cause.cause_value != REQUESTACCEPTED)){
		count = upf_ctx->csr_cnt;
	}

	for (uint8_t i = 0; i < count; i++) {
		get_error_rsp_info(msg, &info_resp, i);
		int ebi_index = GET_EBI_INDEX(info_resp.ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return -1;
		}


		uint32_t teid = info_resp.teid;

		if (msg->msg_type == PFCP_SESSION_DELETION_RESPONSE) {
			uint64_t seid = msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid;

			if (msg->pfcp_msg.pfcp_sess_del_resp.usage_report_count != 0) {
				for(int i=0 ; i< msg->pfcp_msg.pfcp_sess_del_resp.usage_report_count; i++)
					fill_cdr_info_sess_del_resp(seid,
							&msg->pfcp_msg.pfcp_sess_del_resp.usage_report[i]);
			}
		}

		cleanup_ue_and_bearer(teid, ebi_index);
	}
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":SM_ERROR: Error handler UE_Proc: %u UE_State: %u "
			"%u and Message_Type:%s\n", LOG_VALUE,
			msg->proc, msg->state,msg->event,
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}


int
process_default_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT":SM_ERROR: No handler found for UE_Proc: %s UE_State: %s UE_event: "
			"%s and Message_Type: %s\n", LOG_VALUE,
			get_proc_string(msg->proc), get_state_string(msg->state),get_event_string(msg->event),
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}

int process_pfcp_sess_mod_resp_ubr_handler(void *data, void *unused_param)
{
	int ret = 0;
	struct resp_info *resp = NULL;
	struct pdn_connection_t *pdn = NULL;
	ue_context *context = NULL;
	int ebi_index = 0;

	msg_info *msg = (msg_info *)data;
	uint32_t teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);


	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
																			&resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for session id: %lu\n", LOG_VALUE, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	if(resp->bearer_count){
		/*extract ebi_id from array as all the ebi's will be of same pdn.*/
		ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[0]);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_SYSTEM_FAILURE);
			return -1;
		}

	}
	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"UE Context for teid: %d\n", LOG_VALUE, teid);
		pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND);

		return -1;
	}

	if (config.use_gx) {
		eps_bearer *bearer = NULL;
		uint64_t seid = msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid;
		if (msg->pfcp_msg.pfcp_sess_mod_resp.usage_report_count != 0) {
			for(int iCnt=0 ; iCnt< msg->pfcp_msg.pfcp_sess_mod_resp.usage_report_count; iCnt++)
				fill_cdr_info_sess_mod_resp(seid,
						&msg->pfcp_msg.pfcp_sess_mod_resp.usage_report[iCnt]);
		}
		pdn = GET_PDN(context, ebi_index);
		if(pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn"
				" for ebi_index: %d\n",
				LOG_VALUE, ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		/*delete rule name after receiving pfcp mod resp*/
		bearer = context->eps_bearers[ebi_index];
		if(bearer != NULL) {
			for(int idx = 0; idx < pdn->policy.count; idx++) {

				for(int idx2 = 0; idx2 < bearer->pdr_count; idx2++) {


					if((pdn->policy.pcc_rule[idx].action == bearer->action) &&
							(strncmp(pdn->policy.pcc_rule[idx].dyn_rule.rule_name,
									bearer->pdrs[idx2]->rule_name, RULE_NAME_LEN) == 0)) {

						if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_REMOVE_RULE) {

							int ret = delete_pdr_qer_for_rule(bearer, bearer->pdrs[idx2]->rule_id);
							if(ret == 0) {
								idx2--;
							}
						}
					}
				}
			}
		}
		if(pdn->proc != UE_REQ_BER_RSRC_MOD_PROC &&
			pdn->proc != HSS_INITIATED_SUB_QOS_MOD) {

			rar_funtions rar_function = NULL;
			rar_function = rar_process(pdn, pdn->proc);

			if(rar_function != NULL){
				ret = rar_function(pdn);
				if(ret)
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
					" processing RAR function with cause: %s \n",
					LOG_VALUE, cause_str(ret));
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Non of the RAR function "
					"returned\n", LOG_VALUE);
			}
		} else {
			provision_ack_ccr(pdn, context->eps_bearers[ebi_index],
						RULE_ACTION_MODIFY, NO_FAIL);
		}
	}

	resp->state = pdn->state;
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_mod_resp_li_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":Processes response for modification response for  %s UE_State: %s UE_event: "
			"%s and Message_Type: %s\n", LOG_VALUE,
			get_proc_string(msg->proc), get_state_string(msg->state),get_event_string(msg->event),
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_cbr_error_occured_handler(void *data, void *unused_param)
{
	struct resp_info *resp = NULL;
	msg_info *msg = (msg_info *)data;

	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for session id: %lu\n", LOG_VALUE, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Processes response for modification"
			"response for  %s UE_State: %s UE_event: "
			"%s and Message_Type: %s\n", LOG_VALUE,
			get_proc_string(msg->proc), get_state_string(msg->state),get_event_string(msg->event),
			gtp_type_str(msg->msg_type));

	reset_resp_info_structure(resp);

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_dbr_error_occured_handler(void *data, void *unused_param)
{
	struct resp_info *resp = NULL;
	msg_info *msg = (msg_info *)data;

	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for session id: %lu\n", LOG_VALUE, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return -1;
	}

	if (msg->msg_type == MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC) {
		/*TODO : Add handling of Failure Provisional Ack*/
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Processes response for"
				"modification response for  %s UE_State: %s UE_event: "
		"%s and Message_Type: %s\n", LOG_VALUE,
		get_proc_string(msg->proc), get_state_string(msg->state), get_event_string(msg->event),
		gtp_type_str(msg->msg_type));
	}

	reset_resp_info_structure(resp);

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_bearer_resource_cmd_error_handler(void *data, void *unused_param)
{
	struct resp_info *resp = NULL;
	msg_info *msg = (msg_info *)data;

	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for sess ID: %lu\n", LOG_VALUE, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return -1;
	}

	reset_resp_info_structure(resp);

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Processes response for "
			"modification response for  %s UE_State: %s UE_event: "
			"%s and Message_Type: %s\n", LOG_VALUE,
			get_proc_string(msg->proc), get_state_string(msg->state),get_event_string(msg->event),
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_update_pdn_set_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT":Processes response for modification response for  %s UE_State: %s UE_event: "
			"%s and Message_Type: %s\n", LOG_VALUE,
			get_proc_string(msg->proc), get_state_string(msg->state),get_event_string(msg->event),
			gtp_type_str(msg->msg_type));

	int ret = proc_pfcp_sess_mbr_udp_csid_req(&msg->gtpc_msg.upd_pdn_req);
	if(ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Update PDN Set Request with cause: %s \n",
			LOG_VALUE, cause_str(ret));
		update_pdn_connection_set_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0);
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_sess_mod_resp_upd_handler(void *data, void *unused_param)
{

	uint8_t payload_length = 0;
	struct resp_info *resp = NULL;
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	uint32_t teid = 0;
	int ret = 0;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);

	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for session id: %lu\n", LOG_VALUE, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return -1;
	}

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret) {
		if(ret != -1)
			pfcp_modification_error_response(resp, msg, ret);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
				"context for teid: %u\n", LOG_VALUE, teid);
		return -1;
	}

	upd_pdn_conn_set_rsp_t upd_pdn_rsp = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *) &upd_pdn_rsp,
			GTP_UPDATE_PDN_CONNECTION_SET_RSP,
				context->s11_mme_gtpc_teid, context->sequence, 0);

	set_cause_accepted(&upd_pdn_rsp.cause, IE_INSTANCE_ZERO);

	for(uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = context->eps_bearers[i];
		if(bearer == NULL)
			continue;
		else
			break;
	}

	pdn = bearer->pdn;

	payload_length = encode_upd_pdn_conn_set_rsp(&upd_pdn_rsp, (uint8_t *)gtpv2c_tx);

	ret = set_dest_address(pdn->s5s8_sgw_gtpc_ip, &s5s8_recv_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			s5s8_recv_sockaddr, SENT);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));

	}

	pdn = bearer->pdn;
	resp->state = CONNECTED_STATE;
	pdn->state = CONNECTED_STATE;

	RTE_SET_USED(unused_param);
	return 0;
}


int process_upd_pdn_set_response_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	eps_bearer *bearer =  NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	int ret = get_ue_context_by_sgw_s5s8_teid(msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid,
					&context);

	if (ret < 0 || !context) {

		/*TODO:AAQUILALI: Handling for both message MABR and MBR*/

		mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
				CAUSE_SOURCE_SET_TO_0, msg->interface_type);
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to get UE Context for teid:%d\n",
				LOG_VALUE, msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid);
		return -1;
	}

	ret = get_bearer_by_teid(msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid, &bearer);
	if(ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Bearer found "
				"for teid: %d\n", LOG_VALUE,
				msg->gtpc_msg.upd_pdn_rsp.header.teid.has_teid.teid);

		if(context->procedure == MODIFY_BEARER_PROCEDURE) {
			mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
					CAUSE_SOURCE_SET_TO_0, context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		} else {
			mod_access_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0);
		}
		return -1;
	}

	pdn = bearer->pdn;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"No Session Entry Found for session id: %lu\n",
				LOG_VALUE, pdn->seid);

		if(context->procedure == MODIFY_BEARER_PROCEDURE) {
			mbr_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND,
					CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
		} else {

			mod_access_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, CAUSE_SOURCE_SET_TO_0);
		}
		return -1;
	}

	if(context->procedure == MODIFY_BEARER_PROCEDURE) {
		set_modify_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer, &resp->gtpc_msg.mbr);
	} else {

		set_modify_access_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer, &resp->gtpc_msg.mod_acc_req);
	}

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	int payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr, ACC);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
						config.s11_ip.s_addr,
						config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						s11_mme_sockaddr.ipv4.sin_addr.s_addr,
						s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s11_mme_sockaddr.ipv4.sin_port) :
					ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}

	RTE_SET_USED(unused_param);

	resp->state = CONNECTED_STATE;
	pdn->state =  CONNECTED_STATE;


	return 0;
}

int process_upd_pdn_conn_set_req(void *data, void *unused_param)
{
	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int process_upd_pdn_conn_set_rsp(void *data, void *unused_param)
{
	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_sess_del_resp_context_replacement_handler(void *data, void *unused_param)
{
	int ebi = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	msg_info *msg = (msg_info *)data;

	uint64_t sess_id = msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);
	int eps_bearer_id = UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);
	ebi = GET_EBI_INDEX(eps_bearer_id);

	if (get_sess_entry(sess_id, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, sess_id);
		return -1;
	}

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret) {
		pfcp_modification_error_response(resp, msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"context for teid: %u\n", LOG_VALUE, teid);
		return -1;
	}

	pdn = GET_PDN(context, ebi);
	if (pdn == NULL) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
				"pdn for ebi_index %d\n", LOG_VALUE, ebi);

		return -1;
	}

	/* CDR handling in case of context replacement */
	if (msg->pfcp_msg.pfcp_sess_del_resp.usage_report_count != 0) {

		for(int i=0 ; i< msg->pfcp_msg.pfcp_sess_del_resp.usage_report_count; i++) {

			fill_cdr_info_sess_del_resp(sess_id, &msg->pfcp_msg.pfcp_sess_del_resp.usage_report[i]);
		}
	}

	/* delete all rule entries and bearer context */
	for (int i = 0; i < MAX_BEARERS; i++) {

		if (pdn->eps_bearers[i] != NULL) {

			uint8_t ebi = pdn->eps_bearers[i]->eps_bearer_id;
			ebi = GET_EBI_INDEX(ebi);

			if (del_rule_entries(pdn, ebi) != 0 ){
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
						"Failed to delete Rule for ebi_index: %d\n", LOG_VALUE, ebi);
			}

			if (delete_bearer_context(pdn, ebi) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Error : While deleting Bearer Context for EBI %d \n", LOG_VALUE, ebi);
			}
		}
	}

	msg->gtpc_msg.csr = resp->gtpc_msg.csr;

	/* deleting UE context */
	delete_sess_context(context, pdn);

	/* new csr handling */
	ret = process_create_sess_req(&msg->gtpc_msg.csr,
			&context, msg->upf_ip, msg->cp_mode);

	if (ret != 0 && ret != GTPC_RE_TRANSMITTED_REQ) {

		if (ret == GTPC_CONTEXT_REPLACEMENT) {
			/* return success value for context replacement case */
			return 0;
		}

		if (ret != -1){

			cs_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0,
					msg->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error recieved while"
			" processing Create Session Request with cause: %s \n",
				LOG_VALUE, cause_str(ret));
		return -1;
	}

	if (SGWC == context->cp_mode) {


		if (pdn->upf_ip.ip_type == 0) {


			if (config.use_dns) {
				push_dns_query(pdn);
				return 0;
			} else {
			/*SJ : Add Conditional based IP assignment for IPv6/IPv4*/
			pdn->upf_ip.ipv4_addr = config.upf_pfcp_ip.s_addr;
			}
		}

		if (!context->promotion_flag) {
			process_pfcp_sess_setup(pdn);
		}

	}

	RTE_SET_USED(unused_param);
	RTE_SET_USED(data);

	return ret;
}

int
process_create_indir_data_frwd_req_handler(void *data, void *unused_param)
{

	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	int ret = 0;

	ret = process_create_indir_data_frwd_tun_request(&msg->gtpc_msg.crt_indr_tun_req, &context);
	if(ret != 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Error in Creating Indirect Tunnel", LOG_VALUE);

		crt_indir_data_frwd_tun_error_response(msg, ret);
		return -1;
	}

	if( context == NULL ) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Context Not Found ", LOG_VALUE);

		crt_indir_data_frwd_tun_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND);
		return -1;
	}


	ret = process_pfcp_assoication_request(context->indirect_tunnel->pdn,
			(context->indirect_tunnel->pdn->default_bearer_id - NUM_EBI_RESERVED));

	if(ret) {
		if(ret != -1) {
			crt_indir_data_frwd_tun_error_response(msg, ret);
		}
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Error in Association Req Handling For Create Indirect Tunnel MSG",
				LOG_VALUE);

		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_del_indirect_tunnel_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	int ret = 0;

	ret = process_del_indirect_tunnel_request(&msg->gtpc_msg.dlt_indr_tun_req);
	if(ret) {
		if(ret != -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Error in del indirect tunnel req", LOG_VALUE);
			delete_indir_data_frwd_error_response(msg, ret);
		}
	return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_del_resp_del_indirect_handler(void *data, void *unused_param)
{

	int li_sock_fd = -1;
	uint64_t uiImsi = 0;
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_del_resp_indirect_tunnel(
			msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx, &uiImsi, &li_sock_fd);

	if(ret) {
		if(ret != -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"Error in PFCP DEL Rsp. For DEL Indirect Tunnel req",
					LOG_VALUE);

			delete_indir_data_frwd_error_response(msg, ret);
		}
		return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr,ACC);

	update_sys_stat(number_of_users, DECREMENT);
	update_sys_stat(number_of_active_session, DECREMENT);

	/*
	process_cp_li_msg(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			S11_INTFC_OUT, tx_buf, payload_length,
			ntohl(config.s11_ip.s_addr), ntohl(s11_mme_sockaddr.ipv4.sin_addr.s_addr),
			config.s11_port, ntohs(s11_mme_sockaddr.ipv4.sin_port));

	process_cp_li_msg_for_cleanup(
			uiImsi, li_sock_fd, tx_buf, payload_length,
			config.s11_ip.s_addr, s11_mme_sockaddr.ipv4.sin_addr.s_addr,
			config.s11_port, s11_mme_sockaddr.ipv4.sin_port);
	*/

	RTE_SET_USED(unused_param);
	return 0;
}


int process_modify_access_bearer_handler(void *data, void *unused_param)
{
	ue_context *context = NULL;
	msg_info *msg = (msg_info *)data;

	/*Retrive UE state. */
	if(get_ue_context(msg->gtpc_msg.mod_acc_req.header.teid.has_teid.teid, &context) != 0) {

		mod_access_bearer_error_response(msg, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, S11_IFACE);
		return -1;
	}

	ret = modify_acc_bearer_req_pre_check(&msg->gtpc_msg.mod_acc_req);
	if(ret != 0) {

		mod_access_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Conditional IE missing Modify Access Bearer Request",
				LOG_VALUE);

		return -1;
	}

	context->procedure  = MODIFY_ACCESS_BEARER_PROC;
	/* CHECK FOR Retranmission of Message */
	if(context->mabr_info.seq ==  msg->gtpc_msg.mod_acc_req.header.teid.has_teid.seq) {
		if(context->mabr_info.status == MABR_IN_PROGRESS) {
			/* Discarding re-transmitted mbr */
			return GTPC_RE_TRANSMITTED_REQ;
		}else{
			/* Restransmitted MABR but processing altready done for previous req */
			context->mabr_info.status = MABR_IN_PROGRESS;
		}
	}else{
		context->mabr_info.seq = msg->gtpc_msg.mod_acc_req.header.teid.has_teid.seq;
		context->mabr_info.status = MABR_IN_PROGRESS;
	}

	ret = process_pfcp_mod_req_modify_access_req(&msg->gtpc_msg.mod_acc_req);
	if (ret != 0) {
		mod_access_bearer_error_response(msg, ret, CAUSE_SOURCE_SET_TO_0);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Error in Modify Access Bearer Request Handling", LOG_VALUE);
	}

	RTE_SET_USED(unused_param);
	return 0;
}
