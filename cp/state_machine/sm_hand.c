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
#include "clogger.h"

#ifdef USE_REST
#include "main.h"
#endif


int ret = 0;

pfcp_config_t pfcp_config;

extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

extern struct rte_hash *bearer_by_fteid_hash;
extern struct cp_stats_t cp_stats;

#ifdef GX_BUILD
extern int gx_app_sock;
#endif /* GX_BUILD */

int
gx_setup_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;

	ret = process_create_sess_req(&msg->gtpc_msg.csr,
			&context, &msg->upf_ipv4);
	if (ret != 0 && ret != -2) {
		if (ret != -1){

			cs_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Error: %d \n",
				__file__, __func__, __LINE__, ret);
		return -1;
	}

	RTE_SET_USED(unused_param);
	return ret;
}

int
association_setup_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_context = NULL;
	struct resp_info *resp = NULL;

	/* VS: Populate the UE context, PDN and Bearer information */
	ret = process_create_sess_req(&msg->gtpc_msg.csr,
			&context, &msg->upf_ipv4);
	if (ret) {
		if(ret != -1){
			if(ret == -2 )
				return ret;
			cs_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Error: %d \n",
				__file__, __func__, __LINE__, ret);
		return -1;
	}

	uint32_t ebi_index = msg->gtpc_msg.csr.bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi - 5;
	ret = process_pfcp_assoication_request(context->pdns[ebi_index], ebi_index);
	if(ret){
		if(ret != -1){
			cs_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(sxlogger, eCLSeverityCritical, "%s:%s:%d Error: %d \n",
				__file__, __func__, __LINE__, ret);
	return -1;
	}

	pdn = context->pdns[ebi_index];

	/* Retrive association state based on UPF IP. */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ipv4.s_addr),
			(void **) &(upf_context));
	if (upf_context->state != PFCP_ASSOC_RESP_RCVD_STATE) {
		if (ret >= 0) {
			upf_context->csr = msg->gtpc_msg.csr;
		}
	}
	if (upf_context->state == PFCP_ASSOC_RESP_RCVD_STATE) {
 		ret = get_sess_entry(pdn->seid, &resp);
		if(ret != -1 && resp != NULL){
			resp->gtpc_msg.csr = msg->gtpc_msg.csr;
		}
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_assoc_resp_handler(void *data, void *addr)
{
	msg_info *msg = (msg_info *)data;
	struct sockaddr_in *peer_addr = (struct sockaddr_in *)addr;

	ret = process_pfcp_ass_resp(msg, peer_addr);
	if(ret){
		if(ret != -1){
			cs_error_response(msg, ret,
							spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, addr);
		}
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return -1;
	}
	return 0;
}

int
process_cs_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_sgwc_s5s8_create_sess_rsp(&msg->gtpc_msg.cs_rsp);
	if (ret) {
			if(ret != -1){
				cs_error_response(msg, ret, S11_IFACE);
				process_error_occured_handler(data, unused_param);
			}
			clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
					__func__, __LINE__, ret);
			return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_est_resp_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_est_resp(
			&msg->pfcp_msg.pfcp_sess_est_resp, gtpv2c_tx);
	//ret = process_pfcp_sess_est_resp(
	//		msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
	//		gtpv2c_tx,
	//		msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid);

	if (ret) {
		if(ret != -1){
			cs_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return -1;
	}
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == PGWC)) {
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);


		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
							gtpv2c_tx->gtpc.message_type,SENT,S5S8);

		if (SGWC == pfcp_config.cp_type) {
			add_gtpv2c_if_timer_entry(
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid),
				&s5s8_recv_sockaddr, tx_buf, payload_length,
				UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid) - 5,
				S5S8_IFACE);
		}

		//s5s8_sgwc_msgcnt++;
	} else {
		/* Send response on s11 interface */
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);

		update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, ACC,S11);

	}
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_mb_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_pfcp_sess_mod_request(&msg->gtpc_msg.mbr);
	if (ret != 0) {
		if(ret != -1)
			mbr_error_response(msg, ret,
					spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_mod_resp_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_mod_resp(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx);
	if (ret != 0) {
		if(ret != -1)
			mbr_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, tx_buf, payload_length,
			(struct sockaddr *) &s11_mme_sockaddr,
			s11_mme_sockaddr_len);

	update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type,ACC,S11);

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_rel_access_ber_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	/* TODO: Check return type and do further processing */
	ret = process_release_access_bearer_request(&msg->gtpc_msg.rel_acc_ber_req_t,
			msg->proc);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_ds_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	if (pfcp_config.cp_type == SGWC && msg->gtpc_msg.dsr.indctn_flgs.indication_oi == 1) {
		/* Indication flag 1 mean dsr needs to be sent to PGW otherwise dont send it to PGW */
		ret = process_sgwc_delete_session_request(&msg->gtpc_msg.dsr);
	} else {
		ret = process_pfcp_sess_del_request(&msg->gtpc_msg.dsr);
	}

	if (ret){
		if(ret != -1)
			ds_error_response(msg, ret,
								spgw_cfg != PGWC ? S11_IFACE :S5S8_IFACE);
		return ret;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_del_resp_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

#ifdef GX_BUILD
	uint16_t msglen = 0;
	char *buffer = NULL;
	gx_msg ccr_request = {0};
#endif

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	if( pfcp_config.cp_type != SGWC ) {
		/* Lookup value in hash using session id and fill pfcp response and delete entry from hash*/
#ifdef GX_BUILD

		ret = process_pfcp_sess_del_resp(
				msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
				gtpv2c_tx, &ccr_request, &msglen);

		buffer = rte_zmalloc_socket(NULL, msglen + sizeof(ccr_request.msg_type),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (buffer == NULL) {
			clLog(sxlogger, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return -1;
		}

		memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

		if (gx_ccr_pack(&(ccr_request.data.ccr),
					(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msglen) == 0) {
			clLog(clSystemLog, eCLSeverityCritical, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
			return -1;
		}
#else
		ret = process_pfcp_sess_del_resp(
				msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
				gtpv2c_tx, NULL, NULL);

#endif /* GX_BUILD */
	}  else {
		/**/
		ret = process_pfcp_sess_del_resp(
				msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
				gtpv2c_tx, NULL, NULL);
	}

	if (ret) {
		ds_error_response(msg, ret,
				spgw_cfg != PGWC ? S11_IFACE :S5S8_IFACE);
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((pfcp_config.cp_type == PGWC) ) {
		/* Forward s11 delete_session_request on s5s8 */
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);

		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, SENT,S5S8);
		update_sys_stat(number_of_users, DECREMENT);
		update_sys_stat(number_of_active_session, DECREMENT);
		//s5s8_sgwc_msgcnt++;
	} else {
		/* Send response on s11 interface */
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);

		/*CLI:CSResp sent cnt*/
		update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, ACC,S11);
		update_sys_stat(number_of_users, DECREMENT);
		update_sys_stat(number_of_active_session, DECREMENT);

	}
#ifdef GX_BUILD
	/* VS: Write or Send CCR -T msg to Gx_App */
	if ( pfcp_config.cp_type != SGWC) {
		send_to_ipc_channel(gx_app_sock, buffer,
				msglen + sizeof(ccr_request.msg_type));
	}

    	struct sockaddr_in saddr_in;
    	saddr_in.sin_family = AF_INET;
    	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
    	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_TERMINATE, SENT, GX);
#endif

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_ds_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	if (pfcp_config.cp_type == SGWC) {
		ret = process_sgwc_s5s8_delete_session_request(&msg->gtpc_msg.ds_rsp);
		if (ret) {
			if(ret  != -1)
				ds_error_response(msg, ret,
						           spgw_cfg != PGWC ? S11_IFACE :S5S8_IFACE);
			/* Error handling not implemented */
			clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
		}
	} else {
		/*Code should not reach here since this handler is only for SGWC*/
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

	uint8_t delay = 0; /*TODO move this when more implemented?*/
	ret = process_ddn_ack(msg->gtpc_msg.ddn_ack, &delay);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d:Error"
				"\n\tprocess_ddn_ack_resp_hand "
				"%s: (%d) %s\n", __func__, __LINE__,
				gtp_type_str(msg->msg_type), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
		/* Error handling not implemented */
		return ret;
	}

	/* TODO something with delay if set */
	/* TODO Implemente the PFCP Session Report Resp message sent to dp */

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

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_est_resp(
			&msg->pfcp_msg.pfcp_sess_est_resp, gtpv2c_tx);
	//ret = process_pfcp_sess_est_resp(
	//		msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid,
	//		gtpv2c_tx,
	//		msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid);

	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return -1;
	}
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

//	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == PGWC)) {

	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);

	update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, SENT,S5S8);

	if (SGWC == pfcp_config.cp_type) {
		add_gtpv2c_if_timer_entry(
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid),
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid) - 5,
			S5S8_IFACE);
	}

	RTE_SET_USED(data);
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
		clLog(clSystemLog, eCLSeverityCritical, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
				msg->gx_msg.cca.session_id.val);
		return -1;
	}

	if(rte_hash_del_key(gx_context_by_sess_id_hash, msg->gx_msg.cca.session_id.val) < 0){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s %s - Error on gx_context_by_sess_id_hash deletion\n",__file__,
				strerror(ret));
	}

	rte_free(gx_context);
	return 0;
}

/*
 * This function handles the message received
 * from PCEF in case of handover.
 * This handler comes when MBR is received
 * from the new SGWC on the PGWC.
 * */
int cca_u_msg_handler_handover(void *data, void *unused)
{
	msg_info *msg = (msg_info *)data;
	int ret = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint8_t ebi_index = 0;
	eps_bearer *bearer = NULL;

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&msg->gx_msg.cca.session_id.val, &call_id);
	if (ret < 0) {
	        clLog(clSystemLog, eCLSeverityCritical, "%s:No Call Id found from session id:%s\n", __func__,
	                       (char*) &msg->gx_msg.cca.session_id.val);
	        return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn = get_pdn_conn_entry(call_id);
	if (pdn == NULL)
	{
	      clLog(clSystemLog, eCLSeverityCritical, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
	                          __func__, call_id);
	      return -1;
	}

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&msg->gx_msg.cca.session_id.val, &call_id);
	if (ret < 0) {
	        clLog(clSystemLog, eCLSeverityCritical, "%s:No Call Id found from session id:%s\n", __func__,
	                       (char*) &msg->gx_msg.cca.session_id.val);
	        return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn = get_pdn_conn_entry(call_id);
	if (pdn == NULL)
	{
	      clLog(clSystemLog, eCLSeverityCritical, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
	                          __func__, call_id);
	      return -1;
	}

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", pdn->seid);
		return -1;
	}

	ebi_index = resp->gtpc_msg.mbr.bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi -5  ;

	if (!(pdn->context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}

	bearer = pdn->eps_bearers[ebi_index];

	ret = send_pfcp_sess_mod_req_handover(pdn, bearer, &resp->gtpc_msg.mbr);
	 if (ret) {
	        clLog(clSystemLog, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
	         return ret;
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused);

	return 0;
}

/*
This function Handles the msgs received from PCEF
*/
int
cca_msg_handler(void *data, void *unused_param)
{
	int8_t ebi_index = 0;
	upf_context_t *upf_context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	msg_info *msg = (msg_info *)data;

	RTE_SET_USED(msg);

#ifdef GX_BUILD
	/* Handle the CCR-T Message */
	if (msg->gx_msg.cca.cc_request_type == TERMINATION_REQUEST) {
		clLog(gxlogger, eCLSeverityDebug, FORMAT"Received GX CCR-T Response..!! \n",
				ERR_MSG);
		return 0;
	}

	/* VS: Retrive the ebi index */
	ret = parse_gx_cca_msg(&msg->gx_msg.cca, &pdn);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d:Error"
				"\n%s: (%d) %s\n", __func__, __LINE__,
				gx_type_str(msg->msg_type), ebi_index,
				(ebi_index < 0 ? strerror(-ebi_index) : cause_str(ebi_index)));
		clLog(clSystemLog, eCLSeverityCritical, "Failed to establish session on PGWU, Send Failed CSResp back to SGWC\n");
		return ret;
	}

#endif /* GX_BUILD */
	ebi_index = pdn->default_bearer_id - 5;
	/* VS: Send the Association setup request */
	ret = process_pfcp_assoication_request(pdn, ebi_index);
	if (ret) {
		if(ret != -1){
			cs_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			process_error_occured_handler(data, unused_param);
		}
		clLog(sxlogger, eCLSeverityCritical, "%s:%s:%d Error: %d \n",
				__FILE__, __func__, __LINE__, ret);
		return -1;
	}
	/* Retrive association state based on UPF IP. */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
	                 (const void*) &(pdn->upf_ipv4.s_addr),
	                 (void **) &(upf_context));
	if(upf_context->state != PFCP_ASSOC_RESP_RCVD_STATE) {
	       if (ret >= 0) {
			if(pfcp_config.cp_type == PGWC) {
	                        upf_context->csr.sender_fteid_ctl_plane.teid_gre_key = pdn->s5s8_sgw_gtpc_teid;
	                }
	                if(pfcp_config.cp_type == SAEGWC) {
	                        upf_context->csr.sender_fteid_ctl_plane.teid_gre_key = pdn->context->s11_mme_gtpc_teid;
	                }
	                upf_context->csr.header.teid.has_teid.seq = pdn->context->sequence;
	                upf_context->csr.bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi = ebi_index + 5;
	                if (pfcp_config.cp_type == PGWC) {
	                        /* : we need teid for send ccr-T to GX  */
	                        upf_context->csr.header.teid.has_teid.teid = pdn->s5s8_pgw_gtpc_teid;
	                }
	                if(pfcp_config.cp_type == SAEGWC) {
	                         upf_context->csr.header.teid.has_teid.teid = pdn->context->s11_sgw_gtpc_teid;
	                }

	       }
	}
	/* send error response in case of pfcp est. fail using this data */
	if(upf_context->state == PFCP_ASSOC_RESP_RCVD_STATE) {
                ret = get_sess_entry(pdn->seid, &resp);
                if(ret != -1 && resp != NULL){
                        if(pfcp_config.cp_type == PGWC) {
                                resp->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = pdn->s5s8_sgw_gtpc_teid;
                        }
                        if(pfcp_config.cp_type == SAEGWC) {
                                resp->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = pdn->context->s11_mme_gtpc_teid;
                        }
                        resp->gtpc_msg.csr.header.teid.has_teid.seq = pdn->context->sequence;
                        resp->gtpc_msg.csr.bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi = ebi_index + 5;
                        if (pfcp_config.cp_type == PGWC) {
                                /* : we need teid for send ccr-T to PCRF  */
                                resp->gtpc_msg.csr.header.teid.has_teid.teid = pdn->s5s8_pgw_gtpc_teid;
                        }
                        if(pfcp_config.cp_type == SAEGWC) {
                                 resp->gtpc_msg.csr.header.teid.has_teid.teid = pdn->context->s11_sgw_gtpc_teid;
                        }
                }
        }

	RTE_SET_USED(unused_param);
	return 0;
}


int
process_mb_req_sgw_reloc_handler(void *data, void *unused_param)
{
	/* msg_info *msg = (msg_info *)data;
	 * Handle MBR for PGWC received from SGWC in case
	 * of SGW Relocation
	*/
	msg_info *msg = (msg_info *)data;
	ret = process_pfcp_sess_mod_req_handover(&msg->gtpc_msg.mbr);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_sess_mod_resp_sgw_reloc_handler(void *data, void *unused_param)
{

	/* Use below function for reference
	 * This function is used in SGWU
	 * Create similar function to handle pfcp mod resp on PGWC
	 */

	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_mod_resp_handover(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx);
	if (ret) {
		if(ret != -1)
			mbr_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
		       (struct sockaddr *) &s5s8_recv_sockaddr,
		          s5s8_sockaddr_len);

	update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, SENT,S5S8);


	if (SGWC == pfcp_config.cp_type) {
		add_gtpv2c_if_timer_entry(
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid) - 5,
			S5S8_IFACE);
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_pfcp_sess_mod_resp_cbr_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_mod_resp(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx);
	if (ret != 0) {
		if(ret != -1)
			/* TODO for cbr
			 * mbr_error_response(&msg->gtpc_msg.mbr, ret,
								spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE); */
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
																			&resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if ((SAEGWC != pfcp_config.cp_type) && ((resp->msg_type == GTP_CREATE_BEARER_RSP) ||
			(resp->msg_type == GX_RAR_MSG))){
	    gtpv2c_send(s5s8_fd, tx_buf, payload_length,
	            (struct sockaddr *) &s5s8_recv_sockaddr,
	            s5s8_sockaddr_len);
		if(resp->msg_type != GTP_CREATE_BEARER_RSP){
			add_gtpv2c_if_timer_entry(
					UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
					&s5s8_recv_sockaddr, tx_buf, payload_length,
					UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid) - 5,
					S5S8_IFACE);
		}
		if (resp->msg_type == GTP_CREATE_BEARER_RSP) {

			update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, ACC,S5S8);
		}
		else {

			update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, SENT,S5S8);
		}

	} else {
		if(resp->msg_type != GX_RAA_MSG) {
		    gtpv2c_send(s11_fd, tx_buf, payload_length,
		            (struct sockaddr *) &s11_mme_sockaddr,
		            s11_mme_sockaddr_len);

			add_gtpv2c_if_timer_entry(
					UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
					&s11_mme_sockaddr, tx_buf, payload_length,
					UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid) - 5,
					S11_IFACE);

			update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, SENT,S11);
		}
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_cbresp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_pgwc_create_bearer_rsp(&msg->gtpc_msg.cb_rsp);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int process_mbr_resp_handover_handler(void *data, void *rx_buf)
{

	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	ret = process_sgwc_s5s8_modify_bearer_response(&(msg->gtpc_msg.mb_rsp) ,gtpv2c_tx);

	if (ret) {
		mbr_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, tx_buf, payload_length,
			(struct sockaddr *) &s11_mme_sockaddr,
			s11_mme_sockaddr_len);

	update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, ACC,S11);
	update_sys_stat(number_of_users, INCREMENT);
	update_sys_stat(number_of_active_session, INCREMENT);

	RTE_SET_USED(data);
	RTE_SET_USED(rx_buf);

	return 0;
}

int
process_create_bearer_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_sgwc_create_bearer_rsp(&msg->gtpc_msg.cb_rsp);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
					__func__, __LINE__, ret);
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
			clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
					__func__, __LINE__, ret);
			return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_rar_request_handler(void *data, void *unused_param)
{
#ifdef GX_BUILD
	msg_info *msg = (msg_info *)data;

	ret = parse_gx_rar_msg(&msg->gx_msg.rar);
	if (ret) {
		if(ret != -1){
			uint32_t call_id = 0;
			pdn_connection *pdn_cntxt = NULL;
			ret = retrieve_call_id((char *)&msg->gx_msg.rar.session_id.val, &call_id);
			if (ret < 0) {
	        		clLog(clSystemLog, eCLSeverityCritical, "%s:No Call Id found from session id:%s\n", __func__,
	                        msg->gx_msg.rar.session_id.val);
	        			return -1;
			}

			/* Retrieve PDN context based on call id */
			pdn_cntxt = get_pdn_conn_entry(call_id);
			if (pdn_cntxt == NULL)
			{
	      		clLog(clSystemLog, eCLSeverityCritical, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
	         	                 								__func__, call_id);
	      		return -1;
			}
			gen_reauth_error_response(pdn_cntxt, ret);
		}
		clLog(sxlogger, eCLSeverityCritical, "%s:%s:%d Error: %d \n",
				__FILE__, __func__, __LINE__, ret);
		return -1;
	}
#else
	RTE_SET_USED(data);
#endif
	RTE_SET_USED(unused_param);
	return 0;
}

int
pfd_management_handler(void *data, void *unused_param)
{
	clLog(sxlogger, eCLSeverityDebug,
		"Pfcp Pfd Management Response Recived Successfully \n");

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_mod_resp_delete_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_mod_resp(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx);
	if (ret) {
		mbr_error_response(msg, ret, spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if (pfcp_config.cp_type == SGWC) {
		/* Forward s11 delete_session_request on s5s8 */
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);

		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
						gtpv2c_tx->gtpc.message_type, SENT,S5S8);
		add_gtpv2c_if_timer_entry(
			UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid) - 5,
			S5S8_IFACE);

	} else {
		/*Code should not reach here since this handler is only for SGWC*/
		return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}



/*PDN initiated deactivation */
int
process_pfcp_sess_mod_resp_dbr_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_delete_bearer_pfcp_sess_response(
		msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
		gtpv2c_tx);
	if (ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if (get_sess_entry(
		msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
		&resp) != 0) {
		clLog(sxlogger, eCLSeverityCritical,
			"%s:%d NO Session Entry Found for sess ID:%lu\n",
			__func__, __LINE__,
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if ((SAEGWC != pfcp_config.cp_type) &&
		((resp->msg_type == GTP_DELETE_BEARER_RSP) ||
		(resp->msg_type == GX_RAR_MSG))) {
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
	            (struct sockaddr *) &s5s8_recv_sockaddr,
	            s5s8_sockaddr_len);

		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, SENT, S5S8);

		if (resp->msg_type != GTP_DELETE_BEARER_RSP) {
			add_gtpv2c_if_timer_entry(
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
				&s5s8_recv_sockaddr, tx_buf, payload_length,
				UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid) - 5,
				S5S8_IFACE);
		}

	} else if (resp->msg_type != GX_RAA_MSG) {
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);

		add_gtpv2c_if_timer_entry(
				UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid),
				&s11_mme_sockaddr, tx_buf, payload_length,
				UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid) - 5,
				S11_IFACE);

		update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, SENT,
				S11);
	}

	RTE_SET_USED(unused_param);

	return 0;
}

int
process_delete_bearer_request_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_delete_bearer_request(&msg->gtpc_msg.db_req ,0);
	if (ret) {
		clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
			__func__, __LINE__, ret);
		return -1;
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);

	return 0;
}


int
process_delete_bearer_resp_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	if (msg->gtpc_msg.db_rsp.lbi.header.len != 0) {
		/* Delete Default Bearer. Send PFCP Session Deletion Request */
		process_pfcp_sess_del_request_delete_bearer_rsp(&msg->gtpc_msg.db_rsp);
	} else {
		/* Delete Dedicated Bearer. Send PFCP Session Modification Request */
		process_delete_bearer_resp(&msg->gtpc_msg.db_rsp , 0);
	}

	RTE_SET_USED(data);
	RTE_SET_USED(unused_param);

	return 0;
}


int
process_pfcp_sess_del_resp_dbr_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;
	struct resp_info *resp = NULL;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_delete_bearer_pfcp_sess_response(
		msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
		gtpv2c_tx);
	if (ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if (get_sess_entry(
		msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
		&resp) != 0) {
		clLog(sxlogger, eCLSeverityCritical,
			"%s:%d NO Session Entry Found for sess ID:%lu\n",
			__func__, __LINE__,
			msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if ((SAEGWC != pfcp_config.cp_type) &&
		((resp->msg_type == GTP_DELETE_BEARER_RSP))) {
			gtpv2c_send(s5s8_fd, tx_buf, payload_length,
		            (struct sockaddr *) &s5s8_recv_sockaddr,
	        	    s5s8_sockaddr_len);

		if (resp->msg_type == GTP_DELETE_BEARER_RSP) {
			update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, SENT, S5S8);
		}
	}

	RTE_SET_USED(unused_param);

	return 0;
}

/*UPDATE bearer */
int process_update_bearer_response_handler(void *data, void *unused_param)
{
	int ret = 0;
	msg_info *msg = (msg_info *)data;
	if (SGWC == pfcp_config.cp_type) {

		ret = process_s11_upd_bearer_response(&msg->gtpc_msg.ub_rsp);
		if(ret && ret != -1)
				ubr_error_response(msg, ret, S5S8_IFACE);
	} else {

		ret = process_s5s8_upd_bearer_response(&msg->gtpc_msg.ub_rsp);
		if(ret && ret != -1)
				ubr_error_response(msg, ret, GX_IFACE);
	}
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
					__func__, __LINE__, ret);
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
			ubr_error_response(msg, ret, S5S8_IFACE);
		clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
					__func__, __LINE__, ret);
		return -1;
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
	uint16_t payload_length = 0;

	msg_info *msg = (msg_info *)data;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_delete_bearer_cmd_request(&msg->gtpc_msg.del_ber_cmd, gtpv2c_tx);

	if(ret != 0) {
	/* TODO:set error response*/
	clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
	}

	if (SGWC == pfcp_config.cp_type ) {
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);


	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
			(struct sockaddr *) &s5s8_recv_sockaddr,
				   s5s8_sockaddr_len);
	}

	RTE_SET_USED(unused_param);

	return 0;
}

/*
 * This handler is called when CCA-U is received on PGWC.
 * and PGWC will send session modification to PGWU.
 * On Combined, SAEGWC will send this to SAEGWU.
 *
*/

int del_bearer_cmd_ccau_handler(void *data, void *unused_param)
{

	msg_info *msg = (msg_info *)data;
	int ret = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn = NULL;

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&msg->gx_msg.cca.session_id.val, &call_id);
	if (ret < 0) {
	        clLog(clSystemLog, eCLSeverityCritical, "%s:No Call Id found from session id:%s\n", __func__,
	                       (char*) &msg->gx_msg.cca.session_id.val);
	        return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn = get_pdn_conn_entry(call_id);
	if (pdn == NULL)
	{
	      clLog(clSystemLog, eCLSeverityCritical, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
	                          __func__, call_id);
	      return -1;
	}


	ret = process_sess_mod_req_del_cmd(pdn);
	if (ret != 0) {
		clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}
	RTE_SET_USED(unused_param);
	return 0;
}


/* This handler is called when SGWC-PGWC-SAEWC receives
 * delete bearer response from MME-SGWC-MME
 *
 */

int
process_delete_bearer_response_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	int ret = 0;
	ret = process_delete_bearer_resp(&msg->gtpc_msg.db_rsp, 1);
	if (ret != 0) {
		clLog(s11logger, eCLSeverityCritical, "%s:%d Error: %d \n",
				__func__, __LINE__, ret);
		return ret;
	}
	RTE_SET_USED(unused_param);
	return 0;
}

/*
 * This handler will be called when PFCP MOD is received from
 * PGWU on PGWC
 * On combined it will be recieved on SAEGWC
 * */

int
del_bearer_cmd_mbr_resp_handler(void *data, void *unused_param)
{

	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;
	int ret = 0;
	uint8_t flag = -1;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	ret = process_pfcp_sess_mod_resp_del_cmd
			(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			 gtpv2c_tx ,&flag);

	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}
	if(flag == 0){
		return 0;
	}
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);


	if (PGWC == pfcp_config.cp_type ) {
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);
		update_cli_stats(s5s8_recv_sockaddr.sin_addr.s_addr,
				gtpv2c_tx->gtpc.message_type, SENT,
				S5S8);
	} else if ((SGWC == pfcp_config.cp_type) ||
				(SAEGWC == pfcp_config.cp_type)) {

		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);
	}

	RTE_SET_USED(unused_param);
	return 0;
}


/*PGWC send Delete Bearer Request to SGWC*/
int process_delete_bearer_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;
	int ret = process_delete_bearer_request(&msg->gtpc_msg.db_req, 1);
	if(ret !=0 ) {
		/*TODO: set error response*/
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
	}

	RTE_SET_USED(unused_param);
	return 0;
}


void
get_info_filled(msg_info *msg, err_rsp_info *info_resp , uint8_t index)
{
	struct resp_info *resp = NULL;
	//pdn_connection *pdn = NULL;

	switch(msg->msg_type){
		case GTP_CREATE_SESSION_REQ:
			info_resp->ebi_index = msg->gtpc_msg.csr.bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi - 5;
			info_resp->teid =  msg->gtpc_msg.csr.header.teid.has_teid.teid;
	   		break;

		case PFCP_ASSOCIATION_SETUP_RESPONSE:{

			upf_context_t *upf_context = NULL;
			ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));
			if(ret < 0){
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d]UPF context not found for Msg_Type:%u, UPF IP:%u\n",
					 __file__, __func__, __LINE__,msg->msg_type, msg->upf_ipv4.s_addr);
				return;
			}

			context_key *key = (context_key *)upf_context->pending_csr_teid[index];
			info_resp->ebi_index = key->ebi_index + 5;
			info_resp->teid = key->teid;
			break;
		}

		case PFCP_SESSION_ESTABLISHMENT_RESPONSE: {

			if(get_sess_entry(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {

				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d]: Session entry not found Msg_Type:%u, Sess ID:%lu, Error_no:%d\n",
						 __file__, __func__, __LINE__, msg->msg_type, msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid, ret);
			}

			info_resp->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);
			if(resp)
				info_resp->ebi_index = resp->eps_bearer_id + 5;
			break;
		}

		case GTP_CREATE_SESSION_RSP:{

			if(msg->gtpc_msg.cs_rsp.bearer_contexts_created.eps_bearer_id.ebi_ebi)
				info_resp->ebi_index = msg->gtpc_msg.cs_rsp.bearer_contexts_created.eps_bearer_id.ebi_ebi - 5;
			info_resp->teid = msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid;
			break;
		}

		case PFCP_SESSION_DELETION_RESPONSE: {

			info_resp->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);
			info_resp->ebi_index = UE_BEAR_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid) - 5;

			break;
		}

	}
}

/* Function */
int
process_del_pdn_conn_set_req(void *data, void *unused_param)
{
#ifdef USE_CSID
	uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_del_pdn_conn_set_req_t(&msg->gtpc_msg.del_pdn_req,
			gtpv2c_tx);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
			return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if (msg->gtpc_msg.del_pdn_req.pgw_fqcsid.number_of_csids) {
		/* Send the delete PDN set request to MME */
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);

		memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
	}

	if (msg->gtpc_msg.del_pdn_req.mme_fqcsid.number_of_csids) {
		/* Send the delete PDN set request to PGW */
		if (pfcp_config.cp_type == SGWC ) {
			gtpv2c_send(s5s8_fd, tx_buf, payload_length,
					(struct sockaddr *) &s5s8_recv_sockaddr,
					s5s8_sockaddr_len);

		}
		memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
	}
	/* Send Response back to peer node */
	ret = fill_gtpc_del_set_pdn_conn_rsp(gtpv2c_tx,
			msg->gtpc_msg.del_pdn_req.header.teid.has_teid.seq,
			GTPV2C_CAUSE_REQUEST_ACCEPTED);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
			return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if (msg->gtpc_msg.del_pdn_req.pgw_fqcsid.number_of_csids) {
		/* Send response to PGW */
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);
	}

	if (msg->gtpc_msg.del_pdn_req.mme_fqcsid.number_of_csids) {
		/* Send the delete PDN set request to MME */
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */

	RTE_SET_USED(unused_param);
	return 0;
}

/* Function */
//int
//process_s5s8_del_pdn_conn_set_req(void *data, void *unused_param)
//{
//#ifdef USE_CSID
//	uint16_t payload_length = 0;
//	msg_info *msg = (msg_info *)data;
//
//	bzero(&tx_buf, sizeof(tx_buf));
//	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
//
//	ret = process_del_pdn_conn_set_req_t(&msg->gtpc_msg.del_pdn_req,
//			gtpv2c_tx);
//	if (ret) {
//			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
//					ERR_MSG, ret);
//			return -1;
//	}
//
//	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
//		+ sizeof(gtpv2c_tx->gtpc);
//
//	/* Send the delete PDN set request to MME */
//	if (pfcp_config.cp_type == SGWC ) {
//		gtpv2c_send(s11_fd, tx_buf, payload_length,
//				(struct sockaddr *) &s11_mme_sockaddr,
//				s11_mme_sockaddr_len);
//	}
//
//	/* Send Response back to peer node */
//	ret = fill_gtpc_del_set_pdn_conn_rsp(gtpv2c_tx,
//			msg->gtpc_msg.del_pdn_req.header.teid.has_teid.seq,
//			GTPV2C_CAUSE_REQUEST_ACCEPTED);
//	if (ret) {
//			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
//					ERR_MSG, ret);
//			return -1;
//	}
//
//	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
//		+ sizeof(gtpv2c_tx->gtpc);
//
//	/* Send response to PGW */
//	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
//			(struct sockaddr *) &s5s8_recv_sockaddr,
//			s5s8_sockaddr_len);
//#else
//	RTE_SET_USED(data);
//#endif /* USE_CSID */
//
//	RTE_SET_USED(unused_param);
//	return 0;
//}
/* Function */
int
process_del_pdn_conn_set_rsp(void *data, void *unused_param)
{
#ifdef USE_CSID
	//uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	ret = process_del_pdn_conn_set_rsp_t(&msg->gtpc_msg.del_pdn_rsp);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
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
process_upd_pdn_conn_set_req(void *data, void *unused_param)
{
#ifdef USE_CSID
	//uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	ret = process_upd_pdn_conn_set_req_t(&msg->gtpc_msg.upd_pdn_req);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
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
process_upd_pdn_conn_set_rsp(void *data, void *unused_param)
{
#ifdef USE_CSID
	//uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	ret = process_upd_pdn_conn_set_rsp_t(&msg->gtpc_msg.upd_pdn_rsp);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
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

	if (msg->gtpc_msg.pgw_rstrt_notif_ack.cause.cause_value ==
			GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */
	RTE_SET_USED(unused_param);
	return 0;
}

/* Function */
int process_pfcp_sess_set_del_req(void *data, void *unused_param)
{
#ifdef USE_CSID
	//uint16_t payload_length = 0;
	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = process_pfcp_sess_set_del_req_t(&msg->pfcp_msg.pfcp_sess_set_del_req,
			gtpv2c_tx);
	if (ret) {
			clLog(sxlogger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
			return -1;
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */
	RTE_SET_USED(unused_param);
	return 0;
}

/* Function */
int process_pfcp_sess_set_del_rsp(void *data, void *unused_param)
{
#ifdef USE_CSID
	msg_info *msg = (msg_info *)data;

	ret = process_pfcp_sess_set_del_rsp_t(&msg->pfcp_msg.pfcp_sess_set_del_rsp);
	if (ret) {
			clLog(sxlogger, eCLSeverityCritical, FORMAT"Error: %d \n",
					ERR_MSG, ret);
			return -1;
	}
#else
	RTE_SET_USED(data);
#endif /* USE_CSID */
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_error_occured_handler(void *data, void *unused_param)
{
	int ret = 0;
	msg_info *msg = (msg_info *)data;

	err_rsp_info info_resp = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint8_t count = 1;
	upf_context_t *upf_ctx = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_ctx));

	if(ret >= 0 && (msg->msg_type == PFCP_ASSOCIATION_SETUP_RESPONSE)
			&& (msg->pfcp_msg.pfcp_ass_resp.cause.cause_value != REQUESTACCEPTED)){
		count = upf_ctx->csr_cnt;
	}
	for (uint8_t i = 0; i < count; i++) {
	get_info_filled(msg, &info_resp, i);
	uint8_t ebi_index = info_resp.ebi_index;
	uint32_t teid = info_resp.teid;


		if (get_ue_context_while_error(teid, &context) == 0){
			pdn = GET_PDN(context ,ebi_index);
			if ((upf_context_entry_lookup(pdn->upf_ipv4.s_addr,&upf_ctx)) ==  0) {
				if(upf_ctx->state < PFCP_ASSOC_RESP_RCVD_STATE){
					rte_hash_del_key(upf_context_by_ip_hash, (const void *) &pdn->upf_ipv4.s_addr);

					for (i = 0; i < upf_ctx->csr_cnt; i++) {
						rte_free(upf_ctx->pending_csr[i]);
						rte_free(upf_ctx->pending_csr_teid[i]);
						upf_ctx->csr_cnt--;
					}
					rte_free(upf_ctx);
					upf_ctx = NULL;
				}
			}
			if (get_sess_entry(pdn->seid, &resp) == 0) {
				rte_hash_del_key(sm_hash, (const void *) &(pdn->seid));
				rte_free(resp);
			}
			for(int8_t idx = 0; idx < MAX_BEARERS; idx++) {
				if(context->eps_bearers[idx] == NULL) {
					continue;
				}else {
					if(context->eps_bearers[idx] != NULL){
						rte_free(pdn->eps_bearers[idx]);
						pdn->eps_bearers[idx] = NULL;
						context->eps_bearers[idx] = NULL;
						if(pdn->num_bearer != 0) {
							pdn->num_bearer--;
						}
					}
				}
			}

			if(pdn->num_bearer == 0){
				//rte_hash_del_key(pdn_by_fteid_hash, (const void*) &teid);
				if(pdn->s5s8_sgw_gtpc_teid != 0) {
					  rte_hash_del_key(bearer_by_fteid_hash, (const void *)
								&(pdn->s5s8_sgw_gtpc_teid));
				}
				if(pdn != NULL) {
					rte_free(pdn);
					context->num_pdns --;
				}
			}
			if (context->num_pdns == 0){
				rte_hash_del_key(ue_context_by_imsi_hash,(const void *) &(*context).imsi);
				rte_hash_del_key(ue_context_by_fteid_hash,(const void *) &teid);
				if(context != NULL )
					rte_free(context);
				context = NULL;
			}


		}
	}
	clLog(clSystemLog, eCLSeverityCritical, "%s:%d:SM_ERROR: Error handler UE_Proc: %u UE_State: %u "
			"%u and Message_Type:%s\n", __func__, __LINE__,
			msg->proc, msg->state,msg->event,
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}


int
process_default_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	clLog(clSystemLog, eCLSeverityCritical, "%s:%d:SM_ERROR: No handler found for UE_Proc: %u UE_State: %u UE_event"
			"%u and Message_Type:%s\n", __func__, __LINE__,
			msg->proc, msg->state,msg->event,
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}


int process_pfcp_sess_mod_resp_ubr_handler(void *data, void *unused_param)
{
	int ret = 0;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	uint8_t ebi_index = 0;

	msg_info *msg = (msg_info *)data;
	uint32_t teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);


	if (get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
																			&resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	if(resp->num_of_bearers)
		ebi_index = resp->list_bearer_ids[0] - 5;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
	}

	#ifdef GX_BUILD
	gen_reauth_response(context, ebi_index);
	#endif

	context->eps_bearers[ebi_index]->pdn->state = CONNECTED_STATE;

	RTE_SET_USED(unused_param);
	return 0;

}
