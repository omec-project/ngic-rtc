#include "gtpv2c_error_rsp.h"

#ifdef CP_BUILD
#include "sm_arr.h"
#include "cp_config.h"
#include "cp_stats.h"
#include "ipc_api.h"
#endif /* CP_BUILD */

struct sockaddr_in upf_pfcp_sockaddr;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_sockaddr_len;
extern uint16_t payload_length;
extern int s5s8_fd;
extern int pfcp_fd;
extern pfcp_config_t pfcp_config;

#ifdef GX_BUILD
#include "pfcp.h"
extern int gx_app_sock;
#else
extern struct sockaddr_in s5s8_recv_sockaddr;
#endif /* GX_BUILD */

void
clean_up_while_error(uint8_t ebi, uint32_t teid, uint64_t *imsi_val, uint16_t imsi_len,uint32_t seq)
{
	uint64_t imsi = UINT64_MAX;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint8_t ebi_index = ebi - 5;
	struct resp_info *resp;
	int ret;

	if (get_ue_context(teid, &context) == 0) {
		if (get_pdn(teid, &pdn) == 0){
			if (get_sess_entry(pdn->seid, &resp) == 0) {
				if (spgw_cfg == SGWC){
				pfcp_sess_del_req_t pfcp_sess_del_req = {0};
				fill_pfcp_sess_del_req(&pfcp_sess_del_req);

				pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;
				uint8_t pfcp_msg[512]={0};
				int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
				pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
				header->message_len = htons(encoded - 4);

				pfcp_send(pfcp_fd, pfcp_msg,encoded, &upf_pfcp_sockaddr);
			}

				resp->state = ERROR_OCCURED_STATE;
				resp->msg_type = GTP_CREATE_SESSION_RSP;
				resp->eps_bearer_id = ebi_index;
			}
				context->state = ERROR_OCCURED_STATE;
		}
	}else {
		memcpy(&imsi, imsi_val, imsi_len);
		ret = rte_hash_lookup_data(ue_context_by_imsi_hash,&imsi,(void **) &(*context));

		if (ret == -ENOENT)
			return;

		rte_hash_del_key(ue_context_by_imsi_hash,(const void *) &imsi);
		rte_hash_del_key(ue_context_by_fteid_hash,(const void *) &teid);
		rte_free(context);
		context = NULL;
	}
	RTE_SET_USED(ebi_index);
	RTE_SET_USED(seq);
}

void get_error_rsp_info(msg_info *msg, err_rsp_info *rsp_info, uint8_t index){

	int ret = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;

	switch(msg->msg_type) {

		case GTP_CREATE_SESSION_REQ:{

			rsp_info->sender_teid = msg->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key;
			rsp_info->seq = msg->gtpc_msg.csr.header.teid.has_teid.seq;
			rsp_info->ebi_index = msg->gtpc_msg.csr.bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi;
			rsp_info->teid =  msg->gtpc_msg.csr.header.teid.has_teid.teid;

			if (!msg->gtpc_msg.csr.bearer_contexts_to_be_created.header.len)
				rsp_info->offending = GTP_IE_CREATE_SESS_REQUEST_BEARER_CTXT_TO_BE_CREATED;

			if (!msg->gtpc_msg.csr.sender_fteid_ctl_plane.header.len)
				rsp_info->offending = GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT;

			if (!msg->gtpc_msg.csr.imsi.header.len)
				rsp_info->offending = GTP_IE_IMSI;

			if (!msg->gtpc_msg.csr.apn_ambr.header.len)
				rsp_info->offending = GTP_IE_AGG_MAX_BIT_RATE;

			if (!msg->gtpc_msg.csr.pdn_type.header.len)
					rsp_info->offending = GTP_IE_PDN_TYPE;

			if (!msg->gtpc_msg.csr.bearer_contexts_to_be_created.bearer_lvl_qos.header.len)
				rsp_info->offending = GTP_IE_BEARER_QLTY_OF_SVC;

			if (!msg->gtpc_msg.csr.rat_type.header.len)
				rsp_info->offending = GTP_IE_RAT_TYPE;

			if (!msg->gtpc_msg.csr.apn.header.len)
				rsp_info->offending = GTP_IE_ACC_PT_NAME;

			break;
		}

		case PFCP_ASSOCIATION_SETUP_RESPONSE:{

			upf_context_t *upf_context = NULL;

			/*Retrive association state based on UPF IP. */
			ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));
			if(ret < 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UPF context not found for Msg_Type:%u, UPF IP:%u\n",
										    __file__, __func__, __LINE__,msg->msg_type, msg->upf_ipv4.s_addr);
				return;
			}

			context_key *key = (context_key *)upf_context->pending_csr_teid[index];

			if (get_ue_context(key->teid, &context) != 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}

			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->ebi_index = key->ebi_index + 5;
			rsp_info->teid = key->teid;
			break;
		}

		case PFCP_SESSION_ESTABLISHMENT_RESPONSE: {


			if(get_sess_entry(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {

				fprintf(stderr, "[%s]:[%s]:[%d]: Session entry not found Msg_Type:%u, Sess ID:%lu, Error_no:%d\n",
						 __file__, __func__, __LINE__, msg->msg_type, msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid, ret);
			}

			if(get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid), &context) != 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}

			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_est_resp.header.seid_seqno.has_seid.seid);
			if(resp)
				rsp_info->ebi_index = resp->eps_bearer_id + 5;
			break;
		}

		case GTP_CREATE_SESSION_RSP:{


			if (get_ue_context(msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid, &context) != 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}

			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			if(msg->gtpc_msg.cs_rsp.bearer_contexts_created.eps_bearer_id.ebi_ebi)
				rsp_info->ebi_index = msg->gtpc_msg.cs_rsp.bearer_contexts_created.eps_bearer_id.ebi_ebi;
			rsp_info->teid = msg->gtpc_msg.cs_rsp.header.teid.has_teid.teid;
			break;
		}

		case GTP_MODIFY_BEARER_REQ:{

			rsp_info->seq = msg->gtpc_msg.mbr.header.teid.has_teid.seq;
			rsp_info->teid = msg->gtpc_msg.mbr.header.teid.has_teid.teid;
			rsp_info->ebi_index = msg->gtpc_msg.mbr.bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;
			if (get_ue_context(msg->gtpc_msg.mbr.header.teid.has_teid.teid, &context) != 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}

			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
		}

		case PFCP_SESSION_MODIFICATION_RESPONSE: {

			if(get_sess_entry(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid, &resp) != 0) {

				fprintf(stderr, "[%s]:[%s]:[%d]: Session entry not found Msg_Type:%u, Sess ID:%lu, Error_no:%d\n",
						 __file__, __func__, __LINE__, msg->msg_type, msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid, ret);
			}


			if (get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid), &context) != 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid);
			if(resp)
				rsp_info->ebi_index = resp->eps_bearer_id;
			break;
		}

		case GTP_DELETE_SESSION_REQ: {

			rsp_info->seq = msg->gtpc_msg.dsr.header.teid.has_teid.seq;
			rsp_info->teid = msg->gtpc_msg.dsr.header.teid.has_teid.teid;

			if(get_ue_context(msg->gtpc_msg.dsr.header.teid.has_teid.teid,
							&context) != 0) {
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			break;
		}

		case PFCP_SESSION_DELETION_RESPONSE: {

			if (get_ue_context(UE_SESS_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid), &context)!= 0){
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;
			}
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->teid = UE_SESS_ID(msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid);
			break;

		}

		case GTP_DELETE_SESSION_RSP: {

			if(get_ue_context(msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid, &context) != 0) {
				fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
				return;

			}
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->teid = msg->gtpc_msg.ds_rsp.header.teid.has_teid.teid;
			break;
		}
#ifdef GX_BUILD
		case GX_CCA_MSG: {

			rsp_info->ebi_index = parse_gx_cca_msg(&msg->gx_msg.cca, &context) + 5;
			rsp_info->sender_teid = context->s11_mme_gtpc_teid;
			rsp_info->seq = context->sequence;
			rsp_info->teid = context->s11_sgw_gtpc_teid;

			break;
		}
#endif /*GX_BUILD*/
	}
}

void cs_error_response(msg_info *msg, uint8_t cause_value, int iface){

	uint8_t count = 1;
	upf_context_t *upf_context = NULL;
	int ret = 0;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));

	if(ret >= 0 && (msg->msg_type == PFCP_ASSOCIATION_SETUP_RESPONSE)
			&& (msg->pfcp_msg.pfcp_ass_resp.cause.cause_value != REQUESTACCEPTED)){
		count = upf_context->csr_cnt;
	}

	for(uint8_t i = 0; i < count; i++){

		err_rsp_info rsp_info = {0};
		get_error_rsp_info(msg, &rsp_info, i);

				//Sending CCR-T in case of failure
#ifdef GX_BUILD
		if (pfcp_config.cp_type != SGWC){
			send_ccr_t_req(msg, rsp_info.ebi_index, rsp_info.teid);
		}
#endif
		bzero(&tx_buf, sizeof(tx_buf));
		gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

		create_sess_rsp_t cs_resp = {0};

		set_gtpv2c_teid_header(&cs_resp.header,
				GTP_CREATE_SESSION_RSP,
				rsp_info.sender_teid,
				rsp_info.seq);

		 if(cause_value == GTPV2C_CAUSE_MANDATORY_IE_MISSING ){
			set_ie_header(&cs_resp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			           sizeof(struct cause_ie));
			 cs_resp.cause.offend_ie_type = rsp_info.offending;
			 cs_resp.cause.offend_ie_len = 0;
			      }
		   else{
			set_ie_header(&cs_resp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
		                  sizeof(struct cause_ie_hdr_t));
		   }
		   cs_resp.cause.cause_value = cause_value;
		   cs_resp.cause.pce = 0;
		   cs_resp.cause.bce = 0;
		   cs_resp.cause.spareinstance = 0;
		   if(pfcp_config.cp_type != SGWC || pfcp_config.cp_type !=SAEGWC )
		         cs_resp.cause.cs = 1;
		   else
		         cs_resp.cause.cs = 0;



		set_ie_header(&cs_resp.bearer_contexts_created.header, GTP_IE_BEARER_CONTEXT,
					IE_INSTANCE_ZERO, 0);


		set_ebi(&cs_resp.bearer_contexts_created.eps_bearer_id, IE_INSTANCE_ZERO,
					rsp_info.ebi_index);

		cs_resp.bearer_contexts_created.header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_cause_error_value(&cs_resp.bearer_contexts_created.cause, IE_INSTANCE_ZERO, cause_value);

		cs_resp.bearer_contexts_created.header.len += sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

		uint16_t msg_len = 0;
		msg_len = encode_create_sess_rsp(&cs_resp,(uint8_t *)gtpv2c_tx);
		gtpv2c_tx->gtpc.length = htons(msg_len - 4);

		payload_length = ntohs(gtpv2c_tx->gtpc.length) + sizeof(gtpv2c_tx->gtpc);

		clean_up_while_error(rsp_info.ebi_index, rsp_info.teid,&msg->gtpc_msg.csr.imsi.imsi_number_digits, msg->gtpc_msg.csr.imsi.header.len, rsp_info.seq);
		if(iface == S11_IFACE){
			gtpv2c_send(s11_fd, tx_buf, payload_length,
					(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);

			get_current_time(cp_stats.stat_timestamp);
			update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,gtpv2c_tx->gtpc.type,REJ,cp_stats.stat_timestamp);
		}else{
			gtpv2c_send(s5s8_fd, tx_buf, payload_length,
					 (struct sockaddr *)&s5s8_recv_sockaddr,s5s8_sockaddr_len);

			struct sockaddr_in *s5s8_ip = (struct sockaddr_in *)&s5s8_recv_sockaddr;
			get_current_time(cp_stats.stat_timestamp);
			update_cli_stats(s5s8_ip->sin_addr.s_addr,gtpv2c_tx->gtpc.type,REJ,cp_stats.stat_timestamp);

		}
	}
}


void mbr_error_response(msg_info *msg, uint8_t cause_value, int iface){

	err_rsp_info rsp_info = {0};

	get_error_rsp_info(msg, &rsp_info, 0);

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	mod_bearer_rsp_t mb_resp = {0};
	set_gtpv2c_teid_header(&mb_resp.header,
			GTP_MODIFY_BEARER_RSP,
			rsp_info.sender_teid,
			rsp_info.seq);

	set_cause_error_value(&mb_resp.cause, IE_INSTANCE_ZERO, cause_value);

	set_ie_header(&mb_resp.bearer_contexts_modified.header,
			GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);

	set_cause_error_value(&mb_resp.bearer_contexts_modified.cause,
			IE_INSTANCE_ZERO,cause_value);


	mb_resp.bearer_contexts_modified.header.len += sizeof(struct cause_ie_hdr_t) +
													IE_HEADER_SIZE;

	set_ebi(&mb_resp.bearer_contexts_modified.eps_bearer_id, IE_INSTANCE_ZERO,
			rsp_info.ebi_index);

	 mb_resp.bearer_contexts_modified.header.len += sizeof(uint8_t)+ IE_HEADER_SIZE;

	struct in_addr ip;
	ue_context *context = NULL;

	if (get_ue_context(rsp_info.teid, &context) != 0){
		fprintf(stderr, "[%s]:[%s]:[%d]UE context not found \n", __file__, __func__, __LINE__);
	}
	if(context){
		uint8_t ebi = rsp_info.ebi_index - 5;
		ip.s_addr = context->eps_bearers[ebi]->s1u_enb_gtpu_ipv4.s_addr;
	}

	set_ipv4_fteid(&mb_resp.bearer_contexts_modified.s1u_sgw_fteid,
			 GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, ip,
			 rsp_info.teid);

	mb_resp.bearer_contexts_modified.header.len += sizeof(struct fteid_ie_hdr_t) +
											sizeof(struct in_addr) + IE_HEADER_SIZE;



	uint16_t msg_len = 0;
	msg_len = encode_mod_bearer_rsp(&mb_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);

	payload_length = ntohs(gtpv2c_tx->gtpc.length) + sizeof(gtpv2c_tx->gtpc);

	if(iface == S11_IFACE){
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);

		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,gtpv2c_tx->gtpc.type,REJ,cp_stats.stat_timestamp);
	}else{
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *)&s5s8_recv_sockaddr, s5s8_sockaddr_len);

		struct sockaddr_in *s5s8_ip = (struct sockaddr_in *)&s5s8_recv_sockaddr;
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(s5s8_ip->sin_addr.s_addr,gtpv2c_tx->gtpc.type,REJ,cp_stats.stat_timestamp);
	}
}


void ds_error_response(msg_info *msg, uint8_t cause_value, int iface){

	err_rsp_info rsp_info = {0};

	get_error_rsp_info(msg, &rsp_info, 0);

	bzero(&tx_buf, sizeof(tx_buf));

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;

	del_sess_rsp_t ds_resp = {0};

	set_gtpv2c_teid_header(&ds_resp.header,
								   GTP_DELETE_SESSION_RSP,
								   rsp_info.sender_teid,
								   rsp_info.seq);

	set_cause_error_value(&ds_resp.cause, IE_INSTANCE_ZERO, cause_value);

	uint16_t msg_len = 0;
	msg_len = encode_del_sess_rsp(&ds_resp,(uint8_t *)gtpv2c_tx);
	gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;
	header->gtpc.message_len = htons(msg_len - 4);

	payload_length = ntohs(gtpv2c_tx->gtpc.length) + sizeof(gtpv2c_tx->gtpc);

	if(iface == S11_IFACE){
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);

		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(s11_mme_sockaddr.sin_addr.s_addr,gtpv2c_tx->gtpc.type,REJ,cp_stats.stat_timestamp);
	}else{
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *)&s5s8_recv_sockaddr, s5s8_sockaddr_len);

		struct sockaddr_in *s5s8_ip = (struct sockaddr_in *)&s5s8_recv_sockaddr;
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(s5s8_ip->sin_addr.s_addr,gtpv2c_tx->gtpc.type,REJ,cp_stats.stat_timestamp);
	}

}

#ifdef GX_BUILD
void send_ccr_t_req(msg_info *msg, uint8_t ebi, uint32_t teid){

	int ret = 0;
	pdn_connection *pdn =  NULL;
	ue_context *context = NULL;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		fprintf(stderr, "%s:%d Failed to get UE State for teid: %u\n",
			__func__, __LINE__, teid);
	}else{
		int ebi_index = ebi - 5;
		pdn = context->eps_bearers[ebi_index]->pdn;
		gx_context_t *gx_context = NULL;
		uint16_t msglen = 0;
		char *buffer = NULL;
		/* Retrive Gx_context based on Sess ID. */
		ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
								(const void*)(pdn->gx_sess_id),
								(void **)&gx_context);
		if (ret < 0) {
			RTE_LOG_DP(ERR, CP, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
				pdn->gx_sess_id);
		}else{
			gx_msg ccr_request = {0};
			/* VS: Set the Msg header type for CCR-T */
			ccr_request.msg_type = GX_CCR_MSG ;
			/* VS: Set Credit Control Request type */
			ccr_request.data.ccr.presence.cc_request_type = PRESENT;
			ccr_request.data.ccr.cc_request_type = TERMINATION_REQUEST ;
			/* VG: Set Credit Control Bearer opertaion type */
			ccr_request.data.ccr.presence.bearer_operation = PRESENT;
			ccr_request.data.ccr.bearer_operation = TERMINATION ;
			if(fill_ccr_request(&ccr_request.data.ccr, context, ebi_index, pdn->gx_sess_id) != 0) {
				fprintf(stderr, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
				return;
			}
			msglen = gx_ccr_calc_length(&ccr_request.data.ccr);
			buffer = rte_zmalloc_socket(NULL, msglen + sizeof(ccr_request.msg_type),
										RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (buffer == NULL) {
			fprintf(stderr, "Failure to allocate CCR Buffer memory"
							"structure: %s (%s:%d)\n",
							 rte_strerror(rte_errno),
							 __FILE__,
							 __LINE__);
				return;
			}

			memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

			if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msglen) == 0) {
				fprintf(stderr, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
				return;
			}

			send_to_ipc_channel(gx_app_sock, buffer, msglen + sizeof(ccr_request.msg_type));

			if(rte_hash_del_key(gx_context_by_sess_id_hash, msg->gx_msg.cca.session_id.val) < 0){
				fprintf(stderr, "%s %s - Error on gx_context_by_sess_id_hash deletion\n"
								,__file__, strerror(ret));
			}

			rte_free(gx_context);
		}
	}
}
#endif /* GX_BUILD */

void send_version_not_supported(int iface, uint32_t seq){

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;
	gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;

	set_gtpv2c_header(header, 0, GTP_VERSION_NOT_SUPPORTED_IND, 0, seq);


	uint16_t msg_len = 0;
	msg_len = encode_gtpv2c_header_t(header, (uint8_t *)gtpv2c_tx);
	header->gtpc.message_len = htons(msg_len - 4);

	payload_length = msg_len;
	if(iface == S11_IFACE){
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);

	}else{
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *)&s5s8_recv_sockaddr, s5s8_sockaddr_len);

	}
	return;
}
