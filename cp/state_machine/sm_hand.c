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
#include "sm_enum.h"
#include "sm_hand.h"
#include "cp_stats.h"
#include "debug_str.h"
#include "sm_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"

#ifdef C3PO_OSS
#include "cp_config.h"
#endif /* C3PO_OSS */

int ret = 0;

pfcp_config_t pfcp_config;

extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

extern struct cp_stats_t cp_stats;

int
association_setup_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_pfcp_assoication_request(&msg->s11_msg.csr);
	if (ret) {
			clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
csr_buffer_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	upf_context_t *upf_context = NULL;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));
	if (ret < 0) {
		fprintf(stderr, "%s: upf_context not found!\n", __func__);
		return -1;
	}

	ret = buffer_csr_request(&msg->s11_msg.csr, upf_context);
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
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
	if (ret) {
			clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}
	return 0;
}

int
process_cs_req_handler(void *data, void *rx_buf)
{
	msg_info *msg = (msg_info *)data;
	gtpv2c_header *gtpv2c_rx = (gtpv2c_header *)rx_buf;

	if (pfcp_config.cp_type == PGWC) {
		ret = process_pgwc_s5s8_create_session_request(gtpv2c_rx,
				&msg->upf_ipv4);
	}else {
		ret = process_pfcp_sess_est_request(&msg->s11_msg.csr,
							&msg->upf_ipv4);
	}

	if (ret) {
			clLog(s11logger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}

	return 0;
}

int
process_cs_resp_handler(void *unused_param, void *rx_buf)
{
	gtpv2c_header *gtpv2c_rx = (gtpv2c_header *)rx_buf;

	ret = process_sgwc_s5s8_create_session_response(gtpv2c_rx);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
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
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *)tx_buf;

	ret = process_pfcp_sess_est_resp(
			msg->pfcp_msg.pfcp_sess_est_resp.up_fseid.seid,
			gtpv2c_tx);

	if (ret) {
			clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}
	payload_length = ntohs(gtpv2c_tx->gtpc.length)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == PGWC)) {
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);

		cp_stats.sm_create_session_req_sent++;
		get_current_time(cp_stats.sm_create_session_req_sent_time);
		//s5s8_sgwc_msgcnt++;
	} else {
		/* Send response on s11 interface */
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);
	}
	RTE_SET_USED(unused_param);
	return 0;
}

int
process_mb_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	ret = process_pfcp_sess_mod_request(&msg->s11_msg.mbr);
	if (ret) {
		clLog(s11logger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
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
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *)tx_buf;

	ret = process_pfcp_sess_mod_resp(
			msg->pfcp_msg.pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.length)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s11_fd, tx_buf, payload_length,
			(struct sockaddr *) &s11_mme_sockaddr,
			s11_mme_sockaddr_len);

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_rel_access_ber_req_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	/* TODO: Check return type and do further processing */
	ret = process_release_access_bearer_request(&msg->s11_msg.rel_acc_ber_req_t);
	if (ret) {
			clLog(s11logger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_ds_req_handler(void *data, void *rx_buf)
{
	msg_info *msg = (msg_info *)data;
	gtpv2c_header *gtpv2c_rx = (gtpv2c_header *)rx_buf;


	if (pfcp_config.cp_type == PGWC) {
		ret = process_pgwc_s5s8_delete_session_request(gtpv2c_rx);
	}else {
		ret = process_pfcp_sess_del_request(&msg->s11_msg.dsr);
	}

	if (ret < 0)
		return ret;

	cp_stats.number_of_ues--;

	return 0;
}

int
process_sess_del_resp_handler(void *data, void *unused_param)
{
	uint16_t payload_length = 0;

	msg_info *msg = (msg_info *)data;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *)tx_buf;

	/* Lookup value in hash using session id and fill pfcp response and delete entry from hash*/
	ret = process_pfcp_sess_del_resp(
			msg->pfcp_msg.pfcp_sess_del_resp.header.seid_seqno.has_seid.seid,
			gtpv2c_tx);
	if (ret) {
			clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}

	payload_length = ntohs(gtpv2c_tx->gtpc.length)
		+ sizeof(gtpv2c_tx->gtpc);

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == PGWC) ) {
		/* Forward s11 delete_session_request on s5s8 */
		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len);
				//cp_stats.sm_delete_session_req_sent++;

		cp_stats.sm_delete_session_req_sent++;
		get_current_time(cp_stats.sm_delete_session_req_sent_time);
		//s5s8_sgwc_msgcnt++;
	} else {
		/* Send response on s11 interface */
		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);
	}

	RTE_SET_USED(unused_param);
	return 0;
}

int
process_ds_resp_handler(void *unused_param, void *rx_buf)
{
	uint16_t payload_length = 0;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *)tx_buf;
	gtpv2c_header *gtpv2c_rx = (gtpv2c_header *)rx_buf;

	ret = process_sgwc_s5s8_delete_session_response(
			gtpv2c_rx, gtpv2c_tx);
	if (ret) {
		/* Error handling not implemented */
			clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
			return -1;
	}

	//cp_stats.session_deletion_req_sent++;
	cp_stats.sm_delete_session_resp_acc_rcvd++;
	get_current_time(cp_stats.sm_delete_session_resp_acc_rcvd_time);
	//s11_msgcnt++;
	//cp_stats.session_deletion_resp_acc_rcvd++;

	payload_length = ntohs(gtpv2c_tx->gtpc.length)
		+ sizeof(gtpv2c_tx->gtpc);

	/* Send response on s11 interface */
	gtpv2c_send(s11_fd, tx_buf, payload_length,
			(struct sockaddr *) &s11_mme_sockaddr,
			s11_mme_sockaddr_len);

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
	ret = process_ddn_ack(msg->s11_msg.ddn_ack, &delay);
	if (ret) {
		fprintf(stderr, "%s::Error"
				"\n\tprocess_ddn_ack_resp_hand "
				"%s: (%d) %s\n", __func__,
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
process_default_handler(void *data, void *unused_param)
{
	msg_info *msg = (msg_info *)data;

	fprintf(stderr, "%s::SM_ERROR: No handler found for UE_State:"
			"%u and Message_Type:%s\n", __func__,
			msg->state,
			gtp_type_str(msg->msg_type));

	RTE_SET_USED(unused_param);
	return 0;
}
