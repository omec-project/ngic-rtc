/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http: *www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <rte_byteorder.h>


#include "util.h"
#include "pfcp_util.h"
#include "interface.h"
#include "pfcp_set_ie.h"
#include "vepc_cp_dp_api.h"
#include "pfcp_messages_encoder.h"


#ifdef CP_BUILD
#include "cp.h"
#include "nb.h"
#include "main.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "sm_struct.h"

//TODO:Remove it
#include "cdr.h"
#include "meter.h"
#endif /* CP_BUILD */

/******************** IPC msgs **********************/
#ifdef CP_BUILD
extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;

/**
 * @brief Pack the message which has to be sent to DataPlane.
 * @param mtype
 *	mtype - Message type.
 * @param dp_id
 *	dp_id - identifier which is unique across DataPlanes.
 * @param param
 *	param - parameter to be parsed based on msg type.
 * @param  msg_payload
 *	msg_payload - message payload to be sent.
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
build_dp_msg(enum dp_msg_type mtype, struct dp_id dp_id,
					void *param, struct msgbuf *msg_payload)
{
	msg_payload->mtype = mtype;
	msg_payload->dp_id = dp_id;
	switch (mtype) {
	case MSG_SDF_CRE:
	case MSG_ADC_TBL_CRE:
	case MSG_PCC_TBL_CRE:
	case MSG_SESS_TBL_CRE:
	case MSG_MTR_CRE:
		msg_payload->msg_union.msg_table.max_elements =
						*(uint32_t *)param;
		break;
	case MSG_EXP_CDR:
		msg_payload->msg_union.ue_cdr =
				*(struct msg_ue_cdr *)param;
		break;
	case MSG_SDF_DES:
	case MSG_ADC_TBL_DES:
	case MSG_PCC_TBL_DES:
	case MSG_SESS_TBL_DES:
	case MSG_MTR_DES:
		break;
	case MSG_SDF_ADD:
	case MSG_SDF_DEL:
		msg_payload->msg_union.pkt_filter_entry =
					*(struct pkt_filter *)param;
		break;
	case MSG_ADC_TBL_ADD:
	case MSG_ADC_TBL_DEL:
		msg_payload->msg_union.adc_filter_entry =
					*(struct adc_rules *)param;
		break;
	case MSG_PCC_TBL_ADD:
	case MSG_PCC_TBL_DEL:
		msg_payload->msg_union.pcc_entry =
					*(struct pcc_rules *)param;
		break;
	case MSG_SESS_CRE:
	case MSG_SESS_MOD:
	case MSG_SESS_DEL:
		msg_payload->msg_union.sess_entry =
				*(struct session_info *)param;
		break;
	case MSG_MTR_ADD:
	case MSG_MTR_DEL:
		msg_payload->msg_union.mtr_entry =
				*(struct mtr_entry *)param;
		break;
	case MSG_DDN_ACK:
		msg_payload->msg_union.dl_ddn =
				*(struct downlink_data_notification *)param;
		break;
	default:
		clLog(apilogger, eCLSeverityCritical, "build_dp_msg: Invalid msg type\n");
		return -1;
	}
	return 0;
}
/**
 * Send message to DP.
 * @param dp_id
 *	dp_id - identifier which is unique across DataPlanes.
 * @param  msg_payload
 *	msg_payload - message payload to be sent.
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
send_dp_msg(struct dp_id dp_id, struct msgbuf *msg_payload)
{
	RTE_SET_USED(dp_id);
	pfcp_pfd_mgmt_req_t pfd_mgmt_req;
	memset(&pfd_mgmt_req, 0, sizeof(pfcp_pfd_mgmt_req_t));
	/* Fill pfd contents costum ie as rule  string */
	set_pfd_contents(&pfd_mgmt_req.app_ids_pfds[0].pfd_context[0].pfd_contents[0], msg_payload);
	/*Fill pfd request */
	fill_pfcp_pfd_mgmt_req(&pfd_mgmt_req, 0);

	uint8_t pfd_msg[512]={0};
	uint16_t  pfd_msg_len=encode_pfcp_pfd_mgmt_req_t(&pfd_mgmt_req, pfd_msg);

	pfcp_header_t *header=(pfcp_header_t *) pfd_msg;
	header->message_len = htons(pfd_msg_len - 4);

	if (pfcp_send(pfcp_fd, (char *)pfd_msg, pfd_msg_len, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
		free(pfd_mgmt_req.app_ids_pfds[0].pfd_context[0].pfd_contents[0].cstm_pfd_cntnt);
		return -1;
	}
	else {
		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats(upf_pfcp_sockaddr.sin_addr.s_addr,
								PFCP_PFD_MGMT_REQ,
								REQ,cp_stats.stat_timestamp);
	}
	free(pfd_mgmt_req.app_ids_pfds[0].pfd_context[0].pfd_contents[0].cstm_pfd_cntnt);
	return 0;
}
//#endif /* CP_BUILD*/
/******************** SDF Pkt filter **********************/
int
sdf_filter_table_create(struct dp_id dp_id, uint32_t max_elements)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SDF_CRE, dp_id, (void *)&max_elements, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_sdf_filter_table_create(dp_id, max_elements);
#endif
}

int
sdf_filter_table_delete(struct dp_id dp_id)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SDF_DES, dp_id, (void *)NULL, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_sdf_filter_table_delete(dp_id);
#endif
}

int
sdf_filter_entry_add(struct dp_id dp_id, struct pkt_filter pkt_filter_entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SDF_ADD, dp_id, (void *)&pkt_filter_entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_sdf_filter_entry_add(dp_id, &pkt_filter_entry);
#endif
}

int
sdf_filter_entry_delete(struct dp_id dp_id, struct pkt_filter pkt_filter_entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SDF_DEL, dp_id, (void *)&pkt_filter_entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_sdf_filter_entry_delete(dp_id, &pkt_filter_entry);
#endif
}

/******************** ADC Rule Table **********************/
int
adc_table_create(struct dp_id dp_id, uint32_t max_elements)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_ADC_TBL_CRE, dp_id, (void *)&max_elements, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_adc_table_create(dp_id, max_elements);
#endif
}

int adc_table_delete(struct dp_id dp_id)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_ADC_TBL_DES, dp_id, (void *)NULL, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_adc_table_delete(dp_id);
#endif
}

int adc_entry_add(struct dp_id dp_id, struct adc_rules entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_ADC_TBL_ADD, dp_id, (void *)&entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_adc_entry_add(dp_id, &entry);
#endif
}

int adc_entry_delete(struct dp_id dp_id, struct adc_rules entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_ADC_TBL_DEL, dp_id, (void *)&entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_adc_entry_delete(dp_id, &entry);
#endif
}

/******************** PCC Rule Table **********************/
int
pcc_table_create(struct dp_id dp_id, uint32_t max_elements)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_PCC_TBL_CRE, dp_id, (void *)&max_elements, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_pcc_table_create(dp_id, max_elements);
#endif
}

int
pcc_table_delete(struct dp_id dp_id)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_PCC_TBL_DES, dp_id, (void *)NULL, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_pcc_table_delete(dp_id);
#endif
}

int
pcc_entry_add(struct dp_id dp_id, struct pcc_rules entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_PCC_TBL_ADD, dp_id, (void *)&entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_pcc_entry_add(dp_id, &entry);
#endif
}

int
pcc_entry_delete(struct dp_id dp_id, struct pcc_rules entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_PCC_TBL_DEL, dp_id, (void *)&entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_pcc_entry_delete(dp_id, &entry);
#endif
}

/******************** Bearer Session Table **********************/
int
session_table_create(struct dp_id dp_id, uint32_t max_elements)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SESS_TBL_CRE, dp_id, (void *)&max_elements, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_session_table_create(dp_id, max_elements);
#endif
}

int
session_table_delete(struct dp_id dp_id)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SESS_TBL_DES, dp_id, (void *)NULL, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_session_table_delete(dp_id);
#endif
}

int
session_create(struct dp_id dp_id,
					struct session_info entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SESS_CRE, dp_id, (void *)&entry, &msg_payload);

#ifdef SYNC_STATS
	struct sync_stats info = {0};
	info.op_id = (op_id-1);
	info.type = 1;
	info.session_id = entry.sess_id;
	add_stats_entry(&info);

#endif /* SYNC_STATS */

#ifdef SDN_ODL_BUILD
	switch(spgw_cfg) {
	case SGWC :
	case SAEGWC :
		return send_nb_create_modify(
				JSON_OBJ_OP_TYPE_CREATE,
				JSON_OBJ_INSTR_3GPP_MOB_CREATE,
				entry.sess_id,
				htonl(entry.ue_addr.u.ipv4_addr),
				htonl(entry.dl_s1_info.enb_addr.u.ipv4_addr),
				htonl(entry.ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr),
				htonl(entry.ul_s1_info.sgw_addr.u.ipv4_addr),
				htonl(entry.dl_s1_info.enb_teid),
				htonl(entry.ul_s1_info.sgw_teid),
				htonl(entry.ue_addr.u.ipv4_addr),
				UE_BEAR_ID(entry.sess_id));
		break;

	case PGWC :
		return send_nb_create_modify(
				JSON_OBJ_OP_TYPE_CREATE,
				JSON_OBJ_INSTR_3GPP_MOB_CREATE,
				entry.sess_id,
				htonl(entry.ue_addr.u.ipv4_addr),
				htonl(entry.dl_s1_info.enb_addr.u.ipv4_addr),
				htonl(entry.dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr),
				htonl(entry.ul_s1_info.sgw_addr.u.ipv4_addr),
				htonl(entry.dl_s1_info.enb_teid),
				htonl(entry.ul_s1_info.sgw_teid),
				htonl(entry.ue_addr.u.ipv4_addr),
				UE_BEAR_ID(entry.sess_id));
		break;

	default :
		rte_panic("ERROR: INVALID DPN Type :%d\n", spgw_cfg);
	}

#else
	return send_dp_msg(dp_id, &msg_payload);
#endif		/* SDN_ODL_BUILD */
#else
	return dp_session_create(dp_id, &entry);
#endif		/* CP_BUILD */
}

int
session_modify(struct dp_id dp_id,
					struct session_info entry)
{
#ifdef CP_BUILD

	struct msgbuf msg_payload;
	build_dp_msg(MSG_SESS_MOD, dp_id, (void *)&entry, &msg_payload);

#ifdef SYNC_STATS
	struct sync_stats info = {0};
	info.op_id = (op_id-1);
	info.type = 2;
	info.session_id = entry.sess_id;
	add_stats_entry(&info);

#endif /* SYNC_STATS */

#ifdef SDN_ODL_BUILD
	return send_nb_create_modify(
			JSON_OBJ_OP_TYPE_UPDATE,
			JSON_OBJ_INSTR_3GPP_MOB_MODIFY,
			entry.sess_id,
			htonl(entry.ue_addr.u.ipv4_addr),
			htonl(entry.dl_s1_info.enb_addr.u.ipv4_addr),
			htonl(entry.ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr),
			htonl(entry.ul_s1_info.sgw_addr.u.ipv4_addr),
			htonl(entry.dl_s1_info.enb_teid),
			htonl(entry.ul_s1_info.sgw_teid),
			htonl(entry.ue_addr.u.ipv4_addr),
			UE_BEAR_ID(entry.sess_id));
#else
	return send_dp_msg(dp_id, &msg_payload);
#endif		/* SDN_ODL_BUILD */
#else
	return dp_session_modify(dp_id, &entry);
#endif		/* CP_BUILD */
}

#ifdef CP_BUILD
int
send_ddn_ack(struct dp_id dp_id,
				struct downlink_data_notification entry)
{
	struct msgbuf msg_payload;
	build_dp_msg(MSG_DDN_ACK, dp_id, (void *)&entry, &msg_payload);

#ifdef SDN_ODL_BUILD
	return send_nb_ddn_ack(entry.dl_buff_cnt,
				entry.dl_buff_duration);
#else
	return send_dp_msg(dp_id, &msg_payload);
#endif		/* SDN_ODL_BUILD */
}
#endif		/* CP_BUILD */

#ifdef DP_BUILD
int
send_ddn_ack(struct dp_id dp_id,
				struct downlink_data_notification_ack_t entry)
{
	return dp_ddn_ack(dp_id, &entry);
}
#endif		/* DP_BUILD */

int
session_delete(struct dp_id dp_id,
					struct session_info entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_SESS_DEL, dp_id, (void *)&entry, &msg_payload);

#ifdef SYNC_STATS
	struct sync_stats info = {0};
	info.op_id = (op_id-1);
	info.type = 3;
	info.session_id = entry.sess_id;
	add_stats_entry(&info);

#endif /* SYNC_STATS */

#ifdef SDN_ODL_BUILD
	return send_nb_delete(entry.sess_id);
#else
	return send_dp_msg(dp_id, &msg_payload);
#endif		/* SDN_ODL_BUILD */
#else
	return dp_session_delete(dp_id, &entry);
#endif		/* CP_BUILD */
}

/******************** Meter Table **********************/
int
meter_profile_table_create(struct dp_id dp_id, uint32_t max_elements)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_MTR_CRE, dp_id, (void *)&max_elements, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_meter_profile_table_create(dp_id, max_elements);
#endif
}

int
meter_profile_table_delete(struct dp_id dp_id)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_MTR_DES, dp_id, (void *)NULL, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_meter_profile_table_delete(dp_id);
#endif
}

int
meter_profile_entry_add(struct dp_id dp_id, struct mtr_entry entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_MTR_ADD, dp_id, (void *)&entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_meter_profile_entry_add(dp_id, &entry);
#endif
}

int
meter_profile_entry_delete(struct dp_id dp_id, struct mtr_entry entry)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_MTR_DEL, dp_id, (void *)&entry, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_meter_profile_entry_delete(dp_id, &entry);
#endif
}

int
ue_cdr_flush(struct dp_id dp_id, struct msg_ue_cdr ue_cdr)
{
#ifdef CP_BUILD
	struct msgbuf msg_payload;
	build_dp_msg(MSG_EXP_CDR, dp_id, (void *)&ue_cdr, &msg_payload);
	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_ue_cdr_flush(dp_id, &ue_cdr);
#endif
}
#endif /* CP_BUILD*/
