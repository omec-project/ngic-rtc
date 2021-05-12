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
#include "main.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "sm_struct.h"

//TODO:Remove it
#include "cdr.h"
#endif /* CP_BUILD */

extern uint32_t li_seq_no;
extern int clSystemLog;

/******************** IPC msgs **********************/
#ifdef CP_BUILD
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern peer_addr_t upf_pfcp_sockaddr;
/**
 * @brief  : Pack the message which has to be sent to DataPlane.
 * @param  : mtype
 *           mtype - Message type.
 * @param  : dp_id
 *           dp_id - identifier which is unique across DataPlanes.
 * @param  : param
 *           param - parameter to be parsed based on msg type.
 * @param  : msg_payload
 *           msg_payload - message payload to be sent.
 * @return : Returns 0 in case of success , -1 otherwise
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"build_dp_msg: "
			"Invalid msg type\n", LOG_VALUE);
		return -1;
	}
	return 0;
}
/**
 * @brief  : Send message to DP.
 * @param  : dp_id
 *           dp_id - identifier which is unique across DataPlanes.
 * @param  : msg_payload
 *           msg_payload - message payload to be sent.
 * @return : Returns 0 in case of success , -1 otherwise
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

	uint8_t pfd_msg[PFCP_MSG_LEN]={0};
	uint16_t  pfd_msg_len=encode_pfcp_pfd_mgmt_req_t(&pfd_mgmt_req, pfd_msg);

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, (char *)pfd_msg, pfd_msg_len, upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error sending PFCP "
			"PFD Management Request %i\n",errno);
		free(pfd_mgmt_req.app_ids_pfds[0].pfd_context[0].pfd_contents[0].cstm_pfd_cntnt);
		return -1;
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

	return send_dp_msg(dp_id, &msg_payload);
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

	return send_dp_msg(dp_id, &msg_payload);
#else
	return dp_session_modify(dp_id, &entry);
#endif		/* CP_BUILD */
}

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
	return send_dp_msg(dp_id, &msg_payload);
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
#endif /* CP_BUILD*/

int
encode_li_header(li_header_t *header, uint8_t *buf)
{

	int encoded = 0;
	uint32_t tmp = 0;
	uint16_t tmpport = 0;
	uint64_t tmpid = 0;

	tmp = htonl(header->packet_len);
	memcpy(buf + encoded, &tmp, sizeof(uint32_t));
	encoded += sizeof(uint32_t);

	memcpy(buf + encoded, &(header->type_of_payload), 1);
	encoded += 1;

	tmpid = header->id;
	memcpy(buf + encoded, &tmpid, sizeof(uint64_t));
	encoded += sizeof(uint64_t);

	tmpid = header->imsi;
	memcpy(buf + encoded, &tmpid, sizeof(uint64_t));
	encoded += sizeof(uint64_t);

	memcpy(buf + encoded, &(header->src_ip_type), 1);
	encoded += 1;


	tmp = htonl(header->src_ipv4);
	memcpy(buf + encoded, &tmp, sizeof(uint32_t));
	encoded += sizeof(uint32_t);

	memcpy(buf + encoded, &(header->src_ipv6), IPV6_ADDRESS_LEN);
	encoded += IPV6_ADDRESS_LEN;

	tmpport = htons(header->src_port);
	memcpy(buf + encoded, &tmpport, sizeof(uint16_t));
	encoded += sizeof(uint16_t);

	memcpy(buf + encoded, &(header->dst_ip_type), 1);
	encoded += 1;


	tmp = htonl(header->dst_ipv4);
	memcpy(buf + encoded, &tmp, sizeof(uint32_t));
	encoded += sizeof(uint32_t);

	memcpy(buf + encoded, &(header->dst_ipv6), IPV6_ADDRESS_LEN);
	encoded += IPV6_ADDRESS_LEN;

	tmpport = htons(header->dst_port);
	memcpy(buf + encoded, &tmpport, sizeof(uint16_t));
	encoded += sizeof(uint16_t);

	memcpy(buf + encoded, &(header->operation_mode), sizeof(uint8_t));
	encoded += sizeof(uint8_t);

	tmp = htonl(header->seq_no);
	memcpy(buf + encoded, &tmp, sizeof(uint32_t));
	encoded += sizeof(uint32_t);

	tmp = htonl(header->len);
	memcpy(buf + encoded, &tmp, sizeof(uint32_t));
	encoded += sizeof(uint32_t);

	return encoded;
}

int8_t
create_li_header(uint8_t *uiPayload, int *iPayloadLen, uint8_t type,
		uint64_t uiId, uint64_t uiImsi, struct ip_addr srcIp, struct ip_addr dstIp,
		uint16_t uiSrcPort, uint16_t uiDstPort, uint8_t uiOprMode)
{
	int iEncoded;
	li_header_t liHdr = {0};
	uint8_t uiTmp[MAX_LI_HDR_SIZE] = {0};

	for (int iCnt = 0; iCnt < *iPayloadLen; iCnt++) {
		uiTmp[iCnt] = uiPayload[iCnt];
	}

	if (type != NOT_PRESENT) {
		liHdr.type_of_payload = PRESENT;
	} else {
		liHdr.type_of_payload = NOT_PRESENT;
	}

	liHdr.id = uiId;
	liHdr.imsi = uiImsi;
	liHdr.src_ip_type = srcIp.iptype;

	if (srcIp.iptype == IPTYPE_IPV4) {

		liHdr.src_ipv4 = srcIp.u.ipv4_addr;
	} else { /* IPTYPE_IPV6 */

		memcpy(liHdr.src_ipv6, srcIp.u.ipv6_addr, IPV6_ADDRESS_LEN);
	}

	liHdr.packet_len += sizeof(liHdr.src_ipv4);
	liHdr.packet_len += IPV6_ADDRESS_LEN;

	liHdr.src_port = uiSrcPort;
	liHdr.dst_ip_type = dstIp.iptype;

	if (dstIp.iptype == IPTYPE_IPV4) {

		liHdr.dst_ipv4 = dstIp.u.ipv4_addr;
	} else { /* IPTYPE_IPV6 */

		memcpy(liHdr.dst_ipv6, dstIp.u.ipv6_addr, IPV6_ADDRESS_LEN);
	}

	liHdr.packet_len += sizeof(liHdr.dst_ipv4);
	liHdr.packet_len += IPV6_ADDRESS_LEN;

	liHdr.dst_port = uiDstPort;
	liHdr.operation_mode = uiOprMode;
	liHdr.seq_no = li_seq_no++;
	liHdr.len = *iPayloadLen;

	liHdr.packet_len += sizeof(liHdr.packet_len) + sizeof(liHdr.type_of_payload)
			+ sizeof(liHdr.len) + sizeof(liHdr.id) + sizeof(liHdr.imsi) +
			+ sizeof(liHdr.src_ip_type) + sizeof(liHdr.dst_ip_type)
			+ sizeof(liHdr.src_port) + sizeof(liHdr.dst_port) + sizeof(liHdr.operation_mode) +
			sizeof(liHdr.seq_no) +*iPayloadLen;

	iEncoded = encode_li_header(&liHdr, uiPayload);
	for (int iCnt = 0; iCnt < *iPayloadLen; iCnt++) {
		uiPayload[iEncoded++] = uiTmp[iCnt];
	}

	*iPayloadLen = iEncoded;
	return 0;
}

inline
struct ip_addr
fill_ip_info(uint8_t ip_type, uint32_t ipv4, uint8_t *ipv6) {

	struct ip_addr node;

	if (ip_type == IPTYPE_IPV4_LI) {
		node.u.ipv4_addr = ipv4;
		node.iptype = IPTYPE_IPV4;
	} else {	/* IPTYPE_IPV6 */
		memcpy(node.u.ipv6_addr, ipv6, IPV6_ADDRESS_LEN);
		node.iptype = IPTYPE_IPV6;
	}

	return node;
}
