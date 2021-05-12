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


#include "ue.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_set_ie.h"

extern int clSystemLog;
extern pfcp_config_t config;

void
set_create_indir_data_frwd_tun_response(gtpv2c_header_t *gtpv2c_tx, pdn_connection *pdn)
{
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	int ret = 0;
	create_indir_data_fwdng_tunn_rsp_t crt_resp = {0};
	node_address_t ip = {0};

	context= pdn->context;
	ret = fill_ip_addr(config.s11_ip.s_addr, config.s11_ip_v6.s6_addr, &ip);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	set_gtpv2c_teid_header((gtpv2c_header_t *) &crt_resp, GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RSP,
			pdn->context->s11_mme_gtpc_teid, pdn->context->sequence, 0);

	set_cause_accepted(&crt_resp.cause, IE_INSTANCE_ZERO);

	set_gtpc_fteid(&crt_resp.sender_fteid_ctl_plane,
			GTPV2C_IFTYPE_S11S4_SGW_GTPC,
			IE_INSTANCE_ZERO,
			ip, (pdn->context->s11_sgw_gtpc_teid));


	for (uint8_t uiCnt = 0; uiCnt < MAX_BEARERS; ++uiCnt) {
		bearer = context->indirect_tunnel->pdn->eps_bearers[uiCnt];
		if(bearer == NULL)
			continue;

		set_ie_header(&crt_resp.bearer_contexts[uiCnt].header, GTP_IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);

		set_cause_accepted(&crt_resp.bearer_contexts[uiCnt].cause, IE_INSTANCE_ZERO);
		crt_resp.bearer_contexts[uiCnt].header.len +=
			sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

		set_ebi(&crt_resp.bearer_contexts[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
				bearer->eps_bearer_id);
		crt_resp.bearer_contexts[uiCnt].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_gtpc_fteid(&crt_resp.bearer_contexts[uiCnt].sgw_fteid_dl_data_fwdng,
				GTPV2C_IFTYPE_S1U_SGW_GTPU ,IE_INSTANCE_THREE, bearer->s1u_sgw_gtpu_ip,
				bearer->s1u_sgw_gtpu_teid);

		crt_resp.bearer_contexts[uiCnt].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;

	}

	uint16_t msg_len = 0;
	msg_len = encode_create_indir_data_fwdng_tunn_rsp(&crt_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
}
