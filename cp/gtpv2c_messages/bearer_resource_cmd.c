/*
 * Copyright (c) 2017 Intel Corporation
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

#include <rte_errno.h>

#include "gtpv2c_set_ie.h"
#include "clogger.h"
#include "sm_struct.h"
#include "gtpc_session.h"
#include "teid.h"
#include "cp.h"

#define DEFAULT_BEARER_QOS_PRIORITY (15)

extern pfcp_config_t pfcp_config;

/**
 * @brief  : The structure to contain required information from a parsed Bearer Resource
 *           Command message
 *           Contains UE context, bearer, and PDN connection, as well as information
 *           elements required to process message.
 */
struct parse_bearer_resource_command_t {
	ue_context *context;
	pdn_connection *pdn;
	eps_bearer *bearer;
	gtpv2c_ie *linked_eps_bearer_id;
	gtpv2c_ie *procedure_transaction_id;
	traffic_aggregation_description *tad;
	gtpv2c_ie *flow_quality_of_service;
};

/**
 * @brief  : Parse bearer resource commnad
 * @param  : gtpv2c_rx , gtpv2c header
 * @param  : brc, command
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
parse_bearer_resource_cmd(gtpv2c_header_t *gtpv2c_rx,
			  struct parse_bearer_resource_command_t *brc)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *limit_ie;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid.has_teid.teid,
	    (void **) &brc->context);

	if (ret < 0 || !brc->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	/** @todo: fully verify mandatory fields within received message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == GTP_IE_EPS_BEARER_ID &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			brc->linked_eps_bearer_id = current_ie;
		} else if (current_ie->type == GTP_IE_PROC_TRANS_ID &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			brc->procedure_transaction_id = current_ie;
		} else if (current_ie->type == GTP_IE_FLOW_QLTY_OF_SVC &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			brc->flow_quality_of_service = current_ie;
		} else if (current_ie->type == GTP_IE_TRAFFIC_AGG_DESC &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			brc->tad = IE_TYPE_PTR_FROM_GTPV2C_IE(
				traffic_aggregation_description, current_ie);
		}
	}

	if (!brc->linked_eps_bearer_id
	    || !brc->procedure_transaction_id
	    || !brc->tad) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Improper Bearer Resource Command - "
				"Dropping packet\n", LOG_VALUE);
		return -EPERM;
	}

	int ebi = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
	    brc->linked_eps_bearer_id);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}
	if (!(brc->context->bearer_bitmap &
			(1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
		    "Received Bearer Resource Command for non-existent LBI - "
		    "Dropping packet\n", LOG_VALUE);
		return -EPERM;
	}

	brc->bearer = brc->context->eps_bearers[ebi_index];
	if (!brc->bearer) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
		    "Received Bearer Resource Command on non-existent LBI - "
		    "Bitmap Inconsistency - Dropping packet\n", LOG_VALUE);
		return -EPERM;
	}

	brc->pdn = brc->bearer->pdn;
	return 0;
}

/**
 * @brief  : parse packet filter
 * @param  : cpf
 *           packet filter corresponding to table 10.5.144b in 3gpp 2.008 contained
 *           within gtpv2c message
 * @param  : pf
 *           packet filter structure for internal use to CP
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
static int
parse_packet_filter(create_pkt_filter *cpf, pkt_fltr *pf)
{
	reset_packet_filter(pf);

	/*TODO: Precedence is removed from SDF.
	 * Check impact in this case*/
	pf->direction = cpf->direction;

	packet_filter_component *filter_component =
	    (packet_filter_component *) &cpf[1];
	uint8_t length = cpf->pkt_filter_length;

	while (length) {
		if (length <
			PACKET_FILTER_COMPONENT_SIZE[filter_component->type]) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
			    "Insufficient space in packet filter for"
			    " component type %u\n", LOG_VALUE,
			    filter_component->type);
			return GTPV2C_CAUSE_INVALID_LENGTH;
		}
		length -= PACKET_FILTER_COMPONENT_SIZE[filter_component->type];
		switch (filter_component->type) {
		case IPV4_REMOTE_ADDRESS:
			pf->remote_ip_addr =
					filter_component->type_union.ipv4.ipv4;
			if (filter_component->type_union.ipv4.mask.s_addr
			    && filter_component->type_union.ipv4.mask.s_addr
			    != UINT32_MAX
			    && __builtin_clzl(~filter_component->type_union.
					    ipv4.mask.s_addr)
				+ __builtin_ctzl(
					filter_component->type_union.ipv4.mask.
					s_addr) != 32) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in ipmask:\n",LOG_VALUE);
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IPV4_REMOTE_ADDRESS: %s\n",LOG_VALUE,
				    inet_ntoa(pf->remote_ip_addr));
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Filter component: %s\n",LOG_VALUE,
				    inet_ntoa(filter_component->type_union.
						    ipv4.mask));
			}
			pf->remote_ip_mask = __builtin_popcountl(
			    filter_component->type_union.ipv4.mask.s_addr);
			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.ipv4.next_component;

			break;
		case IPV4_LOCAL_ADDRESS:
			pf->local_ip_addr =
					filter_component->type_union.ipv4.ipv4;
			if (filter_component->type_union.ipv4.mask.s_addr
			    && filter_component->type_union.ipv4.mask.s_addr !=
					    UINT32_MAX
			    && __builtin_clzl(~filter_component->type_union.
					    ipv4.mask.s_addr)
				+ __builtin_ctzl(
					filter_component->type_union.ipv4.mask.
					s_addr) != 32) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in ipmask: \n", LOG_VALUE);
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IPV4_REMOTE_ADDRESS: %s\n", LOG_VALUE,
					inet_ntoa(pf->local_ip_addr));
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Filter Component: %s\n", LOG_VALUE,
					inet_ntoa(
					filter_component->type_union.ipv4.
					mask));
			}
			pf->local_ip_mask = __builtin_popcountl(
			    filter_component->type_union.ipv4.mask.s_addr);
			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.ipv4.next_component;

			break;
		case PROTOCOL_ID_NEXT_HEADER:
			pf->proto = filter_component->type_union.proto.proto;
			/* 3gpp specifies no mask so we use exact match */
			pf->proto_mask = UINT8_MAX;

			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.proto.next_component;
			break;
		case SINGLE_LOCAL_PORT:
			pf->local_port_low =
					filter_component->type_union.port.port;
			pf->local_port_high = pf->local_port_low;

			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.port.next_component;
			break;
		case LOCAL_PORT_RANGE:
			pf->local_port_low =
			    filter_component->type_union.port_range.port_low;
			pf->local_port_high =
			    filter_component->type_union.port_range.port_high;

			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.port_range.
			    next_component;
			break;
		case SINGLE_REMOTE_PORT:
			pf->remote_port_low =
					filter_component->type_union.port.port;
			pf->remote_port_high = pf->remote_port_low;

			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.port.next_component;
			break;
		case REMOTE_PORT_RANGE:
			pf->remote_port_low =
			    filter_component->type_union.port_range.port_low;
			pf->remote_port_high =
			    filter_component->type_union.port_range.port_high;

			filter_component =
			    (packet_filter_component *)
			    &filter_component->type_union.port_range.
			    next_component;
			break;
		default:
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid/Unsupported TFT Filter"
					" Component\n", LOG_VALUE);
			return GTPV2C_CAUSE_SERVICE_NOT_SUPPORTED;
		}
	}
	return 0;
}


/**
 * @brief  : install packet filter
 * @param  : ded_bearer
 * @param  : tad
 *           Traffic Aggregation Description information element as described by
 *           clause 10.5.6.12 3gpp 24.008, as referenced by clause 8.20 3gpp 29.274
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
static int
install_packet_filters(eps_bearer *ded_bearer,
		       traffic_aggregation_description *tad)
{
	uint8_t tad_filter_index = 0;
	uint8_t bearer_filter_id = 0;
	int ret;
	uint64_t mbr;

	create_pkt_filter *cpf = (create_pkt_filter *) &tad[1];

	for (tad_filter_index = 0; tad_filter_index < MAX_FILTERS_PER_UE;
	    ++tad_filter_index) {
		ded_bearer->packet_filter_map[tad_filter_index] = -ENOENT;
	}

	/* for each filter in tad */
	for (tad_filter_index = 0; tad_filter_index < tad->num_pkt_filters;
	    ++tad_filter_index) {

		/* look for a free filter id in the bearer */
		for (; bearer_filter_id < MAX_FILTERS_PER_UE;
				++bearer_filter_id) {
			if (ded_bearer->packet_filter_map[bearer_filter_id]
					== -ENOENT)

				break;
		}

		if (bearer_filter_id == MAX_FILTERS_PER_UE) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Not enough packet filter "
					"identifiers available", LOG_VALUE);
			return -EPERM;
		}

		packet_filter pf;
		ret = parse_packet_filter(cpf, &pf.pkt_fltr);
		if (ret)
			return -ret;

		int dp_packet_filter_id = get_packet_filter_id(&pf.pkt_fltr);

		/*TODO : rating group is moved to PCC.
		 * Handle appropriately here. */
		/*pf.pkt_fltr.rating_group = ded_bearer->qos.qos.qci;*/

		if (dp_packet_filter_id == -ENOENT) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
			    "Packet filters must be pre-defined by static "
			    "file prior to reference by s11 Message\n", LOG_VALUE);
			/* TODO: Implement dynamic installation of packet
			 * filters on DP  - remove continue*/
			continue;
			mbr = ded_bearer->qos.ul_mbr;
			/* Convert bit rate into Bytes as CIR stored in bytes */
			pf.ul_mtr_idx = meter_profile_index_get(mbr);

			mbr = ded_bearer->qos.dl_mbr;
			/* Convert bit rate into Bytes as CIR stored in bytes */
			pf.dl_mtr_idx = meter_profile_index_get(mbr);

			dp_packet_filter_id = install_packet_filter(&pf);
			if (dp_packet_filter_id < 0)
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		ded_bearer->num_packet_filters++;
		ded_bearer->packet_filter_map[bearer_filter_id] =
				dp_packet_filter_id;
		ded_bearer->pdn->packet_filter_map[bearer_filter_id] =
				ded_bearer;

	}
	return 0;
}
/**
 * @brief  : from parameters, populates gtpv2c message 'create bearer request' and
 *           populates required information elements as defined by
 *           clause 7.2.3 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'create bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be created
 * @param  : bearer
 *           EPS Bearer data structure to be created
 * @param  : lbi
 *           'Linked Bearer Identifier': indicates the default bearer identifier
 *           associated to the PDN connection to which the dedicated bearer is to be
 *           created
 * @param  : pti
 *           'Procedure Transaction Identifier' according to clause 8.35 3gpp 29.274,
 *           as specified by table 7.2.3-1 3gpp 29.274, 'shall be the same as the one
 *           used in the corresponding bearer resource command'
 * @param  : eps_bearer_lvl_tft
 * @param  : tft_len
 * @return : Returns nothing
 */
int
set_create_bearer_request(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	pdn_connection *pdn, uint8_t lbi, uint8_t pti,
	struct resp_info *resp,  uint8_t is_piggybacked, bool req_for_mme)
{
	uint8_t len = 0;
	uint8_t idx = 0;
	ue_context *context = NULL;
	create_bearer_req_t cb_req = {0};
	eps_bearer *bearer  = NULL;

	context = pdn->context;
	if(req_for_mme == TRUE){
		sequence = generate_seq_number();
	}

	if (context->cp_mode != PGWC) {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &cb_req, GTP_CREATE_BEARER_REQ,
		    context->s11_mme_gtpc_teid, sequence, 0);
	} else {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &cb_req, GTP_CREATE_BEARER_REQ,
		    pdn->s5s8_sgw_gtpc_teid, sequence, 0);
	}

	if (pti) {
		set_pti(&cb_req.pti, IE_INSTANCE_ZERO, pti);
	}
	set_ebi(&cb_req.lbi, IE_INSTANCE_ZERO, lbi);

	for(idx = 0; idx < resp->bearer_count; idx++) {
		int8_t ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[idx]);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}
		bearer = context->eps_bearers[ebi_index];
		if (bearer == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Retrive modify bearer "
					"context but EBI is non-existent- "
					"Bitmap Inconsistency - Dropping packet\n",LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		} else {
			set_ie_header(&cb_req.bearer_contexts[idx].header, GTP_IE_BEARER_CONTEXT,
				IE_INSTANCE_ZERO, 0);

			set_ebi(&cb_req.bearer_contexts[idx].eps_bearer_id, IE_INSTANCE_ZERO, 0);
			cb_req.bearer_contexts[idx].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

			set_bearer_qos(&cb_req.bearer_contexts[idx].bearer_lvl_qos,
				IE_INSTANCE_ZERO, bearer);
			cb_req.bearer_contexts[idx].header.len += sizeof(gtp_bearer_qlty_of_svc_ie_t);
			if(SGWC != context->cp_mode) {

				if(pdn->policy.pcc_rule[idx].predefined_rule){
					len = set_bearer_tft(&cb_req.bearer_contexts[idx].tft, IE_INSTANCE_ZERO,
							TFT_CREATE_NEW, bearer, TRUE, NULL);
				}else{
					len = set_bearer_tft(&cb_req.bearer_contexts[idx].tft, IE_INSTANCE_ZERO,
							TFT_CREATE_NEW, bearer, FALSE, NULL);
				}
				cb_req.bearer_contexts[idx].header.len += len;
			}else{
				memset(cb_req.bearer_contexts[idx].tft.eps_bearer_lvl_tft, 0, MAX_TFT_LEN);
				memcpy(cb_req.bearer_contexts[idx].tft.eps_bearer_lvl_tft,
											resp->eps_bearer_lvl_tft[idx], MAX_TFT_LEN);
				set_ie_header(&cb_req.bearer_contexts[idx].tft.header,
								GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL,
								IE_INSTANCE_ZERO, resp->tft_header_len[idx]);
				len = resp->tft_header_len[idx] + IE_HEADER_SIZE;
					cb_req.bearer_contexts[idx].header.len += len;
			}
			set_charging_id(&cb_req.bearer_contexts[idx].charging_id, IE_INSTANCE_ZERO, 1);
			cb_req.bearer_contexts[idx].header.len += sizeof(gtp_charging_id_ie_t);
		}

		if (PGWC == context->cp_mode) {
			set_ipv4_fteid(&cb_req.bearer_contexts[idx].s58_u_pgw_fteid,
				GTPV2C_IFTYPE_S5S8_PGW_GTPU, IE_INSTANCE_ONE, bearer->s5s8_pgw_gtpu_ipv4,
				bearer->s5s8_pgw_gtpu_teid);
		} else if(SGWC == context->cp_mode){
			set_ipv4_fteid(&cb_req.bearer_contexts[idx].s58_u_pgw_fteid,
				GTPV2C_IFTYPE_S5S8_PGW_GTPU, IE_INSTANCE_ONE, bearer->s5s8_pgw_gtpu_ipv4,
				bearer->s5s8_pgw_gtpu_teid);

			set_ipv4_fteid(&cb_req.bearer_contexts[idx].s1u_sgw_fteid,
				GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, bearer->s1u_sgw_gtpu_ipv4,
				bearer->s1u_sgw_gtpu_teid);

			cb_req.bearer_contexts[idx].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;
		} else {
			set_ipv4_fteid(&cb_req.bearer_contexts[idx].s1u_sgw_fteid,
				GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, bearer->s1u_sgw_gtpu_ipv4,
				bearer->s1u_sgw_gtpu_teid);

			/* Add the PGW F-TEID in the CBReq to support promotion and demotion */
			if ((bearer->s5s8_pgw_gtpu_teid != 0) && (bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0)) {
				set_ipv4_fteid(&cb_req.bearer_contexts[idx].s58_u_pgw_fteid,
					GTPV2C_IFTYPE_S5S8_PGW_GTPU, IE_INSTANCE_ONE, bearer->s5s8_pgw_gtpu_ipv4,
					bearer->s5s8_pgw_gtpu_teid);

				cb_req.bearer_contexts[idx].header.len += sizeof(struct fteid_ie_hdr_t) +
				sizeof(struct in_addr) + IE_HEADER_SIZE;
			}
		}

		cb_req.bearer_contexts[idx].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;
		cb_req.bearer_cnt++;
	}

	uint16_t msg_len = 0;
	msg_len = encode_create_bearer_req(&cb_req, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);
	RTE_SET_USED(is_piggybacked);
	return 0;
}

int
set_create_bearer_response(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
						pdn_connection *pdn, uint8_t lbi, uint8_t pti,
						struct resp_info *resp)
{
	int ebi_index = 0;
	uint8_t idx = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	create_bearer_rsp_t cb_resp = {0};

	context = pdn->context;

	set_gtpv2c_teid_header((gtpv2c_header_t *) &cb_resp, GTP_CREATE_BEARER_RSP,
					pdn->s5s8_pgw_gtpc_teid , sequence, 0);

	set_cause_accepted(&cb_resp.cause, IE_INSTANCE_ZERO);

	if (pti) {}
	if (lbi) {}

	for(idx = 0; idx < resp->bearer_count; idx++) {
		ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[idx]);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return -1;
		}

		bearer = context->eps_bearers[ebi_index];
		if (bearer == NULL) {
			fprintf(stderr,
				LOG_FORMAT" Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
		else{
		set_ie_header(&cb_resp.bearer_contexts[idx].header, GTP_IE_BEARER_CONTEXT,
							IE_INSTANCE_ZERO, 0);

		set_ebi(&cb_resp.bearer_contexts[idx].eps_bearer_id, IE_INSTANCE_ZERO, (resp->eps_bearer_ids[idx]));
		cb_resp.bearer_contexts[idx].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_cause_accepted(&cb_resp.bearer_contexts[idx].cause, IE_INSTANCE_ZERO);
		cb_resp.bearer_contexts[idx].header.len += sizeof(uint16_t) + IE_HEADER_SIZE;

		set_ipv4_fteid(&cb_resp.bearer_contexts[idx].s58_u_pgw_fteid,
			GTPV2C_IFTYPE_S5S8_PGW_GTPU, IE_INSTANCE_THREE, bearer->s5s8_pgw_gtpu_ipv4,
			bearer->s5s8_pgw_gtpu_teid);

		cb_resp.bearer_contexts[idx].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;

		set_ipv4_fteid(&cb_resp.bearer_contexts[idx].s58_u_sgw_fteid,
			GTPV2C_IFTYPE_S5S8_SGW_GTPU, IE_INSTANCE_TWO, bearer->s5s8_sgw_gtpu_ipv4,
			bearer->s5s8_sgw_gtpu_teid);

		cb_resp.bearer_contexts[idx].header.len += sizeof(struct fteid_ie_hdr_t) +
			sizeof(struct in_addr) + IE_HEADER_SIZE;
		}
	}
	cb_resp.bearer_cnt = resp->bearer_count;
	uint16_t msg_len = 0;
	msg_len = encode_create_bearer_rsp(&cb_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);
	return 0;
}

/**
 * @brief  : When a bearer resource command is received for some UE Context/PDN connection
 *           with a traffic aggregation description requesting the installation of some
 *           packet filters, we create a dedicated bearer using those filters. Here, we
 *           are bypassing any PCRF interaction and relying on static rules
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing bearer resource command message
 * @param  : gtpv2c_tx
 *           gtpv2c message transmission buffer to contain transmit 'create bearer
 *           request' message
 * @param  : brc
 *           bearer resource command parsed data
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
static int
create_dedicated_bearer(gtpv2c_header_t *gtpv2c_rx,
			gtpv2c_header_t *gtpv2c_tx,
			struct parse_bearer_resource_command_t *brc)
{
	flow_qos_ie *fqos;
	eps_bearer *ded_bearer;

	if (brc->context->ded_bearer != NULL)
		return -EPERM;


	if (brc->flow_quality_of_service == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Received Bearer Resource Command without Flow "
				"QoS IE\n", LOG_VALUE);
		return -EPERM;
	}
	fqos = IE_TYPE_PTR_FROM_GTPV2C_IE(flow_qos_ie,
	    brc->flow_quality_of_service);

	ded_bearer = brc->context->ded_bearer =
			rte_zmalloc_socket(NULL, sizeof(eps_bearer),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (ded_bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"Memory for Bearer, Error: %s \n", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ded_bearer->pdn = brc->pdn;

	if (install_packet_filters(ded_bearer, brc->tad))
		return -EPERM;

	ded_bearer->s1u_sgw_gtpu_teid = get_s1u_sgw_gtpu_teid(ded_bearer->pdn->upf_ipv4.s_addr, ded_bearer->pdn->context->cp_mode, &upf_teid_info_head);

	/* TODO: Need to handle when providing dedicate beare feature */
	/* ded_bearer->s1u_sgw_gtpu_ipv4 = s1u_sgw_ip; */
	ded_bearer->pdn = brc->pdn;
	/* VS: Remove memcpy */
	//memcpy(&ded_bearer->qos.qos, &fqos->qos, sizeof(qos_segment));
	/**
	 * IE specific data segment for Quality of Service (QoS).
	 *
	 * Definition used by bearer_qos_ie and flow_qos_ie.
	 */
	ded_bearer->qos.qci = fqos->qos.qci;
	ded_bearer->qos.ul_mbr = fqos->qos.ul_mbr;
	ded_bearer->qos.dl_mbr = fqos->qos.dl_mbr;
	ded_bearer->qos.ul_gbr = fqos->qos.ul_gbr;
	ded_bearer->qos.dl_gbr = fqos->qos.dl_gbr;

	/* default values - to be considered later */
	ded_bearer->qos.arp.preemption_capability =
			BEARER_QOS_IE_PREMPTION_DISABLED;
	ded_bearer->qos.arp.preemption_vulnerability =
			BEARER_QOS_IE_PREMPTION_ENABLED;
	ded_bearer->qos.arp.priority_level = DEFAULT_BEARER_QOS_PRIORITY;

	set_create_bearer_request(gtpv2c_tx, gtpv2c_rx->teid.has_teid.seq,
	    brc->pdn, IE_TYPE_PTR_FROM_GTPV2C_IE(eps_bearer_id_ie,
			    brc->linked_eps_bearer_id)->ebi,
	    *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
			    brc->procedure_transaction_id), NULL, 0, FALSE);

	return 0;
}


/**
 * @brief  : When a bearer resource command is received for some UE Context/PDN connection
 *           with a traffic aggregation description requesting the removal of some
 *           packet filters, we check if all filters are removed from the dedicated bearer
 *           and if so, request the deletion of that bearer
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing bearer resource command message
 * @param  : gtpv2c_tx
 *           gtpv2c message transmission buffer to contain transmit 'delete bearer
 *           request' message
 * @param  : brc
 *           bearer resource command parsed data
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
static int
delete_packet_filter(gtpv2c_header_t *gtpv2c_rx,
	gtpv2c_header_t *gtpv2c_tx, struct parse_bearer_resource_command_t *brc)
{

	uint8_t filter_index;
	delete_pkt_filter *dpf = (delete_pkt_filter *) &brc->tad[1];
	eps_bearer *b = brc->pdn->packet_filter_map[dpf->pkt_filter_id];

	if (b == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Requesting the deletion of non-existent "
				"packet filter\n", LOG_VALUE);
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"\t"
				"%"PRIx32"\t"
		"%"PRIx32"\n", LOG_VALUE, brc->context->s11_mme_gtpc_teid,
		    brc->context->s11_sgw_gtpc_teid);
		return -ENOENT;
	}

	for (filter_index = 0; filter_index < brc->tad->num_pkt_filters;
	    ++filter_index) {
		b->packet_filter_map[dpf->pkt_filter_id] = -ENOENT;
		brc->pdn->packet_filter_map[dpf->pkt_filter_id] = NULL;
		b->num_packet_filters--;
	}

	if (b->num_packet_filters == 0) {
		/* we delete this bearer */
		set_gtpv2c_teid_header(gtpv2c_tx, GTP_DELETE_BEARER_REQ,
			brc->context->s11_mme_gtpc_teid,
			gtpv2c_rx->teid.has_teid.seq, 0);

		set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ONE, b->eps_bearer_id);
		set_pti_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			*IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
					brc->procedure_transaction_id));
	} else {
		/* TODO: update DP with modified packet filters */
	}

	return 0;
}


int
process_bearer_resource_command(gtpv2c_header_t *gtpv2c_rx,
	gtpv2c_header_t *gtpv2c_tx)
{
	int ret;
	struct parse_bearer_resource_command_t bearer_resource_command = {0};

	ret = parse_bearer_resource_cmd(gtpv2c_rx, &bearer_resource_command);
	if (ret)
		return ret;

	/* Bearer Resource Commands are supported to allow for UE requested
	 * bearer resource modification procedure as defined by 3gpp 23.401
	 * cause 5.4.5.
	 * Currently this command initiates either Dedicated Bearer Activation
	 * or De-activation procedures according to the Traffic Aggregation
	 * Description operation code
	 */
	if (bearer_resource_command.tad->tft_op_code == TFT_OP_CREATE_NEW) {
		return create_dedicated_bearer(gtpv2c_rx, gtpv2c_tx,
		    &bearer_resource_command);
	} else if (bearer_resource_command.tad->tft_op_code
	    == TFT_OP_DELETE_FILTER_EXISTING) {
		return delete_packet_filter(gtpv2c_rx, gtpv2c_tx,
				&bearer_resource_command);
	} else {
		return -EPERM;
	}
}
