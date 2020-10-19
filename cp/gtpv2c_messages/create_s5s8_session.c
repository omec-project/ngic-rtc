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

#include <errno.h>
#include <byteswap.h>

#include "packet_filters.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

#include "pfcp.h"
#include "gtpv2c.h"
#include "pfcp_enum.h"
#include "pfcp_util.h"
#include "sm_struct.h"
#include "../cp_stats.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_messages_encoder.h"
#include "cp_config.h"

#ifdef CP_BUILD
#include "cp_timer.h"
#endif /* CP_BUILD */

#ifdef USE_REST
#include "main.h"
#endif /* USE_REST */


extern pfcp_config_t pfcp_config;

extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;
extern struct sockaddr_in s5s8_recv_sockaddr;

/* PGWC S5S8 handlers:
 * static int parse_pgwc_s5s8_create_session_request(...)
 * int process_pgwc_s5s8_create_session_request(...)
 * static void set_pgwc_s5s8_create_session_response(...)
 *
 */

/**
 * @brief  : Table 7.2.1-1: Information Elements in a Create Session Request -
 *           incomplete list
 */
struct parse_pgwc_s5s8_create_session_request_t {
	uint8_t *bearer_context_to_be_created_ebi;
	fteid_ie *s5s8_sgw_gtpc_fteid;
	gtpv2c_ie *apn_ie;
	gtpv2c_ie *apn_restriction_ie;
	gtpv2c_ie *imsi_ie;
	gtpv2c_ie *uli_ie;
	gtpv2c_ie *serving_network_ie;
	gtpv2c_ie *msisdn_ie;
	gtpv2c_ie *apn_ambr_ie;
	gtpv2c_ie *pdn_type_ie;
	gtpv2c_ie *charging_characteristics_ie;
	gtpv2c_ie *bearer_qos_ie;
	gtpv2c_ie *bearer_tft_ie;
	gtpv2c_ie *s5s8_sgw_gtpu_fteid;
};
/**
 * @brief  : from parameters, populates gtpv2c message 'create session response' and
 *           populates required information elements as defined by
 *           clause 7.2.2 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'create session response' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the session to be created
 * @param  : pdn
 *           PDN Connection data structure pertaining to the session to be created
 * @param  : bearer
 *           Default EPS Bearer corresponding to the PDN Connection to be created
 * @return : returns nothing
 */
void
set_pgwc_s5s8_create_session_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer)
{

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_CREATE_SESSION_RSP,
	    pdn->s5s8_sgw_gtpc_teid, sequence, 0);

	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);
	set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_PGW_GTPC,
			IE_INSTANCE_ONE,
			pdn->s5s8_pgw_gtpc_ipv4, htonl(pdn->s5s8_pgw_gtpc_teid));
	set_ipv4_paa_ie(gtpv2c_tx, IE_INSTANCE_ZERO, pdn->ipv4);
	set_apn_restriction_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			pdn->apn_restriction);
	{
		gtpv2c_ie *bearer_context_group =
				create_bearer_context_ie(gtpv2c_tx,
		    IE_INSTANCE_ZERO);
		add_grouped_ie_length(bearer_context_group,
		    set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
				    bearer->eps_bearer_id));
		add_grouped_ie_length(bearer_context_group,
		    set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO));

		add_grouped_ie_length(bearer_context_group,
			set_bearer_qos_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			bearer));

		add_grouped_ie_length(bearer_context_group,
	    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_PGW_GTPU,
			    IE_INSTANCE_ZERO, bearer->s5s8_pgw_gtpu_ipv4,
			    htonl(bearer->s5s8_pgw_gtpu_teid)));
	}
}

/**
 * @brief  : parses gtpv2c message and populates parse_sgwc_s5s8_create_session_response_t structure
 * @param  : gtpv2c_rx
 *           buffer containing create bearer response message
 * @param  : csr
 *           data structure to contain required information elements from create
 *           create session response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */

int
parse_sgwc_s5s8_create_session_response(gtpv2c_header_t *gtpv2c_rx,
		struct parse_sgwc_s5s8_create_session_response_t *csr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == GTP_IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			FOR_EACH_GROUPED_IE(current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == GTP_IE_EPS_BEARER_ID &&
					current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_context_to_be_created_ebi =
					    IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
							    current_group_ie);
				} else if (current_group_ie->type ==
						GTP_IE_BEARER_QLTY_OF_SVC &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_qos_ie = current_group_ie;
				} else if (current_group_ie->type == GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_tft_ie = current_group_ie;
				} else if (current_group_ie->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT &&
						current_group_ie->instance ==
						IE_INSTANCE_ZERO) {
					csr->s5s8_pgw_gtpu_fteid = current_group_ie;
				}
			}

		} else if (current_ie->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT &&
				current_ie->instance == IE_INSTANCE_ONE) {
			csr->pgw_s5s8_gtpc_fteid =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie, current_ie);
		} else if (current_ie->type == GTP_IE_PDN_ADDR_ALLOC &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->pdn_addr_alloc_ie = current_ie;
		} else if (current_ie->type == GTP_IE_APN_RESTRICTION &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_restriction_ie = current_ie;
		}
	}

	if (!csr->apn_restriction_ie
		|| !csr->bearer_context_to_be_created_ebi
		|| !csr->pgw_s5s8_gtpc_fteid) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Improper Create Session"
			" Request ---Dropping packet\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	return 0;
}

int
gen_sgwc_s5s8_create_session_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer, char *sgwu_fqdn)
{

	gtpv2c_ie *current_rx_ie;
	gtpv2c_ie *limit_rx_ie;

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_CREATE_SESSION_REQ,
		    0, sequence, 0);

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_rx_ie, limit_rx_ie)
	{
		if (current_rx_ie->type == GTP_IE_BEARER_CONTEXT &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			gtpv2c_ie *bearer_context_group =
				create_bearer_context_ie(gtpv2c_tx,
			    IE_INSTANCE_ZERO);
			add_grouped_ie_length(bearer_context_group,
			    set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			    bearer->eps_bearer_id));
			add_grouped_ie_length(bearer_context_group,
				set_bearer_qos_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
				bearer));
			add_grouped_ie_length(bearer_context_group,
			    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_SGW_GTPU,
			    IE_INSTANCE_TWO, bearer->s5s8_sgw_gtpu_ipv4,
			    htonl(bearer->s5s8_sgw_gtpu_teid)));
		} else if (current_rx_ie->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT &&
				current_rx_ie->instance == IE_INSTANCE_ONE) {
			continue;
		} else if (current_rx_ie->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
				IE_INSTANCE_ZERO,
				pdn->s5s8_sgw_gtpc_ipv4, htonl(pdn->s5s8_sgw_gtpc_teid));
		} else if (current_rx_ie->type == GTP_IE_ACC_PT_NAME &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_APN_RESTRICTION &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_IMSI &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_AGG_MAX_BIT_RATE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_PDN_TYPE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_CHRGNG_CHAR &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_INDICATION &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			continue;
		} else if (current_rx_ie->type == GTP_IE_MBL_EQUIP_IDNTY &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			continue;
		} else if (current_rx_ie->type == GTP_IE_MSISDN &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_USER_LOC_INFO &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_SERVING_NETWORK &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_RAT_TYPE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_SELECTION_MODE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_PDN_ADDR_ALLOC &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == GTP_IE_PROT_CFG_OPTS &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		}
	}

	set_fqdn_ie(gtpv2c_tx, sgwu_fqdn);

	return 0;
}

int
process_sgwc_s5s8_modify_bearer_response(mod_bearer_rsp_t *mb_rsp, gtpv2c_header_t *gtpv2c_s11_tx,
		ue_context **_context)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int ret = 0;
	struct resp_info *resp = NULL;
	int ebi_index = 0;

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	ebi_index = GET_EBI_INDEX(mb_rsp->bearer_contexts_modified[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */

	ret = get_ue_context_by_sgw_s5s8_teid(mb_rsp->header.teid.has_teid.teid, &context);
	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
		    "Ue context for teid: %d\n",
		    LOG_VALUE, mb_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;
	*_context = context;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
			"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	/* PGW FQ-CSID */
	if (mb_rsp->pgw_fqcsid.header.len) {
		/* Remove Exsiting PGW CSID linked with session */
		if ((context->pgw_fqcsid)->num_csid) {
			memset(context->pgw_fqcsid, 0, sizeof(fqcsid_t));
		}
		/* Stored the PGW CSID by PGW Node address */
		ret = add_fqcsid_entry(&mb_rsp->pgw_fqcsid, context->pgw_fqcsid);
		if(ret)
			return ret;
	} else {
		tmp = get_peer_addr_csids_entry(pdn->s5s8_pgw_gtpc_ipv4.s_addr,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: Failed to "
				"add PGW CSID by PGW Node addres %s \n", LOG_VALUE,
				strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		(context->pgw_fqcsid)->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	}

	/* Link local CSID with PGW CSID */
	if (context->pgw_fqcsid != NULL) {
		if ((context->pgw_fqcsid)->num_csid) {
			if (link_gtpc_peer_csids((pdn->context)->pgw_fqcsid,
						(pdn->context)->sgw_fqcsid, S5S8_SGWC_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with PGW FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}
			/* TODO: Fill the PFCP Modification Request and sent the PGWC CSID to UP */
			/* Set PGW FQ-CSID */
			//set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, context->pgw_fqcsid);
		}
	}

	/* TODO: Fill the PFCP Modification Request and sent the PGWC CSID to UP */

#endif /* USE_CSID */
	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		/* Fill the modify bearer response */
		set_modify_bearer_response(
				gtpv2c_s11_tx, mb_rsp->header.teid.has_teid.seq,
				context, bearer, &resp->gtpc_msg.mbr);
		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;
	}else{
		set_create_session_response(
				gtpv2c_s11_tx, mb_rsp->header.teid.has_teid.seq,
				context, pdn, 0);

		pdn->state =  CONNECTED_STATE;
		pdn->proc = INITIAL_PDN_ATTACH_PROC;
		pdn->csr_sequence =0;
	}
	return 0;
}


int
process_sgwc_s5s8_mbr_for_mod_proc(mod_bearer_rsp_t *mb_rsp, gtpv2c_header_t *gtpv2c_s11_tx)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int ret = 0;
	struct resp_info *resp = NULL;
	int ebi_index = 0;

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	ebi_index = GET_EBI_INDEX(mb_rsp->bearer_contexts_modified[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}


	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */

	 ret = get_ue_context_by_sgw_s5s8_teid(mb_rsp->header.teid.has_teid.teid, &context);
	 if (ret < 0 || !context)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			" Ue context for teid: %d\n",
				LOG_VALUE, mb_rsp->header.teid.has_teid.teid);
	    return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	/* Fill the modify bearer response */
	set_modify_bearer_response_handover(
			gtpv2c_s11_tx, mb_rsp->header.teid.has_teid.seq,
			context, bearer, &resp->gtpc_msg.mbr);
	resp->state = CONNECTED_STATE;
	/* Update the UE state */
	pdn->state = CONNECTED_STATE;

	s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);

	return 0;
}

int
process_create_bearer_request(create_bearer_req_t *cbr)
{
	int ret = 0;
	int ebi_index = 0;
	uint8_t idx = 0;
	uint8_t new_ebi_index = 0;
	uint32_t  seq_no = 0;
	eps_bearer *bearers[MAX_BEARERS],*bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context_by_sgw_s5s8_teid(cbr->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"UE context for teid: %d\n", LOG_VALUE, cbr->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;

	seq_no = cbr->header.teid.has_teid.seq;

	if(!cbr->lbi.header.len){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Mandatory IE"
			" (EPS bearer id) is missing in create bearer request \n",
			LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	ebi_index = GET_EBI_INDEX(cbr->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	for(idx = 0; idx < cbr->bearer_cnt; ++idx) {
		bearer = rte_zmalloc_socket(NULL, (sizeof(eps_bearer)),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"Memory for Bearer, Error: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		new_ebi_index = (idx + MAX_BEARERS);
		resp->eps_bearer_ids[idx] = new_ebi_index + NUM_EBI_RESERVED;

		bearer->pdn = pdn;
		context->eps_bearers[new_ebi_index] = bearer;
		resp->bearer_count++;
		pdn->num_bearer++;
		if(!cbr->bearer_contexts[idx].eps_bearer_id.header.len){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error: Mandatory IE "
				"(EPS bearer id) is missing in bearer context in create bearer request \n",
				LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		pdn->eps_bearers[new_ebi_index] = bearer;
		if(cbr->bearer_contexts[idx].bearer_lvl_qos.header.len){
			bearer->qos.arp.preemption_vulnerability = cbr->bearer_contexts[idx].bearer_lvl_qos.pvi;

			bearer->qos.arp.priority_level = cbr->bearer_contexts[idx].bearer_lvl_qos.pl;

			bearer->qos.arp.preemption_capability = cbr->bearer_contexts[idx].bearer_lvl_qos.pci;

			bearer->qos.qci = cbr->bearer_contexts[idx].bearer_lvl_qos.qci;

			bearer->qos.ul_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_uplnk;

			bearer->qos.dl_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_dnlnk;

			bearer->qos.ul_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_uplnk;

			bearer->qos.dl_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_dnlnk;
		}
		else{
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error: Mandatory IE"
				" (bearer level QoS) is missing in Create Bearer Request\n",
				LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = cbr->bearer_contexts[idx].s58_u_pgw_fteid.ipv4_address;

		bearer->s5s8_pgw_gtpu_teid = cbr->bearer_contexts[idx].s58_u_pgw_fteid.teid_gre_key;

		if(cbr->bearer_contexts[idx].tft.header.len){
			memset(resp->eps_bearer_lvl_tft[idx], 0, MAX_TFT_LEN);
			memcpy(resp->eps_bearer_lvl_tft[idx],
				cbr->bearer_contexts[idx].tft.eps_bearer_lvl_tft, MAX_TFT_LEN);
			resp->tft_header_len[idx] = cbr->bearer_contexts[idx].tft.header.len;
		}
		else{
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error: Mandatory IE"
				" (bearer level TFT) is missing in Create Bearer Request\n",
				LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}
		fill_dedicated_bearer_info(bearer, context, pdn, FALSE);

		pfcp_sess_mod_req.create_pdr_count += bearer->pdr_count;

		bearers[idx] = bearer;

		bearer->sequence = cbr->header.teid.has_teid.seq;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cbr->header, bearers, pdn, update_far, 0, cbr->bearer_cnt, context);
	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending modification "
			"request to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	else
	{

#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = seq_no;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->gtpc_msg.cb_req = *cbr;
	resp->bearer_count = cbr->bearer_cnt;
	resp->linked_eps_bearer_id = pdn->default_bearer_id;
	resp->msg_type = GTP_CREATE_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = DED_BER_ACTIVATION_PROC;
	resp->cp_mode = context->cp_mode;
	pdn->proc = DED_BER_ACTIVATION_PROC;

	return 0;
}


int
process_delete_bearer_request(del_bearer_req_t *db_req, ue_context *context, uint8_t proc_type)
{
	int ebi_index = 0;
	uint8_t bearer_cntr = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	int default_bearer_index = 0;
	eps_bearer *bearers[MAX_BEARERS] = {0};
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	uint8_t jCnt = 0;

	s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;

	if (db_req->lbi.header.len != 0) {

		default_bearer_index = GET_EBI_INDEX(db_req->lbi.ebi_ebi);
		if (default_bearer_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		pdn = GET_PDN(context, default_bearer_index);
		if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, default_bearer_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		for (uint8_t iCnt = 0; iCnt < MAX_BEARERS; ++iCnt) {
			if (NULL != pdn->eps_bearers[iCnt]) {
				bearers[jCnt] = pdn->eps_bearers[iCnt];
				bearers[jCnt]->sequence = db_req->header.teid.has_teid.seq;
				jCnt++;
			}
		}
		bearer_cntr = pdn->num_bearer;
	} else {
		for (uint8_t iCnt = 0; iCnt < db_req->bearer_count; ++iCnt) {
			ebi_index = GET_EBI_INDEX(db_req->eps_bearer_ids[iCnt].ebi_ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			bearers[iCnt] = context->eps_bearers[ebi_index];
			bearers[iCnt]->sequence = db_req->header.teid.has_teid.seq;
		}

		pdn = GET_PDN(context, ebi_index);
		if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
		bearer_cntr = db_req->bearer_count;
	}

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, pdn, bearers, bearer_cntr);

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending Session "
			"Modification Request to SGW-U. Error: %i\n", LOG_VALUE, errno);
	} else {
#ifdef CP_BUILD
		ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
				&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = db_req->header.teid.has_teid.seq;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	if (db_req->lbi.header.len != 0) {
		resp->linked_eps_bearer_id = db_req->lbi.ebi_ebi;
		resp->bearer_count = 0;
	} else {
		resp->bearer_count = db_req->bearer_count;
		for (uint8_t iCnt = 0; iCnt < db_req->bearer_count; ++iCnt) {
			resp->eps_bearer_ids[iCnt] = db_req->eps_bearer_ids[iCnt].ebi_ebi;
		}
	}

	resp->msg_type = GTP_DELETE_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = proc_type;
	resp->cp_mode = context->cp_mode;
	resp->gtpc_msg.db_req = *db_req;
	pdn->proc = proc_type;

	return 0;
}

int
process_delete_bearer_resp(del_bearer_rsp_t *db_rsp, ue_context *context, uint8_t proc_type)
{
	int ebi_index = 0;
	uint8_t bearer_cntr = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	eps_bearer *bearers[MAX_BEARERS] = {0};
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;

	for (uint8_t iCnt = 0; iCnt < db_rsp->bearer_count; ++iCnt) {
		ebi_index = GET_EBI_INDEX(db_rsp->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		bearers[iCnt] = context->eps_bearers[ebi_index];
	}
	bearer_cntr = db_rsp->bearer_count;

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	fill_pfcp_sess_mod_req_pgw_init_remove_pdr(&pfcp_sess_mod_req, pdn, bearers, bearer_cntr);

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error in Sending "
			"Modification Request to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	} else {
#ifdef CP_BUILD
		ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		add_pfcp_if_timer_entry(db_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = db_rsp->header.teid.has_teid.seq;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->bearer_count = db_rsp->bearer_count;
	for (uint8_t iCnt = 0; iCnt < db_rsp->bearer_count; ++iCnt) {
		resp->eps_bearer_ids[iCnt] = db_rsp->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi;
	}

	if(resp->proc == UE_REQ_BER_RSRC_MOD_PROC) {
		resp->msg_type = GTP_DELETE_BEARER_RSP;
		resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
		pdn->proc = PDN_GW_INIT_BEARER_DEACTIVATION;
	}else{

		resp->msg_type = GTP_DELETE_BEARER_RSP;
		resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
		resp->proc = proc_type;
		pdn->proc = proc_type;
	}

	resp->cp_mode = context->cp_mode;
	return 0;
}

int
process_cs_resp_cb_request(create_bearer_req_t *cbr)
{
	int ret = 0;
	int ebi_index = 0;
	uint8_t idx = 0;
	uint8_t new_ebi_index = 0;
	uint32_t  seq_no = 0;
	eps_bearer *bearers[MAX_BEARERS],*bearer = NULL,*dedicated_bearer = NULL;
	uint8_t index = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context_by_sgw_s5s8_teid(cbr->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
			"UE context for teid: %d\n", LOG_VALUE, cbr->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;

	seq_no = cbr->header.teid.has_teid.seq;

	ebi_index = GET_EBI_INDEX(cbr->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn = context->eps_bearers[ebi_index]->pdn;
	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No PDN found "
			"for ebi_index : %lu", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	{
		struct in_addr ip = {0};
		pdn->apn_restriction = resp->gtpc_msg.cs_rsp.apn_restriction.rstrct_type_val;

		ip = *(struct in_addr *)resp->gtpc_msg.cs_rsp.paa.pdn_addr_and_pfx;

		pdn->ipv4.s_addr = ip.s_addr;
		pdn->s5s8_pgw_gtpc_ipv4.s_addr =
			resp->gtpc_msg.cs_rsp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address;
		pdn->s5s8_pgw_gtpc_teid =
	        resp->gtpc_msg.cs_rsp.pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.teid_gre_key;
	}

	 bearer = context->eps_bearers[ebi_index];

	{
		/* TODO: Implement TFTs on default bearers
		 *          if (create_s5s8_session_response.bearer_tft_ie) {
		 *                     }
		 *                            */
		/* TODO: Implement PGWC S5S8 bearer QoS */
		if (resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.header.len) {
			bearer->qos.qci = resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.qci;
			bearer->qos.ul_mbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_uplnk;
			bearer->qos.dl_mbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_dnlnk;
			bearer->qos.ul_gbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_uplnk;
			bearer->qos.dl_gbr =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_dnlnk;
			bearer->qos.arp.preemption_vulnerability =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.pvi;
			bearer->qos.arp.spare1 =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.spare2;
			bearer->qos.arp.priority_level =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.pl;
			bearer->qos.arp.preemption_capability =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.pci;
			bearer->qos.arp.spare2 =
				resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].bearer_lvl_qos.spare3;
		}
		else{
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}
		bearer->s5s8_pgw_gtpu_ipv4.s_addr =
			resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.ipv4_address;
		bearer->s5s8_pgw_gtpu_teid =
			resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.teid_gre_key;
		bearer->pdn = pdn;

		update_far[index].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_pgw_gtpu_teid;
		update_far[index].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_pgw_gtpu_ipv4.s_addr;
		update_far[index].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(resp->gtpc_msg.cs_rsp.bearer_contexts_created[index].s5s8_u_pgw_fteid.interface_type,
					context->cp_mode);
		update_far[index].far_id.far_id_value =
			get_far_id(bearer, update_far[index].upd_frwdng_parms.dst_intfc.interface_value);

		pfcp_sess_mod_req.update_far_count++;
		index++;
	}
	bearers[0]= bearer;
	for(idx = 0; idx < cbr->bearer_cnt; ++idx) {
		dedicated_bearer = rte_zmalloc_socket(NULL, (sizeof(eps_bearer)),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (dedicated_bearer == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for Bearer, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		new_ebi_index = idx + MAX_BEARERS;
		resp->eps_bearer_ids[idx] = new_ebi_index + NUM_EBI_RESERVED;

		dedicated_bearer->pdn = pdn;

		context->eps_bearers[new_ebi_index] = dedicated_bearer;
		pdn->eps_bearers[new_ebi_index] = dedicated_bearer;

		dedicated_bearer->qos.arp.preemption_vulnerability = cbr->bearer_contexts[idx].bearer_lvl_qos.pvi;

		dedicated_bearer->qos.arp.priority_level = cbr->bearer_contexts[idx].bearer_lvl_qos.pl;

		dedicated_bearer->qos.arp.preemption_capability = cbr->bearer_contexts[idx].bearer_lvl_qos.pci;

		dedicated_bearer->qos.qci = cbr->bearer_contexts[idx].bearer_lvl_qos.qci;

		dedicated_bearer->qos.ul_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_uplnk;

		dedicated_bearer->qos.dl_mbr = cbr->bearer_contexts[idx].bearer_lvl_qos.max_bit_rate_dnlnk;

		dedicated_bearer->qos.ul_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_uplnk;

		dedicated_bearer->qos.dl_gbr = cbr->bearer_contexts[idx].bearer_lvl_qos.guarntd_bit_rate_dnlnk;

		dedicated_bearer->s5s8_pgw_gtpu_ipv4.s_addr = cbr->bearer_contexts[idx].s58_u_pgw_fteid.ipv4_address;

		dedicated_bearer->s5s8_pgw_gtpu_teid = cbr->bearer_contexts[idx].s58_u_pgw_fteid.teid_gre_key;

		memset(resp->eps_bearer_lvl_tft[idx], 0, MAX_TFT_LEN);
		memcpy(resp->eps_bearer_lvl_tft[idx],
			cbr->bearer_contexts[idx].tft.eps_bearer_lvl_tft, MAX_TFT_LEN);
		resp->tft_header_len[idx] = cbr->bearer_contexts[idx].tft.header.len;

		fill_dedicated_bearer_info(dedicated_bearer, context, pdn, FALSE);

		pfcp_sess_mod_req.create_pdr_count += dedicated_bearer->pdr_count;
		bearers[index] = dedicated_bearer;
		index++;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cbr->header, bearers, pdn, update_far, 0, cbr->bearer_cnt + 1, context);

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, INTERFACE) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending MBR to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	else
	{

		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = seq_no;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->bearer_count = cbr->bearer_cnt;
	resp->msg_type = GTP_CREATE_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = ATTACH_DEDICATED_PROC;
	pdn->proc = ATTACH_DEDICATED_PROC;
	resp->cp_mode = context->cp_mode;

	return 0;
}

int
process_mb_request_cb_response(mod_bearer_req_t *mbr)
{

	int ret = 0;
	int ebi_index = 0, index = 0, idx = 0;
	uint8_t seq_no;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL, *bearers[MAX_BEARERS], *dedicated_bearer =  NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mbr->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = GET_EBI_INDEX(mbr->bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	bearer = context->eps_bearers[ebi_index];

	if (get_sess_entry(bearer->pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, bearer->pdn->seid);
		return -1;
	}

	pfcp_sess_mod_req.update_far_count = 0;

	for(uint8_t i = 0; i< mbr->bearer_count; i++) {

		if (!mbr->bearer_contexts_to_be_modified[i].eps_bearer_id.header.len
				|| !mbr->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Dropping packet\n",
					LOG_VALUE);
			return GTPV2C_CAUSE_INVALID_LENGTH;
		}

		ebi_index = GET_EBI_INDEX(mbr->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (!(context->bearer_bitmap & (1 << ebi_index))) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT" Received modify bearer on non-existent EBI - "
					"Dropping packet\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		bearer = context->eps_bearers[ebi_index];

		pdn = bearer->pdn;


		if (mbr->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.header.len  != 0){
			bearer->s5s8_sgw_gtpu_ipv4.s_addr =
				mbr->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.ipv4_address;
			bearer->s5s8_sgw_gtpu_teid =
				mbr->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.teid_gre_key;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
				bearer->s5s8_sgw_gtpu_teid;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
				bearer->s5s8_sgw_gtpu_ipv4.s_addr;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
				check_interface_type(mbr->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.interface_type,
						context->cp_mode);
			update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
				get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
			if (context->cp_mode != PGWC) {
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(context);
			}
			pfcp_sess_mod_req.update_far_count++;
		}

		bearers[i] = bearer;
		index++;

	} /*forloop*/
	/* Set create session response */
/*	resp->eps_bearer_id = default_bearer_id;//mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->gtpc_msg.mbr = *mb_req;*/


	for(idx = 0; idx < resp->gtpc_msg.cb_rsp.bearer_cnt; idx++) {
		ebi_index = GET_EBI_INDEX(resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		dedicated_bearer = context->eps_bearers[ebi_index];
		resp->eps_bearer_ids[idx] = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi;
		if(dedicated_bearer == NULL)
		{
			/* TODO:
			 * This mean ebi we allocated and received doesnt match
			 * In correct design match the bearer in transtient struct from sgw-u teid
			 * */
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		dedicated_bearer->s1u_enb_gtpu_ipv4.s_addr = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.ipv4_address;
		dedicated_bearer->s1u_enb_gtpu_teid = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.teid_gre_key;
		dedicated_bearer->s1u_sgw_gtpu_ipv4.s_addr = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_sgw_fteid.ipv4_address;
		dedicated_bearer->s1u_sgw_gtpu_teid = resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_sgw_fteid.teid_gre_key;

		if (resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.header.len  != 0) {
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
				dedicated_bearer->s1u_enb_gtpu_teid;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
				dedicated_bearer->s1u_enb_gtpu_ipv4.s_addr;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
				check_interface_type(resp->gtpc_msg.cb_rsp.bearer_contexts[idx].s1u_enb_fteid.interface_type,
						context->cp_mode);
			update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
				get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(context);
			pfcp_sess_mod_req.update_far_count++;
		}
		bearers[index] = dedicated_bearer;
		index++;
	}



	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &resp->gtpc_msg.cb_rsp.header, bearers, pdn,
			update_far, 0, resp->gtpc_msg.cb_rsp.bearer_cnt + mbr->bearer_count, context);
	s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;

	seq_no = resp->gtpc_msg.cb_rsp.header.teid.has_teid.seq;


	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, INTERFACE) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending MBR to SGW-U. err_no: %i\n", LOG_VALUE, errno);
	else
	{

		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(resp->gtpc_msg.cb_rsp.header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = seq_no;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->bearer_count = resp->gtpc_msg.cb_rsp.bearer_cnt;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->cp_mode = context->cp_mode;

	return 0;
}

