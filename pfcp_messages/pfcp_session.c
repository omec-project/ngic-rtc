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

#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"

#ifdef CP_BUILD
#include "ue.h"
#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "ipc_api.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "gtpc_session.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "cp_timer.h"

extern const uint32_t s5s8_sgw_gtpc_base_teid; /* 0xE0FFEE */
static uint32_t s5s8_sgw_gtpc_teid_offset;

#endif /* CP_BUILD */

#ifdef DP_BUILD
extern struct in_addr dp_comm_ip;
#endif /* DP_BUILD */

#ifdef CP_BUILD
pfcp_config_t pfcp_config;

extern int gx_app_sock;

#define size sizeof(pfcp_sess_mod_req_t)
/* Header Size of set_upd_forwarding_param ie */
#define UPD_PARAM_HEADER_SIZE 4
extern int pfcp_fd;

/* len of flags*/
#define FLAG_LEN 2

void
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req)
{
	uint32_t seq = 1;

	memset(pfcp_sess_del_req, 0, sizeof(pfcp_sess_del_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_DELETION_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_req->header),
		PFCP_SESSION_DELETION_REQUEST, HAS_SEID, seq);

}

void
fill_pfcp_sess_set_del_req( pfcp_sess_set_del_req_t *pfcp_sess_set_del_req)
{

	uint32_t seq = 1;
	char sgwc_addr[INET_ADDRSTRLEN] = {0};
	char pgwc_addr[INET_ADDRSTRLEN] = {0};
	char mme_addr[INET_ADDRSTRLEN]  = {0};
	char sgwu_addr[INET_ADDRSTRLEN] = {0};
	char pgwu_addr[INET_ADDRSTRLEN] = {0};
	uint32_t node_value = 0;

	/*Added hardcoded value to remove compile error.Right now,we are using
	function. Will remove hard value  */
	const char* pAddr = "192.168.0.10";
	const char* twan_addr = "192.16.0.1";
	const char* epdg_addr = "192.16.0.2";
	unsigned long sgwc_value = 0;

	memset(pfcp_sess_set_del_req, 0, sizeof(pfcp_sess_set_del_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_SET_DELETION_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, HAS_SEID, seq);

	node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
	sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->sgw_c_fqcsid), sgwc_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->pgw_c_fqcsid), pgwc_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwu_addr, INET_ADDRSTRLEN);
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->sgw_u_fqcsid), sgwu_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwu_addr, INET_ADDRSTRLEN);
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->pgw_u_fqcsid), pgwu_value);

	// set of twan fqcsid
	//TODO : IP addres for twan is hardcoded
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->twan_fqcsid), twan_value);

	// set of epdg fqcsid
	//TODO : IP addres for epdgg is hardcoded
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->epdg_fqcsid), epdg_value);

	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->mme_fqcsid), mme_value);

}

void
fill_pfcp_gx_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn)
{

	int ret = 0;
	uint8_t bearer_id = 0;
	uint32_t seq = 0;
	eps_bearer *bearer = NULL;
	upf_context_t *upf_ctx = NULL;


	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return;
	}

	memset(pfcp_sess_mod_req,0,sizeof(pfcp_sess_mod_req_t));
	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	if ((pfcp_config.cp_type == PGWC) ||
			(SAEGWC == pfcp_config.cp_type))
	{
		for (int idx=0; idx <  (pdn->policy.count - pdn->policy.num_charg_rule_delete); idx++)
		{
			if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_ADD)
			{
				/*
				 * Installing new rule
				 */
				 bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].dyn_rule.qos);
				 if(bearer == NULL)
				 {
					/*
					 * create dedicated bearer
					 */
					bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
					if(bearer == NULL)
					{
						clLog(sxlogger, eCLSeverityCritical,
							"Failure to allocate bearer "
							"structure: %s (%s:%d)\n",
							rte_strerror(rte_errno),
							 __FILE__,  __LINE__);
						return;
						/* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
					}
					bzero(bearer,  sizeof(eps_bearer));
					bearer->pdn = pdn;
					bearer_id = get_new_bearer_id(pdn);
					pdn->eps_bearers[bearer_id] = bearer;
					pdn->context->eps_bearers[bearer_id] = bearer;
					pdn->num_bearer++;
					set_s5s8_pgw_gtpu_teid_using_pdn(bearer, pdn);
					fill_dedicated_bearer_info(bearer, pdn->context, pdn);
					memcpy(&(bearer->qos), &(pdn->policy.pcc_rule[idx].dyn_rule.qos), sizeof(bearer_qos_ie));

				 }
				 bearer->dynamic_rules[bearer->num_dynamic_filters] = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
						 RTE_CACHE_LINE_SIZE, rte_socket_id());
				 if (bearer->dynamic_rules[bearer->num_dynamic_filters] == NULL)
				 {
					 clLog(sxlogger, eCLSeverityCritical,
						"Failure to allocate dynamic rule memory "
						"structure: %s (%s:%d)\n",
						rte_strerror(rte_errno),
						__FILE__, __LINE__);
					 return;
					 /* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
				 }

				 fill_pfcp_entry(bearer, &pdn->policy.pcc_rule[idx].dyn_rule, RULE_ACTION_ADD);

				 memcpy( (bearer->dynamic_rules[bearer->num_dynamic_filters]),
						 &(pdn->policy.pcc_rule[idx].dyn_rule),
						 sizeof(dynamic_rule_t));

				 fill_create_pfcp_info(pfcp_sess_mod_req, &pdn->policy.pcc_rule[idx].dyn_rule);
				 bearer->num_dynamic_filters++;

				//Adding rule and bearer id to a hash
				bearer_id_t *id;
				id = malloc(sizeof(bearer_id_t));
				memset(id, 0 , sizeof(bearer_id_t));
				rule_name_key_t key = {0};
				id->bearer_id = bearer_id;
				strncpy(key.rule_name, pdn->policy.pcc_rule[idx].dyn_rule.rule_name,
						strlen(pdn->policy.pcc_rule[idx].dyn_rule.rule_name));
				sprintf(key.rule_name, "%s%d", key.rule_name, pdn->call_id);
				if (add_rule_name_entry(key, id) != 0) {
					clLog(sxlogger, eCLSeverityCritical,
						"%s:%d Failed to add_rule_name_entry with rule_name\n",
						__func__, __LINE__);
					return;
				}
			}
			else if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY)
			{
				/*
				 * Currently not handling dynamic rule qos modificaiton
				 */
				bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].dyn_rule.qos);
				if(bearer == NULL)
				{
					 clLog(sxlogger, eCLSeverityCritical, "Failure to find bearer "
							 "structure: %s (%s:%d)\n",
							 rte_strerror(rte_errno),
							 __FILE__,
							 __LINE__);
					 return;
					 /* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
				}
				fill_pfcp_entry(bearer, &pdn->policy.pcc_rule[idx].dyn_rule, RULE_ACTION_MODIFY);
				fill_update_pfcp_info(pfcp_sess_mod_req, &pdn->policy.pcc_rule[idx].dyn_rule);

			}
		}

		/* TODO: Remove Below section START after install, modify and remove support */
		if (pdn->policy.num_charg_rule_delete != 0) {
			memset(pfcp_sess_mod_req,0,sizeof(pfcp_sess_mod_req_t));
			seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

			set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
							           HAS_SEID, seq);

			pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

			//TODO modify this hard code to generic
			inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
			node_value = inet_addr(pAddr);

			set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);
		}
		/* TODO: Remove Below section END */

		uint8_t idx_offset =  pdn->policy.num_charg_rule_install + pdn->policy.num_charg_rule_modify;
		for (int idx = 0; idx < pdn->policy.num_charg_rule_delete; idx++) {
			if(RULE_ACTION_DELETE == pdn->policy.pcc_rule[idx + idx_offset].action)
			{
				/* bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx + idx_offset].dyn_rule.qos);
				if(NULL == bearer)
				{
					 clLog(clSystemLog, eCLSeverityCritical, "Failure to find bearer "
							 "structure: %s (%s:%d)\n",
							 rte_strerror(rte_errno),
							 __FILE__,
							 __LINE__);
					 return;
				} */

				rule_name_key_t rule_name = {0};
				memset(rule_name.rule_name, '\0', sizeof(rule_name.rule_name));
				strncpy(rule_name.rule_name, pdn->policy.pcc_rule[idx + idx_offset].dyn_rule.rule_name,
					   strlen(pdn->policy.pcc_rule[idx + idx_offset].dyn_rule.rule_name));
				sprintf(rule_name.rule_name, "%s%d",
						rule_name.rule_name, pdn->call_id);
				int8_t bearer_id = get_rule_name_entry(rule_name);
				if (-1 == bearer_id) {
					/* TODO: Error handling bearer not found */
				}

				if ((bearer_id + 5) == pdn->default_bearer_id) {
					for (uint8_t iCnt = 0; iCnt < MAX_BEARERS; ++iCnt) {
						if (NULL != pdn->eps_bearers[iCnt]) {
							fill_remove_pfcp_info(pfcp_sess_mod_req, pdn->eps_bearers[iCnt]);
						}
					}
				} else {
					fill_remove_pfcp_info(pfcp_sess_mod_req, pdn->eps_bearers[bearer_id]);
				}
			}
		}
	}
}
#define MAX_PDR_PER_RULE 2
int
fill_create_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule)
{

	uint8_t sdf_filter_count = 0;
	pfcp_create_pdr_ie_t *pdr = NULL;
	pfcp_create_far_ie_t *far = NULL;
	pfcp_create_qer_ie_t *qer = NULL;

	for(int i=0; i<MAX_PDR_PER_RULE; i++)
	{
		pdr = &(pfcp_sess_mod_req->create_pdr[i]);
		far = &(pfcp_sess_mod_req->create_far[i]);
		qer = &(pfcp_sess_mod_req->create_qer[i]);

		pdr->qer_id_count = 1;
		pdr->qer_id_count = 1;

		creating_pdr(pdr, i);

		pdr->pdr_id.rule_id = dyn_rule->pdr[i]->rule_id;
		pdr->precedence.prcdnc_val = dyn_rule->pdr[i]->prcdnc_val;
		pdr->far_id.far_id_value = dyn_rule->pdr[i]->far.far_id_value;
		pdr->qer_id[0].qer_id_value = dyn_rule->pdr[i]->qer.qer_id;

		pdr->pdi.ue_ip_address.ipv4_address =
			htonl(dyn_rule->pdr[i]->pdi.ue_addr.ipv4_address);
		pdr->pdi.local_fteid.teid =
			dyn_rule->pdr[i]->pdi.local_fteid.teid;
		pdr->pdi.local_fteid.ipv4_address =
				htonl(dyn_rule->pdr[i]->pdi.local_fteid.ipv4_address);
		pdr->pdi.src_intfc.interface_value =
				dyn_rule->pdr[i]->pdi.src_intfc.interface_value;
		strncpy((char *)pdr->pdi.ntwk_inst.ntwk_inst,
				(char *)&dyn_rule->pdr[i]->pdi.ntwk_inst.ntwk_inst, 32);

		pdr->pdi.src_intfc.interface_value =
			dyn_rule->pdr[i]->pdi.src_intfc.interface_value;

		if (pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) {
			uint32_t size_teid = 0;
			size_teid = pdr->pdi.local_fteid.header.len + sizeof(pfcp_ie_header_t);
			pdr->pdi.header.len = pdr->pdi.header.len - size_teid;
			pdr->header.len = pdr->header.len - size_teid;
			pdr->pdi.local_fteid.header.len = 0;
		} else if (pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {
			uint32_t size_ie = pdr->pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t) + pdr->pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);

			pdr->pdi.header.len -= size_ie;
			pdr->header.len -= size_ie;

			pdr->pdi.ue_ip_address.header.len = 0;
			pdr->pdi.ntwk_inst.header.len = 0;
		}
#if 0
		memcpy(&(pdr->pdi.sdf_filter[pdr->pdi.sdf_filter_count].flow_desc),
			&(dyn_rule->pdr[i]->pdi.sdf_filter[pdr->pdi.sdf_filter_count].flow_desc),
				dyn_rule->pdr[i]->pdi.sdf_filter[pdr->pdi.sdf_filter_count].len_of_flow_desc);

		pdr->pdi.sdf_filter[pdr->pdi.sdf_filter_count].len_of_flow_desc =
				dyn_rule->pdr[i]->pdi.sdf_filter[pdr->pdi.sdf_filter_count].len_of_flow_desc;

		pdr->pdi.sdf_filter_count++;
#endif
		for(int itr = 0; itr < dyn_rule->num_flw_desc; itr++) {

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {

				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

					sdf_pkt_filter_gx_mod(
							pdr, dyn_rule, sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
					sdf_filter_count++;
				}

			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {
				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					sdf_pkt_filter_gx_mod(
							pdr, dyn_rule, sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					sdf_filter_count++;
				}
			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}
		}
		pdr->pdi.sdf_filter_count = sdf_filter_count;

		creating_far(far);
		far->far_id.far_id_value = dyn_rule->pdr[i]->far.far_id_value;
		set_destination_interface(&(far->frwdng_parms.dst_intfc));
		pfcp_set_ie_header(&(far->frwdng_parms.header),
				IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

		far->frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

		uint16_t len = 0;
		len += sizeof(pfcp_dst_intfc_ie_t);
		len += UPD_PARAM_HEADER_SIZE;

		far->header.len += len;
		far->frwdng_parms.dst_intfc.interface_value = dyn_rule->pdr[i]->far.dst_intfc.interface_value;

		far->apply_action.forw = PRESENT;

		creating_qer(qer);
		qer->qer_id.qer_id_value  = dyn_rule->pdr[i]->qer.qer_id;

		qer->maximum_bitrate.ul_mbr  = dyn_rule->pdr[i]->qer.max_bitrate.ul_mbr;
		qer->maximum_bitrate.dl_mbr  = dyn_rule->pdr[i]->qer.max_bitrate.dl_mbr;
		qer->guaranteed_bitrate.ul_gbr  = dyn_rule->pdr[i]->qer.guaranteed_bitrate.ul_gbr;
		qer->guaranteed_bitrate.dl_gbr  = dyn_rule->pdr[i]->qer.guaranteed_bitrate.dl_gbr;
		qer->gate_status.ul_gate  = dyn_rule->pdr[i]->qer.gate_status.ul_gate;
		qer->gate_status.dl_gate  = dyn_rule->pdr[i]->qer.gate_status.dl_gate;

		pfcp_sess_mod_req->create_pdr_count++;
		pfcp_sess_mod_req->create_far_count++;
		pfcp_sess_mod_req->create_qer_count++;
	}
	return 0;
}

int
fill_update_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule)
{

	uint8_t sdf_filter_count = 0;
	pfcp_update_pdr_ie_t *pdr = NULL;
	pfcp_update_far_ie_t *far = NULL;
	pfcp_update_qer_ie_t *qer = NULL;

	for(int i=0; i<MAX_PDR_PER_RULE; i++)
	{
		pdr = &(pfcp_sess_mod_req->update_pdr[pfcp_sess_mod_req->update_pdr_count+i]);
		far = &(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count+i]);
		qer = &(pfcp_sess_mod_req->update_qer[pfcp_sess_mod_req->update_qer_count+i]);

		updating_pdr(pdr, i);

		pdr->pdr_id.rule_id = dyn_rule->pdr[i]->rule_id;
		pdr->precedence.prcdnc_val = dyn_rule->pdr[i]->prcdnc_val;
		pdr->qer_id.qer_id_value = dyn_rule->pdr[i]->qer_id[0].qer_id;
		pdr->far_id.far_id_value = dyn_rule->pdr[i]->far.far_id_value;


		pdr->pdi.ue_ip_address.ipv4_address =
			htonl(dyn_rule->pdr[i]->pdi.ue_addr.ipv4_address);
		pdr->pdi.local_fteid.teid =
			dyn_rule->pdr[i]->pdi.local_fteid.teid;
		pdr->pdi.local_fteid.ipv4_address =
				htonl(dyn_rule->pdr[i]->pdi.local_fteid.ipv4_address);
		pdr->pdi.src_intfc.interface_value =
				dyn_rule->pdr[i]->pdi.src_intfc.interface_value;
		strncpy((char *)pdr->pdi.ntwk_inst.ntwk_inst,
				(char *)&dyn_rule->pdr[i]->pdi.ntwk_inst.ntwk_inst, 32);

		pdr->pdi.src_intfc.interface_value =
			dyn_rule->pdr[i]->pdi.src_intfc.interface_value;

		if (pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) {
			uint32_t size_teid = 0;
			size_teid = pdr->pdi.local_fteid.header.len + sizeof(pfcp_ie_header_t);
			pdr->pdi.header.len = pdr->pdi.header.len - size_teid;
			pdr->header.len = pdr->header.len - size_teid;
			pdr->pdi.local_fteid.header.len = 0;
		} else if (pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {
			uint32_t size_ie = pdr->pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t) + pdr->pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);

			pdr->pdi.header.len -= size_ie;
			pdr->header.len -= size_ie;

			pdr->pdi.ue_ip_address.header.len = 0;
			pdr->pdi.ntwk_inst.header.len = 0;
		}
#if 0
		memcpy(&(pdr->pdi.sdf_filter[pdr->pdi.sdf_filter_count].flow_desc),
			&(dyn_rule->pdr[i]->pdi.sdf_filter[pdr->pdi.sdf_filter_count].flow_desc),
				dyn_rule->pdr[i]->pdi.sdf_filter[pdr->pdi.sdf_filter_count].len_of_flow_desc);

		pdr->pdi.sdf_filter[pdr->pdi.sdf_filter_count].len_of_flow_desc =
				dyn_rule->pdr[i]->pdi.sdf_filter[pdr->pdi.sdf_filter_count].len_of_flow_desc;

		pdr->pdi.sdf_filter_count++;
#endif
		for(int itr = 0; itr < dyn_rule->num_flw_desc; itr++) {

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {

				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

					/* TODO: Revisit following line, change funtion signature and remove type casting */
					sdf_pkt_filter_gx_mod((pfcp_create_pdr_ie_t *)pdr, dyn_rule,
							 sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
					sdf_filter_count++;
				}

			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {
				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					/* TODO: Revisit following line, change funtion signature and remove type casting */
					sdf_pkt_filter_gx_mod((pfcp_create_pdr_ie_t *) pdr, dyn_rule,
							sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					sdf_filter_count++;
				}
			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}
		}
		pdr->pdi.sdf_filter_count = sdf_filter_count;

		updating_far(far);
		far->far_id.far_id_value = dyn_rule->pdr[i]->far.far_id_value;
		set_destination_interface(&(far->upd_frwdng_parms.dst_intfc));
		pfcp_set_ie_header(&(far->upd_frwdng_parms.header),
				IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

		far->upd_frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

		uint16_t len = 0;
		len += sizeof(pfcp_dst_intfc_ie_t);
		len += UPD_PARAM_HEADER_SIZE;

		far->header.len += len;
		far->upd_frwdng_parms.dst_intfc.interface_value = dyn_rule->pdr[i]->far.dst_intfc.interface_value;

		far->apply_action.forw = PRESENT;

		updating_qer(qer);
		qer->qer_id.qer_id_value  = dyn_rule->pdr[i]->qer.qer_id;

		qer->maximum_bitrate.ul_mbr  = dyn_rule->pdr[i]->qer.max_bitrate.ul_mbr;
		qer->maximum_bitrate.dl_mbr  = dyn_rule->pdr[i]->qer.max_bitrate.dl_mbr;
		qer->guaranteed_bitrate.ul_gbr  = dyn_rule->pdr[i]->qer.guaranteed_bitrate.ul_gbr;
		qer->guaranteed_bitrate.dl_gbr  = dyn_rule->pdr[i]->qer.guaranteed_bitrate.dl_gbr;
		qer->gate_status.ul_gate  = dyn_rule->pdr[i]->qer.gate_status.ul_gate;
		qer->gate_status.dl_gate  = dyn_rule->pdr[i]->qer.gate_status.dl_gate;

		pfcp_sess_mod_req->update_pdr_count++;
		pfcp_sess_mod_req->update_far_count++;
		pfcp_sess_mod_req->update_qer_count++;
	}
	return 0;
}

int
fill_remove_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer)
{
	pfcp_update_far_ie_t *far = NULL;

	for(int i=0; i<MAX_PDR_PER_RULE; i++)
	{
		far = &(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]);

		updating_far(far);
		far->far_id.far_id_value = bearer->pdrs[i]->far.far_id_value;
		far->apply_action.drop = PRESENT;

		pfcp_sess_mod_req->update_far_count++;
	}
	return 0;
}

void sdf_pkt_filter_upd_bearer(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
    eps_bearer* bearer,
    int pdr_counter,
    int sdf_filter_count,
    int dynamic_filter_cnt,
    int flow_cnt,
    uint8_t direction)
{
    int len = 0;
    pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].fd = 1;
    sdf_pkt_filter_to_string(&(bearer->dynamic_rules[dynamic_filter_cnt]->flow_desc[flow_cnt].sdf_flw_desc),
        (char*)(pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc), direction);

    pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc =
        strlen((char*)(&pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc));

    len += FLAG_LEN;
    len += sizeof(uint16_t);
    len += pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc;

    pfcp_set_ie_header(
        &(pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

    /*VG updated the header len of pdi as sdf rules has been added*/
    pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.header.len += (len + sizeof(pfcp_ie_header_t));
    pfcp_sess_mod_req->update_pdr[pdr_counter].header.len += (len + sizeof(pfcp_ie_header_t));
}

int fill_upd_bearer_sdf_rule(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
								eps_bearer* bearer,	int pdr_counter){
    int ret = 0;
    int sdf_filter_count = 0;
    /*VG convert pkt_filter_strucutre to char string*/
    for(int index = 0; index < bearer->num_dynamic_filters; index++) {

        pfcp_sess_mod_req->update_pdr[pdr_counter].precedence.prcdnc_val = bearer->dynamic_rules[index]->precedence;
        // itr is for flow information counter
        // sdf_filter_count is for SDF information counter
        for(int itr = 0; itr < bearer->dynamic_rules[index]->num_flw_desc; itr++) {

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {

                if((pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

                    sdf_pkt_filter_upd_bearer(pfcp_sess_mod_req, bearer, pdr_counter,
                    			sdf_filter_count, index, itr, TFT_DIRECTION_UPLINK_ONLY);
                    sdf_filter_count++;
                }

            } else {
                clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {
                if((pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
                    sdf_pkt_filter_upd_bearer(pfcp_sess_mod_req, bearer, pdr_counter,
                    		sdf_filter_count, index, itr, TFT_DIRECTION_DOWNLINK_ONLY);
                    sdf_filter_count++;
                }
            } else {
                clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }
        }

		pfcp_sess_mod_req->update_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

    }
    return ret;
}

void
fill_update_pdr(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer){

	int size1 = 0;

	for(int i = pfcp_sess_mod_req->update_pdr_count;
			i < pfcp_sess_mod_req->update_pdr_count + NUMBER_OF_PDR_PER_BEARER;
			i++){

		size1 = 0;
		size1 += set_pdr_id(&(pfcp_sess_mod_req->update_pdr[i].pdr_id));
		size1 += set_precedence(&(pfcp_sess_mod_req->update_pdr[i].precedence));
		size1 += set_pdi(&(pfcp_sess_mod_req->update_pdr[i].pdi));

		int itr = i - pfcp_sess_mod_req->update_pdr_count;

		pfcp_set_ie_header(&(pfcp_sess_mod_req->update_pdr[i].header), IE_UPDATE_PDR, size1);

		pfcp_sess_mod_req->update_pdr[i].pdr_id.rule_id = bearer->pdrs[itr]->rule_id;

		pfcp_sess_mod_req->update_pdr[i].pdi.local_fteid.teid =
			bearer->pdrs[itr]->pdi.local_fteid.teid;

		if((pfcp_config.cp_type == SGWC) ||
				(bearer->pdrs[itr]->pdi.src_intfc.interface_value ==
				SOURCE_INTERFACE_VALUE_ACCESS)) {
			/*No need to send ue ip and network instance for pgwc access interface or
			 * for any sgwc interface */
			uint32_t size_ie = 0;
			size_ie = pfcp_sess_mod_req->update_pdr[i].pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t);
			size_ie = size_ie + pfcp_sess_mod_req->update_pdr[i].pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->update_pdr[i].pdi.header.len =
				pfcp_sess_mod_req->update_pdr[i].pdi.header.len - size_ie;
			pfcp_sess_mod_req->update_pdr[i].header.len =
				pfcp_sess_mod_req->update_pdr[i].header.len - size_ie;
			pfcp_sess_mod_req->update_pdr[i].pdi.ue_ip_address.header.len = 0;
			pfcp_sess_mod_req->update_pdr[i].pdi.ntwk_inst.header.len = 0;
		}else{
			pfcp_sess_mod_req->update_pdr[i].pdi.ue_ip_address.ipv4_address =
				bearer->pdrs[itr]->pdi.ue_addr.ipv4_address;
			strncpy((char *)pfcp_sess_mod_req->update_pdr[i].pdi.ntwk_inst.ntwk_inst,
				(char *)&bearer->pdrs[itr]->pdi.ntwk_inst.ntwk_inst, 32);
		}

		if (
				((PGWC == pfcp_config.cp_type) || (SAEGWC == pfcp_config.cp_type)) &&
				(SOURCE_INTERFACE_VALUE_CORE ==
				bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {

			uint32_t size_ie = 0;

			size_ie = pfcp_sess_mod_req->update_pdr[i].pdi.local_fteid.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->update_pdr[i].pdi.header.len =
				pfcp_sess_mod_req->update_pdr[i].pdi.header.len - size_ie;
			pfcp_sess_mod_req->update_pdr[i].header.len =
				pfcp_sess_mod_req->update_pdr[i].header.len - size_ie;
			pfcp_sess_mod_req->update_pdr[i].pdi.local_fteid.header.len = 0;

		} else {
			pfcp_sess_mod_req->update_pdr[i].pdi.local_fteid.ipv4_address =
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
		}

		pfcp_sess_mod_req->update_pdr[i].pdi.src_intfc.interface_value =
			bearer->pdrs[itr]->pdi.src_intfc.interface_value;

		fill_upd_bearer_sdf_rule(pfcp_sess_mod_req, bearer, i);
	}

	pfcp_sess_mod_req->update_pdr_count += NUMBER_OF_PDR_PER_BEARER;
	return;
}

/* REVIEW: Context will remove after merging */
void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, eps_bearer *bearer,
		pdn_connection *pdn, pfcp_update_far_ie_t update_far[], uint8_t x2_handover_flag)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return;
	}

	if( header != NULL)
		clLog(sxlogger, eCLSeverityDebug, "TEID[%d]\n", header->teid.has_teid.teid);

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	/*SP: This depends on condition in pcrf data(pcrf will send bar_rule_id if it needs to be delated). Need to handle after pcrf integration*/
	/* removing_bar(&(pfcp_sess_mod_req->remove_bar)); */

	//set create PDR

	/************************************************
	 *  cp_type  count     FTEID_1          FTEID_2 *
	 *************************************************
	 In case MBR received from MME:-
	 SGWC         1      enodeB               -
	 PGWC         -        -                  -
	 SAEGWC       1      enodeB               -
	 *************************************************
	 In case of CSResp received from PGWC to SGWC :-
	 SGWC <----CSResp--- PGWC
	 |
	 pfcp_sess_mod_req
	 |
	 v
	 SGWU
	 In above scenario:
	 count = 1 ,     FTEID_1 = s5s8 PGWU
	 ************************************************/
	/*SP: create pdr IE is not needed in session modification request , hence removing*/
	/*
	pfcp_sess_mod_req->create_pdr_count = 1;

	for( int i = 0; i < pfcp_sess_mod_req->create_pdr_count ; i++)
		creating_pdr(&(pfcp_sess_mod_req->create_pdr[i]));
	*/

	if (pfcp_sess_mod_req->create_pdr_count) {
		fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req, bearer);
	}

	/*SP: This depends on condition  if the CP function requests the UP function to create a new BAR
	  Need to add condition to check if CP needs creation of BAR*/
	for( int i = 0; i < pfcp_sess_mod_req->create_pdr_count ; i++){
		if((pfcp_sess_mod_req->create_pdr[i].header.len) &&
				(pfcp_sess_mod_req->create_pdr[i].far_id.header.len)){
			for( int j = 0; j < pfcp_sess_mod_req->create_far_count ; j++){
				if(pfcp_sess_mod_req->create_far[i].bar_id.header.len){
					/* TODO: Pass bar_id from pfcp_session_mod_req->create_far[i].bar_id.bar_id_value
					   to set bar_id*/
					creating_bar(&(pfcp_sess_mod_req->create_bar));
				}
			}
		}
	}

	/*SP: Adding FAR IE*/
	for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count ; itr1++) {
		for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
			if(bearer->pdrs[itr]->pdi.src_intfc.interface_value !=
					update_far[itr1].upd_frwdng_parms.dst_intfc.interface_value){
				pdr_ctxt = bearer->pdrs[itr];
				updating_far(&(pfcp_sess_mod_req->update_far[itr1]));
				pfcp_sess_mod_req->update_far[itr1].far_id.far_id_value =
					pdr_ctxt->far.far_id_value;
				pfcp_sess_mod_req->update_far[itr1].apply_action.forw = PRESENT;
				if (pfcp_sess_mod_req->update_far[itr1].apply_action.forw == PRESENT) {
					uint16_t len = 0;
					len += set_upd_forwarding_param(&(pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms));
					/* Currently take as hardcoded value */
					len += UPD_PARAM_HEADER_SIZE;
					pfcp_sess_mod_req->update_far[itr1].header.len += len;
				}
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.outer_hdr_creation.teid =
					update_far[itr1].upd_frwdng_parms.outer_hdr_creation.teid;
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
					(update_far[itr1].upd_frwdng_parms.outer_hdr_creation.ipv4_address);
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.dst_intfc.interface_value =
					update_far[itr1].upd_frwdng_parms.dst_intfc.interface_value;

				if(x2_handover_flag) {

					set_pfcpsmreqflags(&(pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.pfcpsmreq_flags));
					pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.pfcpsmreq_flags.sndem = 1;
					pfcp_sess_mod_req->update_far[itr1].header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);
					pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);

				}
			}

		}
	}

	switch (pfcp_config.cp_type)
	{
		case SGWC :
		case SAEGWC :
			if(pfcp_sess_mod_req->create_pdr_count){
				for(int itr = 0; itr < pfcp_sess_mod_req->create_pdr_count; itr++) {
					pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.teid =
						bearer->pdrs[itr]->pdi.local_fteid.teid ;
					/* TODO: Revisit this for change in yang */
					pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address =
						htonl(bearer->pdrs[itr]->pdi.ue_addr.ipv4_address);
					pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.ipv4_address =
						bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
					pfcp_sess_mod_req->create_pdr[itr].pdi.src_intfc.interface_value =
						bearer->pdrs[itr]->pdi.src_intfc.interface_value;
				}
			}
			break;

		case PGWC :
			break;

		default :
			clLog(clSystemLog, eCLSeverityDebug,"%s:%d default pfcp sess mod req\n", __func__, __LINE__);
			break;
	}

	// set of update QER
	/*SP: No QER is not generated previously, No update needed*/
	/*
	pfcp_sess_mod_req->update_qer_count = bearer->qer_count;

	for(int i=0; i < pfcp_sess_mod_req->update_qer_count; i++ ){
		updating_qer(&(pfcp_sess_mod_req->update_qer[i]));
		pfcp_sess_mod_req->update_qer[i] == bearer->qer_id.qer.id;
	}
	*/

	// set of update BAR
	/*SP: If previously created BAR needs to be modified, this IE should be included*/
	/*
	 updating_bar(&(pfcp_sess_mod_req->update_bar));
	*/

	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	/*SP: This IE is included if one of DROBU and QAURR flag is set,
	      excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}

	/*SP: This IE is included if node supports Partial failure handling support
	      excluding this IE since we dont have this support  */
	/*
	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_mod_req->sgw_c_fqcsid), sgwc_value);

	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_mod_req->mme_fqcsid), mme_value);

	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_mod_req->pgw_c_fqcsid), pgwc_value);

	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "0.0.0.0";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_mod_req->epdg_fqcsid), epdg_value);

	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "0.0.0.0";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_mod_req->twan_fqcsid), twan_value);
	*/

	 /*SP: Not in use*/
	 /*
		set_up_inactivity_timer(&(pfcp_sess_mod_req->user_plane_inact_timer));
	 */

	/*SP: This IE is included if QAURR flag is set (this flag is in PFCPSMReq-Flags IE) or Query URR IE is present,
	  Adding check to exclud  this IE if any of these condition is not satisfied*/
	if(pfcp_sess_mod_req->pfcpsmreq_flags.qaurr ||
			pfcp_sess_mod_req->query_urr_count){
		set_query_urr_refernce(&(pfcp_sess_mod_req->query_urr_ref));
	}

	if (upf_ctx->up_supp_features & UP_TRACE)
		set_trace_info(&(pfcp_sess_mod_req->trc_info));

}

void
sdf_pkt_filter_to_string(sdf_pkt_fltr *sdf_flow,
		char *sdf_str , uint8_t direction)
{
	char local_ip[INET_ADDRSTRLEN];
	char remote_ip[INET_ADDRSTRLEN];

	snprintf(local_ip, sizeof(local_ip), "%s",
			inet_ntoa(sdf_flow->local_ip_addr));
	snprintf(remote_ip, sizeof(remote_ip), "%s",
			inet_ntoa(sdf_flow->remote_ip_addr));

	if (direction == TFT_DIRECTION_DOWNLINK_ONLY) {
		snprintf(sdf_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
				PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
				" 0x%"PRIx8"/0x%"PRIx8"",
				local_ip, sdf_flow->local_ip_mask, remote_ip,
				sdf_flow->remote_ip_mask,
				(sdf_flow->local_port_low),
				(sdf_flow->local_port_high),
				(sdf_flow->remote_port_low),
				(sdf_flow->remote_port_high),
				sdf_flow->proto_id, sdf_flow->proto_mask);
	} else if (direction == TFT_DIRECTION_UPLINK_ONLY) {
		snprintf(sdf_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
				PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
				" 0x%"PRIx8"/0x%"PRIx8"",
				local_ip, sdf_flow->local_ip_mask, remote_ip,
				sdf_flow->remote_ip_mask,
				(sdf_flow->local_port_low),
				(sdf_flow->local_port_high),
				(sdf_flow->remote_port_low),
				(sdf_flow->remote_port_high),
				sdf_flow->proto_id, sdf_flow->proto_mask);
	}
}

void
fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		eps_bearer *bearer)
{
	pfcp_sess_mod_req->create_pdr_count = bearer->pdr_count;

	for(int i = 0; i < pfcp_sess_mod_req->create_pdr_count; i++) {
		pfcp_sess_mod_req->create_pdr[i].qer_id_count = 1;
		//pfcp_sess_mod_req->create_pdr[i].qer_id_count = bearer->qer_count;
		creating_pdr(&(pfcp_sess_mod_req->create_pdr[i]), bearer->pdrs[i]->pdi.src_intfc.interface_value);
		pfcp_sess_mod_req->create_far_count++;
		creating_far(&(pfcp_sess_mod_req->create_far[i]));
	}

	for(int itr = 0; itr < pfcp_sess_mod_req->create_pdr_count ; itr++) {
		pfcp_sess_mod_req->create_pdr[itr].pdr_id.rule_id  =
			bearer->pdrs[itr]->rule_id;
		pfcp_sess_mod_req->create_pdr[itr].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;
		pfcp_sess_mod_req->create_pdr[itr].precedence.prcdnc_val =
			bearer->pdrs[itr]->prcdnc_val;

		pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.teid =
			bearer->pdrs[itr]->pdi.local_fteid.teid;

		if((pfcp_config.cp_type == SGWC) ||
				(bearer->pdrs[itr]->pdi.src_intfc.interface_value ==
				SOURCE_INTERFACE_VALUE_ACCESS)) {
			/*No need to send ue ip and network instance for pgwc access interface or
			 * for any sgwc interface */
			uint32_t size_ie = 0;
			size_ie = pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t);
			size_ie = size_ie + pfcp_sess_mod_req->create_pdr[itr].pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->create_pdr[itr].pdi.header.len =
				pfcp_sess_mod_req->create_pdr[itr].pdi.header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].header.len =
				pfcp_sess_mod_req->create_pdr[itr].header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.header.len = 0;
			pfcp_sess_mod_req->create_pdr[itr].pdi.ntwk_inst.header.len = 0;
		}else{
			pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address =
				bearer->pdrs[itr]->pdi.ue_addr.ipv4_address;
			strncpy((char *)pfcp_sess_mod_req->create_pdr[itr].pdi.ntwk_inst.ntwk_inst,
				(char *)&bearer->pdrs[itr]->pdi.ntwk_inst.ntwk_inst, 32);
		}

		if (
				((PGWC == pfcp_config.cp_type) || (SAEGWC == pfcp_config.cp_type)) &&
				(SOURCE_INTERFACE_VALUE_CORE ==
				bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {

			uint32_t size_ie = 0;

			size_ie = pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->create_pdr[itr].pdi.header.len =
				pfcp_sess_mod_req->create_pdr[itr].pdi.header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].header.len =
				pfcp_sess_mod_req->create_pdr[itr].header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.header.len = 0;

		} else {
			pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.ipv4_address =
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
		}

		pfcp_sess_mod_req->create_pdr[itr].pdi.src_intfc.interface_value =
			bearer->pdrs[itr]->pdi.src_intfc.interface_value;

		pfcp_sess_mod_req->create_far[itr].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;

#ifdef GX_BUILD
		if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
			pfcp_sess_mod_req->create_pdr[itr].qer_id_count =
				bearer->pdrs[itr]->qer_id_count;
			for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_pdr[itr].qer_id_count; itr1++) {
				pfcp_sess_mod_req->create_pdr[itr].qer_id[itr1].qer_id_value =
					bearer->pdrs[itr]->qer_id[itr1].qer_id;
			}
		}
#endif

		if ((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) {
			pfcp_sess_mod_req->create_far[itr].apply_action.forw = PRESENT;
			if (pfcp_sess_mod_req->create_far[itr].apply_action.forw == PRESENT) {
				uint16_t len = 0;

				if (
						(SAEGWC == pfcp_config.cp_type) ||
						(SOURCE_INTERFACE_VALUE_ACCESS ==
						 bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {
					set_destination_interface(&(pfcp_sess_mod_req->create_far[itr].frwdng_parms.dst_intfc));
					pfcp_set_ie_header(&(pfcp_sess_mod_req->create_far[itr].frwdng_parms.header),
							IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

					pfcp_sess_mod_req->create_far[itr].frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

					len += sizeof(pfcp_dst_intfc_ie_t);
					len += UPD_PARAM_HEADER_SIZE;

					pfcp_sess_mod_req->create_far[itr].header.len += len;

					pfcp_sess_mod_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
						bearer->pdrs[itr]->far.dst_intfc.interface_value;
				} else {
					pfcp_sess_mod_req->create_far[itr].apply_action.forw = NO_FORW_ACTION;
				}
			}
		} else
		if ((SGWC == pfcp_config.cp_type) &&
			(DESTINATION_INTERFACE_VALUE_CORE ==
			 bearer->pdrs[itr]->far.dst_intfc.interface_value) &&
			(bearer->s5s8_pgw_gtpu_teid != 0) &&
			(bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0))
		{
			uint16_t len = 0;
			len += set_forwarding_param(&(pfcp_sess_mod_req->create_far[itr].frwdng_parms));
			/* Currently take as hardcoded value */
			len += UPD_PARAM_HEADER_SIZE;
			pfcp_sess_mod_req->create_far[itr].header.len += len;

			pfcp_sess_mod_req->create_far[itr].apply_action.forw = PRESENT;
			pfcp_sess_mod_req->create_far[itr].frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->pdrs[itr]->far.outer_hdr_creation.ipv4_address;
			pfcp_sess_mod_req->create_far[itr].frwdng_parms.outer_hdr_creation.teid =
					bearer->pdrs[itr]->far.outer_hdr_creation.teid;
			pfcp_sess_mod_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
					bearer->pdrs[itr]->far.dst_intfc.interface_value;
		}

	} /*for loop*/

#ifdef GX_BUILD
	if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
		pfcp_sess_mod_req->create_qer_count = bearer->qer_count;
		qer_t *qer_context = NULL;
		for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_qer_count ; itr1++) {
			creating_qer(&(pfcp_sess_mod_req->create_qer[itr1]));
			pfcp_sess_mod_req->create_qer[itr1].qer_id.qer_id_value  =
				bearer->qer_id[itr1].qer_id;
			qer_context = get_qer_entry(pfcp_sess_mod_req->create_qer[itr1].qer_id.qer_id_value);
			/* Assign the value from the PDR */
			if(qer_context){
				pfcp_sess_mod_req->create_qer[itr1].maximum_bitrate.ul_mbr  =
					qer_context->max_bitrate.ul_mbr;
				pfcp_sess_mod_req->create_qer[itr1].maximum_bitrate.dl_mbr  =
					qer_context->max_bitrate.dl_mbr;
				pfcp_sess_mod_req->create_qer[itr1].guaranteed_bitrate.ul_gbr  =
					qer_context->guaranteed_bitrate.ul_gbr;
				pfcp_sess_mod_req->create_qer[itr1].guaranteed_bitrate.dl_gbr  =
					qer_context->guaranteed_bitrate.dl_gbr;
			}
		}

		for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_pdr_count ; itr1++) {
			fill_sdf_rules_modification(pfcp_sess_mod_req, bearer, itr1);
		}
	}
#endif /* GX_BUILD */

}

void fill_gate_status(pfcp_sess_estab_req_t *pfcp_sess_est_req,
	int qer_counter,
	enum flow_status f_status)
{
	switch(f_status)
	{
		case FL_ENABLED_UPLINK:
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_OPEN;
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_CLOSED;
			break;

		case FL_ENABLED_DOWNLINK:
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_CLOSED;
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_OPEN;
			break;

		case FL_ENABLED:
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_OPEN;
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_OPEN;
			break;

		case FL_DISABLED:
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_CLOSED;
			pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_CLOSED;
			break;
		case FL_REMOVED:
			/*TODO*/
			break;
	}
}

void sdf_pkt_filter_add(pfcp_sess_estab_req_t* pfcp_sess_est_req,
		dynamic_rule_t *dynamic_rules,
		int pdr_counter,
		int sdf_filter_count,
		int flow_cnt,
		uint8_t direction)
{
	int len = 0;
	pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].fd = 1;
	sdf_pkt_filter_to_string(&(dynamic_rules->flow_desc[flow_cnt].sdf_flw_desc),
			(char*)(pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc), direction);

	pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc =
		strlen((char*)(&pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc));

	len += FLAG_LEN;
	len += sizeof(uint16_t);
	len += pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc;

	pfcp_set_ie_header(
			&(pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

	/*VG updated the header len of pdi as sdf rules has been added*/
	pfcp_sess_est_req->create_pdr[pdr_counter].pdi.header.len += (len + sizeof(pfcp_ie_header_t));
	pfcp_sess_est_req->create_pdr[pdr_counter].header.len += (len + sizeof(pfcp_ie_header_t));
}

void sdf_pkt_filter_mod(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
		eps_bearer* bearer,
		int pdr_counter,
		int sdf_filter_count,
		int dynamic_filter_cnt,
		int flow_cnt,
		uint8_t direction)
{
	int len = 0;
	pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].fd = 1;
	sdf_pkt_filter_to_string(&(bearer->dynamic_rules[dynamic_filter_cnt]->flow_desc[flow_cnt].sdf_flw_desc),
			(char*)(pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc), direction);

	pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc =
		strlen((char*)(&pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc));

	len += FLAG_LEN;
	len += sizeof(uint16_t);
	len += pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc;

	pfcp_set_ie_header(
			&(pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

	/*VG updated the header len of pdi as sdf rules has been added*/
	pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.header.len += (len + sizeof(pfcp_ie_header_t));
	pfcp_sess_mod_req->create_pdr[pdr_counter].header.len += (len + sizeof(pfcp_ie_header_t));
}
void sdf_pkt_filter_gx_mod(pfcp_create_pdr_ie_t *pdr, dynamic_rule_t *dyn_rule, int sdf_filter_count, int flow_cnt, uint8_t direction)
{
	int len = 0;
	pdr->pdi.sdf_filter[sdf_filter_count].fd = 1;
	sdf_pkt_filter_to_string(&(dyn_rule->flow_desc[flow_cnt].sdf_flw_desc),
			(char*)(pdr->pdi.sdf_filter[sdf_filter_count].flow_desc), direction);

	pdr->pdi.sdf_filter[sdf_filter_count].len_of_flow_desc =
		strlen((char*)(&pdr->pdi.sdf_filter[sdf_filter_count].flow_desc));

	len += FLAG_LEN;
	len += sizeof(uint16_t);
	len += pdr->pdi.sdf_filter[sdf_filter_count].len_of_flow_desc;

	pfcp_set_ie_header(
			&(pdr->pdi.sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

	/*VG updated the header len of pdi as sdf rules has been added*/
	pdr->pdi.header.len += (len + sizeof(pfcp_ie_header_t));
	pdr->header.len += (len + sizeof(pfcp_ie_header_t));
}
int fill_sdf_rules_modification(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
	eps_bearer* bearer,
	int pdr_counter)
{
	int ret = 0;
	int sdf_filter_count = 0;
	/*VG convert pkt_filter_strucutre to char string*/
	for(int index = 0; index < bearer->num_dynamic_filters; index++) {

		pfcp_sess_mod_req->create_pdr[pdr_counter].precedence.prcdnc_val = bearer->dynamic_rules[index]->precedence;
		// itr is for flow information counter
		// sdf_filter_count is for SDF information counter
		for(int itr = 0; itr < bearer->dynamic_rules[index]->num_flw_desc; itr++) {

			if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {

				if((pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

					sdf_pkt_filter_mod(
							pfcp_sess_mod_req, bearer, pdr_counter, sdf_filter_count, index, itr, TFT_DIRECTION_UPLINK_ONLY);
					sdf_filter_count++;
				}

			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {
				if((pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					sdf_pkt_filter_mod(
							pfcp_sess_mod_req, bearer, pdr_counter, sdf_filter_count, index, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					sdf_filter_count++;
				}
			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}
		}

		pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

	}
	return ret;
}

int fill_sdf_rules(pfcp_sess_estab_req_t* pfcp_sess_est_req,
	dynamic_rule_t *dynamic_rules,
	int pdr_counter)
{
	int ret = 0;
	int sdf_filter_count = 0;
	/*VG convert pkt_filter_strucutre to char string*/

		pfcp_sess_est_req->create_pdr[pdr_counter].precedence.prcdnc_val = dynamic_rules->precedence;
		// itr is for flow information counter
		// sdf_filter_count is for SDF information counter
	for(int itr = 0; itr < dynamic_rules->num_flw_desc; itr++) {

			if(dynamic_rules->flow_desc[itr].sdf_flow_description != NULL) {

				if((pfcp_sess_est_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

					sdf_pkt_filter_add(
							pfcp_sess_est_req, dynamic_rules, pdr_counter, sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
					sdf_filter_count++;
				}

			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(dynamic_rules->flow_desc[itr].sdf_flow_description != NULL) {
				if((pfcp_sess_est_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					sdf_pkt_filter_add(
							pfcp_sess_est_req, dynamic_rules, pdr_counter, sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					sdf_filter_count++;
				}
			} else {
				clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}
		}

		pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

	return ret;
}

int
fill_qer_entry(pdn_connection *pdn, eps_bearer *bearer, uint8_t itr)
{
	int ret = -1;
	qer_t *qer_ctxt = NULL;
	qer_ctxt = rte_zmalloc_socket(NULL, sizeof(qer_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (qer_ctxt == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return ret;
	}
	qer_ctxt->qer_id = bearer->qer_id[itr].qer_id;;
	qer_ctxt->session_id = pdn->seid;
	qer_ctxt->max_bitrate.ul_mbr = bearer->qos.ul_mbr;
	qer_ctxt->max_bitrate.dl_mbr = bearer->qos.dl_mbr;
	qer_ctxt->guaranteed_bitrate.ul_gbr = bearer->qos.ul_gbr;
	qer_ctxt->guaranteed_bitrate.dl_gbr = bearer->qos.dl_gbr;

	ret = add_qer_entry(qer_ctxt->qer_id,qer_ctxt);
	if(ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
				__func__, __LINE__, ret);
		return ret;
	}

	return ret;
}

static int
add_qer_into_hash(qer_t *qer)
{
	int ret = -1;
	qer_t *qer_ctxt = NULL;
	qer_ctxt = rte_zmalloc_socket(NULL, sizeof(qer_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (qer_ctxt == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return ret;
	}

	qer_ctxt->qer_id = qer->qer_id;
	qer_ctxt->session_id = qer->session_id;
	qer_ctxt->max_bitrate.ul_mbr = qer->max_bitrate.ul_mbr;
	qer_ctxt->max_bitrate.dl_mbr = qer->max_bitrate.dl_mbr;
	qer_ctxt->guaranteed_bitrate.ul_gbr = qer->guaranteed_bitrate.ul_gbr;
	qer_ctxt->guaranteed_bitrate.dl_gbr = qer-> guaranteed_bitrate.dl_gbr;

	ret = add_qer_entry(qer_ctxt->qer_id, qer_ctxt);

	if(ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
				__func__, __LINE__, ret);
		return ret;
	}


	return ret;
}

int fill_pfcp_entry(eps_bearer *bearer, dynamic_rule_t *dyn_rule,
		enum rule_action_t rule_action)
{
	/*
	 * For ever PCC rule create 2 PDR and 2 QER and 2 FAR
	 * all these struture should be created and filled here
	 * also store its reference in rule itself
	 * May be pdr arrary in bearer not needed
	 */
	char mnc[4] = {0};
	char mcc[4] = {0};
	char nwinst[32] = {0};
	ue_context *context = bearer->pdn->context;
	pdn_connection *pdn = bearer->pdn;
	pdr_t *pdr_ctxt = NULL;
	int ret;
	uint16_t flow_len = 0;

	if (context->serving_nw.mnc_digit_3 == 15) {
		sprintf(mnc, "0%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2);
	} else {
		sprintf(mnc, "%u%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2,
				context->serving_nw.mnc_digit_3);
	}

	sprintf(mcc, "%u%u%u", context->serving_nw.mcc_digit_1,
			context->serving_nw.mcc_digit_2,
			context->serving_nw.mcc_digit_3);

	sprintf(nwinst, "mnc%s.mcc%s", mnc, mcc);

	for(int i =0; i < 2; i++)
	{

		pdr_ctxt = rte_zmalloc_socket(NULL, sizeof(pdr_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (pdr_ctxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return -1;
		}
		memset(pdr_ctxt,0,sizeof(pdr_t));

		pdr_ctxt->rule_id =  generate_pdr_id();
		pdr_ctxt->prcdnc_val =  dyn_rule->precedence;
		pdr_ctxt->far.far_id_value = generate_far_id();
		pdr_ctxt->session_id = pdn->seid;
		/*to be filled in fill_sdf_rule*/
		pdr_ctxt->pdi.sdf_filter_cnt = 0;
		dyn_rule->pdr[i] = pdr_ctxt;
		for(int itr = 0; itr < dyn_rule->num_flw_desc; itr++)
		{
			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL)
			{
				flow_len = dyn_rule->flow_desc[itr].flow_desc_len;
				memcpy(&(pdr_ctxt->pdi.sdf_filter[pdr_ctxt->pdi.sdf_filter_cnt].flow_desc),
						&(dyn_rule->flow_desc[itr].sdf_flow_description),
						flow_len);
				pdr_ctxt->pdi.sdf_filter[pdr_ctxt->pdi.sdf_filter_cnt].len_of_flow_desc = flow_len;
				pdr_ctxt->pdi.sdf_filter_cnt++;
			}
		}

		if (i == SOURCE_INTERFACE_VALUE_ACCESS) {

			if (pfcp_config.cp_type == PGWC) {
				pdr_ctxt->pdi.local_fteid.teid = bearer->s5s8_pgw_gtpu_teid;
				pdr_ctxt->pdi.local_fteid.ipv4_address =
						bearer->s5s8_pgw_gtpu_ipv4.s_addr;
			} else {
				pdr_ctxt->pdi.local_fteid.teid = bearer->s1u_sgw_gtpu_teid;
				pdr_ctxt->pdi.local_fteid.ipv4_address =
						bearer->s1u_sgw_gtpu_ipv4.s_addr;
			}
			pdr_ctxt->far.actions.forw = 0;

			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		}
		else
		{
			pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;
			pdr_ctxt->pdi.local_fteid.teid = 0;
			pdr_ctxt->pdi.local_fteid.ipv4_address = 0;
			pdr_ctxt->far.actions.forw = 0;
			if(pfcp_config.cp_type == PGWC)
			{
				pdr_ctxt->far.outer_hdr_creation.ipv4_address =
					bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				pdr_ctxt->far.outer_hdr_creation.teid =
					bearer->s5s8_sgw_gtpu_teid;
				pdr_ctxt->far.dst_intfc.interface_value =
					DESTINATION_INTERFACE_VALUE_ACCESS;
			}
		}

		if(rule_action == RULE_ACTION_ADD)
		{
			bearer->pdrs[bearer->pdr_count++] = pdr_ctxt;
		}

		ret = add_pdr_entry(pdr_ctxt->rule_id, pdr_ctxt);
		if ( ret != 0) {
			clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding pdr entry Error: %d \n", __file__,
					__func__, __LINE__, ret);
			return -1;
		}

		pdr_ctxt->pdi.src_intfc.interface_value = i;
		strncpy((char * )pdr_ctxt->pdi.ntwk_inst.ntwk_inst, (char *)nwinst, 32);
		pdr_ctxt->qer.qer_id = bearer->qer_id[i].qer_id;
		pdr_ctxt->qer_id[0].qer_id = pdr_ctxt->qer.qer_id;
		pdr_ctxt->qer.session_id = pdn->seid;
		pdr_ctxt->qer.max_bitrate.ul_mbr = dyn_rule->qos.ul_mbr;
		pdr_ctxt->qer.max_bitrate.dl_mbr = dyn_rule->qos.dl_mbr;
		pdr_ctxt->qer.guaranteed_bitrate.ul_gbr = dyn_rule->qos.ul_gbr;
		pdr_ctxt->qer.guaranteed_bitrate.dl_gbr = dyn_rule->qos.dl_gbr;

		ret = add_qer_into_hash(&pdr_ctxt->qer);

		if(ret != 0) {
			clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
					__func__, __LINE__, ret);
			return ret;
		}
		enum flow_status f_status = dyn_rule->flow_status;
		switch(f_status)
		{
			case FL_ENABLED_UPLINK:
				pdr_ctxt->qer.gate_status.ul_gate  = UL_GATE_OPEN;
				pdr_ctxt->qer.gate_status.dl_gate  = UL_GATE_CLOSED;
				break;

			case FL_ENABLED_DOWNLINK:
				pdr_ctxt->qer.gate_status.ul_gate  = UL_GATE_CLOSED;
				pdr_ctxt->qer.gate_status.dl_gate  = UL_GATE_OPEN;
				break;

			case FL_ENABLED:
				pdr_ctxt->qer.gate_status.ul_gate  = UL_GATE_OPEN;
				pdr_ctxt->qer.gate_status.dl_gate  = UL_GATE_OPEN;
				break;

			case FL_DISABLED:
				pdr_ctxt->qer.gate_status.ul_gate  = UL_GATE_CLOSED;
				pdr_ctxt->qer.gate_status.dl_gate  = UL_GATE_CLOSED;
				break;
			case FL_REMOVED:
				/*TODO*/
				break;
		}
	}
	return 0;
}

pdr_t *
fill_pdr_entry(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, uint8_t iface, uint8_t itr)
{
	char mnc[4] = {0};
	char mcc[4] = {0};
	char nwinst[32] = {0};
	pdr_t *pdr_ctxt = NULL;
	int ret;

	if (context->serving_nw.mnc_digit_3 == 15) {
		sprintf(mnc, "0%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2);
	} else {
		sprintf(mnc, "%u%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2,
				context->serving_nw.mnc_digit_3);
	}

	sprintf(mcc, "%u%u%u", context->serving_nw.mcc_digit_1,
			context->serving_nw.mcc_digit_2,
			context->serving_nw.mcc_digit_3);

	sprintf(nwinst, "mnc%s.mcc%s", mnc, mcc);

	pdr_ctxt = rte_zmalloc_socket(NULL, sizeof(pdr_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (pdr_ctxt == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return NULL;
	}
	memset(pdr_ctxt,0,sizeof(pdr_t));

	pdr_ctxt->rule_id =  generate_pdr_id();
	pdr_ctxt->prcdnc_val =  1;
	pdr_ctxt->far.far_id_value = generate_far_id();
	pdr_ctxt->session_id = pdn->seid;
	/*to be filled in fill_sdf_rule*/
	pdr_ctxt->pdi.sdf_filter_cnt = 0;
	pdr_ctxt->pdi.src_intfc.interface_value = iface;
	strncpy((char * )pdr_ctxt->pdi.ntwk_inst.ntwk_inst, (char *)nwinst, 32);

	/* TODO: NS Add this changes after DP related changes of VS
	 * if(pfcp_config.cp_type != SGWC){
	 * pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;
	 * }
	 */

#ifdef GX_BUILD
	if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
		/* TODO Hardcode 1 set because one PDR contain only 1 QER entry
		 * Revist again in case of multiple rule support
		 */
		pdr_ctxt->qer_id_count = 1;

		if(iface == SOURCE_INTERFACE_VALUE_ACCESS) {
				pdr_ctxt->qer_id[0].qer_id = bearer->qer_id[QER_INDEX_FOR_ACCESS_INTERFACE].qer_id;
		} else if(iface == SOURCE_INTERFACE_VALUE_CORE)
		{
			pdr_ctxt->qer_id[0].qer_id = bearer->qer_id[QER_INDEX_FOR_CORE_INTERFACE].qer_id;
		}
	}
#endif

	pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;

	if (iface == SOURCE_INTERFACE_VALUE_ACCESS) {
		pdr_ctxt->pdi.local_fteid.teid = bearer->s1u_sgw_gtpu_teid;
		pdr_ctxt->pdi.local_fteid.ipv4_address = 0;

		if ((SGWC == pfcp_config.cp_type) &&
				(bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0) &&
				(bearer->s5s8_pgw_gtpu_teid != 0)) {
			pdr_ctxt->far.actions.forw = 2;
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
			pdr_ctxt->far.outer_hdr_creation.ipv4_address =
				bearer->s5s8_pgw_gtpu_ipv4.s_addr;
			pdr_ctxt->far.outer_hdr_creation.teid =
				bearer->s5s8_pgw_gtpu_teid;
		} else {
			pdr_ctxt->far.actions.forw = 0;
		}

		if ((pfcp_config.cp_type == PGWC) ||
				(SAEGWC == pfcp_config.cp_type)) {
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		}
	} else{
		if(pfcp_config.cp_type == SGWC){
			pdr_ctxt->pdi.local_fteid.teid = (bearer->s5s8_sgw_gtpu_teid);
			pdr_ctxt->pdi.local_fteid.ipv4_address = 0;
		}else{
			pdr_ctxt->pdi.local_fteid.teid = 0;
			pdr_ctxt->pdi.local_fteid.ipv4_address = 0;
			pdr_ctxt->far.actions.forw = 0;
			if(pfcp_config.cp_type == PGWC){
				pdr_ctxt->far.outer_hdr_creation.ipv4_address =
					bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				pdr_ctxt->far.outer_hdr_creation.teid =
					bearer->s5s8_sgw_gtpu_teid;
				pdr_ctxt->far.dst_intfc.interface_value =
					DESTINATION_INTERFACE_VALUE_ACCESS;
			}
		}
	}

	bearer->pdrs[itr] = pdr_ctxt;
	ret = add_pdr_entry(bearer->pdrs[itr]->rule_id, bearer->pdrs[itr]);
	if ( ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding pdr entry Error: %d \n", __file__,
				__func__, __LINE__, ret);
		return NULL;
	}
	return pdr_ctxt;
}

eps_bearer* get_default_bearer(pdn_connection *pdn)
{
	return pdn->eps_bearers[pdn->default_bearer_id - 5];

}

eps_bearer* get_bearer(pdn_connection *pdn, bearer_qos_ie *qos)
{
	eps_bearer *bearer = NULL;
	for(uint8_t idx = 0; idx < MAX_BEARERS; idx++)
	{
		bearer = pdn->eps_bearers[idx];
		if(bearer != NULL)
		{
			/* Comparing each member in arp */
			if((bearer->qos.qci == qos->qci) &&
				(bearer->qos.arp.preemption_vulnerability == qos->arp.preemption_vulnerability) &&
				(bearer->qos.arp.priority_level == qos->arp.priority_level) &&
				(bearer->qos.arp.preemption_capability == qos->arp.preemption_capability))
			{
				return bearer;
			}
		}

	}
	return NULL;
}

int8_t
compare_default_bearer_qos(bearer_qos_ie *default_bearer_qos,
					 bearer_qos_ie *rule_qos)
{
	if(default_bearer_qos->qci != rule_qos->qci)
		return -1;

	if(default_bearer_qos->arp.preemption_vulnerability != rule_qos->arp.preemption_vulnerability)
		return -1;

	if(default_bearer_qos->arp.priority_level != rule_qos->arp.priority_level)
		return -1;

	if(default_bearer_qos->arp.preemption_vulnerability != rule_qos->arp.preemption_vulnerability)
		return -1;

	return 0;

}

void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		pdn_connection *pdn, uint32_t seq)
{
	/*TODO :generate seid value and store this in array
	  to send response from cp/dp , first check seid is there in array or not if yes then
	  fill that seid in response and if not then seid =0 */

	int ret = 0;
	uint8_t bearer_id = 0;
	eps_bearer *bearer = NULL;
	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return;
	}

	memset(pfcp_sess_est_req,0,sizeof(pfcp_sess_estab_req_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req->header), PFCP_SESSION_ESTABLISHMENT_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_est_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(pAddr);

	set_node_id(&(pfcp_sess_est_req->node_id), node_value);

	set_fseid(&(pfcp_sess_est_req->cp_fseid), pdn->seid, node_value);

	if ((pfcp_config.cp_type == PGWC) ||
		(SAEGWC == pfcp_config.cp_type))
	{
		pfcp_sess_est_req->create_pdr_count = pdn->policy.num_charg_rule_install * 2;
		/*
		 * For pgw create pdf, far and qer while handling pfcp messages
		 */

		for (int idx=0; idx <  pdn->policy.num_charg_rule_install; idx++)
		{
			bearer = NULL;
			if(compare_default_bearer_qos(&pdn->policy.default_bearer_qos, &pdn->policy.pcc_rule[idx].dyn_rule.qos) == 0)
			{
				/*
				 * This means this Dynamic rule going to install in default bearer
				 */

				bearer = get_default_bearer(pdn);
			}
			else
			{
				/*
				 * dedicated bearer
				 */
				bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].dyn_rule.qos);
				if(bearer == NULL)
				{
					/*
					 * create dedicated bearer
					 */
					bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
					if(bearer == NULL)
					{
						clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate bearer "
								"structure: %s (%s:%d)\n",
								rte_strerror(rte_errno),
								 __FILE__,
								  __LINE__);
						return;
						/* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
					}
					bzero(bearer,  sizeof(eps_bearer));
					bearer->pdn = pdn;
					bearer_id = get_new_bearer_id(pdn);
					pdn->eps_bearers[bearer_id] = bearer;
					pdn->context->eps_bearers[bearer_id] = bearer;
					pdn->num_bearer++;
					set_s5s8_pgw_gtpu_teid_using_pdn(bearer, pdn);
					fill_dedicated_bearer_info(bearer, pdn->context, pdn);
					memcpy(&(bearer->qos), &(pdn->policy.pcc_rule[idx].dyn_rule.qos), sizeof(bearer_qos_ie));

				}

			}

			if (pfcp_config.cp_type == SGWC) {
				set_s1u_sgw_gtpu_teid(bearer, bearer->pdn->context);
				update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, bearer->s1u_sgw_gtpu_ipv4.s_addr, SOURCE_INTERFACE_VALUE_ACCESS);
				set_s5s8_sgw_gtpu_teid(bearer, bearer->pdn->context);
				update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, bearer->s5s8_sgw_gtpu_ipv4.s_addr, SOURCE_INTERFACE_VALUE_CORE);
			} else if (pfcp_config.cp_type == SAEGWC) {
				set_s1u_sgw_gtpu_teid(bearer, bearer->pdn->context);
				update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, bearer->s1u_sgw_gtpu_ipv4.s_addr, SOURCE_INTERFACE_VALUE_ACCESS);
			} else if (pfcp_config.cp_type == PGWC){
				set_s5s8_pgw_gtpu_teid(bearer, bearer->pdn->context);
				update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, bearer->s5s8_pgw_gtpu_ipv4.s_addr, SOURCE_INTERFACE_VALUE_ACCESS);
			}

			bearer->dynamic_rules[bearer->num_dynamic_filters] = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (bearer->dynamic_rules[bearer->num_dynamic_filters] == NULL)
			{
				clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate dynamic rule memory "
						"structure: %s (%s:%d)\n",
						rte_strerror(rte_errno),
						__FILE__,
						__LINE__);
				return;
				/* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
			}
			memcpy( (bearer->dynamic_rules[bearer->num_dynamic_filters]),
					&(pdn->policy.pcc_rule[idx].dyn_rule),
					sizeof(dynamic_rule_t));
			// Create 2 PDRs and 2 QERsfor every rule

			bearer->dynamic_rules[bearer->num_dynamic_filters]->pdr[0] = fill_pdr_entry(pdn->context, pdn, bearer, SOURCE_INTERFACE_VALUE_ACCESS, bearer->pdr_count++);
			bearer->qer_id[bearer->qer_count].qer_id = generate_qer_id();
			fill_qer_entry(pdn, bearer, bearer->qer_count++);

			enum flow_status f_status = bearer->dynamic_rules[bearer->num_dynamic_filters]->flow_status; // consider dynamic rule is 1 only /*TODO*/
			// assuming no of qer and pdr is same /*TODO*/
			fill_gate_status(pfcp_sess_est_req, bearer->qer_count, f_status);

			bearer->dynamic_rules[bearer->num_dynamic_filters]->pdr[1] = fill_pdr_entry(pdn->context, pdn, bearer, SOURCE_INTERFACE_VALUE_CORE, bearer->pdr_count++);
			bearer->qer_id[bearer->qer_count].qer_id = generate_qer_id();
			fill_qer_entry(pdn, bearer, bearer->qer_count++);

			f_status = bearer->dynamic_rules[bearer->num_dynamic_filters]->flow_status; // consider dynamic rule is 1 only /*TODO*/
			// assuming no of qer and pdr is same /*TODO*/
			fill_gate_status(pfcp_sess_est_req, bearer->qer_count, f_status);
			bearer->num_dynamic_filters++;
		}

		if (pfcp_config.cp_type == SAEGWC) {
			update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid,
					upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
		} else if (pfcp_config.cp_type == PGWC) {
			update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid,
					upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);
		}
	} else {
		bearer = get_default_bearer(pdn);
		pfcp_sess_est_req->create_pdr_count = bearer->pdr_count;

		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
		update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);
	}

	{
		uint8_t pdr_idx =0;
		for(uint8_t i = 0; i < MAX_BEARERS; i++)
		{
			bearer = pdn->eps_bearers[i];
			if(bearer != NULL)
			{
				for(uint8_t idx = 0; idx < bearer->pdr_count; idx++)
				{
					pfcp_sess_est_req->create_pdr[pdr_idx].qer_id_count = 1;
					creating_pdr(&(pfcp_sess_est_req->create_pdr[pdr_idx]), bearer->pdrs[idx]->pdi.src_intfc.interface_value);
					pfcp_sess_est_req->create_far_count++;
					creating_far(&(pfcp_sess_est_req->create_far[pdr_idx]));
					pdr_idx++;
				}
			}
		}
	}

	/* SGW Relocation Case*/
	/*SP: Need to think of this*/
	//if(context->indication_flag.oi != 0) {
	//pfcp_sess_est_req->create_far_count = 2;
	//}

	{
		uint8_t pdr_idx =0;
		for(uint8_t i = 0; i < MAX_BEARERS; i++)
		{
			bearer = pdn->eps_bearers[i];
			if(bearer != NULL)
			{
				for(uint8_t idx = 0; idx < MAX_PDR_PER_RULE; idx++)
				{
					pfcp_sess_est_req->create_pdr[pdr_idx].pdr_id.rule_id  =
						bearer->pdrs[idx]->rule_id;
					pfcp_sess_est_req->create_pdr[pdr_idx].precedence.prcdnc_val =
						bearer->pdrs[idx]->prcdnc_val;

					if(((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) &&
							(bearer->pdrs[idx]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE))
					{
						uint32_t size_teid = 0;
						size_teid = pfcp_sess_est_req->create_pdr[pdr_idx].pdi.local_fteid.header.len +
							sizeof(pfcp_ie_header_t);
						// TODO : check twice reduce teid size needed ?
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.header.len =
							pfcp_sess_est_req->create_pdr[pdr_idx].pdi.header.len - size_teid;
						pfcp_sess_est_req->create_pdr[pdr_idx].header.len =
							pfcp_sess_est_req->create_pdr[pdr_idx].header.len - size_teid;
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.local_fteid.header.len = 0;

					}
					else
					{
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.local_fteid.teid =
							bearer->pdrs[idx]->pdi.local_fteid.teid;
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.local_fteid.ipv4_address =
							bearer->pdrs[idx]->pdi.local_fteid.ipv4_address;
					}
					if((pfcp_config.cp_type == SGWC) ||
							(bearer->pdrs[idx]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS)){
						/*No need to send ue ip and network instance for pgwc access interface or
						 * for any sgwc interface */
						uint32_t size_ie = 0;
						size_ie = pfcp_sess_est_req->create_pdr[pdr_idx].pdi.ue_ip_address.header.len +
							sizeof(pfcp_ie_header_t);
						size_ie = size_ie + pfcp_sess_est_req->create_pdr[pdr_idx].pdi.ntwk_inst.header.len +
							sizeof(pfcp_ie_header_t);
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.header.len =
							pfcp_sess_est_req->create_pdr[pdr_idx].pdi.header.len - size_ie;
						pfcp_sess_est_req->create_pdr[pdr_idx].header.len =
							pfcp_sess_est_req->create_pdr[pdr_idx].header.len - size_ie;
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.ue_ip_address.header.len = 0;
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.ntwk_inst.header.len = 0;
					}else{
						pfcp_sess_est_req->create_pdr[pdr_idx].pdi.ue_ip_address.ipv4_address =
							bearer->pdrs[idx]->pdi.ue_addr.ipv4_address;
						strncpy((char *)pfcp_sess_est_req->create_pdr[pdr_idx].pdi.ntwk_inst.ntwk_inst,
								(char *)&bearer->pdrs[idx]->pdi.ntwk_inst.ntwk_inst, 32);
					}

					pfcp_sess_est_req->create_pdr[pdr_idx].pdi.src_intfc.interface_value =
						bearer->pdrs[idx]->pdi.src_intfc.interface_value;

					pfcp_sess_est_req->create_far[pdr_idx].far_id.far_id_value =
						bearer->pdrs[idx]->far.far_id_value;
					 pfcp_sess_est_req->create_pdr[pdr_idx].far_id.far_id_value =
						 bearer->pdrs[idx]->far.far_id_value;

					/* SGW Relocation*/
					if(pdn->context->indication_flag.oi != 0) {
						uint8_t len  = 0;
						//if(itr == 1)
						//TODO :: Betting on stars allignments to make below code works
						if(pdr_idx%2)
						{
							pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
							len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms));
							len += UPD_PARAM_HEADER_SIZE;
							pfcp_sess_est_req->create_far[pdr_idx].header.len += len;

							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.ipv4_address =
								bearer->s1u_enb_gtpu_ipv4.s_addr;

							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.teid =
								bearer->s1u_enb_gtpu_teid;
							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc.interface_value =
								DESTINATION_INTERFACE_VALUE_ACCESS;

						}
						//else if(itr == 0)
					    else
						{
							pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
							len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms));
							len += UPD_PARAM_HEADER_SIZE;
							pfcp_sess_est_req->create_far[pdr_idx].header.len += len;

							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.ipv4_address =
								bearer->s5s8_pgw_gtpu_ipv4.s_addr;
							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.teid =
								bearer->s5s8_pgw_gtpu_teid;
							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc.interface_value =
								DESTINATION_INTERFACE_VALUE_CORE;
						}
					}
#ifdef GX_BUILD
					if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
						pfcp_sess_est_req->create_pdr[pdr_idx].qer_id_count =
							bearer->pdrs[idx]->qer_id_count;
						for(int itr1 = 0; itr1 < bearer->pdrs[idx]->qer_id_count; itr1++) {
							pfcp_sess_est_req->create_pdr[pdr_idx].qer_id[itr1].qer_id_value =
								//bearer->pdrs[idx]->qer_id[itr1].qer_id;
								bearer->qer_id[idx].qer_id;
						}
					}
#endif

					if ((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) {
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
						if (pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw == PRESENT) {
							uint16_t len = 0;

							if ((SAEGWC == pfcp_config.cp_type) ||
									(SOURCE_INTERFACE_VALUE_ACCESS == bearer->pdrs[idx]->pdi.src_intfc.interface_value)) {
								set_destination_interface(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc));
								pfcp_set_ie_header(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.header),
										IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

								len += sizeof(pfcp_dst_intfc_ie_t);
								len += UPD_PARAM_HEADER_SIZE;

								pfcp_sess_est_req->create_far[pdr_idx].header.len += len;
								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc.interface_value =
									bearer->pdrs[pdr_idx]->far.dst_intfc.interface_value;
							} else {
								len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms));
								/* Currently take as hardcoded value */
								len += UPD_PARAM_HEADER_SIZE;
								pfcp_sess_est_req->create_far[pdr_idx].header.len += len;

								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.ipv4_address =
									bearer->pdrs[pdr_idx]->far.outer_hdr_creation.ipv4_address;
								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.teid =
									bearer->pdrs[pdr_idx]->far.outer_hdr_creation.teid;
								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc.interface_value =
									bearer->pdrs[pdr_idx]->far.dst_intfc.interface_value;
							}
						}
					}

					pdr_idx++;
				}
			}
		}
	} /*for loop*/

#ifdef GX_BUILD
	{
		uint8_t qer_idx = 0;
		qer_t *qer_context;
		if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC)
		{
			for(uint8_t i = 0; i < MAX_BEARERS; i++)
			{
				bearer = pdn->eps_bearers[i];
				if(bearer != NULL)
				{
					pfcp_sess_est_req->create_qer_count += bearer->qer_count;
						for(uint8_t idx = 0; idx < bearer->qer_count; idx++)
						{
							creating_qer(&(pfcp_sess_est_req->create_qer[qer_idx]));
							pfcp_sess_est_req->create_qer[qer_idx].qer_id.qer_id_value  =
								bearer->qer_id[qer_idx].qer_id;
							qer_context = get_qer_entry(pfcp_sess_est_req->create_qer[qer_idx].qer_id.qer_id_value);
							qer_idx++;
							/* Assign the value from the PDR */
							if(qer_context){
								//pfcp_sess_est_req->create_pdr[qer_idx].qer_id[0].qer_id_value =
								//	pfcp_sess_est_req->create_qer[qer_idx].qer_id.qer_id_value;
								pfcp_sess_est_req->create_qer[qer_idx].maximum_bitrate.ul_mbr  =
									qer_context->max_bitrate.ul_mbr;
								pfcp_sess_est_req->create_qer[qer_idx].maximum_bitrate.dl_mbr  =
									qer_context->max_bitrate.dl_mbr;
								pfcp_sess_est_req->create_qer[qer_idx].guaranteed_bitrate.ul_gbr  =
									qer_context->guaranteed_bitrate.ul_gbr;
								pfcp_sess_est_req->create_qer[qer_idx].guaranteed_bitrate.dl_gbr  =
									qer_context->guaranteed_bitrate.dl_gbr;
							}
						}
				}
			}
		}
	}

		uint8_t pdr_idx = 0;
		for(int itr1 = 0; itr1 <  pdn->policy.num_charg_rule_install; itr1++) {
			/*
			 * call fill_sdf_rules twice because one rule create 2 PDRs
			 */
			enum flow_status f_status = pdn->policy.pcc_rule[itr1].dyn_rule.flow_status;

			fill_sdf_rules(pfcp_sess_est_req, &pdn->policy.pcc_rule[itr1].dyn_rule, pdr_idx);
			fill_gate_status(pfcp_sess_est_req, pdr_idx, f_status);
			pdr_idx++;

			fill_sdf_rules(pfcp_sess_est_req, &pdn->policy.pcc_rule[itr1].dyn_rule, pdr_idx);
			fill_gate_status(pfcp_sess_est_req, pdr_idx, f_status);
			pdr_idx++;

		}

#endif /* GX_BUILD */

	/* VS: Set the pdn connection type */
	set_pdn_type(&(pfcp_sess_est_req->pdn_type), &(pdn->pdn_type));

#if 0
	creating_bar(&(pfcp_sess_est_req->create_bar));

	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_est_req->sgw_c_fqcsid), sgwc_value);

	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_est_req->mme_fqcsid), mme_value);

	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_est_req->pgw_c_fqcsid), pgwc_value);

	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "0.0.0.0";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_est_req->epdg_fqcsid), epdg_value);

	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "0.0.0.0";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_est_req->twan_fqcsid), twan_value);

	set_up_inactivity_timer(&(pfcp_sess_est_req->user_plane_inact_timer));

	set_user_id(&(pfcp_sess_est_req->user_id));
#endif

	if (upf_ctx->up_supp_features & UP_TRACE)
		set_trace_info(&(pfcp_sess_est_req->trc_info));

}

/**
 * @brief  : Fill ULI information into UE context from CSR
 * @param  : uli is pointer to structure to store uli info
 * @param  : context is a pointer to ue context structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_uli_info(gtp_user_loc_info_ie_t *uli, ue_context *context)
{
	if (uli->lai) {
		context->uli.lai = uli->lai;
		context->uli.lai2.lai_mcc_digit_2 = uli->lai2.lai_mcc_digit_2;
		context->uli.lai2.lai_mcc_digit_1 = uli->lai2.lai_mcc_digit_1;
		context->uli.lai2.lai_mnc_digit_3 = uli->lai2.lai_mnc_digit_3;
		context->uli.lai2.lai_mcc_digit_3 = uli->lai2.lai_mcc_digit_3;
		context->uli.lai2.lai_mnc_digit_2 = uli->lai2.lai_mnc_digit_2;
		context->uli.lai2.lai_mnc_digit_1 = uli->lai2.lai_mnc_digit_1;
		context->uli.lai2.lai_lac = uli->lai2.lai_lac;
	}

	if (uli->tai) {
		context->uli.tai = uli->tai;
		context->uli.tai2.tai_mcc_digit_2 = uli->tai2.tai_mcc_digit_2;
		context->uli.tai2.tai_mcc_digit_1 = uli->tai2.tai_mcc_digit_1;
		context->uli.tai2.tai_mnc_digit_3 = uli->tai2.tai_mnc_digit_3;
		context->uli.tai2.tai_mcc_digit_3 = uli->tai2.tai_mcc_digit_3;
		context->uli.tai2.tai_mnc_digit_2 = uli->tai2.tai_mnc_digit_2;
		context->uli.tai2.tai_mnc_digit_1 = uli->tai2.tai_mnc_digit_1;
		context->uli.tai2.tai_tac = uli->tai2.tai_tac;
	}

	if (uli->rai) {
		context->uli.rai = uli->rai;
		context->uli.rai2.ria_mcc_digit_2 = uli->rai2.ria_mcc_digit_2;
		context->uli.rai2.ria_mcc_digit_1 = uli->rai2.ria_mcc_digit_1;
		context->uli.rai2.ria_mnc_digit_3 = uli->rai2.ria_mnc_digit_3;
		context->uli.rai2.ria_mcc_digit_3 = uli->rai2.ria_mcc_digit_3;
		context->uli.rai2.ria_mnc_digit_2 = uli->rai2.ria_mnc_digit_2;
		context->uli.rai2.ria_mnc_digit_1 = uli->rai2.ria_mnc_digit_1;
		context->uli.rai2.ria_lac = uli->rai2.ria_lac;
		context->uli.rai2.ria_rac = uli->rai2.ria_rac;
	}

	if (uli->sai) {
		context->uli.sai = uli->sai;
		context->uli.sai2.sai_mcc_digit_2 = uli->sai2.sai_mcc_digit_2;
		context->uli.sai2.sai_mcc_digit_1 = uli->sai2.sai_mcc_digit_1;
		context->uli.sai2.sai_mnc_digit_3 = uli->sai2.sai_mnc_digit_3;
		context->uli.sai2.sai_mcc_digit_3 = uli->sai2.sai_mcc_digit_3;
		context->uli.sai2.sai_mnc_digit_2 = uli->sai2.sai_mnc_digit_2;
		context->uli.sai2.sai_mnc_digit_1 = uli->sai2.sai_mnc_digit_1;
		context->uli.sai2.sai_lac = uli->sai2.sai_lac;
		context->uli.sai2.sai_sac = uli->sai2.sai_sac;
	}

	if (uli->cgi) {
		context->uli.cgi = uli->cgi;
		context->uli.cgi2.cgi_mcc_digit_2 = uli->cgi2.cgi_mcc_digit_2;
		context->uli.cgi2.cgi_mcc_digit_1 = uli->cgi2.cgi_mcc_digit_1;
		context->uli.cgi2.cgi_mnc_digit_3 = uli->cgi2.cgi_mnc_digit_3;
		context->uli.cgi2.cgi_mcc_digit_3 = uli->cgi2.cgi_mcc_digit_3;
		context->uli.cgi2.cgi_mnc_digit_2 = uli->cgi2.cgi_mnc_digit_2;
		context->uli.cgi2.cgi_mnc_digit_1 = uli->cgi2.cgi_mnc_digit_1;
		context->uli.cgi2.cgi_lac = uli->cgi2.cgi_lac;
		context->uli.cgi2.cgi_ci = uli->cgi2.cgi_ci;
	}

	if (uli->ecgi) {
		context->uli.ecgi = uli->ecgi;
		context->uli.ecgi2.ecgi_mcc_digit_2 = uli->ecgi2.ecgi_mcc_digit_2;
		context->uli.ecgi2.ecgi_mcc_digit_1 = uli->ecgi2.ecgi_mcc_digit_1;
		context->uli.ecgi2.ecgi_mnc_digit_3 = uli->ecgi2.ecgi_mnc_digit_3;
		context->uli.ecgi2.ecgi_mcc_digit_3 = uli->ecgi2.ecgi_mcc_digit_3;
		context->uli.ecgi2.ecgi_mnc_digit_2 = uli->ecgi2.ecgi_mnc_digit_2;
		context->uli.ecgi2.ecgi_mnc_digit_1 = uli->ecgi2.ecgi_mnc_digit_1;
		context->uli.ecgi2.ecgi_spare = uli->ecgi2.ecgi_spare;
		context->uli.ecgi2.eci = uli->ecgi2.eci;
	}

	if (uli->macro_enodeb_id) {
		context->uli.macro_enodeb_id = uli->macro_enodeb_id;
		context->uli.macro_enodeb_id2.menbid_mcc_digit_2 =
			uli->macro_enodeb_id2.menbid_mcc_digit_2;
		context->uli.macro_enodeb_id2.menbid_mcc_digit_1 =
			uli->macro_enodeb_id2.menbid_mcc_digit_1;
		context->uli.macro_enodeb_id2.menbid_mnc_digit_3 =
			uli->macro_enodeb_id2.menbid_mnc_digit_3;
		context->uli.macro_enodeb_id2.menbid_mcc_digit_3 =
			uli->macro_enodeb_id2.menbid_mcc_digit_3;
		context->uli.macro_enodeb_id2.menbid_mnc_digit_2 =
			uli->macro_enodeb_id2.menbid_mnc_digit_2;
		context->uli.macro_enodeb_id2.menbid_mnc_digit_1 =
			uli->macro_enodeb_id2.menbid_mnc_digit_1;
		context->uli.macro_enodeb_id2.menbid_spare =
			uli->macro_enodeb_id2.menbid_spare;
		context->uli.macro_enodeb_id2.menbid_macro_enodeb_id =
			uli->macro_enodeb_id2.menbid_macro_enodeb_id;
		context->uli.macro_enodeb_id2.menbid_macro_enb_id2 =
			uli->macro_enodeb_id2.menbid_macro_enb_id2;

	}

	if (uli->extnded_macro_enb_id) {
		context->uli.extnded_macro_enb_id = uli->extnded_macro_enb_id;
		context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1 =
			uli->extended_macro_enodeb_id2.emenbid_mcc_digit_1;
		context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3 =
			uli->extended_macro_enodeb_id2.emenbid_mnc_digit_3;
		context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3 =
			uli->extended_macro_enodeb_id2.emenbid_mcc_digit_3;
		context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2 =
			uli->extended_macro_enodeb_id2.emenbid_mnc_digit_2;
		context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1 =
			uli->extended_macro_enodeb_id2.emenbid_mnc_digit_1;
		context->uli.extended_macro_enodeb_id2.emenbid_smenb =
			uli->extended_macro_enodeb_id2.emenbid_smenb;
		context->uli.extended_macro_enodeb_id2.emenbid_spare =
			uli->extended_macro_enodeb_id2.emenbid_spare;
		context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id =
			uli->extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id;
		context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2 =
			uli->extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2;
	}

	return 0;
}

/**
 * @brief  : Fill ue context info from incoming data in create sess request
 * @param  : csr holds data in csr
 * @param  : context , pointer to ue context structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_context_info(create_sess_req_t *csr, ue_context *context)
{
	/* Check ntohl case */
	//context->s11_sgw_gtpc_ipv4.s_addr = ntohl(pfcp_config.s11_ip.s_addr);
	context->s11_sgw_gtpc_ipv4.s_addr = pfcp_config.s11_ip.s_addr;
	context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;
	context->s11_mme_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;


	/* VS: Stored the serving network information in UE context */
	context->serving_nw.mnc_digit_1 = csr->serving_network.mnc_digit_1;
	context->serving_nw.mnc_digit_2 = csr->serving_network.mnc_digit_2;
	context->serving_nw.mnc_digit_3 = csr->serving_network.mnc_digit_3;
	context->serving_nw.mcc_digit_1 = csr->serving_network.mcc_digit_1;
	context->serving_nw.mcc_digit_2 = csr->serving_network.mcc_digit_2;
	context->serving_nw.mcc_digit_3 = csr->serving_network.mcc_digit_3;

	if(csr->indctn_flgs.header.len != 0) {
		context->indication_flag.oi = csr->indctn_flgs.indication_oi;
	}

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(csr->sender_fteid_ctl_plane.ipv4_address);

	return 0;
}
/**
 * @brief  : Fill pdn info from data in incoming csr
 * @param  : csr holds data in csr
 * @param  : pdn , pointer to pdn connction structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_pdn_info(create_sess_req_t *csr, pdn_connection *pdn)
{

	pdn->apn_ambr.ambr_downlink = csr->apn_ambr.apn_ambr_dnlnk;
	pdn->apn_ambr.ambr_uplink = csr->apn_ambr.apn_ambr_uplnk;
	pdn->apn_restriction = csr->max_apn_rstrct.rstrct_type_val;

	if (csr->pdn_type.pdn_type_pdn_type == PDN_TYPE_IPV4)
		pdn->pdn_type.ipv4 = 1;
	else if (csr->pdn_type.pdn_type_pdn_type == PDN_TYPE_IPV6)
		pdn->pdn_type.ipv6 = 1;
	else if (csr->pdn_type.pdn_type_pdn_type == PDN_TYPE_IPV4_IPV6) {
		pdn->pdn_type.ipv4 = 1;
		pdn->pdn_type.ipv6 = 1;
	}

	if (csr->chrgng_char.header.len)
		memcpy(&pdn->charging_characteristics,
				&csr->chrgng_char.chrgng_char_val,
				sizeof(csr->chrgng_char.chrgng_char_val));

	pdn->ue_time_zone_flag = FALSE;
	if(csr->ue_time_zone.header.len)
	{
		pdn->ue_time_zone_flag = TRUE;
		pdn->ue_tz.tz = csr->ue_time_zone.time_zone;
		pdn->ue_tz.dst = csr->ue_time_zone.daylt_svng_time;
	}

	if(csr->rat_type.header.len)
	{
		pdn->rat_type = csr->rat_type.rat_type;
	}

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = ntohl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);
		pdn->s5s8_pgw_gtpc_ipv4.s_addr = csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address;

	} else if (pfcp_config.cp_type == PGWC){
		pdn->s5s8_pgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_pgw_gtpc_ipv4.s_addr = ntohl(pdn->s5s8_pgw_gtpc_ipv4.s_addr); //NIKHIL
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;

		/* Note: s5s8_pgw_gtpc_teid generated from
		 * s5s8_pgw_gtpc_base_teid and incremented
		 * for each pdn connection, similar to
		 * s11_sgw_gtpc_teid
		 */
		set_s5s8_pgw_gtpc_teid(pdn);
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;


	}

	/*VS:TODO*/
	if (pfcp_config.cp_type == SGWC) {
		s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address);
	}

	/* Note: s5s8_pgw_gtpc_teid updated by
	 *                  * process_sgwc_s5s8_create_session_response (...)
	 *                                   */
	//pdn->s5s8_pgw_gtpc_teid = csr->s5s8pgw_pmip.teid_gre;

	return 0;
}

int
check_interface_type(uint8_t iface){
	switch(iface){
		case GTPV2C_IFTYPE_S1U_ENODEB_GTPU:
			if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
				return DESTINATION_INTERFACE_VALUE_ACCESS;
			}
			break;
		case GTPV2C_IFTYPE_S5S8_SGW_GTPU:
			if (pfcp_config.cp_type == PGWC){
				return DESTINATION_INTERFACE_VALUE_ACCESS;
			}
			break;
		case GTPV2C_IFTYPE_S5S8_PGW_GTPU:
			if (pfcp_config.cp_type == SGWC){
				return DESTINATION_INTERFACE_VALUE_CORE;
			}
			break;
		case GTPV2C_IFTYPE_S1U_SGW_GTPU:
		case GTPV2C_IFTYPE_S11_MME_GTPC:
		case GTPV2C_IFTYPE_S11S4_SGW_GTPC:
		case GTPV2C_IFTYPE_S11U_SGW_GTPU:
		case GTPV2C_IFTYPE_S5S8_SGW_GTPC:
		case GTPV2C_IFTYPE_S5S8_PGW_GTPC:
		case GTPV2C_IFTYPE_S5S8_SGW_PIMPv6:
		case GTPV2C_IFTYPE_S5S8_PGW_PIMPv6:
		default:
			return -1;
			break;
	}
	return -1;
}

int
fill_dedicated_bearer_info(eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn)
{
	int ret = 0;
	upf_context_t *upf_ctx = NULL;

	bearer->s5s8_sgw_gtpu_ipv4.s_addr = context->eps_bearers[pdn->default_bearer_id - 5]->s5s8_sgw_gtpu_ipv4.s_addr;

#ifdef CP_BUILD
#ifdef GX_BUILD
	/* TODO: Revisit this for change in yang*/
	if (pfcp_config.cp_type != SGWC){
		bearer->qer_count = NUMBER_OF_QER_PER_BEARER;
		for(uint8_t itr=0; itr < bearer->qer_count; itr++){
			bearer->qer_id[itr].qer_id = generate_qer_id();
			fill_qer_entry(pdn, bearer, itr);
		}
	}
#endif /* GX_BUILD*/
#endif /* CP_BUILD */

	/*SP: As per discussion Per bearer two pdrs and fars will be there*/
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         2      s5s8 PGWU          NA
	 SAEGWC       2      s1u SAEGWU         NA
	 ************************************************/

	if (pfcp_config.cp_type == SGWC){
	bearer->pdr_count = NUMBER_OF_PDR_PER_BEARER;
	for(uint8_t itr=0; itr < bearer->pdr_count; itr++){
		switch(itr){
			case SOURCE_INTERFACE_VALUE_ACCESS:
				fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_ACCESS, itr);
				break;
			case SOURCE_INTERFACE_VALUE_CORE:
				fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_CORE, itr);
				break;
			default:
				break;
		}
	}
	}

	bearer->pdn = pdn;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ipv4.s_addr),
			(void **) &(upf_ctx));
	if (ret < 0) {
		clLog(sxlogger, eCLSeverityDebug, "%s:%d NO ENTRY FOUND IN UPF HASH [%u]\n",
			__func__, __LINE__, (pdn->upf_ipv4.s_addr));
		return GTPV2C_CAUSE_INVALID_PEER;
	}

	if (pfcp_config.cp_type == SGWC) {
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_sgwu_ip;
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);

		set_s5s8_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);
	}else if (pfcp_config.cp_type == SAEGWC) {
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;
		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	} else if (pfcp_config.cp_type == PGWC) {
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_pgwu_ip;

		set_s5s8_pgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	}

	RTE_SET_USED(context);
	return 0;
}

/**
 * @brief  : Fill bearer info from incoming data in csr
 * @param  : csr holds data in csr
 * @param  : bearer , pointer to eps bearer structure
 * @param  : context , pointer to ue context structure
 * @param  : pdn , pointer to pdn connction structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_bearer_info(create_sess_req_t *csr, eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn)
{

	/* Need to re-vist this ARP[Allocation/Retention priority] handling portion */
	bearer->qos.arp.priority_level =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.pl;
	bearer->qos.arp.preemption_capability =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.pci;
	bearer->qos.arp.preemption_vulnerability =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.pvi;

	/* TODO: Implement TFTs on default bearers
	 * if (create_session_request.bearer_tft_ie) {
	 * }**/

	/* VS: Fill the QCI value */
	bearer->qos.qci =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.qci;
	bearer->qos.ul_mbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.max_bit_rate_uplnk;
	bearer->qos.dl_mbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.max_bit_rate_dnlnk;
	bearer->qos.ul_gbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.guarntd_bit_rate_uplnk;
	bearer->qos.dl_gbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.guarntd_bit_rate_dnlnk;

	bearer->s1u_sgw_gtpu_teid = 0;
	bearer->s5s8_sgw_gtpu_teid = 0;

	if (pfcp_config.cp_type == PGWC){
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid = csr->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.teid_gre_key;
	}

#if 0
#ifdef CP_BUILD
#ifdef GX_BUILD
	/* TODO: Revisit this for change in yang*/
	if (pfcp_config.cp_type != SGWC){
		bearer->qer_count = NUMBER_OF_QER_PER_BEARER;
		for(uint8_t itr=0; itr < bearer->qer_count; itr++){
			bearer->qer_id[itr].qer_id = generate_qer_id();
			fill_qer_entry(pdn, bearer,itr);
		}
	}
#endif /* GX_BUILD*/
#endif /* CP_BUILD */
#endif

	/*SP: As per discussion Per bearer two pdrs and fars will be there*/
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         2      s5s8 PGWU          NA
	 SAEGWC       2      s1u SAEGWU         NA
	 ************************************************/

	if (pfcp_config.cp_type == SGWC){

		bearer->pdr_count = NUMBER_OF_PDR_PER_BEARER;
		for(uint8_t itr=0; itr < bearer->pdr_count; itr++){
			switch(itr){
				case SOURCE_INTERFACE_VALUE_ACCESS:
					fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_ACCESS, itr);
					break;
				case SOURCE_INTERFACE_VALUE_CORE:
					fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_CORE, itr);
					break;
				default:
					break;
			}
		}
	}

	bearer->pdn = pdn;

	RTE_SET_USED(context);
	return 0;
}

#ifdef GX_BUILD
static int
gen_ccr_request(ue_context *context, uint8_t ebi_index, create_sess_req_t *csr)
{
	/* VS: Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	char *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	/* VS: Generate unique call id per PDN connection */
	context->pdns[ebi_index]->call_id = generate_call_id();

	/** Allocate the memory for Gx Context
	 */
	gx_context = rte_malloc_socket(NULL,
					sizeof(gx_context_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* VS: Generate unique session id for communicate over the Gx interface */
	if (gen_sess_id_for_ccr(gx_context->gx_sess_id,
				context->pdns[ebi_index]->call_id)) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: %s \n", __func__, __LINE__,
				strerror(errno));
		return -1;
	}

	/* Maintain the gx session id in context */
	memcpy(context->pdns[ebi_index]->gx_sess_id,
			gx_context->gx_sess_id , strlen(gx_context->gx_sess_id));

	/* VS: Maintain the PDN mapping with call id */
	if (add_pdn_conn_entry(context->pdns[ebi_index]->call_id,
				context->pdns[ebi_index]) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to add pdn entry with call id\n", __func__, __LINE__);
		return -1;
	}

	/* VS: Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* VS: Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = INITIAL_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = ESTABLISHMENT ;

	/* VS:TODO: Need to check the bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT ;
	ccr_request.data.ccr.bearer_identifier.len =
		int_to_str((char *)ccr_request.data.ccr.bearer_identifier.val,
				(context->eps_bearers[ebi_index])->eps_bearer_id);

	/* Subscription-Id */
	if(csr->imsi.header.len  || csr->msisdn.header.len)
	{
		uint8_t idx = 0;
		ccr_request.data.ccr.presence.subscription_id = PRESENT;
		ccr_request.data.ccr.subscription_id.count = 1; // IMSI & MSISDN
		ccr_request.data.ccr.subscription_id.list  = rte_malloc_socket(NULL,
				(sizeof(GxSubscriptionId)*1),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		/* Fill IMSI */
		if(csr->imsi.header.len != 0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].presence.subscription_id_type = PRESENT;
			ccr_request.data.ccr.subscription_id.list[idx].presence.subscription_id_data = PRESENT;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_type = END_USER_IMSI;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.len = csr->imsi.header.len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&csr->imsi.imsi_number_digits,
					csr->imsi.header.len);
			idx++;
		}

#if 0
		/* Fill MSISDN */
		if(csr->msisdn.header.len !=0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_type = END_USER_E164;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.len = csr->msisdn.header.len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&csr->msisdn.msisdn_number_digits,
					csr->msisdn.header.len);
		}
#endif
	}

	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	/* TODO: Removing this ie as it is not require.
	 * It's showing padding in pcap
	ccr_request.data.ccr.presence.framed_ip_address = PRESENT;

	ccr_request.data.ccr.framed_ip_address.len = inet_ntoa(ccr_request.data.ccr.framed_ip_address.val,
			                                               context->pdns[ebi_index]);

	char *temp = inet_ntoa(context->pdns[ebi_index]->ipv4);
	memcpy(ccr_request.data.ccr.framed_ip_address.val, &temp, strlen(temp)); */

	/*
	 * nEED TO ADd following to Complete CCR_I, these are all mandatory IEs
	 * AN-GW Addr (SGW)
	 * User Eqip info (IMEI)
	 * 3GPP-ULI
	 * calling station id (APN)
	 * Access n/w charging addr (PGW addr)
	 * Charging Id
	 */


	/* VS: Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, context, ebi_index, gx_context->gx_sess_id) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
		return -1;
	}

	struct sockaddr_in saddr_in;
    	saddr_in.sin_family = AF_INET;
    	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
    	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_INITIAL, SENT, GX);


	/* Update UE State */
	context->pdns[ebi_index]->state = CCR_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = CCR_SNT_STATE;
	gx_context->proc = context->pdns[ebi_index]->proc;

	/* VS: Maintain the Gx context mapping with Gx Session id */
	if (gx_context_entry_add(gx_context->gx_sess_id, gx_context) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: %s \n", __func__, __LINE__,
				strerror(errno));
		return -1;
	}

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	buffer = rte_zmalloc_socket(NULL, msg_len + sizeof(ccr_request.msg_type),
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	/* VS: Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
		return -1;

	}

	/* VS: Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + sizeof(ccr_request.msg_type));
	return 0;
}

static int
fill_tai(uint8_t *buf, tai_field_t *tai) {

	int index = 0;
	buf[index++] = ((tai->tai_mcc_digit_2 << 4) | (tai->tai_mcc_digit_1)) & 0xff;
	buf[index++] = ((tai->tai_mnc_digit_3 << 4 )| (tai->tai_mcc_digit_3)) & 0xff;
	buf[index++] = ((tai->tai_mnc_digit_2 << 4 ) | (tai->tai_mnc_digit_1)) & 0xff;
	buf[index++] = ((tai->tai_tac >>8) & 0xff);
	buf[index++] =  (tai->tai_tac) &0xff;

	return sizeof(tai_field_t);
}

static int
fill_ecgi(uint8_t *buf, ecgi_field_t *ecgi) {

	int index = 0;
	buf[index++] = ((ecgi->ecgi_mcc_digit_2 << 4 ) | (ecgi->ecgi_mcc_digit_1)) & 0xff;
	buf[index++] = ((ecgi->ecgi_mnc_digit_3 << 4 ) | (ecgi->ecgi_mcc_digit_3)) & 0xff;
	buf[index++] = ((ecgi->ecgi_mnc_digit_2 << 4 ) | (ecgi->ecgi_mnc_digit_1)) & 0xff;
	buf[index++] = (((ecgi->ecgi_spare) | (ecgi->eci >> 24 )) & 0xff);
	buf[index++] = (((ecgi->eci >> 16 )) & 0xff);
	buf[index++] = (((ecgi->eci >> 8 )) & 0xff);
	buf[index++] = (ecgi->eci & 0xff);

	return sizeof(ecgi_field_t);
}

static int
fill_lai(uint8_t *buf, lai_field_t *lai) {

	int index = 0;
	buf[index++] = ((lai->lai_mcc_digit_2 << 4) | (lai->lai_mcc_digit_1)) & 0xff;
	buf[index++] = ((lai->lai_mnc_digit_3 << 4 )| (lai->lai_mcc_digit_3)) & 0xff;
	buf[index++] = ((lai->lai_mnc_digit_2 << 4 ) | (lai->lai_mnc_digit_1)) & 0xff;
	buf[index++] = ((lai->lai_lac >>8) & 0xff);
	buf[index++] =  (lai->lai_lac) &0xff;
	return sizeof(lai_field_t);
}

static int
fill_rai(uint8_t *buf, rai_field_t *rai) {

	int index = 0;
	buf[index++] = ((rai->ria_mcc_digit_2 << 4) | (rai->ria_mcc_digit_1)) & 0xff;
	buf[index++] = ((rai->ria_mnc_digit_3 << 4 )| (rai->ria_mcc_digit_3)) & 0xff;
	buf[index++] = ((rai->ria_mnc_digit_2 << 4 ) | (rai->ria_mnc_digit_1)) & 0xff;
	buf[index++] = ((rai->ria_lac >>8) & 0xff);
	buf[index++] =  (rai->ria_lac) &0xff;
	buf[index++] = ((rai->ria_rac >>8) & 0xff);
	buf[index++] =  (rai->ria_rac) &0xff;

	return sizeof(rai_field_t);
}

static int
fill_sai(uint8_t *buf, sai_field_t *sai) {

	int index = 0;
	buf[index++] = ((sai->sai_mcc_digit_2 << 4) | (sai->sai_mcc_digit_1)) & 0xff;
	buf[index++] = ((sai->sai_mnc_digit_3 << 4 )| (sai->sai_mcc_digit_3)) & 0xff;
	buf[index++] = ((sai->sai_mnc_digit_2 << 4 ) | (sai->sai_mnc_digit_1)) & 0xff;
	buf[index++] = ((sai->sai_lac >>8) & 0xff);
	buf[index++] =  (sai->sai_lac) &0xff;
	buf[index++] = ((sai->sai_sac >>8) & 0xff);
	buf[index++] =  (sai->sai_sac) &0xff;
	return sizeof(sai_field_t);
}

static int
fill_cgi(uint8_t *buf, cgi_field_t *cgi) {

	int index = 0;
	buf[index++] = ((cgi->cgi_mcc_digit_2 << 4) | (cgi->cgi_mcc_digit_1)) & 0xff;
	buf[index++] = ((cgi->cgi_mnc_digit_3 << 4 )| (cgi->cgi_mcc_digit_3)) & 0xff;
	buf[index++] = ((cgi->cgi_mnc_digit_2 << 4 ) | (cgi->cgi_mnc_digit_1)) & 0xff;
	buf[index++] = ((cgi->cgi_lac >>8) & 0xff);
	buf[index++] =  (cgi->cgi_lac) &0xff;
	buf[index++] = ((cgi->cgi_ci >>8) & 0xff);
	buf[index++] =  (cgi->cgi_ci) &0xff;
	return sizeof(cgi_field_t);
}


static int
gen_ccru_request(pdn_connection *pdn, eps_bearer *bearer , mod_bearer_req_t *mb_req, uint8_t flag_check)
{
	/*
	 * TODO:
	 * Passing bearer as parameter is a BAD IDEA
	 * because what if multiple bearer changes?
	 * code SHOULD anchor only on pdn.
	 */
	/* VS: Initialize the Gx Parameters */

	uint16_t msg_len = 0;
	char *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	int ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			          (const void*)(pdn->gx_sess_id),
					           (void **)&gx_context);
	  if (ret < 0) {
		       clLog(clSystemLog, eCLSeverityCritical, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
					                pdn->gx_sess_id);
			    return -1;
	}

	/* VS: Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* VS: Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = UPDATE_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = MODIFICATION;

	/* VS:TODO: Need to check the bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT ;
	ccr_request.data.ccr.bearer_identifier.len =
		int_to_str((char *)ccr_request.data.ccr.bearer_identifier.val,
				bearer->eps_bearer_id);

	/* Subscription-Id */
	if(pdn->context->imsi  || pdn->context->msisdn)
	{
		uint8_t idx = 0;
		ccr_request.data.ccr.presence.subscription_id = PRESENT;
		ccr_request.data.ccr.subscription_id.count = 2; // IMSI & MSISDN
		ccr_request.data.ccr.subscription_id.list  = rte_malloc_socket(NULL,
				(sizeof(GxSubscriptionId)*2),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		/* Fill IMSI */
		if(pdn->context->imsi != 0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_type = END_USER_IMSI;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.len = pdn->context->imsi_len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&pdn->context->imsi,
					pdn->context->imsi_len);
			idx++;
		}

		/* Fill MSISDN */
		if(pdn->context->msisdn !=0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_type = END_USER_E164;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.len =  pdn->context->msisdn_len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&pdn->context->msisdn,
					pdn->context->msisdn_len);
		}
	}

	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	/*
	 * nEED TO ADd following to Complete CCR_I, these are all mandatory IEs
	 * AN-GW Addr (SGW)
	 * User Eqip info (IMEI)
	 * 3GPP-ULI
	 * calling station id (APN)
	 * Access n/w charging addr (PGW addr)
	 * Charging Id
	 */

	int index = 0;
	int len = 0;


	if(pdn->context->old_uli_valid == TRUE) {

		if(flag_check  == ECGI_AND_TAI_PRESENT) {
			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_ECGI_AND_TAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len =index ;

			len = fill_tai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.tai2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

			len  = fill_ecgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[len + 1]), &(mb_req->uli.ecgi2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1<< 0)) == TAI_PRESENT) ) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_TAI_TYPE;

			ccr_request.data.ccr.tgpp_user_location_info.len = index ;

			len = fill_tai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.tai2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 4)) == ECGI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_ECGI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_ecgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.ecgi2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 2)) == SAI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_SAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_sai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.sai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 3)) == RAI_PRESENT)) {
			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_RAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_rai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.rai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 1)) == CGI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_CGI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_cgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.cgi2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 6)) == 1)) {
			len = fill_lai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]), &(mb_req->uli.lai2));
		}

	}

	if( pdn->old_ue_tz_valid == TRUE ) {

		index = 0;
		ccr_request.data.ccr.presence.tgpp_ms_timezone = PRESENT;
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = GX_UE_TIMEZONE_TYPE;
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = ((pdn->ue_tz.tz) & 0xff);
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = ((pdn->ue_tz.dst) & 0xff);

		ccr_request.data.ccr.tgpp_ms_timezone.len = index;

	}


	/* VS: Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, pdn->context, (bearer->eps_bearer_id - 5), pdn->gx_sess_id) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
		return -1;
	}

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_INITIAL, SENT, GX);


	/* Update UE State */
	pdn->state = CCRU_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = CCRU_SNT_STATE;
	gx_context->proc = pdn->proc;

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	buffer = rte_zmalloc_socket(NULL, msg_len + sizeof(ccr_request.msg_type),
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	/* VS: Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
		return -1;

	}

	/* VS: Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + sizeof(ccr_request.msg_type));
	return 0;
}

/**
 * @brief  : Generate CCR request
 * @param  : context , pointer to ue context structure
 * @param  : ebi_index, index in array where eps bearer is stored
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
ccru_req_for_bear_termination(pdn_connection *pdn, eps_bearer *bearer)
{

	/*
	 * TODO:
	 * Passing bearer as parameter is a BAD IDEA
	 * because what if multiple bearer changes?
	 * code SHOULD anchor only on pdn.
	 */
	/* VS: Initialize the Gx Parameters */
	int ret = 0;
	uint16_t msg_len = 0;
	char *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
				pdn->gx_sess_id);
	return -1;
	}
	/* VS: Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* VS: Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = UPDATE_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = TERMINATION;

	/* VS:TODO: Need to check the bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT ;
	ccr_request.data.ccr.bearer_identifier.len =
		int_to_str((char *)ccr_request.data.ccr.bearer_identifier.val,
				bearer->eps_bearer_id -5);

	/* Subscription-Id */
	if(pdn->context->imsi  || pdn->context->msisdn)
	{
		uint8_t idx = 0;
		ccr_request.data.ccr.presence.subscription_id = PRESENT;
		ccr_request.data.ccr.subscription_id.count = 1; // IMSI & MSISDN
		ccr_request.data.ccr.subscription_id.list  = rte_malloc_socket(NULL,
				(sizeof(GxSubscriptionId)*1),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		/* Fill IMSI */
		if(pdn->context->imsi != 0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_type = END_USER_IMSI;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.len = pdn->context->imsi_len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&pdn->context->imsi,
					pdn->context->imsi_len);
			idx++;
		}

		/* Fill MSISDN
		if(pdn->context->msisdn !=0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_type = END_USER_E164;
			ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.len =  pdn->context->msisdn_len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&pdn->context->msisdn,
					pdn->context->msisdn_len);
		} */
	}

	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	/* ccr_request.data.ccr.presence.framed_ip_address = PRESENT;
	ccr_request.data.ccr.framed_ip_address.len = inet_ntoa(ccr_request.data.ccr.framed_ip_address.val);
	                                              bearer->eps_bearer_id -5);*/
	int idx = 0;
	ccr_request.data.ccr.presence.charging_rule_report = PRESENT;
	ccr_request.data.ccr.charging_rule_report.count = 1;
	ccr_request.data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleReportList)*1),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	ccr_request.data.ccr.charging_rule_report.list[idx].presence.charging_rule_name = PRESENT;
	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleNameOctetString)*1),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.count = 1;
	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list[idx].len = strlen(bearer->dynamic_rules[idx]->rule_name);

	for(uint16_t i = 0 ; i<strlen(bearer->dynamic_rules[idx]->rule_name); i++){
		ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list[idx].val[i] =
			bearer->dynamic_rules[idx]->rule_name[i];
	}
//	ccr_request.data.ccr.charging_rule_report.list[idx].presence.bearer_identifier = PRESENT;
//	ccr_request.data.ccr.charging_rule_report.list[idx].bearer_identifier.val[idx] =
//		int_to_str((char *)ccr_request.data.ccr.bearer_identifier.val,
//				bearer->eps_bearer_id - 5);

	ccr_request.data.ccr.charging_rule_report.list[idx].presence.pcc_rule_status = PRESENT;
	ccr_request.data.ccr.charging_rule_report.list[idx].pcc_rule_status = INACTIVE;

	ccr_request.data.ccr.charging_rule_report.list[idx].presence.rule_failure_code = PRESENT;
	ccr_request.data.ccr.charging_rule_report.list[idx].rule_failure_code = NO_BEARER_BOUND;

	//ccr_request.data.ccr.charging_rule_report.list[idx].presence.ran_nas_release_cause = PRESENT;
	//ccr_request.data.ccr.charging_rule_report.list[idx].ran_nas_release_cause =;

	char *temp = inet_ntoa(pdn->ipv4);
	memcpy(ccr_request.data.ccr.framed_ip_address.val, &temp, strlen(temp));

	/*
	 * nEED TO ADd following to Complete CCR_I, these are all mandatory IEs
	 * AN-GW Addr (SGW)
	 * User Eqip info (IMEI)
	 * 3GPP-ULI
	 * calling station id (APN)
	 * Access n/w charging addr (PGW addr)
	 * Charging Id
	 */


	/* VS: Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, pdn->context, bearer->eps_bearer_id - 5, pdn->gx_sess_id) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
		return -1;
	}

	struct sockaddr_in saddr_in;
    	saddr_in.sin_family = AF_INET;
    	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
    	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_INITIAL, SENT, GX);


	/* Update UE State */
	pdn->state = CCRU_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = CCRU_SNT_STATE;
	gx_context->proc = pdn->proc;
	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	buffer = rte_zmalloc_socket(NULL, msg_len + sizeof(ccr_request.msg_type),
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	/* VS: Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
		return -1;

	}

	/* VS: Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + sizeof(ccr_request.msg_type));
	return 0;
}
#endif /* GX_BUILD */

int
process_create_sess_req(create_sess_req_t *csr,
		ue_context **_context, struct in_addr *upf_ipv4)
{
	int ret = 0;
	struct in_addr ue_ip = {0};
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;

	apn *apn_requested = get_apn((char *)csr->apn.apn, csr->apn.header.len);

	if(csr->mapped_ue_usage_type.header.len > 0) {
		apn_requested->apn_usage_type = csr->mapped_ue_usage_type.mapped_ue_usage_type;
	}

	uint8_t ebi_index = csr->bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi - 5;


	if (pfcp_config.cp_type != SGWC) {
		ret = acquire_ip(&ue_ip);
	}
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

	/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
	ret = create_ue_context(&csr->imsi.imsi_number_digits, csr->imsi.header.len,
			csr->bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi, &context, apn_requested,
			CSR_SEQUENCE(csr));
	if (ret)
		return ret;


	if (csr->mei.header.len)
		memcpy(&context->mei, &csr->mei.mei, csr->mei.header.len);

	memcpy(&context->msisdn, &csr->msisdn.msisdn_number_digits, csr->msisdn.header.len);

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		if (fill_context_info(csr, context) != 0)
			return -1;
	}else{
		context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;
	}

	/* Retrive procedure of CSR */
	pdn = context->eps_bearers[ebi_index]->pdn;
	pdn->proc = get_csr_proc(csr);

	/* VS: Stored the RAT TYPE information in UE context */
	if (csr->rat_type.header.len != 0) {
		context->rat_type.rat_type = csr->rat_type.rat_type;
		context->rat_type.len = csr->rat_type.header.len;
	}

	/* VS: Stored the RAT TYPE information in UE context */
	if (csr->uli.header.len != 0) {
		if (fill_uli_info(&csr->uli, context) != 0)
			return -1;
	}

	/* VS: Stored the mapped ue usage type information in UE context */
	if (csr->mapped_ue_usage_type.header.len != 0) {
		context->mapped_ue_usage_type =
			csr->mapped_ue_usage_type.mapped_ue_usage_type;
	} else
		context->mapped_ue_usage_type = -1;

	pdn = context->eps_bearers[ebi_index]->pdn;
	/* VS: Maintain the sequence number of CSR */
	pdn->apn_in_use = apn_requested;

	/* VS: Maintain the sequence number of CSR */
	if(csr->header.gtpc.teid_flag == 1) {
		context->sequence = csr->header.teid.has_teid.seq;
		pdn->csr_sequence = csr->header.teid.has_teid.seq;
	}
	else{
		context->sequence = csr->header.teid.no_teid.seq;
		pdn->csr_sequence = csr->header.teid.no_teid.seq;
	}

	/* Store upf ipv4 in pdn structure */
	pdn->upf_ipv4 = *upf_ipv4;

	if (fill_pdn_info(csr, pdn) != 0)
		return -1;

	bearer = context->eps_bearers[ebi_index];

	if (pfcp_config.cp_type == SGWC) {
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		//pdn->s5s8_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
		/* SGWC s55s8 TEID is unique for each PDN or PGWC */
		pdn->s5s8_sgw_gtpc_teid = s5s8_sgw_gtpc_base_teid + s5s8_sgw_gtpc_teid_offset;
		++s5s8_sgw_gtpc_teid_offset;

		context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	} else if (pfcp_config.cp_type == PGWC) {
		/* VS: Maitain the fqdn into table */
		memcpy(pdn->fqdn, (char *)csr->sgw_u_node_name.fqdn,
				csr->sgw_u_node_name.header.len);

		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);
		context->pdns[ebi_index]->seid = SESS_ID(pdn->s5s8_pgw_gtpc_teid, bearer->eps_bearer_id);
	} else {
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);
		context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	}

	if (fill_bearer_info(csr, bearer, context, pdn) != 0)
		return -1;

	/* SGW Handover Storage */
	if (csr->indctn_flgs.header.len != 0)
	{
		memcpy(&(pdn->ipv4.s_addr) ,&(csr->paa.pdn_addr_and_pfx), IPV4_SIZE);
		/*TODO:ntohl is done as in csr response there is htonl*/
		pdn->ipv4.s_addr = ntohl(pdn->ipv4.s_addr);
		context->indication_flag.oi = csr->indctn_flgs.indication_oi;
		pdn->s5s8_pgw_gtpc_teid = csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key;
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created.s5s8_u_pgw_fteid.ipv4_address;
		bearer->s5s8_pgw_gtpu_teid = csr->bearer_contexts_to_be_created.s5s8_u_pgw_fteid.teid_gre_key;
		bearer->s1u_enb_gtpu_teid =   csr->bearer_contexts_to_be_created.s1u_enb_fteid.teid_gre_key;
		bearer->s1u_enb_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created.s1u_enb_fteid.ipv4_address;

	}
	context->pdns[ebi_index]->dp_seid = 0;

#ifdef GX_BUILD
	if ((pfcp_config.cp_type == PGWC) || (pfcp_config.cp_type == SAEGWC)) {

		if (gen_ccr_request(context, ebi_index, csr)) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: %s \n", __func__, __LINE__,
					strerror(errno));
			return -1;
		}
	}
#endif /* GX_BUILD */

#ifdef USE_CSID
	/* Parse and stored MME and SGW FQ-CSID in the context */
	fqcsid_t *tmp = NULL;

	/* Allocate the memory for each session */
	context->mme_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	context->sgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (pfcp_config.cp_type != SAEGWC) {
		context->pgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (context->pgw_fqcsid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
					ERR_MSG);
			return -1;
		}
	}

	if ((context->mme_fqcsid == NULL) ||
			(context->sgw_fqcsid == NULL)) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
				ERR_MSG);
		return -1;
	}

	/* MME FQ-CSID */
	if (csr->mme_fqcsid.header.len) {
		/* Stored the MME CSID by MME Node address */
		tmp = get_peer_addr_csids_entry(csr->mme_fqcsid.node_address,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		/* check ntohl */
		tmp->node_addr = csr->mme_fqcsid.node_address;

		for(uint8_t itr = 0; itr < csr->mme_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == csr->mme_fqcsid.pdn_csid[itr])
					match = 1;
			}

			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					csr->mme_fqcsid.pdn_csid[itr];
			}
		}
		memcpy(context->mme_fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		/* Stored the MME CSID by MME Node address */
		tmp = get_peer_addr_csids_entry(context->s11_mme_gtpc_ipv4.s_addr,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = context->s11_mme_gtpc_ipv4.s_addr;
		memcpy(context->mme_fqcsid, tmp, sizeof(fqcsid_t));
	}

	/* SGW FQ-CSID */
	if (csr->sgw_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
			tmp = get_peer_addr_csids_entry(csr->sgw_fqcsid.node_address,
					ADD);
		} else {
			/* PGWC */
			tmp = get_peer_addr_csids_entry(csr->sgw_fqcsid.node_address,
					ADD);
		}
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = csr->sgw_fqcsid.node_address;

		for(uint8_t itr = 0; itr < csr->sgw_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == csr->sgw_fqcsid.pdn_csid[itr])
					match = 1;
			}
			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					csr->sgw_fqcsid.pdn_csid[itr];
			}
		}
		memcpy(context->sgw_fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
			tmp = get_peer_addr_csids_entry(context->s11_sgw_gtpc_ipv4.s_addr,
					ADD);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			tmp->node_addr = ntohl(context->s11_sgw_gtpc_ipv4.s_addr);

			for(uint8_t itr = 0; itr < csr->sgw_fqcsid.number_of_csids; itr++) {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] == csr->sgw_fqcsid.pdn_csid[itr])
						match = 1;
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						csr->sgw_fqcsid.pdn_csid[itr];
				}
			}
			memcpy(context->sgw_fqcsid, tmp, sizeof(fqcsid_t));
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_config.cp_type == PGWC) {
		tmp = get_peer_addr_csids_entry(pdn->s5s8_pgw_gtpc_ipv4.s_addr,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		memcpy(context->pgw_fqcsid, tmp, sizeof(fqcsid_t));
	}
#endif /* USE_CSID */

	/* VS: Store the context of ue in pdn*/
	pdn->context = context;

	/* VS: Return the UE context */
	*_context = context;
	return 0;

}

int
process_pfcp_sess_est_request(uint32_t teid, pdn_connection *pdn, upf_context_t *upf_ctx)
{
	uint32_t sequence = 0;
	eps_bearer *bearer = NULL;
	struct resp_info *resp = NULL;
	ue_context *context = pdn->context;
	pfcp_sess_estab_req_t pfcp_sess_est_req = {0};

	bearer = pdn->eps_bearers[pdn->default_bearer_id - 5];

	if(bearer == NULL)
	{
		return -1;
	}

	if (pfcp_config.cp_type == SGWC) {
		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
		set_s5s8_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);
	} else if (pfcp_config.cp_type == SAEGWC) {
		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	} else if (pfcp_config.cp_type == PGWC){
		set_s5s8_pgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	}

	sequence = get_pfcp_sequence_number(PFCP_SESSION_ESTABLISHMENT_REQUEST, sequence);

	/* Need to discuss with himanshu */
	if (pfcp_config.cp_type == PGWC) {
		/* VS: Update the PGWU IP address */
		bearer->s5s8_pgw_gtpu_ipv4.s_addr =
			htonl(upf_ctx->s5s8_pgwu_ip);

		/* Filling PDN structure*/
		pfcp_sess_est_req.pdn_type.header.type = PFCP_IE_PDN_TYPE;
		pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
		pfcp_sess_est_req.pdn_type.pdn_type_spare = 0;
		pfcp_sess_est_req.pdn_type.pdn_type =  1;
	} else {
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s5s8_sgwu_ip);
		bearer->s1u_sgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s1u_ip);
	}

	fill_pfcp_sess_est_req(&pfcp_sess_est_req, pdn, sequence);


#ifdef USE_CSID
	/* Add the entry for peer nodes */
	if (fill_peer_node_info(pdn, bearer)) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to fill peer node info and assignment of the CSID Error: %s\n",
				ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Add entry for cp session id with link local csid */
	sess_csid *tmp = NULL;
	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		tmp = get_sess_csid_entry(
				(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1]);
	} else {
		/* PGWC */
		tmp = get_sess_csid_entry(
				(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1]);
	}

	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Link local csid with session id */
	tmp->cp_seid[tmp->seid_cnt++] = pdn->seid;

	/* Fill the fqcsid into the session est request */
	if (fill_fqcsid_sess_est_req(&pfcp_sess_est_req, context)) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to fill FQ-CSID in Sess EST Req ERROR: %s\n",
				ERR_MSG,
				strerror(errno));
		return -1;
	}
#endif /* USE_CSID */

	/* Update UE State */
	bearer->pdn->state = PFCP_SESS_EST_REQ_SNT_STATE;

	/* Allocate the memory for response
	 */
	resp = rte_malloc_socket(NULL,
					sizeof(struct resp_info),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* Set create session response */
	//if (pfcp_config.cp_type == PGWC)
	//	resp->sequence = (htonl(context->sequence) >> 8);
	//else
	//	resp->sequence = context->sequence;


	resp->eps_bearer_id = pdn->default_bearer_id - 5;
	//resp->s11_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
	//resp->context = context;
	resp->msg_type = GTP_CREATE_SESSION_REQ;
	resp->state = PFCP_SESS_EST_REQ_SNT_STATE;
	resp->proc = context->pdns[pdn->default_bearer_id - 5]->proc;

	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error sending: %i\n",
				__func__, __LINE__, errno);
		return -1;
	} else {

		/*pfcp-session-estab-req-sent*/
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_est_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, pdn->default_bearer_id - 5);
#endif /* CP_BUILD */
	}

	if (add_sess_entry(context->pdns[pdn->default_bearer_id - 5]->seid, resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to add response in entry in SM_HASH\n",
				__func__, __LINE__);
		return -1;
	}
	return 0;
}

int8_t
process_pfcp_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint64_t sess_id = pfcp_sess_est_rsp->header.seid_seqno.has_seid.seid;
	uint64_t dp_sess_id = pfcp_sess_est_rsp->up_fseid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

#ifdef USE_CSID
	if (pfcp_config.cp_type == PGWC) {
		memcpy(&pfcp_sess_est_rsp->pgw_u_fqcsid,
			&pfcp_sess_est_rsp->sgw_u_fqcsid, sizeof(pfcp_fqcsid_ie_t));
		memset(&pfcp_sess_est_rsp->sgw_u_fqcsid, 0, sizeof(pfcp_fqcsid_ie_t));
	}

	fqcsid_t *tmp = NULL;
	fqcsid_t *fqcsid = NULL;
	fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
				ERR_MSG);
		return -1;
	}
	/* SGW FQ-CSID */
	if (pfcp_sess_est_rsp->sgw_u_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->sgw_u_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = pfcp_sess_est_rsp->sgw_u_fqcsid.node_address;

		for(uint8_t itr = 0; itr < pfcp_sess_est_rsp->sgw_u_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == pfcp_sess_est_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr]) {
					match = 1;
				}
			}
			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					pfcp_sess_est_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr];
			}
		}
		memcpy(fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->up_fseid.ipv4_address,
					ADD);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			tmp->node_addr = pfcp_sess_est_rsp->sgw_u_fqcsid.node_address;
			memcpy(fqcsid, tmp, sizeof(fqcsid_t));
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_sess_est_rsp->pgw_u_fqcsid.header.len) {
		/* Stored the PGW CSID by PGW Node address */
		tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->pgw_u_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = pfcp_sess_est_rsp->pgw_u_fqcsid.node_address;

		for(uint8_t itr = 0; itr < pfcp_sess_est_rsp->pgw_u_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == pfcp_sess_est_rsp->pgw_u_fqcsid.pdn_conn_set_ident[itr]) {
					match = 1;
				}
			}
			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					pfcp_sess_est_rsp->pgw_u_fqcsid.pdn_conn_set_ident[itr];
			}
		}
		memcpy(fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		if (pfcp_config.cp_type == PGWC) {
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->up_fseid.ipv4_address,
					ADD);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			tmp->node_addr = pfcp_sess_est_rsp->pgw_u_fqcsid.node_address;
			memcpy(fqcsid, tmp, sizeof(fqcsid_t));
		}
	}

	/* TODO: Add the handling if SGW or PGW not support Partial failure */
	/* Link peer node SGW or PGW csid with local csid */
	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		ret = update_peer_csid_link(fqcsid, context->sgw_fqcsid);
	} else if (pfcp_config.cp_type == PGWC) {
		ret = update_peer_csid_link(fqcsid, context->pgw_fqcsid);
	}

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Update entry for up session id with link local csid */
	sess_csid *sess_t = NULL;
	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		if (context->sgw_fqcsid) {
			sess_t = get_sess_csid_entry(
					(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1]);
		}
	} else {
		/* PGWC */
		if (context->pgw_fqcsid) {
			sess_t = get_sess_csid_entry(
					(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1]);
		}
	}

	if (sess_t == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Link local csid with session id */
	sess_t->up_seid[sess_t->seid_cnt - 1] = dp_sess_id;

	/* Update the UP CSID in the context */
	context->up_fqcsid = fqcsid;

#endif /* USE_CSID */

	/*TODO need to think on eps_bearer_id*/
	uint8_t ebi_index = resp->eps_bearer_id;

	pdn = context->eps_bearers[ebi_index]->pdn;
	bearer = context->eps_bearers[ebi_index];
	pdn->dp_seid = dp_sess_id;

	/* Update the UE state */
	pdn->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	if (pfcp_config.cp_type == SAEGWC) {
		set_create_session_response(
				gtpv2c_tx, context->sequence, context, pdn, bearer);

		s11_mme_sockaddr.sin_addr.s_addr =
						htonl(context->s11_mme_gtpc_ipv4.s_addr);

	} else if (pfcp_config.cp_type == PGWC) {
		/*TODO: This needs to be change after support libgtpv2 on S5S8*/
		/* set_pgwc_s5s8_create_session_response(gtpv2c_tx,
				(htonl(context->sequence) >> 8), pdn, bearer); */

		create_sess_rsp_t cs_resp = {0};

		//uint32_t  seq_no = 0;
		//seq_no = bswap_32(resp->sequence);
		//seq_no = seq_no >> 8;
		fill_pgwc_create_session_response(&cs_resp,
			context->sequence, context, ebi_index);

#ifdef USE_CSID
		if ((context->pgw_fqcsid)->num_csid) {
			set_gtpc_fqcsid_t(&cs_resp.pgw_fqcsid, IE_INSTANCE_ZERO,
					context->pgw_fqcsid);
		}
#endif /* USE_CSID */

		uint16_t msg_len = encode_create_sess_rsp(&cs_resp, (uint8_t*)gtpv2c_tx);
		msg_len = msg_len - 4;
		gtpv2c_header_t *header;
		header = (gtpv2c_header_t*) gtpv2c_tx;
			header->gtpc.message_len = htons(msg_len);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);
	} else if (pfcp_config.cp_type == SGWC) {
		uint16_t msg_len = 0;
		upf_context_t *upf_context = NULL;

		ret = rte_hash_lookup_data(upf_context_by_ip_hash,
				(const void*) &((context->pdns[ebi_index])->upf_ipv4.s_addr),
				(void **) &(upf_context));

		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, "%s:%d NO ENTRY FOUND IN UPF HASH [%u]\n", __func__,
					__LINE__, (context->pdns[ebi_index])->upf_ipv4.s_addr);
			return GTPV2C_CAUSE_INVALID_PEER;
		}

		ret = add_bearer_entry_by_sgw_s5s8_tied(pdn->s5s8_sgw_gtpc_teid, &context->eps_bearers[ebi_index]);
		if(ret) {
			return ret;
		}

		if(context->indication_flag.oi == 1) {

			memset(gtpv2c_tx, 0, MAX_GTPV2C_UDP_LEN);
			set_modify_bearer_request(gtpv2c_tx, pdn, bearer);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);

			resp->state = MBR_REQ_SNT_STATE;
			pdn->state = resp->state;
			pdn->proc = SGW_RELOCATION_PROC;
			return 0;

		}

		/*Add procedure based call here
		 * for pdn -> CSR
		 * for sgw relocation -> MBR
		 */

		create_sess_req_t cs_req = {0};

		ret = fill_cs_request(&cs_req, context, ebi_index);

#ifdef USE_CSID
		/* Set the SGW FQ-CSID */
		if ((context->sgw_fqcsid)->num_csid) {
			set_gtpc_fqcsid_t(&cs_req.sgw_fqcsid, IE_INSTANCE_ONE,
					context->sgw_fqcsid);
			cs_req.sgw_fqcsid.node_address = ntohl(pfcp_config.s5s8_ip.s_addr);
		}

		/* Set the MME FQ-CSID */
		if ((context->mme_fqcsid)->num_csid) {
			set_gtpc_fqcsid_t(&cs_req.mme_fqcsid, IE_INSTANCE_ZERO,
					context->mme_fqcsid);
		}
#endif /* USE_CSID */
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, "%s:Failed to create the CSR request \n", __func__);
			return 0;
		}

		msg_len = encode_create_sess_req(
				&cs_req,
				(uint8_t*)gtpv2c_tx);

		msg_len = msg_len - 4;
		gtpv2c_header_t *header;
		header = (gtpv2c_header_t*) gtpv2c_tx;
		header->gtpc.message_len = htons(msg_len);

		if (ret < 0)
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to generate S5S8 SGWC CSR.\n",
					__func__, __LINE__);

		s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[ebi_index]->s5s8_pgw_gtpc_ipv4.s_addr);

		/* Update the session state */
		resp->state = CS_REQ_SNT_STATE;
		/* stored teid in csr header for clean up */
		resp->gtpc_msg.csr.header.teid.has_teid.teid = context->pdns[ebi_index]->s5s8_sgw_gtpc_teid;

		/* Update the UE state */
		pdn->state = CS_REQ_SNT_STATE;
		return 0;
	}

	update_sys_stat(number_of_users,INCREMENT);
	update_sys_stat(number_of_active_session, INCREMENT);

	/* Update the session state */
	resp->state = CONNECTED_STATE;

	/* Update the UE state */
	pdn->state = CONNECTED_STATE;
	return 0;
}


int send_pfcp_sess_mod_req_handover(pdn_connection *pdn, eps_bearer *bearer,
		mod_bearer_req_t *mb_req)
{
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	int ebi_index = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi - 5 ;
	if (!(pdn->context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req.update_far_count = 0;

	if (mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.header.len  != 0){
		/* SGW Relocation */
		bearer->s5s8_sgw_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_sgw_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.interface_type);
		if ( pfcp_config.cp_type != PGWC) {
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		}
		pfcp_sess_mod_req.update_far_count++;
	}

	//context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	pdn->seid = SESS_ID(pdn->context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearer, pdn, update_far, 0);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
						pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
	add_pfcp_if_timer_entry(mb_req->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */

	/*Retrive the session information based on session id. */
	//if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
	//
	//
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", pdn->seid);
		return -1;
	}

	pdn->context->sequence = mb_req->header.teid.has_teid.seq;
	/* Set create session response */
	resp->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi -5 ;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	pdn->proc= SGW_RELOCATION_PROC;//GTP_MODIFY_BEARER_REQ;
	resp->proc = pdn->proc;
	return 0;
}
static int
compare_ecgi(ecgi_field_t *mb_ecgi, ecgi_t *context_ecgi)
{
		if(mb_ecgi->ecgi_mcc_digit_1 != context_ecgi->ecgi_mcc_digit_1)
			return FALSE;
		if(mb_ecgi->ecgi_mcc_digit_2 != context_ecgi->ecgi_mcc_digit_2)
			return FALSE;
		if(mb_ecgi->ecgi_mcc_digit_3 != context_ecgi->ecgi_mcc_digit_3)
			return FALSE;
		if(mb_ecgi->ecgi_mnc_digit_1 != context_ecgi->ecgi_mnc_digit_1)
			return FALSE;
		if(mb_ecgi->ecgi_mnc_digit_2 != context_ecgi->ecgi_mnc_digit_2)
			return FALSE;
		if(mb_ecgi->ecgi_mnc_digit_3 != context_ecgi->ecgi_mnc_digit_3)
			return FALSE;
		if(mb_ecgi->ecgi_spare != context_ecgi->ecgi_spare)
			return FALSE;
		if(mb_ecgi->eci != context_ecgi->eci)
			return FALSE;

		return TRUE;
}
static int
compare_cgi(cgi_field_t *mb_cgi, cgi_t *context_cgi)
{
		if(mb_cgi->cgi_mcc_digit_1 != context_cgi->cgi_mcc_digit_1)
			return FALSE;
		if(mb_cgi->cgi_mcc_digit_2 != context_cgi->cgi_mcc_digit_2)
			return FALSE;
		if(mb_cgi->cgi_mcc_digit_3 != context_cgi->cgi_mcc_digit_3)
			return FALSE;
		if(mb_cgi->cgi_mnc_digit_1 != context_cgi->cgi_mnc_digit_1)
			return FALSE;
		if(mb_cgi->cgi_mnc_digit_2 != context_cgi->cgi_mnc_digit_2)
			return FALSE;
		if(mb_cgi->cgi_mnc_digit_3 != context_cgi->cgi_mnc_digit_3)
			return FALSE;
		if(mb_cgi->cgi_lac != context_cgi->cgi_lac)
			return FALSE;
		if(mb_cgi->cgi_ci != context_cgi->cgi_ci)
			return FALSE;

		return TRUE;
}
static int
compare_sai(sai_field_t *mb_sai, sai_t *context_sai)
{
		if(mb_sai->sai_mcc_digit_1 != context_sai->sai_mcc_digit_1)
			return FALSE;
		if(mb_sai->sai_mcc_digit_2 != context_sai->sai_mcc_digit_2)
			return FALSE;
		if(mb_sai->sai_mcc_digit_3 != context_sai->sai_mcc_digit_3)
			return FALSE;
		if(mb_sai->sai_mnc_digit_1 != context_sai->sai_mnc_digit_1)
			return FALSE;
		if(mb_sai->sai_mnc_digit_2 != context_sai->sai_mnc_digit_2)
			return FALSE;
		if(mb_sai->sai_mnc_digit_3 != context_sai->sai_mnc_digit_3)
			return FALSE;
		if(mb_sai->sai_lac != context_sai->sai_lac)
			return FALSE;
		if(mb_sai->sai_sac != context_sai->sai_sac)
			return FALSE;

		return TRUE;
}

static int
compare_rai(rai_field_t *mb_rai, rai_t *context_rai)
{
		if(mb_rai->ria_mcc_digit_1 != context_rai->ria_mcc_digit_1)
			return FALSE;
		if(mb_rai->ria_mcc_digit_2 != context_rai->ria_mcc_digit_2)
			return FALSE;
		if(mb_rai->ria_mcc_digit_3 != context_rai->ria_mcc_digit_3)
			return FALSE;
		if(mb_rai->ria_mnc_digit_1 != context_rai->ria_mnc_digit_1)
			return FALSE;
		if(mb_rai->ria_mnc_digit_2 != context_rai->ria_mnc_digit_2)
			return FALSE;
		if(mb_rai->ria_mnc_digit_3 != context_rai->ria_mnc_digit_3)
			return FALSE;
		if(mb_rai->ria_lac != context_rai->ria_lac)
			return FALSE;
		if(mb_rai->ria_rac != context_rai->ria_rac)
			return FALSE;

		return TRUE;
}

static int
compare_tai(tai_field_t *mb_tai, tai_t *context_tai)
{
		if(mb_tai->tai_mcc_digit_1 != context_tai->tai_mcc_digit_1)
			return FALSE;
		if(mb_tai->tai_mcc_digit_2 != context_tai->tai_mcc_digit_2)
			return FALSE;
		if(mb_tai->tai_mcc_digit_3 != context_tai->tai_mcc_digit_3)
			return FALSE;
		if(mb_tai->tai_mnc_digit_1 != context_tai->tai_mnc_digit_1)
			return FALSE;
		if(mb_tai->tai_mnc_digit_2 != context_tai->tai_mnc_digit_2)
			return FALSE;
		if(mb_tai->tai_mnc_digit_3 != context_tai->tai_mnc_digit_3)
			return FALSE;
		if(mb_tai->tai_tac != context_tai->tai_tac)
			return FALSE;

		return TRUE;
}


static void
save_tai(tai_field_t *mb_tai, tai_t *context_tai)
{

	//context_tai->uli_old.tai = uli->tai;
	context_tai->tai_mcc_digit_2 = mb_tai->tai_mcc_digit_2;
	context_tai->tai_mcc_digit_1 = mb_tai->tai_mcc_digit_1;
	context_tai->tai_mnc_digit_3 = mb_tai->tai_mnc_digit_3;
	context_tai->tai_mcc_digit_3 = mb_tai->tai_mcc_digit_3;
	context_tai->tai_mnc_digit_2 = mb_tai->tai_mnc_digit_2;
	context_tai->tai_mnc_digit_1 = mb_tai->tai_mnc_digit_1;
	context_tai->tai_tac = mb_tai->tai_tac;

}

static void
save_cgi(cgi_field_t *mb_cgi, cgi_t *context_cgi)
{
		context_cgi->cgi_mcc_digit_2 = mb_cgi->cgi_mcc_digit_2;
		context_cgi->cgi_mcc_digit_1 = mb_cgi->cgi_mcc_digit_1;
		context_cgi->cgi_mnc_digit_3 = mb_cgi->cgi_mnc_digit_3;
		context_cgi->cgi_mcc_digit_3 = mb_cgi->cgi_mcc_digit_3;
		context_cgi->cgi_mnc_digit_2 = mb_cgi->cgi_mnc_digit_2;
		context_cgi->cgi_mnc_digit_1 = mb_cgi->cgi_mnc_digit_1;
		context_cgi->cgi_lac = mb_cgi->cgi_lac;
		context_cgi->cgi_ci = mb_cgi->cgi_ci;

}

static void
save_sai(sai_field_t *mb_sai, sai_t *context_sai)
{
		context_sai->sai_mcc_digit_2 = mb_sai->sai_mcc_digit_2;
		context_sai->sai_mcc_digit_1 = mb_sai->sai_mcc_digit_1;
		context_sai->sai_mnc_digit_3 = mb_sai->sai_mnc_digit_3;
		context_sai->sai_mcc_digit_3 = mb_sai->sai_mcc_digit_3;
		context_sai->sai_mnc_digit_2 = mb_sai->sai_mnc_digit_2;
		context_sai->sai_mnc_digit_1 = mb_sai->sai_mnc_digit_1;
		context_sai->sai_lac         = mb_sai->sai_lac;
		context_sai->sai_sac         = mb_sai->sai_sac;

}

static void
save_rai(rai_field_t *mb_rai, rai_t *context_rai)
{
		context_rai->ria_mcc_digit_2 = mb_rai->ria_mcc_digit_2;
		context_rai->ria_mcc_digit_1 = mb_rai->ria_mcc_digit_1;
		context_rai->ria_mnc_digit_3 = mb_rai->ria_mnc_digit_3;
		context_rai->ria_mcc_digit_3 = mb_rai->ria_mcc_digit_3;
		context_rai->ria_mnc_digit_2 = mb_rai->ria_mnc_digit_2;
		context_rai->ria_mnc_digit_1 = mb_rai->ria_mnc_digit_1;
		context_rai->ria_lac = mb_rai->ria_lac;
		context_rai->ria_rac = mb_rai->ria_rac;

}

static void
save_ecgi(ecgi_field_t *mb_ecgi, ecgi_t *context_ecgi)
{
		context_ecgi->ecgi_mcc_digit_2 = mb_ecgi->ecgi_mcc_digit_2;
		context_ecgi->ecgi_mcc_digit_1 = mb_ecgi->ecgi_mcc_digit_1;
		context_ecgi->ecgi_mnc_digit_3 = mb_ecgi->ecgi_mnc_digit_3;
		context_ecgi->ecgi_mcc_digit_3 = mb_ecgi->ecgi_mcc_digit_3;
		context_ecgi->ecgi_mnc_digit_2 = mb_ecgi->ecgi_mnc_digit_2;
		context_ecgi->ecgi_mnc_digit_1 = mb_ecgi->ecgi_mnc_digit_1;
		context_ecgi->ecgi_spare = mb_ecgi->ecgi_spare;
		context_ecgi->eci = mb_ecgi->eci;
}

int process_pfcp_sess_mod_req_handover(mod_bearer_req_t *mb_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	//pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;

	if(pdn->s5s8_sgw_gtpc_ipv4.s_addr != mb_req->sender_fteid_ctl_plane.ipv4_address)
	{
		pdn->old_sgw_addr = pdn->s5s8_sgw_gtpc_ipv4;
		pdn->old_sgw_addr_valid = true;
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;
	}
	if(mb_req->ue_time_zone.header.len)
	{
		if((mb_req->ue_time_zone.time_zone != pdn->ue_tz.tz) ||
				(mb_req->ue_time_zone.daylt_svng_time != pdn->ue_tz.dst))
		{
			pdn->old_ue_tz = pdn->ue_tz;
			pdn->old_ue_tz_valid = TRUE;
			pdn->ue_tz.tz = mb_req->ue_time_zone.time_zone;
			pdn->ue_tz.dst = mb_req->ue_time_zone.daylt_svng_time;
		}
	}

	uint8_t flag_check_uli = 0;

	/*The above flag will be set bit wise as
	 * Bit 7| Bit 6 | Bit 5 | Bit 4 | Bit 3|  Bit 2|  Bit 1|  Bit 0 |
	 *---------------------------------------------------------------
	 *|     |       |       | ECGI  | RAI  |  SAI  |  CGI  |  TAI   |
	 ----------------------------------------------------------------
	 */


	if(mb_req->uli.header.len) {

		if(mb_req->uli.tai) {

			ret = compare_tai(&mb_req->uli.tai2, &pdn->context->uli.tai2);
			if(ret == FALSE) {
				flag_check_uli |= (1 << 0 );
				pdn->context->old_uli_valid = TRUE;
				save_tai(&mb_req->uli.tai2, &pdn->context->old_uli.tai2);
			}
		}

		if(mb_req->uli.cgi) {
			ret = compare_cgi(&mb_req->uli.cgi2, &pdn->context->uli.cgi2);
			if(ret == FALSE) {
				flag_check_uli |= ( 1<< 1 );
				pdn->context->old_uli_valid = TRUE;
				save_cgi(&mb_req->uli.cgi2, &pdn->context->old_uli.cgi2);
			}
		}
		if(mb_req->uli.sai) {
			ret = compare_sai(&mb_req->uli.sai2, &pdn->context->uli.sai2);
			if(ret == FALSE) {
				flag_check_uli |= (1 << 2 );
				pdn->context->old_uli_valid = TRUE;
				save_sai(&mb_req->uli.sai2, &pdn->context->old_uli.sai2);
			}
		}
		if(mb_req->uli.rai) {
			ret = compare_rai(&mb_req->uli.rai2, &pdn->context->uli.rai2);
			if(ret == FALSE) {
				flag_check_uli |= ( 1 << 3 );
				pdn->context->old_uli_valid = TRUE;
				save_rai(&mb_req->uli.rai2, &pdn->context->old_uli.rai2);
			}
		}
		if(mb_req->uli.ecgi) {
			ret = compare_ecgi(&mb_req->uli.ecgi2, &pdn->context->uli.ecgi2);
			if(ret == FALSE) {
				flag_check_uli |= (1 << 4);
				pdn->context->old_uli_valid = TRUE;
				save_ecgi(&mb_req->uli.ecgi2, &pdn->context->old_uli.ecgi2);
			}
		}
	}

	/* TODO something with modify_bearer_request.delay if set */
	if(((context->old_uli_valid == TRUE) && (((context->event_trigger & (1 << ULI_EVENT_TRIGGER))) != 0))
		|| ((pdn->old_ue_tz_valid == TRUE) && (((context->event_trigger) & (1 << UE_TIMEZONE_EVT_TRIGGER)) != 0))) {

#ifdef GX_BUILD
		ret = gen_ccru_request(pdn, bearer, mb_req, flag_check_uli);
#endif /* GX_BUILD */
		pdn->context->old_uli_valid = FALSE;
		pdn->old_ue_tz_valid = FALSE;

		/*Retrive the session information based on session id. */
		if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", context->pdns[ebi_index]->seid);
			return -1;
		}
		 resp->gtpc_msg.mbr = *mb_req;

		return ret;
	}
	ret = send_pfcp_sess_mod_req_handover(pdn, bearer, mb_req);

	return 0;
}

int
process_pfcp_sess_mod_resp_del_cmd(uint64_t sess_id, gtpv2c_header_t *gtpv2c_rx ,uint8_t *is_del_cmd)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	if(resp->msg_type == GTP_DELETE_BEARER_CMD){
		ret = get_ue_context(teid, &context);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
		}
		resp->state = DELETE_BER_REQ_SNT_STATE;
		ebi_index = resp->eps_bearer_id;
		bearer = context->eps_bearers[ebi_index];
		bearer->pdn->state = DELETE_BER_REQ_SNT_STATE;
		set_delete_bearer_request(gtpv2c_rx, context->sequence,
				context, 0, resp->eps_bearer_ids, resp->bearer_count);

		if(pfcp_config.cp_type == PGWC) {
			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);
		} else if (pfcp_config.cp_type == SAEGWC) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		}
		resp->proc = context->eps_bearers[ebi_index]->pdn->proc;
	}else {
		*is_del_cmd = 0;

		/* Get ue context and update state to connected state */
		ret = get_ue_context(teid, &context);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
		}

		uint8_t ebi_index = UE_BEAR_ID(sess_id);
		context->pdns[ebi_index - 5]->state = CONNECTED_STATE;

		/*  update state to connected state in resp */
		resp->state = CONNECTED_STATE;
	}
	return 0;
}


int
process_sess_mod_req_del_cmd(pdn_connection *pdn)
{
	int ret = 0;
	ue_context *context = NULL;
	eps_bearer *bearers[MAX_BEARER];
	int ebi = 0;
	struct resp_info *resp = NULL;
	int teid = UE_SESS_ID(pdn->seid);
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	int ebi_index = 0;

	ret = get_ue_context(teid, &context);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
	                     __func__, __LINE__,
			   teid);
	}

	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", pdn->seid);
		return -1;
	}
	ebi_index = resp->eps_bearer_id;
	s11_mme_sockaddr.sin_addr.s_addr =
		context->s11_mme_gtpc_ipv4.s_addr;

	for (uint8_t iCnt = 0; iCnt < resp->bearer_count; ++iCnt) {
		ebi = resp->eps_bearer_ids[iCnt];
		bearers[iCnt] = context->eps_bearers[ebi - 5];

		}

	fill_pfcp_sess_mod_req_pgw_del_cmd_update_far(&pfcp_sess_mod_req ,pdn, bearers, resp->bearer_count);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	} else {

		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);

#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */

	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update the sequence number */
	context->sequence = resp->gtpc_msg.del_bearer_cmd.header.teid.has_teid.seq;


//	resp->gtpc_msg.del_bearer_cmd = *del_bearer_cmd;
//	resp->eps_bearer_id = ebi_index;
	resp->s5s8_pgw_gtpc_ipv4 = htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);
	resp->msg_type = GTP_DELETE_BEARER_CMD;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;
//	resp->bearer_count = del_bearer_cmd->bearer_count;
//	for (uint8_t iCnt = 0; iCnt < del_bearer_cmd->bearer_count; ++iCnt) {
//		resp->eps_bearer_ids[iCnt] = del_bearer_cmd->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi;
//	}
	return 0;
}

int
process_delete_bearer_cmd_request(del_bearer_cmd_t *del_bearer_cmd, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	int ebi_index = 0;
	struct resp_info *resp = NULL;

	ret = get_ue_context(del_bearer_cmd->header.teid.has_teid.teid, &context);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
	                     __func__, __LINE__,
	                  del_bearer_cmd->header.teid.has_teid.teid);
	}
	ebi_index = del_bearer_cmd->bearer_contexts[ebi_index].eps_bearer_id.ebi_ebi -5;

	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;


	if (SAEGWC == pfcp_config.cp_type || PGWC == pfcp_config.cp_type) {
#ifdef GX_BUILD
	if (ccru_req_for_bear_termination(pdn , bearer)) {
				clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: %s \n", __func__, __LINE__,
						strerror(errno));
				return -1;
			}
#endif
	} else if(SGWC == pfcp_config.cp_type) {

		set_delete_bearer_command(del_bearer_cmd, pdn, gtpv2c_tx);
		s5s8_recv_sockaddr.sin_addr.s_addr =
			               htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);

	}
	pdn->state = CONNECTED_STATE;
	if (get_sess_entry(pdn->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
					__func__, __LINE__, pdn->seid);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		resp->eps_bearer_id = ebi_index;
		resp->msg_type = GTP_DELETE_BEARER_CMD;
		resp->state = CONNECTED_STATE;//need to see this
		resp->gtpc_msg.del_bearer_cmd = *del_bearer_cmd;
		resp->gtpc_msg.del_bearer_cmd.header.teid.has_teid.seq = del_bearer_cmd->header.teid.has_teid.seq;
		resp->proc = pdn->proc;
		resp->bearer_count = del_bearer_cmd->bearer_count;
		for (uint8_t iCnt = 0; iCnt < del_bearer_cmd->bearer_count; ++iCnt) {
			resp->eps_bearer_ids[iCnt] = del_bearer_cmd->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi;
		}

	return 0;
}

int
process_pfcp_sess_mod_request(mod_bearer_req_t *mb_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if (!mb_req->bearer_contexts_to_be_modified.eps_bearer_id.header.len
			|| !mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.header.len) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Dropping packet\n",
				__func__, __LINE__);
		return GTPV2C_CAUSE_INVALID_LENGTH;
	}

	ebi_index = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Received modify bearer on non-existent EBI - "
				"Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = bearer->pdn;
	if(mb_req->ue_time_zone.header.len)
	{
		if((mb_req->ue_time_zone.time_zone != pdn->ue_tz.tz) ||
				(mb_req->ue_time_zone.daylt_svng_time != pdn->ue_tz.dst))
		{
			pdn->old_ue_tz = pdn->ue_tz;
			pdn->old_ue_tz_valid = true;
			pdn->ue_tz.tz = mb_req->ue_time_zone.time_zone;
			pdn->ue_tz.dst = mb_req->ue_time_zone.daylt_svng_time;
		}
	}

	/* TODO something with modify_bearer_request.delay if set */

	if (mb_req->bearer_contexts_to_be_modified.s11_u_mme_fteid.header.len &&
			(context->s11_mme_gtpc_teid != mb_req->bearer_contexts_to_be_modified.s11_u_mme_fteid.teid_gre_key))
		context->s11_mme_gtpc_teid = mb_req->bearer_contexts_to_be_modified.s11_u_mme_fteid.teid_gre_key;

	bearer->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req.update_far_count = 0;
	uint8_t x2_handover = 0;

	if (mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.header.len  != 0){

		if(bearer->s1u_enb_gtpu_ipv4.s_addr != 0) {
			if((mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.teid_gre_key)
					!= bearer->s1u_enb_gtpu_teid  ||
					(mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.ipv4_address) !=
					bearer->s1u_enb_gtpu_ipv4.s_addr) {

				x2_handover = 1;
			}
		}

		/* Bug 370. No need to send end marker packet in DDN */
		if (CONN_SUSPEND_PROC == pdn->proc) {
			x2_handover = 0;
		}

		bearer->s1u_enb_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.ipv4_address;
		bearer->s1u_enb_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s1u_enb_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s1u_enb_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.interface_type);
		update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		pfcp_sess_mod_req.update_far_count++;

	}

	if (mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.header.len  != 0){
		bearer->s5s8_sgw_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_sgw_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.interface_type);
		if ( pfcp_config.cp_type != PGWC) {
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		}
		pfcp_sess_mod_req.update_far_count++;
	}

	context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearer, pdn, update_far, x2_handover);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	} else {
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(mb_req->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update the Sequence number for the request */
	context->sequence = mb_req->header.teid.has_teid.seq;

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, context->pdns[ebi_index]->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Set create session response */
	resp->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->gtpc_msg.mbr = *mb_req;

	return 0;
}

#ifdef GX_BUILD
/**
 * @brief  : Generate reauth response
 * @param  : context , pointer to ue context structure
 * @param  : ebi_index, index in array where eps bearer is stored
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
gen_reauth_response(ue_context *context, uint8_t ebi_index)
{
	/* VS: Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	char *buffer = NULL;
	gx_msg raa = {0};
	pdn_connection *pdn = NULL;
	gx_context_t *gx_context = NULL;
	uint16_t msg_type_ofs = 0;
	uint16_t msg_body_ofs = 0;
	uint16_t rqst_ptr_ofs = 0;
	uint16_t msg_len_total = 0;

	pdn = context->eps_bearers[ebi_index]->pdn;

	/* Clear Policy in PDN */
	pdn->policy.count = 0;
	pdn->policy.num_charg_rule_install = 0;
	pdn->policy.num_charg_rule_modify = 0;
	pdn->policy.num_charg_rule_delete = 0;

	/* Allocate the memory for Gx Context */
	gx_context = rte_malloc_socket(NULL,
			sizeof(gx_context_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	//strncpy(gx_context->gx_sess_id, context->pdns[ebi_index]->gx_sess_id, strlen(context->pdns[ebi_index]->gx_sess_id));


	raa.data.cp_raa.session_id.len = strlen(pdn->gx_sess_id);
	memcpy(raa.data.cp_raa.session_id.val, pdn->gx_sess_id, raa.data.cp_raa.session_id.len);

	raa.data.cp_raa.presence.session_id = PRESENT;

	/* VS: Set the Msg header type for CCR */
	raa.msg_type = GX_RAA_MSG;

	/* Result code */
	raa.data.cp_raa.result_code = 2001;
	raa.data.cp_raa.presence.result_code = PRESENT;

	/* Update UE State */
	pdn->state = RE_AUTH_ANS_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = RE_AUTH_ANS_SNT_STATE;

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_raa_calc_length(&raa.data.cp_raa);
	msg_body_ofs = sizeof(raa.msg_type);
	rqst_ptr_ofs = msg_len + msg_body_ofs;
	msg_len_total = rqst_ptr_ofs + sizeof(pdn->rqst_ptr);

	//buffer = rte_zmalloc_socket(NULL, msg_len + sizeof(uint64_t) + sizeof(raa.msg_type),
	//		RTE_CACHE_LINE_SIZE, rte_socket_id());
	buffer = rte_zmalloc_socket(NULL, msg_len_total,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	memcpy(buffer + msg_type_ofs, &raa.msg_type, sizeof(raa.msg_type));

	//if (gx_raa_pack(&(raa.data.cp_raa), (unsigned char *)(buffer + sizeof(raa.msg_type)), msg_len) == 0 )
	if (gx_raa_pack(&(raa.data.cp_raa), (unsigned char *)(buffer + msg_body_ofs), msg_len) == 0 )
		clLog(clSystemLog, eCLSeverityDebug,"RAA Packing failure\n");

	//memcpy((unsigned char *)(buffer + sizeof(raa.msg_type) + msg_len), &(context->eps_bearers[1]->rqst_ptr),
	memcpy((unsigned char *)(buffer + rqst_ptr_ofs), &(pdn->rqst_ptr),
			sizeof(pdn->rqst_ptr));
#if 0
	clLog(clSystemLog, eCLSeverityDebug,"While packing RAA %p %p\n", (void*)(context->eps_bearers[1]->rqst_ptr),
			*(void**)(buffer+rqst_ptr_ofs));

	clLog(clSystemLog, eCLSeverityDebug,"msg_len_total [%d] msg_type_ofs[%d] msg_body_ofs[%d] rqst_ptr_ofs[%d]\n",
			msg_len_total, msg_type_ofs, msg_body_ofs, rqst_ptr_ofs);
#endif
	/* VS: Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len_total);
			//msg_len + sizeof(raa.msg_type) + sizeof(unsigned long));

	return 0;
}
#endif


uint8_t
process_delete_bearer_pfcp_sess_response(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);
	uint8_t bearer_id = UE_BEAR_ID(sess_id) - 5;

	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(sxlogger, eCLSeverityCritical,
			"%s:%d NO Session Entry Found for sess ID:%lu\n",
			__func__, __LINE__, sess_id);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(sxlogger, eCLSeverityCritical,
			"%s:%d Failed to update UE State for teid: %u\n",
			__func__, __LINE__, teid);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	context->pdns[bearer_id]->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (resp->msg_type == GX_RAR_MSG) {
		uint8_t lbi = 0;
		uint8_t bearer_count = 0;
		uint8_t eps_bearer_ids[MAX_BEARERS];

#ifdef GX_BUILD
		get_charging_rule_remove_bearer_info(
			context->pdns[bearer_id],
			&lbi, eps_bearer_ids, &bearer_count);
#endif

		set_delete_bearer_request(gtpv2c_tx, context->sequence,
			context, lbi, eps_bearer_ids, bearer_count);

		resp->state = DELETE_BER_REQ_SNT_STATE;
		context->pdns[bearer_id]->state = DELETE_BER_REQ_SNT_STATE;

		if (SAEGWC == pfcp_config.cp_type) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		} else {
			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[bearer_id]->s5s8_sgw_gtpc_ipv4.s_addr);
		}

	} else if (resp->msg_type == GTP_DELETE_BEARER_REQ) {
		set_delete_bearer_request(gtpv2c_tx, context->sequence,
			context, resp->linked_eps_bearer_id,
			resp->eps_bearer_ids, resp->bearer_count);

		resp->state = DELETE_BER_REQ_SNT_STATE;
		context->pdns[bearer_id]->state = DELETE_BER_REQ_SNT_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
			htonl(context->s11_mme_gtpc_ipv4.s_addr);

	} else if (resp->msg_type == GTP_DELETE_BEARER_RSP) {

		if ((SAEGWC == pfcp_config.cp_type) ||
			(PGWC == pfcp_config.cp_type)) {
#ifdef GX_BUILD
			delete_dedicated_bearers(context->pdns[bearer_id],
				resp->eps_bearer_ids, resp->bearer_count);

			gen_reauth_response(context, resp->eps_bearer_id - 5);

			resp->state = CONNECTED_STATE;
			resp->msg_type = GX_RAA_MSG;
			context->pdns[resp->eps_bearer_id - 5]->state = CONNECTED_STATE;

			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
#endif
		} else {
			delete_dedicated_bearers(context->pdns[bearer_id],
				resp->eps_bearer_ids, resp->bearer_count);

			set_delete_bearer_response(gtpv2c_tx, context->sequence,
				resp->linked_eps_bearer_id,
				resp->eps_bearer_ids, resp->bearer_count,
				context->pdns[bearer_id]->s5s8_pgw_gtpc_teid);

			resp->state = CONNECTED_STATE;
			context->pdns[bearer_id]->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[bearer_id]->s5s8_pgw_gtpc_ipv4.s_addr);
		}
	}

	return 0;
}


uint8_t
process_pfcp_sess_mod_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
	}

	ebi_index = UE_BEAR_ID(sess_id) - 5;
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		/* Fill the modify bearer response */
		set_modify_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer);

		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;

		/* Update the next hop IP address */
		if (PGWC != pfcp_config.cp_type) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		}
		return 0;

	} else if (resp->msg_type == GTP_CREATE_SESSION_RSP) {
		/* Fill the Create session response */
		set_create_session_response(
				gtpv2c_tx, context->sequence, context, bearer->pdn, bearer);

	} else if (resp->msg_type == GX_RAR_MSG) {
#ifdef GX_BUILD
		uint8_t ebi = 0;
		get_bearer_info_install_rules(pdn, &ebi);
		bearer = context->eps_bearers[ebi];
		if (!bearer) {
			clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		/* TODO: NC Need to remove hard coded pti value */
		set_create_bearer_request(gtpv2c_tx, context->sequence, context,
				bearer, pdn->default_bearer_id, 0, NULL, 0);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;

		if (SAEGWC == pfcp_config.cp_type) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		} else {
		    s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);
		}

		return 0;
#endif
	} else if (resp->msg_type == GTP_CREATE_BEARER_REQ) {
		bearer = context->eps_bearers[resp->eps_bearer_id - 5];
		set_create_bearer_request(
				gtpv2c_tx, context->sequence, context, bearer,
				pdn->default_bearer_id, 0, resp->eps_bearer_lvl_tft, resp->tft_header_len);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

		return 0;

	} else if (resp->msg_type == GTP_CREATE_BEARER_RSP) {

		if ((SAEGWC == pfcp_config.cp_type) || (PGWC == pfcp_config.cp_type)) {
#ifdef GX_BUILD
			gen_reauth_response(context, resp->eps_bearer_id - 5);
			struct sockaddr_in saddr_in;
			saddr_in.sin_family = AF_INET;
			inet_aton("127.0.0.1", &(saddr_in.sin_addr));
			update_cli_stats(saddr_in.sin_addr.s_addr, OSS_RAA, SENT, GX);

			resp->msg_type = GX_RAA_MSG;
			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			return 0;

#endif
		} else {
			bearer = context->eps_bearers[resp->eps_bearer_id - 5];
			set_create_bearer_response(
				gtpv2c_tx, context->sequence, context, bearer, resp->eps_bearer_id, 0);

			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[0]->s5s8_pgw_gtpc_ipv4.s_addr);

			return 0;
		}
	} else if(resp->msg_type == GTP_DELETE_SESSION_REQ){
		if (pfcp_config.cp_type == SGWC) {
			uint8_t encoded_msg[512];

			/* Indication flags not required in DSR for PGWC */
			resp->gtpc_msg.dsr.indctn_flgs.header.len = 0;
			encode_del_sess_req(
					(del_sess_req_t *)&(resp->gtpc_msg.dsr),
					encoded_msg);

			gtpv2c_header *header;
			header =(gtpv2c_header*) encoded_msg;

			ret =
				gen_sgwc_s5s8_delete_session_request((gtpv2c_header_t *)encoded_msg,
						gtpv2c_tx, htonl(bearer->pdn->s5s8_pgw_gtpc_teid),
						header->teid_u.has_teid.seq,
						resp->eps_bearer_id);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				resp->s5s8_pgw_gtpc_ipv4;

			/* Update the session state */
			resp->state = DS_REQ_SNT_STATE;

			/* Update the UE state */
			ret = update_ue_state(context->s11_sgw_gtpc_teid,
					DS_REQ_SNT_STATE, resp->eps_bearer_id - 5);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State.\n", __func__);
			}

			clLog(sxlogger, eCLSeverityDebug, "SGWC:%s: "
					"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__,
					inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

			return ret;
		}
	} else {
		/* Fill the release bearer response */
		set_release_access_bearer_response(gtpv2c_tx,
				context->sequence, context->s11_mme_gtpc_teid);

		/* Update the session state */
		resp->state = IDEL_STATE;

		/* Update the UE state */
		pdn->state = IDEL_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
						htonl(context->s11_mme_gtpc_ipv4.s_addr);

		clLog(sxlogger, eCLSeverityDebug, "%s:%d s11_mme_sockaddr.sin_addr.s_addr :%s\n",
				__func__, __LINE__,
				inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

		return 0;
	}

	/* Update the session state */
	resp->state = CONNECTED_STATE;

	/* Update the UE state */
	pdn->state = CONNECTED_STATE;

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(sxlogger, eCLSeverityDebug, "%s:%d s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
				__LINE__, inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	return 0;
}

int
process_sgwc_delete_session_request(del_sess_req_t *del_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &del_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = del_req->lbi.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;

	bearer->eps_bearer_id = del_req->lbi.ebi_ebi;

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, &del_req->header, context, pdn);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	} else {
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update the sequence number */
	context->sequence =
		del_req->header.teid.has_teid.seq;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", context->pdns[ebi_index]->seid);
		return -1;
	}

	resp->gtpc_msg.dsr = *del_req;
	resp->eps_bearer_id = del_req->lbi.ebi_ebi;
	resp->s5s8_pgw_gtpc_ipv4 = htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;

	return 0;
}

int
process_pfcp_sess_del_request(del_sess_req_t *ds_req)
{

	int ret = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint32_t s5s8_pgw_gtpc_teid = 0;
	uint32_t s5s8_pgw_gtpc_ipv4 = 0;
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	uint64_t ebi_index = ds_req->lbi.ebi_ebi - 5;

	/* Lookup and get context of delete request */
	ret = delete_context(ds_req->lbi, ds_req->header.teid.has_teid.teid,
		&context, &s5s8_pgw_gtpc_teid, &s5s8_pgw_gtpc_ipv4);
	if (ret)
		return ret;

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->pdns[ebi_index]->dp_seid;

	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"%s:%d Error sending: %i\n", __func__, __LINE__, errno);
		return -1;
	} else  {

				update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_del_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update the sequence number */
	context->sequence =
		ds_req->header.teid.has_teid.seq;

	/* Update UE State */
	pdn = GET_PDN(context, ebi_index);
	pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, context->pdns[ebi_index]->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Store s11 struture data into sm_hash for sending delete response back to s11 */
	resp->gtpc_msg.dsr = *ds_req;
	resp->eps_bearer_id = ds_req->lbi.ebi_ebi;
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
	resp->proc = pdn->proc;

	return 0;
}


int
process_pfcp_sess_del_request_delete_bearer_rsp(del_bearer_rsp_t *db_rsp)
{
	int ret = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t s5s8_pgw_gtpc_teid = 0;
	uint32_t s5s8_pgw_gtpc_ipv4 = 0;
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	uint64_t ebi_index = db_rsp->lbi.ebi_ebi - 5;

	ret = delete_context(db_rsp->lbi, db_rsp->header.teid.has_teid.teid,
		&context, &s5s8_pgw_gtpc_teid, &s5s8_pgw_gtpc_ipv4);
	if (ret)
		return ret;

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->pdns[ebi_index]->dp_seid;

	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		clLog(sxlogger, eCLSeverityCritical,
			"%s:%d Error sending: %i\n", __func__, __LINE__, errno);
		return -1;
	} else  {

		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_del_req.header.message_type, SENT, SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(db_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update the sequence number */
	context->sequence =
		db_rsp->header.teid.has_teid.seq;

	/* Update UE State */
	context->pdns[ebi_index]->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		clLog(sxlogger, eCLSeverityCritical,
			"%s:%d NO Session Entry Found for sess ID:%lu\n",
			__func__, __LINE__, context->pdns[ebi_index]->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->eps_bearer_id = db_rsp->lbi.ebi_ebi;
	resp->msg_type = GTP_DELETE_BEARER_RSP;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
	resp->proc = context->pdns[ebi_index]->proc;

	return 0;
}

int
delete_dedicated_bearers(pdn_connection *pdn,
		uint8_t bearer_ids[], uint8_t bearer_cntr)
{
	eps_bearer *ded_bearer = NULL;

	/* Delete multiple dedicated bearer of pdn */
	for (int iCnt = 0; iCnt < bearer_cntr; ++iCnt) {

		uint8_t ebi = bearer_ids[iCnt] - 5;

		/* Fetch dynamic rules from bearer and delete from hash */
		ded_bearer = pdn->eps_bearers[ebi];

		/* Traverse all dynamic filters from bearer */
		for (uint8_t index = 0; index < ded_bearer->num_dynamic_filters; ++index) {
			rule_name_key_t rule_name = {0};
			strncpy(rule_name.rule_name,
					ded_bearer->dynamic_rules[index]->rule_name,
					strlen(ded_bearer->dynamic_rules[index]->rule_name));
			sprintf(rule_name.rule_name, "%s%d",
					rule_name.rule_name, pdn->call_id);

			/* Delete rule name from hash */
			if (del_rule_name_entry(rule_name)) {
				/* TODO: Error handling rule not found */
				return -1;
			}
		}

		/* Delete PDR, QER of bearer */
		if (del_rule_entries(pdn->context, ebi)) {
			/* TODO: Error message handling in case deletion failed */
			return -1;
		}

		pdn->num_bearer--;
		rte_free(pdn->eps_bearers[ebi]);
		pdn->eps_bearers[ebi] = NULL;
		pdn->context->eps_bearers[ebi] = NULL;
	}

	return 0;
}

int
del_rule_entries(ue_context *context, uint8_t ebi_index)
{
	int ret = 0;
	pdr_t *pdr_ctx =  NULL;

	/*Delete all pdr, far, qer entry from table */
#ifdef GX_BUILD
    for(uint8_t itr = 0; itr < context->eps_bearers[ebi_index]->qer_count ; itr++) {
 		if( del_qer_entry(context->eps_bearers[ebi_index]->qer_id[itr].qer_id) != 0 ){
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s %d %s - Error del_pdr_entry deletion\n",__file__,
					__func__, __LINE__, strerror(ret));
		}
    }
#endif
	for(uint8_t itr = 0; itr < context->eps_bearers[ebi_index]->pdr_count ; itr++) {
		pdr_ctx = context->eps_bearers[ebi_index]->pdrs[itr];
		if(pdr_ctx == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s %d %s - Error no pdr entry \n",__file__,
					__func__, __LINE__, strerror(ret));
		}
		if( del_pdr_entry(context->eps_bearers[ebi_index]->pdrs[itr]->rule_id) != 0 ){
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s %d %s - Error del_pdr_entry deletion\n",__file__,
					__func__, __LINE__, strerror(ret));
		}
	}
	return 0;
}

int8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		gx_msg *ccr_request, uint16_t *msglen )
{
	int ret = 0;
	uint8_t ebi_index = 0;
	uint16_t msg_len = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	del_sess_rsp_t del_resp = {0};
	uint32_t teid = UE_SESS_ID(sess_id);

	//eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_DEL_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
	}


	ebi_index = resp->eps_bearer_id - 5;
	pdn = context->eps_bearers[ebi_index]->pdn;

	/* Update the UE state */
	pdn->state = PFCP_SESS_DEL_RESP_RCVD_STATE;
#ifdef GX_BUILD
	if ( pfcp_config.cp_type != SGWC) {

		gx_context_t *gx_context = NULL;

		/* Retrive Gx_context based on Sess ID. */
		ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
				(const void*)(pdn->gx_sess_id),
				(void **)&gx_context);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
					pdn->gx_sess_id);
			return -1;
		}

		/* VS: Set the Msg header type for CCR-T */
		ccr_request->msg_type = GX_CCR_MSG ;

		/* VS: Set Credit Control Request type */
		ccr_request->data.ccr.presence.cc_request_type = PRESENT;
		ccr_request->data.ccr.cc_request_type = TERMINATION_REQUEST ;

		/* VG: Set Credit Control Bearer opertaion type */
		ccr_request->data.ccr.presence.bearer_operation = PRESENT;
		ccr_request->data.ccr.bearer_operation = TERMINATION ;

		/* VS: Fill the Credit Crontrol Request to send PCRF */
		if(fill_ccr_request(&ccr_request->data.ccr, context, ebi_index, pdn->gx_sess_id) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
			return -1;
		}
		/* Update UE State */
		pdn->state = CCR_SNT_STATE;

		/* VS: Set the Gx State for events */
		gx_context->state = CCR_SNT_STATE;
		gx_context->proc = pdn->proc;

		/* VS: Calculate the max size of CCR msg to allocate the buffer */
		*msglen = gx_ccr_calc_length(&ccr_request->data.ccr);

	}
#else
	 RTE_SET_USED(msglen);
	 RTE_SET_USED(ccr_request);

#endif /* GX_BUILD */

	if ( pfcp_config.cp_type == PGWC) {

		fill_pgwc_ds_sess_rsp(&del_resp, context->sequence,
				pdn->s5s8_sgw_gtpc_teid);

		uint16_t msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

		gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;
		header->gtpc.message_len = htons(msg_len -4);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						htonl(context->pdns[ebi_index]->s5s8_sgw_gtpc_ipv4.s_addr);

		/* Delete entry from session entry */
		if (del_sess_entry(sess_id) != 0){
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for Key sess ID:%lu\n",
					__func__, __LINE__, sess_id);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		clLog(sxlogger, eCLSeverityDebug, "PGWC:%s:%d "
				"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__, __LINE__,
				inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

		if ( del_rule_entries(context, ebi_index) != 0 ){
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s - Error on delete rule entries\n",__file__,
					strerror(ret));
		}
		ret = delete_sgwc_context(teid, &context, &sess_id);
		if (ret)
			return ret;
		if(context->num_pdns == 0){
		/* Delete UE context entry from UE Hash */
		if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0){
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s - Error on ue_context_by_fteid_hash deletion\n",__file__,
					strerror(ret));
		}

#ifdef USE_DNS_QUERY
		/* Delete UPFList entry from UPF Hash */
		if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi))) < 0){
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s - Error on upflist_by_ue_hash deletion of IMSI \n",__file__,
					strerror(ret));
		}
#endif /* USE_DNS_QUERY */

#ifdef USE_CSID
		fqcsid_t *csids = context->pgw_fqcsid;

		/* Get the session ID by csid */
		for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
			sess_csid *tmp = NULL;

			tmp = get_sess_csid_entry(csids->local_csid[itr]);
			if (tmp == NULL)
				continue;

			/* VS: Delete sess id from csid table */
			for(uint16_t cnt = 0; cnt < tmp->seid_cnt; cnt++) {
				if (sess_id == tmp->cp_seid[cnt]) {
					for(uint16_t pos = cnt; pos < (tmp->seid_cnt - 1); pos++ )
						tmp->cp_seid[pos] = tmp->cp_seid[pos + 1];

					tmp->seid_cnt--;
					clLog(clSystemLog, eCLSeverityDebug, "Session Deleted from csid table sid:%lu\n",
							sess_id);
				}
			}

			if (tmp->seid_cnt == 0) {
				/* Cleanup Internal data structures */
				ret = del_peer_csid_entry(&csids->local_csid[itr], S5S8_PGWC_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					return -1;
				}

				/* Clean MME FQ-CSID */
				if (context->mme_fqcsid != 0) {
					ret = del_peer_csid_entry(&(context->mme_fqcsid)->local_csid[itr], S5S8_PGWC_PORT_ID);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
										strerror(errno));
						return -1;
					}
					if (!(context->mme_fqcsid)->num_csid)
						rte_free(context->mme_fqcsid);
				}

				/* Clean UP FQ-CSID */
				if (context->up_fqcsid != 0) {
					ret = del_peer_csid_entry(&(context->up_fqcsid)->local_csid[itr],
							SX_PORT_ID);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
										strerror(errno));
						return -1;
					}
					if (!(context->up_fqcsid)->num_csid)
						rte_free(context->up_fqcsid);
				}
			}

		}

#endif /* USE_CSID */
		rte_free(context);
	}

		return 0;
	}


	/* Fill gtpv2c structure for sending on s11 interface */
	set_gtpv2c_teid_header((gtpv2c_header_t *) &del_resp, GTP_DELETE_SESSION_RSP,
			context->s11_mme_gtpc_teid, context->sequence);
	set_cause_accepted_ie((gtpv2c_header_t *) &del_resp, IE_INSTANCE_ZERO);

	del_resp.cause.header.len = ntohs(del_resp.cause.header.len);

	/*Encode the S11 delete session response message. */
	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(s11logger, eCLSeverityDebug, "SAEGWC:%s:%d"
			"s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__, __LINE__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));


	/* Delete entry from session entry */
	if (del_sess_entry(sess_id) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for Key sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return -1;
	}

	if (del_rule_entries(context, ebi_index) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s %s - Error on delete rule entries\n",__file__,
				strerror(ret));
	}
	ret = delete_sgwc_context(teid, &context, &sess_id);
	if (ret)
		return ret;
	if(context->num_pdns == 0){
	/* Delete UE context entry from UE Hash */
	if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s %s - Error on ue_context_by_fteid_hash del\n",__file__,
				strerror(ret));
	}

#ifdef USE_DNS_QUERY
	/* Delete UPFList entry from UPF Hash */
	if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi))) < 0){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s %s - Error on upflist_by_ue_hash deletion of IMSI \n",__file__,
				strerror(ret));
	}
#endif /* USE_DNS_QUERY */

#ifdef USE_CSID
	fqcsid_t *csids = context->sgw_fqcsid;

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
		sess_csid *tmp = NULL;

		tmp = get_sess_csid_entry(csids->local_csid[itr]);
		if (tmp == NULL)
			continue;

		/* VS: Delete sess id from csid table */
		for(uint16_t cnt = 0; cnt < tmp->seid_cnt; cnt++) {
			if (sess_id == tmp->cp_seid[cnt]) {
				for(uint16_t pos = cnt; pos < (tmp->seid_cnt - 1); pos++ )
					tmp->cp_seid[pos] = tmp->cp_seid[pos + 1];

				tmp->seid_cnt--;
				clLog(clSystemLog, eCLSeverityDebug, "Session Deleted from csid table sid:%lu\n",
						sess_id);
			}
		}

		if (tmp->seid_cnt == 0) {
			/* Cleanup Internal data structures */
			ret = del_peer_csid_entry(&csids->local_csid[itr], S5S8_PGWC_PORT_ID);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
				return -1;
			}

			/* Clean MME FQ-CSID */
			if (context->mme_fqcsid != 0) {
				ret = del_peer_csid_entry(&(context->mme_fqcsid)->local_csid[itr], S5S8_PGWC_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					return -1;
				}
				if (!(context->mme_fqcsid)->num_csid)
					rte_free(context->mme_fqcsid);
			}

			/* Clean UP FQ-CSID */
			if (context->up_fqcsid != 0) {
				ret = del_peer_csid_entry(&(context->up_fqcsid)->local_csid[itr],
						SX_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					return -1;
				}
				if (!(context->up_fqcsid)->num_csid)
					rte_free(context->up_fqcsid);
			}
		}

	}

#endif /* USE_CSID */

	//Free UE context
	rte_free(context);
	}
	return 0;
}

void
fill_pfcp_sess_mod_req_delete( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, ue_context *context, pdn_connection *pdn)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;
	eps_bearer *bearer;

	RTE_SET_USED(context);  /* NK:to be checked */

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	if( header != NULL)
		clLog(sxlogger, eCLSeverityDebug, "TEID[%d]\n", header->teid.has_teid.teid);

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	/*SP: Adding FAR IE*/
	pfcp_sess_mod_req->update_far_count = 0;
	for (int index = 0; index < pdn->num_bearer; index++){
		bearer = pdn->eps_bearers[index];
		if(bearer){
			for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					updating_far(&(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]));
					pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count].far_id.far_id_value = pdr_ctxt->far.far_id_value;
					pfcp_sess_mod_req->update_far_count++;
				}
			}
		}
	}
		switch (pfcp_config.cp_type)
		{
			case SGWC :
				if(pfcp_sess_mod_req->update_far_count){
					for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count; itr1++) {
						pfcp_sess_mod_req->update_far[itr1].apply_action.drop = PRESENT;
					}
				}
				break;

			default :
				clLog(clSystemLog, eCLSeverityDebug,"default pfcp sess mod req\n");
				break;
		}
	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	pfcp_sess_mod_req->pfcpsmreq_flags.drobu = PRESENT;

	/*SP: This IE is included if one of DROBU and QAURR flag is set,
	  excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}
}


void
fill_pfcp_sess_mod_req_pgw_init_update_far(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;
	eps_bearer *bearer = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	pfcp_sess_mod_req->update_far_count = 0;
	for (uint8_t index = 0; index < bearer_cntr; index++){
		bearer = bearers[index];
		if(bearer != NULL) {
			for(uint8_t itr = 0; itr < bearer->pdr_count; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					updating_far(&(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]));
					pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count].far_id.far_id_value = pdr_ctxt->far.far_id_value;
					pfcp_sess_mod_req->update_far_count++;
				}
			}
		}
		bearer = NULL;
	}

	switch (pfcp_config.cp_type)
	{
		case SGWC :
		case PGWC :
		case SAEGWC :
			if(pfcp_sess_mod_req->update_far_count){
				for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count; itr1++) {
					pfcp_sess_mod_req->update_far[itr1].apply_action.drop = PRESENT;
				}
			}
			break;

		default :
			clLog(clSystemLog, eCLSeverityDebug,"default pfcp sess mod req\n");
			break;
	}

	#if 0
	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	pfcp_sess_mod_req->pfcpsmreq_flags.drobu = PRESENT;

	/*SP: This IE is included if one of DROBU and QAURR flag is set,
	  excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}
	#endif
}


void
fill_pfcp_sess_mod_req_pgw_init_remove_pdr(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr)
{
	int ret = 0;
	uint32_t seq = 0;
	eps_bearer *bearer;
	pdr_t *pdr_ctxt = NULL;
	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	pfcp_sess_mod_req->remove_pdr_count = 0;
	for (uint8_t index = 0; index < bearer_cntr; index++){
		bearer = bearers[index];
		if(bearer != NULL) {
			for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					removing_pdr(&(pfcp_sess_mod_req->remove_pdr[pfcp_sess_mod_req->remove_pdr_count]));
					pfcp_sess_mod_req->remove_pdr[pfcp_sess_mod_req->remove_pdr_count].pdr_id.rule_id = pdr_ctxt->rule_id;
					pfcp_sess_mod_req->remove_pdr_count++;
				}
			}
		}

		bearer = NULL;
	}
}

void
fill_pfcp_sess_mod_req_pgw_del_cmd_update_far(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;
	eps_bearer *bearer = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	pfcp_sess_mod_req->update_far_count = 0;
	for (uint8_t index = 0; index < bearer_cntr; index++){
		bearer = bearers[index];
		if(bearer != NULL) {
			for(uint8_t itr = 0; itr < bearer->pdr_count; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					updating_far(&(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]));
					pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count].far_id.far_id_value = pdr_ctxt->far.far_id_value;
					pfcp_sess_mod_req->update_far_count++;
				}
			}
		}
		bearer = NULL;
	}

	switch (pfcp_config.cp_type)
	{
		case SGWC :
		case PGWC :
		case SAEGWC :
			if(pfcp_sess_mod_req->update_far_count){
				for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count; itr1++) {
					pfcp_sess_mod_req->update_far[itr1].apply_action.drop = PRESENT;
				}
			}
			break;

		default :
			clLog(clSystemLog, eCLSeverityDebug,"default pfcp sess mod req\n");
			break;
	}

	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	pfcp_sess_mod_req->pfcpsmreq_flags.drobu = PRESENT;

	/*SP: This IE is included if one of DROBU and QAURR flag is set,
	  excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}

}

uint8_t
process_pfcp_sess_mod_resp_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	//ebi_index = resp->eps_bearer_id - 5;
	ebi_index = resp->eps_bearer_id ;
	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
	         clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
	                 __func__, __LINE__,
	                 teid);
	}

	/* Update the UE state */
	ret = update_ue_state(context->pdns[ebi_index]->s5s8_pgw_gtpc_teid,
			PFCP_SESS_MOD_RESP_RCVD_STATE ,ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State for teid: %u\n", __func__,
				context->pdns[ebi_index]->s5s8_pgw_gtpc_teid);
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}
	/* Fill the modify bearer response */

	set_modify_bearer_response_handover(gtpv2c_tx,
			context->sequence, context, bearer);

	/* Update the session state */
	resp->state = CONNECTED_STATE;
	bearer->pdn->state = CONNECTED_STATE;
	/* Update the UE state */
	ret = update_ue_state(context->s11_sgw_gtpc_teid,
			CONNECTED_STATE,ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State.\n", __func__);
	}

	s5s8_recv_sockaddr.sin_addr.s_addr =
		htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);

	clLog(sxlogger, eCLSeverityDebug, "%s: s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));
	return 0;
}

int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt)
{
	return pdn_cntxt->num_bearer;
}

#endif /* CP_BUILD */

#ifdef DP_BUILD
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_sess_set_del_resp)
{

	/*take seq no from set del request when it is implemented*/
	uint32_t seq  = 1;
	uint32_t node_value = 0 ;

	memset(pfcp_sess_set_del_resp, 0, sizeof(pfcp_sess_set_del_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_resp->header),
		PFCP_SESSION_SET_DELETION_RESPONSE, NO_SEID, seq);

	set_node_id(&(pfcp_sess_set_del_resp->node_id), node_value);
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_sess_set_del_resp->cause), REQUESTACCEPTED);
	//TODO Replace IE_NODE_ID with the  real offendID
	set_offending_ie(&(pfcp_sess_set_del_resp->offending_ie), PFCP_IE_NODE_ID );

}

void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t *
		pfcp_sess_del_resp, uint8_t cause, int offend)
{

	uint32_t seq  = 1;
	memset(pfcp_sess_del_resp, 0, sizeof(pfcp_sess_del_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_resp->header), PFCP_SESSION_DELETION_RESPONSE,
			HAS_SEID, seq);

	set_cause(&(pfcp_sess_del_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING ||
			cause == MANDATORYIEMISSING) {

		set_offending_ie(&(pfcp_sess_del_resp->offending_ie), offend);
	}

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_del_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_del_resp->ovrld_ctl_info));
}

void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *pfcp_sess_modify_resp,
		pfcp_sess_mod_req_t *pfcp_session_mod_req, uint8_t cause, int offend)
{
	uint32_t seq  = 1;
	memset(pfcp_sess_modify_resp, 0, sizeof(pfcp_sess_mod_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_modify_resp->header),
			PFCP_SESSION_MODIFICATION_RESPONSE, HAS_SEID, seq);

	set_cause(&(pfcp_sess_modify_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING
			|| cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_modify_resp->offending_ie), offend);
	}

	//created_bar
	// Need to do
	if(cause == REQUESTACCEPTED){
		if(pfcp_session_mod_req->create_pdr_count > 0 &&
				pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ch){
			set_created_pdr_ie(&(pfcp_sess_modify_resp->created_pdr));
		}
	}

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_modify_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_modify_resp->ovrld_ctl_info));

	if(cause == RULECREATION_MODIFICATIONFAILURE){
		set_failed_rule_id(&(pfcp_sess_modify_resp->failed_rule_id));
	}

	// filling of ADURI
	// Need to do
	if(pfcp_session_mod_req->pfcpsmreq_flags.qaurr ||
			pfcp_session_mod_req->query_urr_count){
		set_additional_usage(&(pfcp_sess_modify_resp->add_usage_rpts_info));
	}

	// filling of CRTEP
	// Need to do
	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		set_created_traffic_endpoint(&(pfcp_sess_modify_resp->createdupdated_traffic_endpt));

}

void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_resp,
			uint8_t cause, int offend, struct in_addr dp_comm_ip,
			pfcp_sess_estab_req_t *pfcp_session_request)
{
	uint32_t seq  = 0;
	uint32_t node_value = 0;

	//memset(pfcp_sess_est_resp, 0, sizeof(pfcp_sess_estab_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_resp->header),
			PFCP_SESSION_ESTABLISHMENT_RESPONSE, HAS_SEID, seq);

	set_node_id(&(pfcp_sess_est_resp->node_id), dp_comm_ip.s_addr);
	set_cause(&(pfcp_sess_est_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING || cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_est_resp->offending_ie), offend);
	}

	if(REQUESTACCEPTED == cause) {
		uint64_t up_seid = pfcp_session_request->header.seid_seqno.has_seid.seid;;
		set_fseid(&(pfcp_sess_est_resp->up_fseid), up_seid, node_value);
	}

	if(pfcp_ctxt.cp_supported_features & CP_LOAD) {
		set_lci(&(pfcp_sess_est_resp->load_ctl_info));
	}

	if(pfcp_ctxt.cp_supported_features & CP_OVRL) {
		set_olci(&(pfcp_sess_est_resp->ovrld_ctl_info));
	}

	/* TODO: Need to add condition for below
	char sgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(dp_comm_ip), sgwu_addr, INET_ADDRSTRLEN);
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->sgw_u_fqcsid), sgwu_value);

	char pgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(dp_comm_ip), pgwu_addr, INET_ADDRSTRLEN);
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->pgw_u_fqcsid), pgwu_value); */


	if(RULECREATION_MODIFICATIONFAILURE == cause) {
		set_failed_rule_id(&(pfcp_sess_est_resp->failed_rule_id));
	}
}
#endif /* DP_BUILD */
