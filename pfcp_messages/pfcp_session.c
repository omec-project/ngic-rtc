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
#include <math.h>
#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "li_config.h"
#include "../cp_dp_api/tcp_client.h"

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
#include "cdr.h"
#include "cp_app.h"

extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

extern const uint32_t s5s8_sgw_gtpc_base_teid; /* 0xE0FFEE */
static uint32_t s5s8_sgw_gtpc_teid_offset;

#endif /* CP_BUILD */

#ifdef DP_BUILD
extern struct in_addr dp_comm_ip;
#endif /* DP_BUILD */

#ifdef CP_BUILD
pfcp_config_t pfcp_config;

#ifdef USE_CSID
extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
#endif /* USE_CSID */

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
	//uint8_t bearer_id = 0;
	uint32_t seq = 0;
	eps_bearer *bearer = NULL;
	upf_context_t *upf_ctx = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error : %d \n", __func__,
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

		if (get_sess_entry(pdn->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
					__func__, __LINE__, pdn->seid);
			return ;
		}

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
						clLog(clSystemLog, eCLSeverityCritical,
							"Failure to allocate bearer "
							"structure: %s (%s:%d)\n",
							rte_strerror(rte_errno),
							 __FILE__,  __LINE__);
						return;
						/* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
					}
					resp->eps_bearer_ids[resp->bearer_count++] = (idx + MAX_BEARERS + 1);
					bzero(bearer,  sizeof(eps_bearer));
					bearer->pdn = pdn;
					//bearer_id = get_new_bearer_id(pdn);
					pdn->eps_bearers[(idx + MAX_BEARERS + 1) - 5] = bearer;
					pdn->context->eps_bearers[(idx + MAX_BEARERS + 1) - 5] = bearer;
					pdn->num_bearer++;
					set_s5s8_pgw_gtpu_teid_using_pdn(bearer, pdn);
					fill_dedicated_bearer_info(bearer, pdn->context, pdn);
					memcpy(&(bearer->qos), &(pdn->policy.pcc_rule[idx].dyn_rule.qos), sizeof(bearer_qos_ie));

				 }
				 bearer->dynamic_rules[bearer->num_dynamic_filters] = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
						 RTE_CACHE_LINE_SIZE, rte_socket_id());
				 if (bearer->dynamic_rules[bearer->num_dynamic_filters] == NULL)
				 {
					 clLog(clSystemLog, eCLSeverityCritical,
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

				 ret = get_ue_context(UE_SESS_ID(pdn->seid), &context);
				 if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
							__LINE__, ret);
					 return;
				 }

				 fill_create_pfcp_info(pfcp_sess_mod_req,
						&pdn->policy.pcc_rule[idx].dyn_rule,
						context);
				 bearer->num_dynamic_filters++;
			}
			else if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY)
			{
				/*
				 * Currently not handling dynamic rule qos modificaiton
				 */
				bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].dyn_rule.qos);
				if(bearer == NULL)
				{
					 clLog(clSystemLog, eCLSeverityCritical, "Failure to find bearer "
							 "structure: %s (%s:%d)\n",
							 rte_strerror(rte_errno),
							 __FILE__,
							 __LINE__);
					 return;
					 /* return GTPV2C_CAUSE_SYSTEM_FAILURE; */
				}
				fill_pfcp_entry(bearer, &pdn->policy.pcc_rule[idx].dyn_rule, RULE_ACTION_MODIFY);
				fill_update_pfcp_info(pfcp_sess_mod_req, &pdn->policy.pcc_rule[idx].dyn_rule, pdn->context);

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
		if (get_sess_entry(pdn->seid, &resp) != 0){
					clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",__func__, __LINE__, (pdn->context));
						return;
		}
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
				snprintf(rule_name.rule_name, RULE_NAME_LEN, "%s%d",
						pdn->policy.pcc_rule[idx + idx_offset].dyn_rule.rule_name, pdn->call_id);
				int8_t bearer_id = get_rule_name_entry(rule_name);
				if (-1 == bearer_id) {
					/* TODO: Error handling bearer not found */
				}
				resp->eps_bearer_ids[resp->bearer_count++] = bearer_id+5;
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
fill_create_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
																	ue_context *context)
{

	uint8_t sdf_filter_count = 0;
	pfcp_create_pdr_ie_t *pdr = NULL;
	pfcp_create_urr_ie_t *urr = NULL;
	pfcp_create_far_ie_t *far = NULL;
	pfcp_create_qer_ie_t *qer = NULL;

	for(int i=0; i<MAX_PDR_PER_RULE; i++)
	{
		int idx = pfcp_sess_mod_req->create_pdr_count;
		pdr = &(pfcp_sess_mod_req->create_pdr[idx]);
		urr = &(pfcp_sess_mod_req->create_urr[idx]);
		far = &(pfcp_sess_mod_req->create_far[idx]);
		qer = &(pfcp_sess_mod_req->create_qer[idx]);

		pdr->qer_id_count = 1;
		pdr->qer_id_count = 1;

		pdr->urr_id_count = 1; //NK:per PDR there is one URR

		creating_pdr(pdr, i);
		creating_urr(urr);

		pdr->pdr_id.rule_id = dyn_rule->pdr[i]->rule_id;
		pdr->precedence.prcdnc_val = dyn_rule->pdr[i]->prcdnc_val;
		pdr->far_id.far_id_value = dyn_rule->pdr[i]->far.far_id_value;

		pdr->urr_id[0].urr_id_value = dyn_rule->pdr[i]->urr.urr_id_value;

		pdr->qer_id[0].qer_id_value = dyn_rule->pdr[i]->qer.qer_id;

		pdr->pdi.ue_ip_address.ipv4_address =
			dyn_rule->pdr[i]->pdi.ue_addr.ipv4_address;
		pdr->pdi.local_fteid.teid =
			dyn_rule->pdr[i]->pdi.local_fteid.teid;
		pdr->pdi.local_fteid.ipv4_address =
				dyn_rule->pdr[i]->pdi.local_fteid.ipv4_address;
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

		for(int itr = 0; itr < dyn_rule->num_flw_desc; itr++) {

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {

				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

					int len = sdf_pkt_filter_add(
							&pdr->pdi, dyn_rule, sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
					pdr->header.len += len;
					sdf_filter_count++;
				}

			} else {
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {
				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					int len = sdf_pkt_filter_add(
							&pdr->pdi, dyn_rule, sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					pdr->header.len += len;
					sdf_filter_count++;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
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
		far->apply_action.dupl = GET_DUP_STATUS(context);

		if(context != NULL){

			struct li_df_config_t *li_config = NULL;
			int ret = get_li_config(context->imsi, &li_config);
			if(!ret){
				if(li_config->uiAction == EVENT_BASED ||
						li_config->uiAction == CC_EVENT_BASED){
					context->li_sock_fd = get_tcp_tunnel(li_config->ddf2_ip.s_addr,
															li_config->uiDDf2Port,
															TCP_CREATE);
				}

				context->dupl = PRESENT;
				far->apply_action.dupl = GET_DUP_STATUS(context);
				if(far->apply_action.dupl == PRESENT){
					far->dupng_parms_count = 1;
					uint16_t len = fill_dup_param(&(far->dupng_parms[0]),
										li_config->ddf2_ip.s_addr,
										li_config->uiDDf2Port,
										li_config->uiAction);
					far->header.len += len;
				}
			}
		}

		creating_qer(qer);
		qer->qer_id.qer_id_value  = dyn_rule->pdr[i]->qer.qer_id;

		qer->maximum_bitrate.ul_mbr  = dyn_rule->pdr[i]->qer.max_bitrate.ul_mbr;
		qer->maximum_bitrate.dl_mbr  = dyn_rule->pdr[i]->qer.max_bitrate.dl_mbr;
		qer->guaranteed_bitrate.ul_gbr  = dyn_rule->pdr[i]->qer.guaranteed_bitrate.ul_gbr;
		qer->guaranteed_bitrate.dl_gbr  = dyn_rule->pdr[i]->qer.guaranteed_bitrate.dl_gbr;
		qer->gate_status.ul_gate  = dyn_rule->pdr[i]->qer.gate_status.ul_gate;
		qer->gate_status.dl_gate  = dyn_rule->pdr[i]->qer.gate_status.dl_gate;

		urr->urr_id.urr_id_value = dyn_rule->pdr[i]->urr.urr_id_value;

		urr->meas_mthd.volum =
			dyn_rule->pdr[i]->urr.mea_mt.volum;
		urr->meas_mthd.durat =
			dyn_rule->pdr[i]->urr.mea_mt.durat;

		if ( (dyn_rule->pdr[i]->urr.rept_trigg.volth == PRESENT) &&
				(dyn_rule->pdr[i]->urr.rept_trigg.timth == PRESENT))
		{

			urr->rptng_triggers.volth =
				dyn_rule->pdr[i]->urr.rept_trigg.volth;

			urr->rptng_triggers.timth =
				dyn_rule->pdr[i]->urr.rept_trigg.timth;

			urr->time_threshold.time_threshold =
				dyn_rule->pdr[i]->urr.time_th.time_threshold;

			if (dyn_rule->pdr[i]->pdi.src_intfc.interface_value ==
					SOURCE_INTERFACE_VALUE_ACCESS)
			{
				urr->vol_thresh.ulvol = PRESENT;
				urr->vol_thresh.uplink_volume =
					dyn_rule->pdr[i]->urr.vol_th.uplink_volume;


				urr->vol_thresh.header.len -= (2 * sizeof(uint64_t));
				urr->header.len -= (2 * sizeof(uint64_t));


			} else {
				urr->vol_thresh.dlvol = PRESENT;
				urr->vol_thresh.downlink_volume =
					dyn_rule->pdr[i]->urr.vol_th.downlink_volume;
				urr->vol_thresh.header.len -= (2 * sizeof(uint64_t));
				urr->header.len -= (2 * sizeof(uint64_t));
			}

		}else if (dyn_rule->pdr[i]->urr.rept_trigg.volth == PRESENT) {

				urr->rptng_triggers.volth =
					dyn_rule->pdr[i]->urr.rept_trigg.volth;


			if (dyn_rule->pdr[i]->pdi.src_intfc.interface_value ==
					SOURCE_INTERFACE_VALUE_ACCESS)
			{
				urr->vol_thresh.ulvol = PRESENT;
				urr->vol_thresh.uplink_volume =
					dyn_rule->pdr[i]->urr.vol_th.uplink_volume;

			} else {
				urr->vol_thresh.dlvol = PRESENT;
				urr->vol_thresh.downlink_volume =
					dyn_rule->pdr[i]->urr.vol_th.downlink_volume;
			}
			urr->vol_thresh.header.len -= (2 * sizeof(uint64_t));
			urr->header.len -= (2 * sizeof(uint64_t));

			urr->time_threshold.header.len = 0;
			urr->header.len -= sizeof(pfcp_time_threshold_ie_t);


		} else {

			urr->rptng_triggers.timth =
				dyn_rule->pdr[i]->urr.rept_trigg.timth;

			urr->time_threshold.time_threshold =
				dyn_rule->pdr[i]->urr.time_th.time_threshold;

			urr->vol_thresh.header.len = 0;
			urr->header.len -= sizeof(pfcp_vol_thresh_ie_t);

		}

		pfcp_sess_mod_req->create_pdr_count++;
		pfcp_sess_mod_req->create_urr_count++;
		pfcp_sess_mod_req->create_far_count++;
		pfcp_sess_mod_req->create_qer_count++;
	}
	return 0;
}

int
fill_update_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
		ue_context *context)
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
			dyn_rule->pdr[i]->pdi.ue_addr.ipv4_address;
		pdr->pdi.local_fteid.teid =
			dyn_rule->pdr[i]->pdi.local_fteid.teid;
		pdr->pdi.local_fteid.ipv4_address =
				dyn_rule->pdr[i]->pdi.local_fteid.ipv4_address;
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
					int len = sdf_pkt_filter_add(&pdr->pdi, dyn_rule,
							 sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
					pdr->header.len += len;
					sdf_filter_count++;
				}

			} else {
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {
				if((pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					/* TODO: Revisit following line, change funtion signature and remove type casting */
					int len = sdf_pkt_filter_add(&pdr->pdi, dyn_rule,
								sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					pdr->header.len += len;
					sdf_filter_count++;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
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
		far->apply_action.dupl = GET_DUP_STATUS(context);

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

int fill_update_pdr_sdf_rule(pfcp_update_pdr_ie_t* update_pdr,
								eps_bearer* bearer,	int pdr_counter){
    int ret = 0;
    int sdf_filter_count = 0;
    /*VG convert pkt_filter_strucutre to char string*/
    for(int index = 0; index < bearer->num_dynamic_filters; index++) {

        update_pdr[pdr_counter].precedence.prcdnc_val = bearer->dynamic_rules[index]->precedence;
        // itr is for flow information counter
        // sdf_filter_count is for SDF information counter
        for(int itr = 0; itr < bearer->dynamic_rules[index]->num_flw_desc; itr++) {

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {

                if((update_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

                    int len = sdf_pkt_filter_add(&update_pdr[pdr_counter].pdi, bearer->dynamic_rules[index],
                    					sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
                	update_pdr[pdr_counter].header.len += len;
                    sdf_filter_count++;
                }

            } else {
                clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {
                if((update_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
                    int len = sdf_pkt_filter_add(&update_pdr[pdr_counter].pdi, bearer->dynamic_rules[index],
						sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
						update_pdr[pdr_counter].header.len += len;
                    sdf_filter_count++;
                }
            } else {
                clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }
        }

		update_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

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

		fill_update_pdr_sdf_rule(pfcp_sess_mod_req->update_pdr, bearer, i);
	}

	pfcp_sess_mod_req->update_pdr_count += NUMBER_OF_PDR_PER_BEARER;
	return;
}

/* REVIEW: Context will remove after merging */
void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, eps_bearer **bearer,
		pdn_connection *pdn, pfcp_update_far_ie_t update_far[], uint8_t x2_handover_flag, uint8_t bearer_count, ue_context *context)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	int ret = 0;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d context not found: %d \n", __func__,
				__LINE__, ret);
		return;
	}

	if( header != NULL)
		clLog(clSystemLog, eCLSeverityDebug, "header is null TEID[%d] %s %d\n", header->teid.has_teid.teid,__func__,__LINE__);

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
	for (int iCnt= 0; iCnt < bearer_count; iCnt++ ){
		if (pfcp_sess_mod_req->create_pdr_count) {
			fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req, bearer[iCnt], context);
		}

		/*SP: This depends on condition  if the CP function requests the UP function to create a new BAR
		  Need to add condition to check if CP needs creation of BAR*/
		if(pfcp_sess_mod_req->create_pdr_count) {
			for( int i = pfcp_sess_mod_req->create_pdr_count - MAX_PDR_PER_RULE;
					i < pfcp_sess_mod_req->create_pdr_count; i++){
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
		}

		/*SP: Adding FAR IE*/
		for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count ; itr1++) {

			updating_far(&(pfcp_sess_mod_req->update_far[itr1]));
			pfcp_sess_mod_req->update_far[itr1].far_id.far_id_value =
				update_far[itr1].far_id.far_id_value;
			pfcp_sess_mod_req->update_far[itr1].apply_action.forw = PRESENT;
			pfcp_sess_mod_req->update_far[itr1].apply_action.dupl = GET_DUP_STATUS(pdn->context);
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

		switch (pfcp_config.cp_type)
		{
			case SGWC :
			case SAEGWC :
				if(pfcp_sess_mod_req->create_pdr_count){
					int itr2 = pfcp_sess_mod_req->create_pdr_count - MAX_PDR_PER_RULE;
					for(int itr = 0; itr < MAX_PDR_PER_RULE; itr++) {
						pfcp_sess_mod_req->create_pdr[itr2].pdi.local_fteid.teid =
							bearer[iCnt]->pdrs[itr]->pdi.local_fteid.teid ;
						/* TODO: Revisit this for change in yang */
						pfcp_sess_mod_req->create_pdr[itr2].pdi.ue_ip_address.ipv4_address =
							htonl(bearer[iCnt]->pdrs[itr]->pdi.ue_addr.ipv4_address);
						pfcp_sess_mod_req->create_pdr[itr2].pdi.local_fteid.ipv4_address =
							bearer[iCnt]->pdrs[itr]->pdi.local_fteid.ipv4_address;
						pfcp_sess_mod_req->create_pdr[itr2].pdi.src_intfc.interface_value =
							bearer[iCnt]->pdrs[itr]->pdi.src_intfc.interface_value;
						itr2++;
					}
				}
				break;

			case PGWC :
				break;

			default :
				clLog(clSystemLog, eCLSeverityDebug,"%s:%d default pfcp sess mod req\n", __func__, __LINE__);
				break;
		}
	}//for loop

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
		eps_bearer *bearer, ue_context *context)
{

	int itr2 = pfcp_sess_mod_req->create_pdr_count - MAX_PDR_PER_RULE;
	for(int i = 0; i < MAX_PDR_PER_RULE; i++) {
		pfcp_sess_mod_req->create_pdr[itr2].qer_id_count = 1;
		pfcp_sess_mod_req->create_pdr[itr2].urr_id_count = 1;
		//pfcp_sess_mod_req->create_pdr[i].qer_id_count = bearer->qer_count;
		creating_pdr(&(pfcp_sess_mod_req->create_pdr[itr2]), bearer->pdrs[i]->pdi.src_intfc.interface_value);
		pfcp_sess_mod_req->create_far_count++;
		creating_far(&(pfcp_sess_mod_req->create_far[itr2]));
		pfcp_sess_mod_req->create_urr_count++;
		creating_urr(&(pfcp_sess_mod_req->create_urr[itr2]));

		itr2++;
	}

	itr2 =  pfcp_sess_mod_req->create_pdr_count - MAX_PDR_PER_RULE;
	for(int itr = 0; itr < MAX_PDR_PER_RULE; itr++) {
		pfcp_sess_mod_req->create_pdr[itr2].pdr_id.rule_id  =
			bearer->pdrs[itr]->rule_id;
		pfcp_sess_mod_req->create_pdr[itr2].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;
		//pfcp_sess_mod_req->create_pdr[itr2].urr_id_count = 1;
		pfcp_sess_mod_req->create_pdr[itr2].urr_id_count =
			bearer->pdrs[itr]->urr_id_count;

			pfcp_sess_mod_req->create_pdr[itr2].urr_id[0].urr_id_value =
				bearer->pdrs[itr]->urr.urr_id_value;

		pfcp_sess_mod_req->create_pdr[itr2].precedence.prcdnc_val =
			bearer->pdrs[itr]->prcdnc_val;

		pfcp_sess_mod_req->create_pdr[itr2].pdi.local_fteid.teid =
			bearer->pdrs[itr]->pdi.local_fteid.teid;

		pfcp_sess_mod_req->create_urr[itr2].urr_id.urr_id_value =
			bearer->pdrs[itr]->urr.urr_id_value;

		pfcp_sess_mod_req->create_urr[itr2].meas_mthd.volum =
			bearer->pdrs[itr]->urr.mea_mt.volum;
		pfcp_sess_mod_req->create_urr[itr2].meas_mthd.durat =
			bearer->pdrs[itr]->urr.mea_mt.durat;

		if ( (bearer->pdrs[itr]->urr.rept_trigg.volth == PRESENT) &&
				(bearer->pdrs[itr]->urr.rept_trigg.timth == PRESENT))
		{

			pfcp_sess_mod_req->create_urr[itr2].rptng_triggers.volth =
				bearer->pdrs[itr]->urr.rept_trigg.volth;

			pfcp_sess_mod_req->create_urr[itr2].rptng_triggers.timth =
				bearer->pdrs[itr]->urr.rept_trigg.timth;

			pfcp_sess_mod_req->create_urr[itr2].time_threshold.time_threshold =
				bearer->pdrs[itr]->urr.time_th.time_threshold;

			if (bearer->pdrs[itr]->pdi.src_intfc.interface_value ==
					SOURCE_INTERFACE_VALUE_ACCESS)
			{
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.ulvol = PRESENT;
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.uplink_volume =
					bearer->pdrs[itr]->urr.vol_th.uplink_volume;


				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.header.len -= (2 * sizeof(uint64_t));
				pfcp_sess_mod_req->create_urr[itr2].header.len -= (2 * sizeof(uint64_t));


			} else {
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.dlvol = PRESENT;
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.downlink_volume =
					bearer->pdrs[itr]->urr.vol_th.downlink_volume;
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.header.len -= (2 * sizeof(uint64_t));
				pfcp_sess_mod_req->create_urr[itr2].header.len -= (2 * sizeof(uint64_t));
			}

		}else if (bearer->pdrs[itr]->urr.rept_trigg.volth == PRESENT) {

			pfcp_sess_mod_req->create_urr[itr2].rptng_triggers.volth =
				bearer->pdrs[itr]->urr.rept_trigg.volth;


			if (bearer->pdrs[itr]->pdi.src_intfc.interface_value ==
					SOURCE_INTERFACE_VALUE_ACCESS)
			{
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.ulvol = PRESENT;
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.uplink_volume =
					bearer->pdrs[itr]->urr.vol_th.uplink_volume;

			} else {
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.dlvol = PRESENT;
				pfcp_sess_mod_req->create_urr[itr2].vol_thresh.downlink_volume =
					bearer->pdrs[itr]->urr.vol_th.downlink_volume;
			}
			pfcp_sess_mod_req->create_urr[itr2].vol_thresh.header.len -= (2 * sizeof(uint64_t));
			pfcp_sess_mod_req->create_urr[itr2].header.len -= (2 * sizeof(uint64_t));

			pfcp_sess_mod_req->create_urr[itr2].time_threshold.header.len = 0;
			pfcp_sess_mod_req->create_urr[itr2].header.len -= sizeof(pfcp_time_threshold_ie_t);


		} else {

			pfcp_sess_mod_req->create_urr[itr2].rptng_triggers.timth =
				bearer->pdrs[itr]->urr.rept_trigg.timth;

			pfcp_sess_mod_req->create_urr[itr2].time_threshold.time_threshold =
				bearer->pdrs[itr]->urr.time_th.time_threshold;

			pfcp_sess_mod_req->create_urr[itr2].vol_thresh.header.len = 0;
			pfcp_sess_mod_req->create_urr[itr2].header.len -= sizeof(pfcp_vol_thresh_ie_t);

		}

		if((pfcp_config.cp_type == SGWC) ||
				(bearer->pdrs[itr]->pdi.src_intfc.interface_value ==
				SOURCE_INTERFACE_VALUE_ACCESS)) {
			/*No need to send ue ip and network instance for pgwc access interface or
			 * for any sgwc interface */
			uint32_t size_ie = 0;
			size_ie = pfcp_sess_mod_req->create_pdr[itr2].pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t);
			size_ie = size_ie + pfcp_sess_mod_req->create_pdr[itr2].pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->create_pdr[itr2].pdi.header.len =
				pfcp_sess_mod_req->create_pdr[itr2].pdi.header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr2].header.len =
				pfcp_sess_mod_req->create_pdr[itr2].header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr2].pdi.ue_ip_address.header.len = 0;
			pfcp_sess_mod_req->create_pdr[itr2].pdi.ntwk_inst.header.len = 0;
		}else{
			pfcp_sess_mod_req->create_pdr[itr2].pdi.ue_ip_address.ipv4_address =
				bearer->pdrs[itr]->pdi.ue_addr.ipv4_address;
			strncpy((char *)pfcp_sess_mod_req->create_pdr[itr2].pdi.ntwk_inst.ntwk_inst,
				(char *)&bearer->pdrs[itr]->pdi.ntwk_inst.ntwk_inst, 32);
		}

		if (
				((PGWC == pfcp_config.cp_type) || (SAEGWC == pfcp_config.cp_type)) &&
				(SOURCE_INTERFACE_VALUE_CORE ==
				bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {

			uint32_t size_ie = 0;

			size_ie = pfcp_sess_mod_req->create_pdr[itr2].pdi.local_fteid.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->create_pdr[itr2].pdi.header.len =
				pfcp_sess_mod_req->create_pdr[itr2].pdi.header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr2].header.len =
				pfcp_sess_mod_req->create_pdr[itr2].header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr2].pdi.local_fteid.header.len = 0;

		} else {
			pfcp_sess_mod_req->create_pdr[itr2].pdi.local_fteid.ipv4_address =
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
		}

		pfcp_sess_mod_req->create_pdr[itr2].pdi.src_intfc.interface_value =
			bearer->pdrs[itr]->pdi.src_intfc.interface_value;

		pfcp_sess_mod_req->create_far[itr2].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;

#ifdef GX_BUILD
		if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
			pfcp_sess_mod_req->create_pdr[itr2].qer_id_count =
				bearer->pdrs[itr]->qer_id_count;
			for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_pdr[itr2].qer_id_count; itr1++) {
				pfcp_sess_mod_req->create_pdr[itr2].qer_id[itr1].qer_id_value =
					bearer->pdrs[itr]->qer_id[itr1].qer_id;
			}
		}
#endif

		if ((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) {
			pfcp_sess_mod_req->create_far[itr2].apply_action.forw = PRESENT;
			pfcp_sess_mod_req->create_far[itr2].apply_action.dupl = GET_DUP_STATUS(context);
			if (pfcp_sess_mod_req->create_far[itr2].apply_action.forw == PRESENT) {
				uint16_t len = 0;

				if (
						(SAEGWC == pfcp_config.cp_type) ||
						(SOURCE_INTERFACE_VALUE_ACCESS ==
						 bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {
					set_destination_interface(&(pfcp_sess_mod_req->create_far[itr2].frwdng_parms.dst_intfc));
					pfcp_set_ie_header(&(pfcp_sess_mod_req->create_far[itr2].frwdng_parms.header),
							IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

					pfcp_sess_mod_req->create_far[itr2].frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

					len += sizeof(pfcp_dst_intfc_ie_t);
					len += UPD_PARAM_HEADER_SIZE;

					pfcp_sess_mod_req->create_far[itr2].header.len += len;

					pfcp_sess_mod_req->create_far[itr2].frwdng_parms.dst_intfc.interface_value =
						bearer->pdrs[itr]->far.dst_intfc.interface_value;
				} else {
					pfcp_sess_mod_req->create_far[itr2].apply_action.forw = NO_FORW_ACTION;
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
			len += set_forwarding_param(&(pfcp_sess_mod_req->create_far[itr2].frwdng_parms));
			/* Currently take as hardcoded value */
			len += UPD_PARAM_HEADER_SIZE;
			pfcp_sess_mod_req->create_far[itr2].header.len += len;

			pfcp_sess_mod_req->create_far[itr2].apply_action.forw = PRESENT;
			pfcp_sess_mod_req->create_far[itr2].apply_action.dupl = GET_DUP_STATUS(context);
			pfcp_sess_mod_req->create_far[itr2].frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->pdrs[itr]->far.outer_hdr_creation.ipv4_address;
			pfcp_sess_mod_req->create_far[itr2].frwdng_parms.outer_hdr_creation.teid =
					bearer->pdrs[itr]->far.outer_hdr_creation.teid;
			pfcp_sess_mod_req->create_far[itr2].frwdng_parms.dst_intfc.interface_value =
					bearer->pdrs[itr]->far.dst_intfc.interface_value;
		}
		if(context != NULL){

			struct li_df_config_t *li_config = NULL;
			int ret = get_li_config(context->imsi, &li_config);
			if(!ret){
				if(li_config->uiAction == EVENT_BASED ||
						li_config->uiAction == CC_EVENT_BASED){
					context->li_sock_fd = get_tcp_tunnel(li_config->ddf2_ip.s_addr,
															li_config->uiDDf2Port,
															TCP_CREATE);
				}

				context->dupl = PRESENT;
				pfcp_sess_mod_req->create_far[itr2].apply_action.dupl = GET_DUP_STATUS(context);
				if(pfcp_sess_mod_req->create_far[itr2].apply_action.dupl == PRESENT){
					pfcp_sess_mod_req->create_far[itr2].dupng_parms_count = 1;
					uint16_t len = fill_dup_param(&(pfcp_sess_mod_req->create_far[itr2].dupng_parms[0]),
																li_config->ddf2_ip.s_addr,
																li_config->uiDDf2Port,
																li_config->uiAction);
					pfcp_sess_mod_req->create_far[itr2].header.len += len;
				}
			}
		}
		itr2++;
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
			for(int index = 0; index < bearer->num_dynamic_filters; index++)
				fill_create_pdr_sdf_rules(pfcp_sess_mod_req->create_pdr,
											bearer->dynamic_rules[index],
																	itr1);
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

int sdf_pkt_filter_add(pfcp_pdi_ie_t* pdi,
		dynamic_rule_t *dynamic_rules,
		int sdf_filter_count,
		int flow_cnt,
		uint8_t direction)
{
	int len = 0;
	pdi->sdf_filter[sdf_filter_count].fd = 1;
	sdf_pkt_filter_to_string(&(dynamic_rules->flow_desc[flow_cnt].sdf_flw_desc),
			(char*)(pdi->sdf_filter[sdf_filter_count].flow_desc), direction);

	pdi->sdf_filter[sdf_filter_count].len_of_flow_desc =
		strnlen((char*)(&pdi->sdf_filter[sdf_filter_count].flow_desc),MAX_FLOW_DESC_LEN);

	len += FLAG_LEN;
	len += sizeof(uint16_t);
	len += pdi->sdf_filter[sdf_filter_count].len_of_flow_desc;

	pfcp_set_ie_header(
			&(pdi->sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

	/*VG updated the header len of pdi as sdf rules has been added*/
	pdi->header.len += (len + sizeof(pfcp_ie_header_t));
	return (len + sizeof(pfcp_ie_header_t));
}

int fill_create_pdr_sdf_rules(pfcp_create_pdr_ie_t *create_pdr,
	dynamic_rule_t *dynamic_rules,	int pdr_counter)
{
	int ret = 0;
	int sdf_filter_count = 0;
	/*VG convert pkt_filter_strucutre to char string*/

	create_pdr[pdr_counter].precedence.prcdnc_val = dynamic_rules->precedence;
	// itr is for flow information counter
	// sdf_filter_count is for SDF information counter
	for(int itr = 0; itr < dynamic_rules->num_flw_desc; itr++) {

			if(dynamic_rules->flow_desc[itr].sdf_flow_description != NULL) {

				if((create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

					int len = sdf_pkt_filter_add(
									&create_pdr[pdr_counter].pdi, dynamic_rules,
									sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
					create_pdr[pdr_counter].header.len += len;
					sdf_filter_count++;
				}

			} else {
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}

			if(dynamic_rules->flow_desc[itr].sdf_flow_description != NULL) {
				if((create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
						((dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					int len = sdf_pkt_filter_add(
								&create_pdr[pdr_counter].pdi, dynamic_rules,
								sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
					create_pdr[pdr_counter].header.len += len;
					sdf_filter_count++;
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
			}
		}

		create_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

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
	qer_ctxt->qer_id = bearer->qer_id[itr].qer_id;
	qer_ctxt->session_id = pdn->seid;
	qer_ctxt->max_bitrate.ul_mbr = bearer->qos.ul_mbr;
	qer_ctxt->max_bitrate.dl_mbr = bearer->qos.dl_mbr;
	qer_ctxt->guaranteed_bitrate.ul_gbr = bearer->qos.ul_gbr;
	qer_ctxt->guaranteed_bitrate.dl_gbr = bearer->qos.dl_gbr;
	ret = add_qer_entry(qer_ctxt->qer_id,qer_ctxt);
	if(ret != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
				__func__, __LINE__, ret);
		return ret;
	}

	return ret;
}

/**
 * @brief  : Add qer entry into hash
 * @param  : qer, data to be added
 * @return : Returns 0 on success, -1 otherwise
 */
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
		clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
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
	char mnc[MCC_MNC_LEN] = {0};
	char mcc[MCC_MNC_LEN] = {0};
	char nwinst[NWINST_LEN] = {0};
	ue_context *context = bearer->pdn->context;
	pdn_connection *pdn = bearer->pdn;
	pdr_t *pdr_ctxt = NULL;
	int ret;
	uint16_t flow_len = 0;

	if (context->serving_nw.mnc_digit_3 == 15) {
		snprintf(mnc, MCC_MNC_LEN,"0%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2);
	} else {
		snprintf(mnc, MCC_MNC_LEN, "%u%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2,
				context->serving_nw.mnc_digit_3);
	}

	snprintf(mcc, MCC_MNC_LEN, "%u%u%u", context->serving_nw.mcc_digit_1,
			context->serving_nw.mcc_digit_2,
			context->serving_nw.mcc_digit_3);

	snprintf(nwinst, NWINST_LEN, "mnc%s.mcc%s", mnc, mcc);

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
		pdr_ctxt->urr.urr_id_value = generate_urr_id();
		pdr_ctxt->session_id = pdn->seid;
		/*to be filled in fill_sdf_rule*/
		pdr_ctxt->pdi.sdf_filter_cnt = 0;
		dyn_rule->pdr[i] = pdr_ctxt;
		for(int itr = 0; itr < dyn_rule->num_flw_desc; itr++)
		{
			if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL)
			{
				flow_len = dyn_rule->flow_desc[itr].flow_desc_len;
				if ((i  == SOURCE_INTERFACE_VALUE_ACCESS) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					memcpy(&(pdr_ctxt->pdi.sdf_filter[pdr_ctxt->pdi.sdf_filter_cnt].flow_desc),
							&(dyn_rule->flow_desc[itr].sdf_flow_description),
							flow_len);
					pdr_ctxt->pdi.sdf_filter[pdr_ctxt->pdi.sdf_filter_cnt].len_of_flow_desc = flow_len;
					pdr_ctxt->pdi.sdf_filter_cnt++;
				} else if ((i == SOURCE_INTERFACE_VALUE_CORE) &&
						((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
						 (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
					memcpy(&(pdr_ctxt->pdi.sdf_filter[pdr_ctxt->pdi.sdf_filter_cnt].flow_desc),
							&(dyn_rule->flow_desc[itr].sdf_flow_description),
							flow_len);
					pdr_ctxt->pdi.sdf_filter[pdr_ctxt->pdi.sdf_filter_cnt].len_of_flow_desc = flow_len;
					pdr_ctxt->pdi.sdf_filter_cnt++;

				}
			}
		}
		if (i == SOURCE_INTERFACE_VALUE_ACCESS) {

			if (pfcp_config.cp_type == PGWC) {
				pdr_ctxt->pdi.local_fteid.teid = bearer->s5s8_pgw_gtpu_teid;
				pdr_ctxt->pdi.local_fteid.ipv4_address =
						htonl(bearer->s5s8_pgw_gtpu_ipv4.s_addr);
			} else {
				pdr_ctxt->pdi.local_fteid.teid = bearer->s1u_sgw_gtpu_teid;
				pdr_ctxt->pdi.local_fteid.ipv4_address =
						htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
			}
			pdr_ctxt->far.actions.forw = 0;

			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		}
		else
		{
			pdr_ctxt->pdi.ue_addr.ipv4_address = htonl(pdn->ipv4.s_addr);
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
			clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding pdr entry Error: %d \n", __file__,
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

		pdr_ctxt->urr.mea_mt.volum = 1;
		pdr_ctxt->urr.mea_mt.durat = 1;

		if(pdn->apn_in_use->trigger_type == 0)
		{
			pdr_ctxt->urr.rept_trigg.volth = 1;
			if (i == SOURCE_INTERFACE_VALUE_ACCESS) {
				pdr_ctxt->urr.vol_th.uplink_volume =
					pdn->apn_in_use->uplink_volume_th;
			} else {
				pdr_ctxt->urr.vol_th.downlink_volume =
					pdn->apn_in_use->downlink_volume_th;
			}

		} else if (pdn->apn_in_use->trigger_type == 1)
		{
			pdr_ctxt->urr.rept_trigg.timth = 1;
			pdr_ctxt->urr.time_th.time_threshold =
				pdn->apn_in_use->time_th;

		} else {
			pdr_ctxt->urr.rept_trigg.volth = 1;
			pdr_ctxt->urr.rept_trigg.timth = 1;
			if (i == SOURCE_INTERFACE_VALUE_ACCESS) {
				pdr_ctxt->urr.vol_th.uplink_volume =
					pdn->apn_in_use->uplink_volume_th;

				pdr_ctxt->urr.time_th.time_threshold =
					pdn->apn_in_use->time_th;
			} else {
				pdr_ctxt->urr.vol_th.downlink_volume =
					pdn->apn_in_use->downlink_volume_th;
				pdr_ctxt->urr.time_th.time_threshold =
					pdn->apn_in_use->time_th;
			}
		}

		ret = add_qer_into_hash(&pdr_ctxt->qer);

		if(ret != 0) {
			clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
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
	char mnc[MCC_MNC_LEN] = {0};
	char mcc[MCC_MNC_LEN] = {0};
	char nwinst[NWINST_LEN] = {0};
	pdr_t *pdr_ctxt = NULL;
	int ret;

	if (context->serving_nw.mnc_digit_3 == 15) {
		snprintf(mnc, MCC_MNC_LEN,"0%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2);
	} else {
		snprintf(mnc, MCC_MNC_LEN,"%u%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2,
				context->serving_nw.mnc_digit_3);
	}

	snprintf(mcc, MCC_MNC_LEN,"%u%u%u", context->serving_nw.mcc_digit_1,
			context->serving_nw.mcc_digit_2,
			context->serving_nw.mcc_digit_3);

	snprintf(nwinst, NWINST_LEN,"mnc%s.mcc%s", mnc, mcc);

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
	pdr_ctxt->urr.urr_id_value = generate_urr_id();


	/*
	 *NK:per pdr there is one URR
	 *   hence hardcoded urr count to one
	 */
	pdr_ctxt->urr_id_count = 1;


	pdr_ctxt->session_id = pdn->seid;
	/*to be filled in fill_sdf_rule*/
	pdr_ctxt->pdi.sdf_filter_cnt += 1;
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
		} else if ((pfcp_config.cp_type == SGWC) && (context->indication_flag.oi != 0)){
			pdr_ctxt->far.outer_hdr_creation.ipv4_address =
				bearer->s5s8_pgw_gtpu_ipv4.s_addr;
			pdr_ctxt->far.outer_hdr_creation.teid =
				bearer->s5s8_pgw_gtpu_teid;
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		}

	} else{
		if(pfcp_config.cp_type == SGWC){
			pdr_ctxt->pdi.local_fteid.teid = (bearer->s5s8_sgw_gtpu_teid);
			pdr_ctxt->pdi.local_fteid.ipv4_address = 0;
			if(context->indication_flag.oi != 0){
				pdr_ctxt->far.outer_hdr_creation.ipv4_address =
					bearer->s1u_enb_gtpu_ipv4.s_addr;
				pdr_ctxt->far.outer_hdr_creation.teid =
					bearer->s1u_enb_gtpu_teid;
				pdr_ctxt->far.dst_intfc.interface_value =
					DESTINATION_INTERFACE_VALUE_ACCESS;
			}

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
			pdr_ctxt->urr.mea_mt.volum = 1;
			pdr_ctxt->urr.mea_mt.durat = 1;

		if(pdn->apn_in_use->trigger_type == 0)
		{
			pdr_ctxt->urr.mea_mt.volum = 1;
			pdr_ctxt->urr.rept_trigg.volth = 1;
			if (iface == SOURCE_INTERFACE_VALUE_ACCESS) {
				pdr_ctxt->urr.vol_th.uplink_volume =
					pdn->apn_in_use->uplink_volume_th;
			} else {
				pdr_ctxt->urr.vol_th.downlink_volume =
					pdn->apn_in_use->downlink_volume_th;
			}

		} else if (pdn->apn_in_use->trigger_type == 1)
		{
			pdr_ctxt->urr.mea_mt.durat = 1;
			pdr_ctxt->urr.rept_trigg.timth = 1;
			pdr_ctxt->urr.time_th.time_threshold =
				pdn->apn_in_use->time_th;

		} else {
			pdr_ctxt->urr.mea_mt.volum = 1;
			pdr_ctxt->urr.mea_mt.durat = 1;
			pdr_ctxt->urr.rept_trigg.volth = 1;
			pdr_ctxt->urr.rept_trigg.timth = 1;
			if (iface == SOURCE_INTERFACE_VALUE_ACCESS) {
				pdr_ctxt->urr.vol_th.uplink_volume =
					pdn->apn_in_use->uplink_volume_th;

				pdr_ctxt->urr.time_th.time_threshold =
					pdn->apn_in_use->time_th;
			} else {
				pdr_ctxt->urr.vol_th.downlink_volume =
					pdn->apn_in_use->downlink_volume_th;
				pdr_ctxt->urr.time_th.time_threshold =
					pdn->apn_in_use->time_th;
			}
		}

	bearer->pdrs[itr] = pdr_ctxt;
	ret = add_pdr_entry(bearer->pdrs[itr]->rule_id, bearer->pdrs[itr]);
	if ( ret != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding pdr entry Error: %d \n", __file__,
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
	for(uint8_t idx = 0; idx < MAX_BEARERS*2; idx++)
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
	if(default_bearer_qos->qci != rule_qos->qci) {
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%d Comparing default bearer qci with the rule qci\n",__func__, __LINE__);
		return -1;
	}

	if(default_bearer_qos->arp.preemption_vulnerability != rule_qos->arp.preemption_vulnerability) {
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%d Comparing default bearer qos arp preemption vulnerablity\n",
				__func__, __LINE__);
		return -1;
	}

	if(default_bearer_qos->arp.priority_level != rule_qos->arp.priority_level) {
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%d Comparing default bearer qos arp priority level\n",
				__func__, __LINE__);
		return -1;
	}
	if(default_bearer_qos->arp.preemption_vulnerability != rule_qos->arp.preemption_vulnerability) {
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%d Comparing default bearer qos arp preemption vulnerablity\n",
				__func__, __LINE__);
		return -1;
	}
	return 0;

}

uint16_t fill_dup_param(pfcp_dupng_parms_ie_t *dup_params, uint32_t ipv4_address,
										uint16_t port_number, uint16_t li_policy){
	/* Start : Need to add condition and all stuff must be in function */

	uint16_t len = 0;
	len += set_duplicating_param(dup_params);

	/* VK : Updating outer header creation ass for
	 * duplating paramteres we needed IP and port 4 for UDP/IPV4 */
	dup_params->outer_hdr_creation.outer_hdr_creation_desc = 0x0400;

	//VK : Harcoding of LI policy should be removed once ADMF in place
	dup_params->frwdng_plcy.frwdng_plcy_ident = li_policy;

	/* VK : Removing teid len for header because for
	 * Dup paramters we dont need teid */
	dup_params->header.len -= sizeof(uint32_t);
	dup_params->outer_hdr_creation.header.len -= sizeof(uint32_t);
	len -= sizeof(uint32_t);

	// Adding len of port number
	dup_params->header.len += sizeof(uint16_t);
	dup_params->outer_hdr_creation.header.len += sizeof(uint16_t);
	len += sizeof(uint16_t);

	dup_params->outer_hdr_creation.ipv4_address = ipv4_address;
	dup_params->outer_hdr_creation.port_number = port_number;
	len += UPD_PARAM_HEADER_SIZE;
	return len;
	/* End : Need to add condition and all stuff must be in function */
}

uint16_t
fill_upd_dup_param(pfcp_upd_dupng_parms_ie_t *dup_params, uint32_t ipv4_address,
		uint16_t port_number, uint16_t li_policy){

	uint16_t len = 0;
	len += set_upd_duplicating_param(dup_params);

	dup_params->outer_hdr_creation.outer_hdr_creation_desc = 0x0400;

	//VK : Harcoding of LI policy should be removed once ADMF in place
	dup_params->frwdng_plcy.frwdng_plcy_ident = li_policy;

	/* VK : Removing teid len for header because for
	 * Dup paramters we dont need teid */
	dup_params->header.len -= sizeof(uint32_t);
	dup_params->outer_hdr_creation.header.len -= sizeof(uint32_t);
	len -= sizeof(uint32_t);

	// Adding len of port number
	dup_params->header.len += sizeof(uint16_t);
	dup_params->outer_hdr_creation.header.len += sizeof(uint16_t);
	len += sizeof(uint16_t);

	dup_params->outer_hdr_creation.ipv4_address = ipv4_address;
	dup_params->outer_hdr_creation.port_number = port_number;
	len += UPD_PARAM_HEADER_SIZE;
	return len;
}

void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		pdn_connection *pdn, uint32_t seq, struct ue_context_t *context)
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
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: UPF context not found : upf ip : %u \n", __func__,
				__LINE__, pdn->upf_ipv4.s_addr);
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

	set_user_id(&(pfcp_sess_est_req->user_id), context->imsi);

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

				if (pfcp_config.cp_type == SAEGWC) {
					set_s1u_sgw_gtpu_teid(bearer, bearer->pdn->context);
					update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, bearer->s1u_sgw_gtpu_ipv4.s_addr, SOURCE_INTERFACE_VALUE_ACCESS);
				} else if (pfcp_config.cp_type == PGWC){
					set_s5s8_pgw_gtpu_teid(bearer, bearer->pdn->context);
					update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, bearer->s5s8_pgw_gtpu_ipv4.s_addr, SOURCE_INTERFACE_VALUE_ACCESS);
				}

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
			bearer->qer_count = 0;
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

			if (pfcp_config.cp_type == SAEGWC) {
				update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid,
						upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
			} else if (pfcp_config.cp_type == PGWC) {
				update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid,
						upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);
			}
		}
	} else {
		bearer = get_default_bearer(pdn);
		pfcp_sess_est_req->create_pdr_count = pdn->context->bearer_count * NUMBER_OF_PDR_PER_BEARER;
			for(int i = 0; i< MAX_BEARERS; i++) {
				bearer =  pdn->eps_bearers[i];
				if(bearer == NULL)
					continue;

				update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
				update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);
			}

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
					pfcp_sess_est_req->create_pdr[pdr_idx].urr_id_count = 1;
					creating_pdr(&(pfcp_sess_est_req->create_pdr[pdr_idx]), bearer->pdrs[idx]->pdi.src_intfc.interface_value);
					pfcp_sess_est_req->create_far_count++;
					creating_far(&(pfcp_sess_est_req->create_far[pdr_idx]));
					pfcp_sess_est_req->create_urr_count++;
					creating_urr(&(pfcp_sess_est_req->create_urr[pdr_idx]));
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


					 pfcp_sess_est_req->create_urr[pdr_idx].urr_id.urr_id_value =
						 bearer->pdrs[idx]->urr.urr_id_value;

					pfcp_sess_est_req->create_pdr[pdr_idx].urr_id_count =
							bearer->pdrs[idx]->urr_id_count;

					for(int itr1 = 0; itr1 < bearer->pdrs[idx]->urr_id_count; itr1++) {
					 pfcp_sess_est_req->create_pdr[pdr_idx].urr_id[itr1].urr_id_value =
						 bearer->pdrs[idx]->urr.urr_id_value;
					}

					 pfcp_sess_est_req->create_urr[pdr_idx].meas_mthd.volum =
						 bearer->pdrs[idx]->urr.mea_mt.volum;
					 pfcp_sess_est_req->create_urr[pdr_idx].meas_mthd.durat =
						 bearer->pdrs[idx]->urr.mea_mt.durat;

					if ( (bearer->pdrs[idx]->urr.rept_trigg.volth == PRESENT) &&
							(bearer->pdrs[idx]->urr.rept_trigg.timth == PRESENT))
					{

					 pfcp_sess_est_req->create_urr[pdr_idx].rptng_triggers.volth =
						 bearer->pdrs[idx]->urr.rept_trigg.volth;

					 pfcp_sess_est_req->create_urr[pdr_idx].rptng_triggers.timth =
						 bearer->pdrs[idx]->urr.rept_trigg.timth;

						pfcp_sess_est_req->create_urr[pdr_idx].time_threshold.time_threshold =
						 bearer->pdrs[idx]->urr.time_th.time_threshold;

					 if (bearer->pdrs[idx]->pdi.src_intfc.interface_value ==
							 SOURCE_INTERFACE_VALUE_ACCESS)
					 {
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.ulvol = PRESENT;
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.uplink_volume =
						 bearer->pdrs[idx]->urr.vol_th.uplink_volume;


						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.header.len -= (2 * sizeof(uint64_t));
						pfcp_sess_est_req->create_urr[pdr_idx].header.len -= (2 * sizeof(uint64_t));


					 } else {
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.dlvol = PRESENT;
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.downlink_volume =
						 bearer->pdrs[idx]->urr.vol_th.downlink_volume;

						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.header.len -= (2 * sizeof(uint64_t));
						pfcp_sess_est_req->create_urr[pdr_idx].header.len -= (2 * sizeof(uint64_t));
					 }

					}else if (bearer->pdrs[idx]->urr.rept_trigg.volth == PRESENT) {

					 pfcp_sess_est_req->create_urr[pdr_idx].rptng_triggers.volth =
						 bearer->pdrs[idx]->urr.rept_trigg.volth;

					 if (bearer->pdrs[idx]->pdi.src_intfc.interface_value ==
							 SOURCE_INTERFACE_VALUE_ACCESS)
					 {
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.ulvol = PRESENT;
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.uplink_volume =
						 bearer->pdrs[idx]->urr.vol_th.uplink_volume;

					 } else {
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.dlvol = PRESENT;
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.downlink_volume =
						 bearer->pdrs[idx]->urr.vol_th.downlink_volume;
					 }
						pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.header.len -= (2 * sizeof(uint64_t));
						pfcp_sess_est_req->create_urr[pdr_idx].header.len -= (2 * sizeof(uint64_t));

						pfcp_sess_est_req->create_urr[pdr_idx].time_threshold.header.len = 0;
						pfcp_sess_est_req->create_urr[pdr_idx].header.len -= sizeof(pfcp_time_threshold_ie_t);


					} else {

					 pfcp_sess_est_req->create_urr[pdr_idx].rptng_triggers.timth =
						 bearer->pdrs[idx]->urr.rept_trigg.timth;

						pfcp_sess_est_req->create_urr[pdr_idx].time_threshold.time_threshold =
						 bearer->pdrs[idx]->urr.time_th.time_threshold;

					 pfcp_sess_est_req->create_urr[pdr_idx].vol_thresh.header.len = 0;
					 pfcp_sess_est_req->create_urr[pdr_idx].header.len -= sizeof(pfcp_vol_thresh_ie_t);

					}

					/* SGW Relocation*/
					if(pdn->context->indication_flag.oi != 0) {
						uint8_t len  = 0;
						//if(itr == 1)
						//TODO :: Betting on stars allignments to make below code works
						if(pdr_idx%2)
						{
							pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
							pfcp_sess_est_req->create_far[pdr_idx].apply_action.dupl = GET_DUP_STATUS(pdn->context);
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
							pfcp_sess_est_req->create_far[pdr_idx].apply_action.dupl = GET_DUP_STATUS(pdn->context);
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
					if(context != NULL){

						struct li_df_config_t *li_config = NULL;
						int ret = get_li_config(context->imsi, &li_config);
						if(!ret){
							if(li_config->uiAction == EVENT_BASED ||
									li_config->uiAction == CC_EVENT_BASED){
								context->li_sock_fd = get_tcp_tunnel(li_config->ddf2_ip.s_addr,
																		li_config->uiDDf2Port,
																		TCP_CREATE);
							}

							context->dupl = PRESENT;
							pfcp_sess_est_req->create_far[pdr_idx].apply_action.dupl = GET_DUP_STATUS(context);
							if(pfcp_sess_est_req->create_far[pdr_idx].apply_action.dupl == PRESENT){
								pfcp_sess_est_req->create_far[pdr_idx].dupng_parms_count = 1;
								uint16_t len = fill_dup_param(&(pfcp_sess_est_req->create_far[pdr_idx].dupng_parms[0]),
													li_config->ddf2_ip.s_addr,
													li_config->uiDDf2Port,
													li_config->uiAction);
								pfcp_sess_est_req->create_far[pdr_idx].header.len += len;
							}
						}
					}

					if ((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) {

						pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.dupl = GET_DUP_STATUS(pdn->context);
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
								bearer->pdrs[idx]->far.dst_intfc.interface_value;
							} else {
								len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms));
								/* Currently take as hardcoded value */
								len += UPD_PARAM_HEADER_SIZE;
								pfcp_sess_est_req->create_far[pdr_idx].header.len += len;

								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.ipv4_address =
									bearer->pdrs[idx]->far.outer_hdr_creation.ipv4_address;
								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.outer_hdr_creation.teid =
									bearer->pdrs[idx]->far.outer_hdr_creation.teid;
								pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc.interface_value =
									bearer->pdrs[idx]->far.dst_intfc.interface_value;
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
								bearer->qer_id[idx].qer_id;
							qer_context = get_qer_entry(pfcp_sess_est_req->create_qer[qer_idx].qer_id.qer_id_value);
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
							qer_idx++;
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

			fill_create_pdr_sdf_rules(pfcp_sess_est_req->create_pdr, &pdn->policy.pcc_rule[itr1].dyn_rule, pdr_idx);
			fill_gate_status(pfcp_sess_est_req, pdr_idx, f_status);
			pdr_idx++;

			fill_create_pdr_sdf_rules(pfcp_sess_est_req->create_pdr, &pdn->policy.pcc_rule[itr1].dyn_rule, pdr_idx);
			fill_gate_status(pfcp_sess_est_req, pdr_idx, f_status);
			pdr_idx++;

		}

#endif /* GX_BUILD */

	/* VS: Set the pdn connection type */
	set_pdn_type(&(pfcp_sess_est_req->pdn_type), &(pdn->pdn_type));

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

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {

	context->s11_sgw_gtpc_ipv4.s_addr = pfcp_config.s11_ip.s_addr;
	context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;
	context->s11_mme_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;

	}


	/* VS: Stored the serving network information in UE context */
	context->serving_nw.mnc_digit_1 = csr->serving_network.mnc_digit_1;
	context->serving_nw.mnc_digit_2 = csr->serving_network.mnc_digit_2;
	context->serving_nw.mnc_digit_3 = csr->serving_network.mnc_digit_3;
	context->serving_nw.mcc_digit_1 = csr->serving_network.mcc_digit_1;
	context->serving_nw.mcc_digit_2 = csr->serving_network.mcc_digit_2;
	context->serving_nw.mcc_digit_3 = csr->serving_network.mcc_digit_3;

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {

	if(csr->indctn_flgs.header.len != 0) {
		context->indication_flag.oi = csr->indctn_flgs.indication_oi;
	}

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(csr->sender_fteid_ctl_plane.ipv4_address);
	}

	return 0;
}

/**
 * @brief  : Fill time zone info in ue context from incoming data in create sess request
 * @param  : tz, holds timezone info
 * @param  : context , pointer to ue context structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_time_zone_info(gtp_ue_time_zone_ie_t *tz, ue_context *context)
{
	context->ue_time_zone_flag = true;
	context->tz.tz = tz->time_zone;
	context->tz.dst = tz->daylt_svng_time;
	return 0;
}

/**
 * @brief  : Fill user csg info in ue context from incoming data in create sess request
 * @param  : uci holds user csg info
 * @param  : context , pointer to ue context structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_user_csg_info(gtp_user_csg_info_ie_t *uci, ue_context *context)
{

	context->uci_flag = true;
	context->uci.mnc_digit_1 = uci->mnc_digit_1;
	context->uci.mnc_digit_2 = uci->mnc_digit_2;
	context->uci.mnc_digit_3 = uci->mnc_digit_3;
	context->uci.mcc_digit_1 = uci->mcc_digit_1;
	context->uci.mcc_digit_2 = uci->mcc_digit_2;
	context->uci.mcc_digit_3 = uci->mcc_digit_3;
	context->uci.csg_id = uci->csg_id;
	context->uci.csg_id2 = uci->csg_id2;
	context->uci.access_mode = uci->access_mode;
	context->uci.lcsg = uci->lcsg;
	context->uci.cmi = uci->cmi;
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
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Invalid interface\n",__func__, __LINE__);
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
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d NO ENTRY FOUND IN UPF HASH [%u]\n",
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
 * @brief  : Fill indication flags from incoming data in csr
 * @param  : csr holds data in csr
 * @param  : context , pointer to ue context structure
 * @return : void
 */
static void
fill_indication_flags(create_sess_req_t *csr,  ue_context *context)
{
	context->indication_flag.oi = csr->indctn_flgs.indication_oi;
	context->indication_flag.crsi = csr->indctn_flgs.indication_crsi;
	context->indication_flag.sgwci= csr->indctn_flgs.indication_sgwci;
	context->indication_flag.hi = csr->indctn_flgs.indication_hi;
	context->indication_flag.ccrsi = csr->indctn_flgs.indication_ccrsi;
	context->indication_flag.cprai = csr->indctn_flgs.indication_cprai;
	context->indication_flag.clii = csr->indctn_flgs.indication_clii;
	context->indication_flag.dfi = csr->indctn_flgs.indication_dfi;
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
		ue_context *context, pdn_connection *pdn, uint8_t ebi_index)
{

	/* Need to re-vist this ARP[Allocation/Retention priority] handling portion */
	bearer->qos.arp.priority_level =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.pl;
	bearer->qos.arp.preemption_capability =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.pci;
	bearer->qos.arp.preemption_vulnerability =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.pvi;

	/* TODO: Implement TFTs on default bearers
	 * if (create_session_request.bearer_tft_ie) {
	 * }**/

	/* VS: Fill the QCI value */
	bearer->qos.qci =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.qci;
	bearer->qos.ul_mbr =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.max_bit_rate_uplnk;
	bearer->qos.dl_mbr =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.max_bit_rate_dnlnk;
	bearer->qos.ul_gbr =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.guarntd_bit_rate_uplnk;
	bearer->qos.dl_gbr =
		csr->bearer_contexts_to_be_created[ebi_index].bearer_lvl_qos.guarntd_bit_rate_dnlnk;

	bearer->s1u_sgw_gtpu_teid = 0;
	bearer->s5s8_sgw_gtpu_teid = 0;

	if (pfcp_config.cp_type == PGWC){
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created[ebi_index].s5s8_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid = csr->bearer_contexts_to_be_created[ebi_index].s5s8_u_sgw_fteid.teid_gre_key;
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
/**
 * @brief  : Generate ccr request
 * @param  : context, ue context
 * @param  : ebi_index
 * @param  : csr, create session request data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
gen_ccr_request(ue_context *context, uint8_t ebi_index, create_sess_req_t *csr)
{
	/* VS: Initialize the Gx Parameters */
	uint8_t ret = 0;
	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	/* VS: Generate unique call id per PDN connection */
	context->pdns[ebi_index]->call_id = generate_call_id();

	/** Allocate the memory for Gx Context
	 */
	gx_context = rte_malloc_socket(NULL,
			sizeof(gx_context_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (gx_context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate gx context "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* VS: Generate unique session id for communicate over the Gx interface */
	if (gen_sess_id_for_ccr(gx_context->gx_sess_id,
				context->pdns[ebi_index]->call_id)) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: %s \n", __func__, __LINE__,
				strerror(errno));
		return -1;
	}

	/* Maintain the gx session id in context */
	memcpy(context->pdns[ebi_index]->gx_sess_id,
			gx_context->gx_sess_id , sizeof(context->pdns[ebi_index]->gx_sess_id));

	/* VS: Maintain the PDN mapping with call id */
	if ((ret = add_pdn_conn_entry(context->pdns[ebi_index]->call_id,
				context->pdns[ebi_index]) )!= 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to add pdn entry with call id\n", __func__, __LINE__);
		return ret;
	}

	/* VS: Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* VS: Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = INITIAL_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = ESTABLISHMENT ;

	/* VS: Set bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT ;
	ccr_request.data.ccr.bearer_identifier.len =
		(1 + (uint32_t)log10((context->eps_bearers[ebi_index])->eps_bearer_id));

	if (ccr_request.data.ccr.bearer_identifier.len >= 255) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Error: Insufficient memory to copy bearer identifier\n", ERR_MSG);
		return -1;
	} else {
		strncpy((char *)ccr_request.data.ccr.bearer_identifier.val,
				(char *)&(context->eps_bearers[ebi_index])->eps_bearer_id,
				ccr_request.data.ccr.bearer_identifier.len);
	}

	/* Subscription-Id */
	if(csr->imsi.header.len  || csr->msisdn.header.len)
	{
		uint8_t idx = 0;
		ccr_request.data.ccr.presence.subscription_id = PRESENT;
		ccr_request.data.ccr.subscription_id.count = 1; // IMSI & MSISDN
		ccr_request.data.ccr.subscription_id.list  = rte_malloc_socket(NULL,
				(sizeof(GxSubscriptionId)*1),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (ccr_request.data.ccr.subscription_id.list == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate subscription_id list"
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

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
	if ((ret = gx_context_entry_add(gx_context->gx_sess_id, gx_context)) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: Failed to add gx context entry : %s \n", __func__, __LINE__,
				strerror(errno));
		return ret;
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
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* VS: Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);

		return GTPV2C_CAUSE_SYSTEM_FAILURE;

	}

	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + sizeof(ccr_request.msg_type));
	return 0;
}

/**
 * @brief  : Fill tai data
 * @param  : buf, buffer to be filled
 * @param  : tai, tai data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_tai(uint8_t *buf, tai_t *tai) {

	int index = 0;
	buf[index++] = ((tai->tai_mcc_digit_2 << 4) | (tai->tai_mcc_digit_1)) & 0xff;
	buf[index++] = ((tai->tai_mnc_digit_3 << 4 )| (tai->tai_mcc_digit_3)) & 0xff;
	buf[index++] = ((tai->tai_mnc_digit_2 << 4 ) | (tai->tai_mnc_digit_1)) & 0xff;
	buf[index++] = ((tai->tai_tac >>8) & 0xff);
	buf[index++] =  (tai->tai_tac) &0xff;

	return sizeof(tai_field_t);
}

/**
 * @brief  : Fill ecgi data
 * @param  : buf, buffer to be filled
 * @param  : ecgi, ecgi data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_ecgi(uint8_t *buf, ecgi_t *ecgi) {
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

/**
 * @brief  : Fill lai data
 * @param  : buf, buffer to be filled
 * @param  : lai, lai data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_lai(uint8_t *buf, lai_t *lai) {

	int index = 0;
	buf[index++] = ((lai->lai_mcc_digit_2 << 4) | (lai->lai_mcc_digit_1)) & 0xff;
	buf[index++] = ((lai->lai_mnc_digit_3 << 4 )| (lai->lai_mcc_digit_3)) & 0xff;
	buf[index++] = ((lai->lai_mnc_digit_2 << 4 ) | (lai->lai_mnc_digit_1)) & 0xff;
	buf[index++] = ((lai->lai_lac >>8) & 0xff);
	buf[index++] =  (lai->lai_lac) &0xff;
	return sizeof(lai_field_t);
}

/**
 * @brief  : Fill rai data
 * @param  : buf, buffer to be filled
 * @param  : sai, rai data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_rai(uint8_t *buf, rai_t *rai) {

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

/**
 * @brief  : Fill sai data
 * @param  : buf, buffer to be filled
 * @param  : sai, sai data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_sai(uint8_t *buf, sai_t *sai) {

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

/**
 * @brief  : Fill cgi data
 * @param  : buf, buffer to be filled
 * @param  : cgi, cgi data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_cgi(uint8_t *buf, cgi_t *cgi) {

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


/**
 * @brief  : Generate ccru request
 * @param  : pdn, pdn connection data
 * @param  : bearer, bearer information
 * @param  : flag_check
 * @return : Returns 0 on success, -1 otherwise
 */
static int
gen_ccru_request(pdn_connection *pdn, eps_bearer *bearer, uint8_t flag_check)
{
	/*
	 * TODO:
	 * Passing bearer as parameter is a BAD IDEA
	 * because what if multiple bearer changes?
	 * code SHOULD anchor only on pdn.
	 */
	/* VS: Initialize the Gx Parameters */

	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	int ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			          (const void*)(pdn->gx_sess_id),
					           (void **)&gx_context);
	  if (ret < 0) {
		       clLog(clSystemLog, eCLSeverityCritical,
					"%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
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

	/* VS: Set bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT;
	ccr_request.data.ccr.bearer_identifier.len =
		(1 + (uint32_t)log10(bearer->eps_bearer_id));

	if (ccr_request.data.ccr.bearer_identifier.len >= 255) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Error: Insufficient memory to copy bearer identifier\n", ERR_MSG);
		return -1;
	} else {
		strncpy((char *)ccr_request.data.ccr.bearer_identifier.val,
				(char *)&bearer->eps_bearer_id,
				ccr_request.data.ccr.bearer_identifier.len);
	}

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
			ccr_request.data.ccr.subscription_id.list[idx].
							subscription_id_type = END_USER_IMSI;
			ccr_request.data.ccr.subscription_id.list[idx].
							subscription_id_data.len = pdn->context->imsi_len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&pdn->context->imsi,
					pdn->context->imsi_len);
			idx++;
		}

		/* Fill MSISDN */
		if(pdn->context->msisdn !=0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].
								subscription_id_type = END_USER_E164;
			ccr_request.data.ccr.subscription_id.list[idx].
								subscription_id_data.len =  pdn->context->msisdn_len;

			memcpy(ccr_request.data.ccr.subscription_id.list[idx].
					subscription_id_data.val, &pdn->context->msisdn,
				    pdn->context->msisdn_len);
		}
	}

	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	int index = 0;
	int len = 0;

	uint8_t evnt_tigger_list[EVENT_TRIGGER_LIST] = {0};

	ccr_request.data.ccr.presence.event_trigger = PRESENT ;
	ccr_request.data.ccr.event_trigger.count = 0 ;

	if(pdn->context->old_uli_valid == TRUE) {

		if(((pdn->context->event_trigger & (1 << ULI_EVENT_TRIGGER)) != 0)) {

			evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = ULI_EVENT_TRIGGER;

		}

		if(flag_check  == ECGI_AND_TAI_PRESENT) {

			if(((pdn->context->event_trigger & (1 << TAI_EVENT_TRIGGER)) != 0)
				&& ((pdn->context->event_trigger &
						(1 << ECGI_EVENT_TRIGGER)) != 0)) {

				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = ECGI_EVENT_TRIGGER;
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = TAI_EVENT_TRIGGER;

			}

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_ECGI_AND_TAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len =index ;
			len = fill_tai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(pdn->context->old_uli.tai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;
			len  = fill_ecgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[len + 1]),
						&(pdn->context->old_uli.ecgi2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1<< 0)) == TAI_PRESENT) ) {

			if(((pdn->context->event_trigger & (1 << TAI_EVENT_TRIGGER)) != 0)) {
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = TAI_EVENT_TRIGGER;
			}

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_TAI_TYPE;

			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len = fill_tai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
							&(pdn->context->old_uli.tai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 4)) == ECGI_PRESENT)) {

			if(((pdn->context->event_trigger & (1 << ECGI_EVENT_TRIGGER)) != 0)) {
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = ECGI_EVENT_TRIGGER;
			}
			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_ECGI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_ecgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
													&(pdn->context->old_uli.ecgi2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 2)) == SAI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_SAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_sai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
													&(pdn->context->old_uli.sai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;
		} else if (((flag_check & (1 << 3)) == RAI_PRESENT)) {

			if(((pdn->context->event_trigger & (1 << RAI_EVENT_TRIGGER)) != 0)) {
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = RAI_EVENT_TRIGGER;
			}
			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_RAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_rai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(pdn->context->old_uli.rai2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 1)) == CGI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_CGI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_cgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(pdn->context->old_uli.cgi2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((flag_check & (1 << 6)) == 1)) {

			len = fill_lai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(pdn->context->old_uli.lai2));
		}
		pdn->context->old_uli_valid = FALSE;
	}

	if( pdn->old_ue_tz_valid == TRUE ) {

		evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = UE_TIMEZONE_EVT_TRIGGER;
		index = 0;
		ccr_request.data.ccr.presence.tgpp_ms_timezone = PRESENT;
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = GX_UE_TIMEZONE_TYPE;
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = ((pdn->ue_tz.tz) & 0xff);
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = ((pdn->ue_tz.dst) & 0xff);
		ccr_request.data.ccr.tgpp_ms_timezone.len = index;
	}

	ccr_request.data.ccr.event_trigger.list = (int32_t *)malloc(ccr_request.data.ccr.
												event_trigger.count * sizeof(int32_t));

	for(uint8_t count = 0; count < ccr_request.data.ccr.event_trigger.count; count++ ) {
		*(ccr_request.data.ccr.event_trigger.list + count) = evnt_tigger_list[count];
	}

	/* VS: Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, pdn->context,
				(bearer->eps_bearer_id - 5), pdn->gx_sess_id) != 0) {

		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed CCR request filling process\n", __func__, __LINE__);
		return -1;
	}

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_UPDATE, SENT, GX);


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
	uint8_t *buffer = NULL;
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

	uint8_t indx_bearer = bearer->eps_bearer_id;
	/* VS: Set bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT;
	ccr_request.data.ccr.bearer_identifier.len =
		(1 + (uint32_t)log10(indx_bearer));

	if (ccr_request.data.ccr.bearer_identifier.len >= 255) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Error: Insufficient memory to copy bearer identifier\n", ERR_MSG);
		return -1;
	} else {
		strncpy((char *)ccr_request.data.ccr.bearer_identifier.val,
				(char *)&indx_bearer,
				ccr_request.data.ccr.bearer_identifier.len);
	}

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
	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list[idx].len = strnlen(bearer->dynamic_rules[idx]->rule_name,MAX_RULE_NAME_LEN);

	for(uint16_t i = 0 ; i<strnlen(bearer->dynamic_rules[idx]->rule_name,MAX_RULE_NAME_LEN); i++){
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
	memcpy(ccr_request.data.ccr.framed_ip_address.val, &temp, strnlen(temp,(GX_FRAMED_IP_ADDRESS_LEN + 1)));

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
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_UPDATE, SENT, GX);


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
	uint8_t ebi_index = 0;
	uint8_t check_if_ue_hash_exist = 0;

	apn *apn_requested = get_apn((char *)csr->apn.apn, csr->apn.header.len);

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	if(csr->mapped_ue_usage_type.header.len > 0) {
		apn_requested->apn_usage_type = csr->mapped_ue_usage_type.mapped_ue_usage_type;
	}

	for(uint8_t i = 0; i< csr->bearer_count ; i++) {

		ebi_index = csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi - 5;

		if (pfcp_config.cp_type != SGWC) {
			ret = acquire_ip(&ue_ip);
		}
		if (ret)
			return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

		/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
		ret = create_ue_context(&csr->imsi.imsi_number_digits, csr->imsi.header.len,
				csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi, &context, apn_requested,
				CSR_SEQUENCE(csr), &check_if_ue_hash_exist);

		*_context = context;

		if (ret)
			return ret;

		/* Retrive procedure of CSR */
		pdn = context->eps_bearers[ebi_index]->pdn;
		bearer = pdn->eps_bearers[ebi_index];

		if (csr->linked_eps_bearer_id.ebi_ebi) {
			pdn->default_bearer_id = csr->linked_eps_bearer_id.ebi_ebi;
		}


		if (pdn->default_bearer_id - 5 == ebi_index) {

			if (csr->mei.header.len)
				memcpy(&context->mei, &csr->mei.mei, csr->mei.header.len);

			memcpy(&context->msisdn, &csr->msisdn.msisdn_number_digits, csr->msisdn.header.len);

			if(fill_context_info(csr, context) != 0)
				return -1;

			if (pfcp_config.cp_type == PGWC)
				context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;

			pdn->proc = get_csr_proc(csr);

			if (csr->uci.header.len != 0) {
				if(fill_user_csg_info(&csr->uci, context) != 0)
					return -1;
			}

			if (csr->ue_time_zone.header.len != 0) {
				if(fill_time_zone_info(&csr->ue_time_zone, context) != 0)
					return -1;
			}

			if( csr->mo_exception_data_cntr.header.len != 0){
				context->mo_exception_data_counter.timestamp_value =  csr->mo_exception_data_cntr.timestamp_value;
				context->mo_exception_data_counter.counter_value = csr->mo_exception_data_cntr.counter_value;
				context->mo_exception_flag = true;
			}

			/* VS: Stored the RAT TYPE information in UE context */
			if (csr->rat_type.header.len != 0) {
				context->rat_type.rat_type = csr->rat_type.rat_type;
				context->rat_type.len = csr->rat_type.header.len;
			}

			/*AALI: Stored the UP selection flag*/
			if(csr->up_func_sel_indctn_flgs.header.len != 0) {
				context->up_selection_flag = TRUE;
				context->dcnr_flag = csr->up_func_sel_indctn_flgs.dcnr;
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


		//	uint8_t default_bearer_id = pdn->default_bearer_id -5 ;
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

		context->pdns[ebi_index]->dp_seid = 0;

		struct li_df_config_t *li_config = NULL;
		int ret = get_li_config(context->imsi, &li_config);
		if (!ret) {
			if ((li_config->uiAction == EVENT_BASED) ||
					(li_config->uiAction == CC_EVENT_BASED)) {
				context->li_sock_fd = get_tcp_tunnel(
										li_config->ddf2_ip.s_addr,
										li_config->uiDDf2Port, TCP_CREATE);
			}

			context->dupl = PRESENT;
		}
	} /*Check UE Exist*/

	if (fill_bearer_info(csr, bearer, context, pdn, ebi_index) != 0)
		return -1;

	/* SGW Handover Storage */
	if (csr->indctn_flgs.header.len != 0)
	{
		fill_indication_flags(csr, context);

			/* SGW Handover Storage */
			if(context->indication_flag.oi) {
				memcpy(&(pdn->ipv4.s_addr) ,&(csr->paa.pdn_addr_and_pfx), IPV4_SIZE);
				/*TODO:ntohl is done as in csr response there is htonl*/
				pdn->ipv4.s_addr = ntohl(pdn->ipv4.s_addr);
				context->indication_flag.oi = csr->indctn_flgs.indication_oi;
				pdn->s5s8_pgw_gtpc_teid = csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key;
				bearer->s5s8_pgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created[i].s5s8_u_pgw_fteid.ipv4_address;
				bearer->s5s8_pgw_gtpu_teid = csr->bearer_contexts_to_be_created[i].s5s8_u_pgw_fteid.teid_gre_key;
				bearer->s1u_enb_gtpu_teid =   csr->bearer_contexts_to_be_created[i].s1u_enb_fteid.teid_gre_key;
				bearer->s1u_enb_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created[i].s1u_enb_fteid.ipv4_address;
			}
	}


	pdn->context = context;
} /*for loop*/

#ifdef GX_BUILD
		if ((pfcp_config.cp_type == PGWC) || (pfcp_config.cp_type == SAEGWC)) {

			if ((ret = gen_ccr_request(context, pdn->default_bearer_id - 5, csr)) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error: Failed to generate CCR requset : %s \n", __func__, __LINE__,
						strerror(errno));
				return ret;
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
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	if ((context->mme_fqcsid == NULL) ||
			(context->sgw_fqcsid == NULL)) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
				ERR_MSG);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* MME FQ-CSID */
	if (csr->mme_fqcsid.header.len) {
		/* Stored the MME CSID by MME Node address */
		tmp = get_peer_addr_csids_entry(csr->mme_fqcsid.node_address,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the MME CSID by MME Node address %s \n", ERR_MSG,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
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

		for(uint8_t itr1 = 0; itr1 < csr->mme_fqcsid.number_of_csids; itr1++) {
				(context->mme_fqcsid)->local_csid[(context->mme_fqcsid)->num_csid++] =
					csr->mme_fqcsid.pdn_csid[itr1];
		}
		(context->mme_fqcsid)->node_addr = csr->mme_fqcsid.node_address;
	} else {
		/* Stored the MME CSID by MME Node address */
		tmp = get_peer_addr_csids_entry(context->s11_mme_gtpc_ipv4.s_addr,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the MME CSID by MME Node address: %s \n", ERR_MSG,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = context->s11_mme_gtpc_ipv4.s_addr;
		(context->mme_fqcsid)->node_addr = context->s11_mme_gtpc_ipv4.s_addr;
	}

	/* SGW FQ-CSID */
	if (csr->sgw_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(csr->sgw_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the SGW CSID by SGW Node address : %s \n", ERR_MSG,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
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
		for(uint8_t itr1 = 0; itr1 < csr->sgw_fqcsid.number_of_csids; itr1++) {
				(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid++] =
					csr->sgw_fqcsid.pdn_csid[itr1];
		}
		(context->sgw_fqcsid)->node_addr = csr->sgw_fqcsid.node_address;
	} else {
		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
			tmp = get_peer_addr_csids_entry(context->s11_sgw_gtpc_ipv4.s_addr,
					ADD);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the SGW CSID by SGW Node address : %s \n", ERR_MSG,
						strerror(errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			tmp->node_addr = ntohl(context->s11_sgw_gtpc_ipv4.s_addr);
			(context->sgw_fqcsid)->node_addr = ntohl(context->s11_sgw_gtpc_ipv4.s_addr);
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_config.cp_type == PGWC) {
		tmp = get_peer_addr_csids_entry(pdn->s5s8_pgw_gtpc_ipv4.s_addr,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the PGW CSID by PGW Node address : %s \n", ERR_MSG,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		(context->pgw_fqcsid)->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	}
#endif /* USE_CSID */

	/* VS: Store the context of ue in pdn*/

	context->bearer_count = csr->bearer_count;
	pdn->context = context;
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
	if(bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Bearer context not found. EBI ID : %d\n",
				__func__, __LINE__, pdn->default_bearer_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	sequence = get_pfcp_sequence_number(PFCP_SESSION_ESTABLISHMENT_REQUEST, sequence);

	for(uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = pdn->eps_bearers[i];
		if(bearer == NULL)
			continue;

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

	}

	fill_pfcp_sess_est_req(&pfcp_sess_est_req, pdn, sequence, context);

#ifdef USE_CSID

	/*Pointing bearer t the default bearer*/
	bearer = pdn->eps_bearers[pdn->default_bearer_id - 5];

	uint16_t tmp_csid = 0;
	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {
			tmp_csid =
				(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1];
		}
	}
	/* Add the entry for peer nodes */
	if (fill_peer_node_info(pdn, bearer)) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Failed to fill peer node info and assignment of the CSID Error: %s\n",
				ERR_MSG,
				strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if (pfcp_config.cp_type != PGWC) {
		if (tmp_csid) {
			if (tmp_csid != (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1]) {
				/* Remove the session link from old CSID */
				sess_csid *tmp1 = NULL;
				tmp1 = get_sess_csid_entry(tmp_csid, REMOVE_NODE);

				if (tmp1 != NULL) {
					/* Remove node from csid linked list */
					tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

					int8_t ret = 0;
					/* Update CSID Entry in table */
					ret = rte_hash_add_key_data(seids_by_csid_hash,
									&tmp_csid, tmp1);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								FORMAT"Failed to add Session IDs entry for CSID = %u"
								"\n\tError= %s\n",
								ERR_MSG, tmp_csid,
								rte_strerror(abs(ret)));
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}
					//tmp1 = get_sess_csid_data_node(tmp1, tmp1->cp_seid);
					//memset(tmp1, 0, sizeof(sess_csid));
				}
				clLog(clSystemLog, eCLSeverityDebug,
						FORMAT"Remove session link from Old CSID:%u\n",
						ERR_MSG, tmp_csid);
			}
		}
	}

	/* Add entry for cp session id with link local csid */
	sess_csid *tmp = NULL;
	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		tmp = get_sess_csid_entry(
				(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1], ADD_NODE);
	} else {
		/* PGWC */
		tmp = get_sess_csid_entry(
				(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1], ADD_NODE);
	}

	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Link local csid with session id */
	/* Check head node created ot not */
	if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
		sess_csid *new_node = NULL;
		/* Add new node into csid linked list */
		new_node = add_sess_csid_data_node(tmp);
		if(new_node == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to ADD new node into CSID"
					"linked list : %s\n", ERR_MSG);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		} else {
			new_node->cp_seid = pdn->seid;
			new_node->up_seid = pdn->dp_seid;
		}

	} else {
		tmp->cp_seid = pdn->seid;
		tmp->up_seid = pdn->dp_seid;
	}

	/* Fill the fqcsid into the session est request */
	if (fill_fqcsid_sess_est_req(&pfcp_sess_est_req, context)) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to fill FQ-CSID in Sess EST Req ERROR: %s\n",
				ERR_MSG,
				strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
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
	int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg, INTERFACE);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error sending: %i\n",
				__func__, __LINE__, errno);
		return -1;
	} else {
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
process_pfcp_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp, gtpv2c_header_t *gtpv2c_tx, uint8_t is_piggybacked)
{
	int ret = 0, msg_len = 0;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint64_t sess_id = pfcp_sess_est_rsp->header.seid_seqno.has_seid.seid;
	uint64_t dp_sess_id = pfcp_sess_est_rsp->up_fseid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);
	gtpv2c_header_t *gtpv2c_cbr_t = NULL;

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

	/*TODO need to think on eps_bearer_id*/
	uint8_t ebi_index = resp->eps_bearer_id;

	pdn = context->eps_bearers[ebi_index]->pdn;
	bearer = context->eps_bearers[ebi_index];

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	fqcsid_t *fqcsid = NULL;
	fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
				ERR_MSG);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* SGW FQ-CSID */
	if (pfcp_sess_est_rsp->sgw_u_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->sgw_u_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the SGW CSID by SGW Node address : %s \n",
					ERR_MSG, strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
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

		for(uint8_t itr1 = 0; itr1 < pfcp_sess_est_rsp->sgw_u_fqcsid.number_of_csids; itr1++) {
				fqcsid->local_csid[fqcsid->num_csid++] =
					pfcp_sess_est_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr1];
		}
		fqcsid->node_addr = pfcp_sess_est_rsp->sgw_u_fqcsid.node_address;
	} else {
		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->up_fseid.ipv4_address,
					ADD);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the SGW CSID by SGW Node address :  %s \n",
						ERR_MSG, strerror(errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			tmp->node_addr = pfcp_sess_est_rsp->up_fseid.ipv4_address;
			fqcsid->node_addr = pfcp_sess_est_rsp->up_fseid.ipv4_address;
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_sess_est_rsp->pgw_u_fqcsid.header.len) {
		/* Stored the PGW CSID by PGW Node address */
		tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->pgw_u_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the PGW CSID by PGW Node address : %s \n", ERR_MSG,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
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
		for(uint8_t itr1 = 0; itr1 < pfcp_sess_est_rsp->pgw_u_fqcsid.number_of_csids; itr1++) {
				fqcsid->local_csid[fqcsid->num_csid++] =
					pfcp_sess_est_rsp->pgw_u_fqcsid.pdn_conn_set_ident[itr1];
		}
		fqcsid->node_addr = pfcp_sess_est_rsp->pgw_u_fqcsid.node_address;
	} else {
		if (pfcp_config.cp_type == PGWC) {
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->up_fseid.ipv4_address,
					ADD);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Add the PGW CSID by PGW Node address %s \n", ERR_MSG,
						strerror(errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			tmp->node_addr = pfcp_sess_est_rsp->up_fseid.ipv4_address;
			fqcsid->node_addr = pfcp_sess_est_rsp->up_fseid.ipv4_address;
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
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to Update and Link Peer node CSID with local CSID : %s \n", ERR_MSG,
				strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Update entry for up session id with link local csid */
	sess_csid *sess_t = NULL;
	sess_csid *sess_tmp = NULL;
	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		if (context->sgw_fqcsid) {
			sess_t = get_sess_csid_entry(
					(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1], UPDATE_NODE);
		}
	} else {
		/* PGWC */
		if (context->pgw_fqcsid) {
			sess_t = get_sess_csid_entry(
					(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1], UPDATE_NODE);
		}
	}

	if (sess_t == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Link local csid with session id */
	sess_tmp = get_sess_csid_data_node(sess_t, pdn->seid);
	if(sess_tmp == NULL ) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to get node data for Seid: %x\n",
				ERR_MSG, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update up SEID in CSID linked list node */
	sess_tmp->up_seid = dp_sess_id;

	/* Update the UP CSID in the context */
	context->up_fqcsid = fqcsid;

#endif /* USE_CSID */

	pdn->dp_seid = dp_sess_id;

	/* Update the UE state */
	pdn->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	if (pfcp_config.cp_type == SAEGWC) {
		msg_len = set_create_session_response(
					gtpv2c_tx, context->sequence, context, pdn, bearer, is_piggybacked);
#ifdef GX_BUILD
		if(is_piggybacked){
			gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + msg_len);
			uint8_t ebi = 0;
			get_bearer_info_install_rules(pdn, &ebi);
			bearer = context->eps_bearers[ebi];
			/*if (!bearer) {
			  clLog(clSystemLog, eCLSeverityCritical,
			  "%s:%d Retrive modify bearer context but EBI is non-existent- "
			  "Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
			  return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			  }*/

			set_create_bearer_request(gtpv2c_cbr_t, context->sequence, pdn,
					pdn->default_bearer_id, 0, resp, is_piggybacked);

			resp->state = CREATE_BER_REQ_SNT_STATE;
			pdn->state = CREATE_BER_REQ_SNT_STATE;


		}
#else
	RTE_SET_USED(gtpv2c_cbr_t);
#endif /* GX_BUILD */
		s11_mme_sockaddr.sin_addr.s_addr =
						htonl(context->s11_mme_gtpc_ipv4.s_addr);

	} else if (pfcp_config.cp_type == PGWC) {
		/*TODO: This needs to be change after support libgtpv2 on S5S8*/
		/* set_pgwc_s5s8_create_session_response(gtpv2c_tx,
				(htonl(context->sequence) >> 8), pdn, bearer); */

		create_sess_rsp_t cs_resp = {0};
		fill_pgwc_create_session_response(&cs_resp,
			context->sequence, context, ebi_index, is_piggybacked);

#ifdef USE_CSID
		if (context->pgw_fqcsid != NULL) {
			if ((context->pgw_fqcsid)->num_csid) {
				set_gtpc_fqcsid_t(&cs_resp.pgw_fqcsid, IE_INSTANCE_ZERO,
						context->pgw_fqcsid);
			}
		}
#endif /* USE_CSID */
		gtpv2c_header_t *header = NULL;

		msg_len = encode_create_sess_rsp(&cs_resp, (uint8_t*)gtpv2c_tx);
		gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + msg_len);
		header = (gtpv2c_header_t*) gtpv2c_tx;
		msg_len = msg_len - 4;
		header->gtpc.message_len = htons(msg_len);
#ifdef GX_BUILD
		if(is_piggybacked){
			uint8_t ebi = 0;
			get_bearer_info_install_rules(pdn, &ebi);
			bearer = context->eps_bearers[ebi];
			if (!bearer) {
				clLog(clSystemLog, eCLSeverityCritical,
						"%s:%d Retrive modify bearer context but EBI is non-existent- "
						"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			set_create_bearer_request(gtpv2c_cbr_t, context->sequence, pdn,
					pdn->default_bearer_id, 0, resp, is_piggybacked);

			resp->state = CREATE_BER_REQ_SNT_STATE;
			pdn->state = CREATE_BER_REQ_SNT_STATE;

		}
#endif /* GX_BUILD */
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
		if (context->sgw_fqcsid != NULL) {
			if ((context->sgw_fqcsid)->num_csid) {
				set_gtpc_fqcsid_t(&cs_req.sgw_fqcsid, IE_INSTANCE_ONE,
						context->sgw_fqcsid);
				cs_req.sgw_fqcsid.node_address = ntohl(pfcp_config.s5s8_ip.s_addr);
			}
		}
		/* Set the MME FQ-CSID */
		if (context->mme_fqcsid != NULL) {
			if ((context->mme_fqcsid)->num_csid) {
				set_gtpc_fqcsid_t(&cs_req.mme_fqcsid, IE_INSTANCE_ZERO,
						context->mme_fqcsid);
			}
		}
#endif /* USE_CSID */
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, "%s:Failed to create the CSR request \n", __func__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
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
	uint8_t ebi_index = 0, index = 0;
	eps_bearer *bearers[MAX_BEARERS];
	uint8_t x2_handover = 0;

	for(uint8_t i = 0; i< mb_req->bearer_count; i++ ) {
		ebi_index = mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi - 5 ;
		if(ebi_index == 0)
			break;
	}

	if (!(pdn->context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}

	bearer = pdn->eps_bearers[ebi_index];
	pdn->seid = SESS_ID(pdn->context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req.update_far_count = 0;

	RTE_SET_USED(update_far);
	for(uint8_t i =0 ;i< MAX_BEARER; i++)
	{
		bearer = pdn->eps_bearers[i];
		if(bearer == NULL)
			continue;

		if ((mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len  != 0) ||
				(mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.header.len  != 0)){
			if (mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len  != 0){
				/* TAU change */
				if(bearer->s1u_enb_gtpu_ipv4.s_addr != 0) {
					if((mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.teid_gre_key)
							!= bearer->s1u_enb_gtpu_teid  ||
							(mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address) !=
							bearer->s1u_enb_gtpu_ipv4.s_addr) {
						x2_handover = 1;
					}
				}
				bearer->s1u_enb_gtpu_ipv4.s_addr =
					mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address;
				bearer->s1u_enb_gtpu_teid =
					mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.teid_gre_key;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
					bearer->s1u_enb_gtpu_teid;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->s1u_enb_gtpu_ipv4.s_addr;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
					check_interface_type(mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.interface_type);
				update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
					get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
				if ( pfcp_config.cp_type != PGWC) {
					update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
					update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(pdn->context);
				}
				pfcp_sess_mod_req.update_far_count++;
			}
			if (mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.header.len  != 0){
				if((pdn->context->eci_changed == TRUE) &&
						((bearer->s5s8_sgw_gtpu_ipv4.s_addr !=
						 mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.ipv4_address) ||
						(bearer->s5s8_sgw_gtpu_teid !=
						 mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.teid_gre_key))){
					x2_handover = 1;
				}
				bearer->s5s8_sgw_gtpu_ipv4.s_addr =
					mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.ipv4_address;
				bearer->s5s8_sgw_gtpu_teid =
					mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.teid_gre_key;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
					bearer->s5s8_sgw_gtpu_teid;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
					check_interface_type(mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.interface_type);
				update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
					get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
				if ( pfcp_config.cp_type != PGWC) {
					update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
					update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(pdn->context);
				}
				pfcp_sess_mod_req.update_far_count++;
			}
			/*Added 0 in the last argument below as it is not X2 handover case*/
			bearers[index] = bearer;
			index++;
		}
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearers, pdn, update_far, x2_handover, index, pdn->context);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg, INTERFACE);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
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
	resp->eps_bearer_id = mb_req->bearer_contexts_to_be_modified[ebi_index].eps_bearer_id.ebi_ebi -5 ;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	if( pdn->proc != MODIFICATION_PROC){
		pdn->proc= SGW_RELOCATION_PROC;//GTP_MODIFY_BEARER_REQ;
	}
	resp->proc = pdn->proc;
	resp->gtpc_msg.mbr = *mb_req;
	return 0;
}

/**
 * @brief  : Compare ecgi data
 * @param  : mb_ecgi, ecgi from incoming request
 * @param  : context_ecgi, ecgi data stored in context
 * @return : Returns 0 on success, -1 otherwise
 */
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

/**
 * @brief  : Compare cgi data
 * @param  : mb_cgi, cgi from incoming request
 * @param  : context_cgi, cgi data stored in context
 * @return : Returns 0 on success, -1 otherwise
 */
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

/**
 * @brief  : Compare sai data
 * @param  : mb_sai, sai from incoming request
 * @param  : context_sai, sai data stored in context
 * @return : Returns 0 on success, -1 otherwise
 */
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

/**
 * @brief  : Compare rai data
 * @param  : mb_rai, rai from incoming request
 * @param  : context_rai, rai data stored in context
 * @return : Returns 0 on success, -1 otherwise
 */
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

/**
 * @brief  : Compare tai data
 * @param  : mb_tai, tai from incoming request
 * @param  : context_tai, tai data stored in context
 * @return : Returns 0 on success, -1 otherwise
 */
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

/**
 * @brief  : Compare uci information
 * @param  : mb_req, data from incoming request
 * @param  : context, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static int
compare_uci(mod_bearer_req_t *mb_req, ue_context *context){
	if(context->uci.mnc_digit_1 != mb_req->uci.mnc_digit_1)
		return FALSE;
	if(context->uci.mnc_digit_2 != mb_req->uci.mnc_digit_2)
		return FALSE;
	if(context->uci.mnc_digit_3 != mb_req->uci.mnc_digit_3)
		return FALSE;
	if(context->uci.mcc_digit_1 != mb_req->uci.mcc_digit_1)
		return FALSE;
	if(context->uci.mcc_digit_2 != mb_req->uci.mcc_digit_2)
		return FALSE;
	if(context->uci.mcc_digit_3 != mb_req->uci.mcc_digit_3)
		return FALSE;
	if(context->uci.csg_id != mb_req->uci.csg_id)
		return FALSE;
	if(context->uci.csg_id2 != mb_req->uci.csg_id2)
		return FALSE;
	if(context->uci.access_mode != mb_req->uci.access_mode)
		return FALSE;
	if(context->uci.lcsg != mb_req->uci.lcsg)
		return FALSE;
	if(context->uci.cmi != mb_req->uci.cmi)
		return FALSE;

	return TRUE;
}

/**
 * @brief  : Compare serving network information
 * @param  : mb_req, data from incoming request
 * @param  : context, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static int
compare_serving_network(mod_bearer_req_t *mb_req, ue_context *context){
	if(context->serving_nw.mnc_digit_1 != mb_req->serving_network.mnc_digit_1)
		return FALSE;
	if(context->serving_nw.mnc_digit_2 != mb_req->serving_network.mnc_digit_2)
		return FALSE;
	if(context->serving_nw.mnc_digit_3 != mb_req->serving_network.mnc_digit_3)
		return FALSE;
	if(context->serving_nw.mcc_digit_1 != mb_req->serving_network.mcc_digit_1)
		return FALSE;
	if(context->serving_nw.mcc_digit_2 != mb_req->serving_network.mcc_digit_2)
		return FALSE;
	if(context->serving_nw.mcc_digit_3 != mb_req->serving_network.mcc_digit_3)
		return FALSE;

	return TRUE;
}

/**
 * @brief  : Save serving network information
 * @param  : mb_req, data from incoming request
 * @param  : context, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_serving_network(mod_bearer_req_t *mb_req, ue_context *context){
	context->serving_nw.mnc_digit_1 = mb_req->serving_network.mnc_digit_1;
	context->serving_nw.mnc_digit_2 = mb_req->serving_network.mnc_digit_2;
	context->serving_nw.mnc_digit_3 = mb_req->serving_network.mnc_digit_3;
	context->serving_nw.mcc_digit_1 = mb_req->serving_network.mcc_digit_1;
	context->serving_nw.mcc_digit_2 = mb_req->serving_network.mcc_digit_2;
	context->serving_nw.mcc_digit_3 = mb_req->serving_network.mcc_digit_3;
}

/**
 * @brief  : Save uci information
 * @param  : recv_uci, data from incoming request
 * @param  : context, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_uci(gtp_user_csg_info_ie_t *recv_uci, ue_context *context){
	context->uci.mnc_digit_1 = recv_uci->mnc_digit_1;
	context->uci.mnc_digit_2 = recv_uci->mnc_digit_2;
	context->uci.mnc_digit_3 = recv_uci->mnc_digit_3;
	context->uci.mcc_digit_1 = recv_uci->mcc_digit_1;
	context->uci.mcc_digit_2 = recv_uci->mcc_digit_2;
	context->uci.mcc_digit_3 = recv_uci->mcc_digit_3;
	context->uci.csg_id      = recv_uci->csg_id;
	context->uci.csg_id2     = recv_uci->csg_id2;
	context->uci.access_mode = recv_uci->access_mode;
	context->uci.lcsg        = recv_uci->lcsg;
	context->uci.cmi         = recv_uci->cmi;
}

/**
 * @brief  : Save tai information
 * @param  : recv_tai, data from incoming request
 * @param  : context_tai, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_tai(tai_field_t *recv_tai, tai_t *context_tai)
{
	//context_tai->uli_old.tai = uli->tai;
	context_tai->tai_mcc_digit_2 = recv_tai->tai_mcc_digit_2;
	context_tai->tai_mcc_digit_1 = recv_tai->tai_mcc_digit_1;
	context_tai->tai_mnc_digit_3 = recv_tai->tai_mnc_digit_3;
	context_tai->tai_mcc_digit_3 = recv_tai->tai_mcc_digit_3;
	context_tai->tai_mnc_digit_2 = recv_tai->tai_mnc_digit_2;
	context_tai->tai_mnc_digit_1 = recv_tai->tai_mnc_digit_1;
	context_tai->tai_tac = recv_tai->tai_tac;

}

/**
 * @brief  : Save cgi information
 * @param  : recv_cgi, data from incoming request
 * @param  : context_cgi, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_cgi(cgi_field_t *recv_cgi, cgi_t *context_cgi)
{
		context_cgi->cgi_mcc_digit_2 = recv_cgi->cgi_mcc_digit_2;
		context_cgi->cgi_mcc_digit_1 = recv_cgi->cgi_mcc_digit_1;
		context_cgi->cgi_mnc_digit_3 = recv_cgi->cgi_mnc_digit_3;
		context_cgi->cgi_mcc_digit_3 = recv_cgi->cgi_mcc_digit_3;
		context_cgi->cgi_mnc_digit_2 = recv_cgi->cgi_mnc_digit_2;
		context_cgi->cgi_mnc_digit_1 = recv_cgi->cgi_mnc_digit_1;
		context_cgi->cgi_lac =recv_cgi->cgi_lac;
		context_cgi->cgi_ci = recv_cgi->cgi_ci;

}

/**
 * @brief  : Save sai information
 * @param  : recv_sai, data from incoming request
 * @param  : context_sai, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_sai(sai_field_t *recv_sai, sai_t *context_sai)
{
		context_sai->sai_mcc_digit_2 = recv_sai->sai_mcc_digit_2;
		context_sai->sai_mcc_digit_1 = recv_sai->sai_mcc_digit_1;
		context_sai->sai_mnc_digit_3 = recv_sai->sai_mnc_digit_3;
		context_sai->sai_mcc_digit_3 = recv_sai->sai_mcc_digit_3;
		context_sai->sai_mnc_digit_2 = recv_sai->sai_mnc_digit_2;
		context_sai->sai_mnc_digit_1 = recv_sai->sai_mnc_digit_1;
		context_sai->sai_lac         = recv_sai->sai_lac;
		context_sai->sai_sac         = recv_sai->sai_sac;

}

/**
 * @brief  : Save rai information
 * @param  : recv_rai, data from incoming request
 * @param  : context_rai, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_rai(rai_field_t *recv_rai, rai_t *context_rai)
{
		context_rai->ria_mcc_digit_2 = recv_rai->ria_mcc_digit_2;
		context_rai->ria_mcc_digit_1 = recv_rai->ria_mcc_digit_1;
		context_rai->ria_mnc_digit_3 = recv_rai->ria_mnc_digit_3;
		context_rai->ria_mcc_digit_3 = recv_rai->ria_mcc_digit_3;
		context_rai->ria_mnc_digit_2 = recv_rai->ria_mnc_digit_2;
		context_rai->ria_mnc_digit_1 = recv_rai->ria_mnc_digit_1;
		context_rai->ria_lac = recv_rai->ria_lac;
		context_rai->ria_rac = recv_rai->ria_rac;

}

/**
 * @brief  : Save ecgi information
 * @param  : recv_ecgi, data from incoming request
 * @param  : context_ecgi, data stored in ue context
 * @return : Returns 0 on success, -1 otherwise
 */
static void
save_ecgi(ecgi_field_t *recv_ecgi, ecgi_t *context_ecgi)
{
		context_ecgi->ecgi_mcc_digit_2 = recv_ecgi->ecgi_mcc_digit_2;
		context_ecgi->ecgi_mcc_digit_1 = recv_ecgi->ecgi_mcc_digit_1;
		context_ecgi->ecgi_mnc_digit_3 = recv_ecgi->ecgi_mnc_digit_3;
		context_ecgi->ecgi_mcc_digit_3 = recv_ecgi->ecgi_mcc_digit_3;
		context_ecgi->ecgi_mnc_digit_2 = recv_ecgi->ecgi_mnc_digit_2;
		context_ecgi->ecgi_mnc_digit_1 = recv_ecgi->ecgi_mnc_digit_1;
		context_ecgi->ecgi_spare = recv_ecgi->ecgi_spare;
		context_ecgi->eci = recv_ecgi->eci;
}

int8_t
update_ue_context(mod_bearer_req_t *mb_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	for(uint8_t i = 0; i< mb_req->bearer_count; i++) {
		ebi_index = mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi - 5;
		if(ebi_index == 0)
			break;
	}

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

	if(pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Cannot find PDN in function %s at line %d\n\n", __func__, __LINE__);
		return -EPERM;
	}


	/*Update Secondary Rat Data if Received on MBR*/
	context->second_rat_flag = FALSE;
	if(mb_req->secdry_rat_usage_data_rpt.header.len != 0 &&
			mb_req->secdry_rat_usage_data_rpt.irpgw == 1) {
		context->second_rat_flag = TRUE;
		context->second_rat.spare2 = mb_req->secdry_rat_usage_data_rpt.spare2;
		context->second_rat.irsgw = mb_req->secdry_rat_usage_data_rpt.irsgw;
		context->second_rat.irpgw = mb_req->secdry_rat_usage_data_rpt.irpgw;
		context->second_rat.rat_type = mb_req->secdry_rat_usage_data_rpt.secdry_rat_type;
		context->second_rat.eps_id = mb_req->secdry_rat_usage_data_rpt.ebi;
		context->second_rat.spare3 = mb_req->secdry_rat_usage_data_rpt.spare3;
		context->second_rat.start_timestamp = mb_req->secdry_rat_usage_data_rpt.start_timestamp;
		context->second_rat.end_timestamp = mb_req->secdry_rat_usage_data_rpt.end_timestamp;
		context->second_rat.usage_data_dl = mb_req->secdry_rat_usage_data_rpt.usage_data_dl;
		context->second_rat.usage_data_ul = mb_req->secdry_rat_usage_data_rpt.usage_data_ul;
	}

	/* Update new MME information */
	if(mb_req->sender_fteid_ctl_plane.header.len){
		context->s11_mme_gtpc_teid = mb_req->sender_fteid_ctl_plane.teid_gre_key;
		context->s11_mme_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;
		s11_mme_sockaddr.sin_addr.s_addr = htonl(mb_req->sender_fteid_ctl_plane.ipv4_address);
		if(pfcp_config.cp_type == PGWC) {
			clLog(clSystemLog, eCLSeverityDebug,
					"Updating S5S8 SGWC FTEID AT PGWC in Case of SGWC Relocation\n\n");

			pdn->s5s8_sgw_gtpc_teid = mb_req->sender_fteid_ctl_plane.teid_gre_key;
			pdn->s5s8_sgw_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;
		}
	}

	/* Update time zone information*/
	if(mb_req->ue_time_zone.header.len){
		if((mb_req->ue_time_zone.time_zone != context->tz.tz) ||
				(mb_req->ue_time_zone.daylt_svng_time != context->tz.dst)){
			context->tz.tz = mb_req->ue_time_zone.time_zone;
			context->tz.dst = mb_req->ue_time_zone.daylt_svng_time;
			context->ue_time_zone_flag = TRUE;
		}
	}

	uint8_t flag_check_uli = 0;

	/*The above flag will be set bit wise as
	 * Bit 7| Bit 6 | Bit 5 | Bit 4 | Bit 3|  Bit 2|  Bit 1|  Bit 0 |
	 *---------------------------------------------------------------
	 *|     |       |       | ECGI  | RAI  |  SAI  |  CGI  |  TAI   |
	 ----------------------------------------------------------------
	 */

	/* Update uli information */
	if(mb_req->uli.header.len) {

		if(mb_req->uli.tai) {
			ret = compare_tai(&mb_req->uli.tai2, &context->uli.tai2);
			if(ret == FALSE) {
				flag_check_uli |= (1 << 0 );
				context->old_uli_valid = TRUE;
				context->uli_flag = TRUE;
				//save_tai(&mb_req->uli.tai2, &context->old_uli.tai2);
			}
		}
		if(mb_req->uli.cgi) {
			ret = compare_cgi(&mb_req->uli.cgi2, &context->uli.cgi2);
			if(ret == FALSE) {
				flag_check_uli |= ( 1<< 1 );
				context->old_uli_valid = TRUE;
				context->uli_flag = TRUE;
				//save_cgi(&mb_req->uli.cgi2, &context->old_uli.cgi2);
			}
		}
		if(mb_req->uli.sai) {
			ret = compare_sai(&mb_req->uli.sai2, &context->uli.sai2);
			if(ret == FALSE) {
				flag_check_uli |= (1 << 2 );
				context->old_uli_valid = TRUE;
				context->uli_flag = TRUE;
				//save_sai(&mb_req->uli.sai2, &context->old_uli.sai2);
			}
		}
		if(mb_req->uli.rai) {
			ret = compare_rai(&mb_req->uli.rai2, &context->uli.rai2);
			if(ret == FALSE) {
				flag_check_uli |= ( 1 << 3 );
				context->old_uli_valid = TRUE;
				context->uli_flag = TRUE;
				//save_rai(&mb_req->uli.rai2, &context->old_uli.rai2);
			}
		}
		if(mb_req->uli.ecgi) {
			ret = compare_ecgi(&mb_req->uli.ecgi2, &context->uli.ecgi2);
			if(ret == FALSE) {
				flag_check_uli |= (1 << 4);
				context->old_uli_valid = TRUE;
				context->uli_flag = TRUE;
				//save_ecgi(&mb_req->uli.ecgi2, &context->old_uli.ecgi2);
			}
		}
	}

	/* Update RAT type information */
	if (mb_req->rat_type.header.len != 0) {
		if( context->rat_type.rat_type != mb_req->rat_type.rat_type ||
				context->rat_type.len != mb_req->rat_type.header.len){
			context->rat_type.rat_type = mb_req->rat_type.rat_type;
			context->rat_type.len = mb_req->rat_type.header.len;
			context->rat_type_flag = TRUE;
		}
	}

	/* Update User CSG information */
	if (mb_req->uci.header.len != 0) {
		ret = compare_uci(mb_req, context);
		if(ret == FALSE) {
			context->uci_flag = TRUE;
			save_uci(&mb_req->uci, context);
		}
	}

	/* Update serving network information */
	if(mb_req->serving_network.header.len){
		ret = compare_serving_network(mb_req, context);
		if(ret == FALSE) {
			context->serving_nw_flag = TRUE;
			save_serving_network(mb_req, context);
		}
	}

	/* LTE-M RAT type reporting to PGW flag */
	if(mb_req->indctn_flgs.header.len){
		if(mb_req->indctn_flgs.indication_ltempi){
			context->ltem_rat_type_flag = true;
		}
	}

	return 0;
}

/**
 * @brief  : Function checks if uli information is changed
 * @param  : uli, data from incoming request
 * @param  : context, data stored in ue context
 * @param  : flag_check, flag to set if uli is changed
 * @return : Returns 0 on success, -1 otherwise
 */
static void
check_for_uli_changes(gtp_user_loc_info_ie_t *uli, ue_context *context, uint8_t *flag_check)
{

	uint8_t ret = 0;

	if(uli->tai) {

		ret = compare_tai(&uli->tai2, &context->uli.tai2);
		if(ret == FALSE) {
			*flag_check |= (1 << 0 );
			context->old_uli_valid = TRUE;
			save_tai(&uli->tai2, &context->uli.tai2);
		}
	}

	if(uli->cgi) {
		ret = compare_cgi(&uli->cgi2, &context->uli.cgi2);
		if(ret == FALSE) {
			*flag_check|= ( 1<< 1 );
			context->old_uli_valid = TRUE;
			save_cgi(&uli->cgi2, &context->uli.cgi2);
		}
	}
	if(uli->sai) {
		ret = compare_sai(&uli->sai2, &context->uli.sai2);
		if(ret == FALSE) {
			*flag_check |= (1 << 2 );
			context->old_uli_valid = TRUE;
			save_sai(&uli->sai2, &context->uli.sai2);
		}
	}
	if(uli->rai) {
		ret = compare_rai(&uli->rai2, &context->uli.rai2);
		if(ret == FALSE) {
			*flag_check |= ( 1 << 3 );
			context->old_uli_valid = TRUE;
			save_rai(&uli->rai2, &context->uli.rai2);
		}
	}
	if(uli->ecgi) {
		ret = compare_ecgi(&uli->ecgi2, &context->uli.ecgi2);
		if(ret == FALSE) {
			*flag_check |= (1 << 4);
			context->old_uli_valid = TRUE;
			save_ecgi(&uli->ecgi2, &context->uli.ecgi2);
		}
	}
}

int process_pfcp_sess_mod_req_handover(mod_bearer_req_t *mb_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	//pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	for(uint8_t i = 0; i< mb_req->bearer_count; i++) {
		ebi_index = mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi - 5;
		if(ebi_index == 0)
			break;
	}
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

	/*Note: Below case is for ERAB MODIFICATION Procedure*/
	if(context->second_rat_flag == TRUE) {

		uint8_t trigg_buff[] = "secondary_rat_usage";
		cdr second_rat_data = {0} ;
		struct timeval unix_start_time;
		struct timeval unix_end_time;

		second_rat_data.cdr_type = CDR_BY_SEC_RAT;
		second_rat_data.change_rat_type_flag = 1;
		/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
		second_rat_data.rat_type = (mb_req->secdry_rat_usage_data_rpt.secdry_rat_type == 0) ? 10 : 0;
		second_rat_data.bearer_id = mb_req->secdry_rat_usage_data_rpt.ebi;
		second_rat_data.seid = pdn->seid;
		second_rat_data.imsi = pdn->context->imsi;
		second_rat_data.start_time = mb_req->secdry_rat_usage_data_rpt.start_timestamp;
		second_rat_data.end_time = mb_req->secdry_rat_usage_data_rpt.end_timestamp;
		second_rat_data.data_volume_uplink = mb_req->secdry_rat_usage_data_rpt.usage_data_ul;
		second_rat_data.data_volume_downlink = mb_req->secdry_rat_usage_data_rpt.usage_data_dl;

		ntp_to_unix_time(&second_rat_data.start_time, &unix_start_time);
		ntp_to_unix_time(&second_rat_data.end_time, &unix_end_time);

		second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
		second_rat_data.data_start_time = 0;
		second_rat_data.data_end_time = 0;
		second_rat_data.total_data_volume = second_rat_data.data_volume_uplink + second_rat_data.data_volume_downlink;

		memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));
		generate_cdr_info(&second_rat_data);
		clLog(clSystemLog, eCLSeverityDebug, "CDR For Secondary Rat is generated\n\n");
	}

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
				if(mb_req->uli.ecgi2.eci != pdn->context->uli.ecgi2.eci){
					pdn->context->eci_changed = TRUE;
				}else{
					pdn->context->eci_changed = FALSE;
				}
				save_ecgi(&mb_req->uli.ecgi2, &pdn->context->old_uli.ecgi2);
			}
		}
	}

#ifdef GX_BUILD
	/* TODO something with modify_bearer_request.delay if set */

	struct resp_info *resp = NULL;
	if(((context->old_uli_valid == TRUE) && (((context->event_trigger & (1 << ULI_EVENT_TRIGGER))) != 0))
		|| ((pdn->old_ue_tz_valid == TRUE) && (((context->event_trigger) & (1 << UE_TIMEZONE_EVT_TRIGGER)) != 0))
		|| (mb_req->rat_type.header.len != 0)) {

		ret = gen_ccru_request(pdn, bearer, flag_check_uli);
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


#endif /* GX_BUILD */
	if((context->second_rat_flag == TRUE) && (PGWC == pfcp_config.cp_type)) {

		uint8_t payload_length = 0;
		bzero(&tx_buf, sizeof(tx_buf));
		gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
		set_modify_bearer_response_handover(gtpv2c_tx, mb_req->header.teid.has_teid.seq, context,
				bearer, mb_req);

		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		s5s8_recv_sockaddr.sin_addr.s_addr =
			htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);

		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len, SENT);

		process_cp_li_msg_using_context(
				context, tx_buf, payload_length,
				pfcp_config.s5s8_ip.s_addr, s5s8_recv_sockaddr.sin_addr.s_addr,
				pfcp_config.s5s8_port, s5s8_recv_sockaddr.sin_port);


		context->second_rat_flag = FALSE;
		return 0;
	} else {
		context->second_rat_flag = FALSE;
		ret = send_pfcp_sess_mod_req_handover(pdn, bearer, mb_req);
	}
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

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req ,pdn, bearers, resp->bearer_count);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg, INTERFACE);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	} else {

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

uint32_t get_far_id(eps_bearer *bearer, int interface_value){
	pdr_t *pdr_ctxt = NULL;
	for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
		if(bearer->pdrs[itr]->pdi.src_intfc.interface_value != interface_value){
			pdr_ctxt = bearer->pdrs[itr];
			/* Update destination interface into create far */
			pdr_ctxt->far.dst_intfc.interface_value = interface_value;
			return pdr_ctxt->far.far_id_value;
		}
	}
	return 0;
}

int
process_pfcp_sess_mod_request(mod_bearer_req_t *mb_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	uint8_t x2_handover = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL, *bearers[MAX_BEARERS] ={NULL};
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE] = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	pfcp_sess_mod_req.update_far_count = 0;
	for(uint8_t i = 0; i < mb_req->bearer_count; i++) {

		if (!mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.header.len
				|| !mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Dropping packet\n",
					__func__, __LINE__);
			return GTPV2C_CAUSE_INVALID_LENGTH;
		}

		ebi_index = mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi - 5;

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

		if (mb_req->bearer_contexts_to_be_modified[i].s11_u_mme_fteid.header.len &&
				(context->s11_mme_gtpc_teid != mb_req->bearer_contexts_to_be_modified[i].s11_u_mme_fteid.teid_gre_key)) {

			context->s11_mme_gtpc_teid = mb_req->bearer_contexts_to_be_modified[i].s11_u_mme_fteid.teid_gre_key;
		}

		bearer->eps_bearer_id = mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi;

		if (mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len != 0) {

			if(bearer->s1u_enb_gtpu_ipv4.s_addr != 0) {
				if((mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.teid_gre_key)
						!= bearer->s1u_enb_gtpu_teid  ||
						(mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address) !=
						bearer->s1u_enb_gtpu_ipv4.s_addr) {
					x2_handover = 1;
				}
			}

			/* Bug 370. No need to send end marker packet in DDN */
			if (CONN_SUSPEND_PROC == pdn->proc ) {
				x2_handover = 0;
			}

			bearer->s1u_enb_gtpu_ipv4.s_addr =
				mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address;
			bearer->s1u_enb_gtpu_teid =
				mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.teid_gre_key;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
				bearer->s1u_enb_gtpu_teid;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
				bearer->s1u_enb_gtpu_ipv4.s_addr;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
				check_interface_type(mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.interface_type);
			update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
				get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(pdn->context);
			pfcp_sess_mod_req.update_far_count++;

		}

		if (mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.header.len  != 0){
			bearer->s5s8_sgw_gtpu_ipv4.s_addr =
				mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.ipv4_address;
			bearer->s5s8_sgw_gtpu_teid =
				mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.teid_gre_key;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
				bearer->s5s8_sgw_gtpu_teid;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
				bearer->s5s8_sgw_gtpu_ipv4.s_addr;
			update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
				check_interface_type(mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.interface_type);
			update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
				get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
			if ( pfcp_config.cp_type != PGWC) {
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl= GET_DUP_STATUS(pdn->context);
			}
			pfcp_sess_mod_req.update_far_count++;
		}

		//context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
		bearers[i] = bearer;

	} /*forloop*/

	ebi_index = pdn->default_bearer_id - 5;
	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;
	pdn->seid = SESS_ID(context->s11_sgw_gtpc_teid, pdn->default_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearers, pdn, update_far, x2_handover, mb_req->bearer_count, context);

	/*Adding the secondary rat usage report to the CDR Entry when it it a E RAB
	 * MODIFICATION*/
	if((context->second_rat_flag == TRUE) && (x2_handover == 1 ) && (mb_req->secdry_rat_usage_data_rpt.irsgw == 1)){
		uint8_t trigg_buff[] = "secondary_rat_usage";
		cdr second_rat_data = {0};
		struct timeval unix_start_time;
		struct timeval unix_end_time;

		second_rat_data.cdr_type = CDR_BY_SEC_RAT;
		second_rat_data.change_rat_type_flag = 1;
		/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
		second_rat_data.rat_type = (mb_req->secdry_rat_usage_data_rpt.secdry_rat_type == 0) ? 10 : 0;
		second_rat_data.bearer_id = mb_req->secdry_rat_usage_data_rpt.ebi;
		second_rat_data.seid = pdn->seid;
		second_rat_data.imsi = pdn->context->imsi;
		second_rat_data.start_time = mb_req->secdry_rat_usage_data_rpt.start_timestamp;
		second_rat_data.end_time = mb_req->secdry_rat_usage_data_rpt.end_timestamp;
		second_rat_data.data_volume_uplink = mb_req->secdry_rat_usage_data_rpt.usage_data_ul;
		second_rat_data.data_volume_downlink = mb_req->secdry_rat_usage_data_rpt.usage_data_dl;

		ntp_to_unix_time(&second_rat_data.start_time, &unix_start_time);
		ntp_to_unix_time(&second_rat_data.end_time, &unix_end_time);

		second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
		second_rat_data.data_start_time = 0;
		second_rat_data.data_end_time = 0;
		second_rat_data.total_data_volume = second_rat_data.data_volume_uplink + second_rat_data.data_volume_downlink;

		memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));
		generate_cdr_info(&second_rat_data);
	}


#ifdef USE_CSID
	/* Generate the permant CSID for SGW */
	if (pfcp_config.cp_type != PGWC) {
		uint16_t tmp_csid = 0;
		if (context->sgw_fqcsid != NULL) {
			if ((context->sgw_fqcsid)->num_csid) {
				tmp_csid = (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1];
			}
		}

		/* Update the entry for peer nodes */
		if (fill_peer_node_info(pdn, bearer)) {
			clLog(clSystemLog, eCLSeverityCritical,
					FORMAT"Failed to fill peer node info and assignment of the CSID Error: %s\n",
					ERR_MSG,
					strerror(errno));
			return  GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (tmp_csid != (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1]) {
			if (tmp_csid) {
				if (tmp_csid != (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1]) {
					/* Remove the session link from old CSID */
					sess_csid *tmp1 = NULL;
					tmp1 = get_sess_csid_entry(tmp_csid, REMOVE_NODE);

					if (tmp1 != NULL) {
						/* Remove node from csid linked list */
						tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

						int8_t ret = 0;
						/* Update CSID Entry in table */
						ret = rte_hash_add_key_data(seids_by_csid_hash,
										&tmp_csid, tmp1);
						if (ret) {
							clLog(clSystemLog, eCLSeverityCritical,
									FORMAT"Failed to add Session IDs entry for CSID = %u"
									"\n\tError= %s\n",
									ERR_MSG, tmp_csid,
									rte_strerror(abs(ret)));
							return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
						}
						//tmp1 = get_sess_csid_data_node(tmp1, tmp1->cp_seid);
						//memset(tmp1, 0, sizeof(sess_csid));

						/* Removing temporary local CSID associated with MME */
						remove_peer_temp_csid(context->mme_fqcsid, tmp_csid, S11_SGW_PORT_ID);

						/* Removing temporary local CSID assocoated with PGWC */
						remove_peer_temp_csid(context->pgw_fqcsid, tmp_csid, S5S8_SGWC_PORT_ID);
					}
					clLog(clSystemLog, eCLSeverityDebug,
							FORMAT"Remove session link from Old CSID:%u\n",
							ERR_MSG, tmp_csid);
				}
			}

			/* update entry for cp session id with link local csid */
			sess_csid *tmp = NULL;
			if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
				tmp = get_sess_csid_entry(
						(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1], ADD_NODE);
			} else {
				/* PGWC */
				tmp = get_sess_csid_entry(
						(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1], ADD_NODE);
			}

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error:Failed to get session of CSID entry %s \n", ERR_MSG,
						strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Link local csid with session id */
			/* Check head node created ot not */
			if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
				sess_csid *new_node = NULL;
				/* Add new node into csid linked list */
				new_node = add_sess_csid_data_node(tmp);
				if(new_node == NULL ) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to ADD new node into CSID"
							"linked list : %s\n",__func__);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				} else {
					new_node->cp_seid = pdn->seid;
					new_node->up_seid = pdn->dp_seid;
				}

			} else {
				tmp->cp_seid = pdn->seid;
				tmp->up_seid = pdn->dp_seid;
			}

			/* Fill the fqcsid into the session est request */
			if (fill_fqcsid_sess_mod_req(&pfcp_sess_mod_req, context)) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to fill FQ-CSID in Sess EST Req ERROR: %s\n",
						ERR_MSG,
						strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
		}
	}

#endif /* USE_CSID */

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg, INTERFACE);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: pfcp message failed %i\n",errno);
	} else {
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
	resp->eps_bearer_id =  pdn->default_bearer_id;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	memcpy(&resp->gtpc_msg.mbr, mb_req, sizeof(mod_bearer_req_t));

	return 0;
}

int
proc_pfcp_sess_mbr_udp_csid_req(mod_bearer_req_t *mb_req,
		gtpv2c_header_t *gtpc_mbr_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer  *bearers[MAX_BEARERS], *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	uint8_t default_bearer_id = 0;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = mb_req->bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi - 5;

	bearer = context->eps_bearers[ebi_index];
	if (bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Bearer value is coming NULL\n",
				__func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = bearer->pdn;
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Pdn connection value is coming NULL\n",__func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearers[0] = bearer;
	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearers, pdn, NULL, 0, 1, context);

#ifdef USE_CSID
	/* Parse and stored MME and SGW FQ-CSID in the context */
	fqcsid_t *tmp = NULL;

	/* SGW FQ-CSID */
	if (mb_req->sgw_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(mb_req->sgw_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		tmp->node_addr = mb_req->sgw_fqcsid.node_address;

		for(uint8_t itr = 0; itr < mb_req->sgw_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == mb_req->sgw_fqcsid.pdn_csid[itr])
					match = 1;
			}
			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					mb_req->sgw_fqcsid.pdn_csid[itr];
			}
		}

		if ((context->sgw_fqcsid)->num_csid) {
			/* Remove the session link from old CSID */
			csid_t *tmp = NULL;
			csid_key_t key = {0};
			key.local_csid = (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1];
			key.node_addr = (context->sgw_fqcsid)->node_addr;

			tmp = get_peer_csid_entry(&key, S5S8_PGWC_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to  get CSID %s \n", ERR_MSG,
						strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			for(uint8_t it = 0; it < tmp->num_csid; it++) {
				if (tmp->local_csid[it] ==
						(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1]) {
					for(uint8_t pos = it; pos < (tmp->num_csid - 1); pos++ ) {
						tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					}
					tmp->num_csid--;
				}
			}

			/* Reset the temp allocated CSID */
			(context->sgw_fqcsid)->num_csid--;
		}

		for(uint8_t itr1 = 0; itr1 < mb_req->sgw_fqcsid.number_of_csids; itr1++) {
			(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid++] =
				mb_req->sgw_fqcsid.pdn_csid[itr1];

		}

		(context->sgw_fqcsid)->node_addr = mb_req->sgw_fqcsid.node_address;
	}

	/* PGW Link local CSID with SGW CSID */
	if ((context->sgw_fqcsid)->num_csid) {
		for (uint8_t itr = 0; itr < (context->sgw_fqcsid)->num_csid; itr++) {
			csid_t *tmp = NULL;
			csid_key_t key = {0};
			key.local_csid = (context->sgw_fqcsid)->local_csid[itr];
			key.node_addr = (context->sgw_fqcsid)->node_addr;
			uint16_t local_csid_t =
				(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1];

			tmp = get_peer_csid_entry(&key, S5S8_PGWC_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: Failed to get CSID %s \n", ERR_MSG,
						strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Link local csid with SGW CSID */
			if (tmp->num_csid == 0) {
				/* Update csid by mme csid */
				tmp->local_csid[tmp->num_csid++] = local_csid_t;
			} else {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
						if (tmp->local_csid[itr1] == local_csid_t)
							match = 1;
				}

				if (!match) {
					tmp->local_csid[tmp->num_csid++] = local_csid_t;
				}
			}
			/* Update the node address */
			tmp->node_addr = (context->pgw_fqcsid)->node_addr;
		}
	}


	/* Fill the fqcsid into the session est request */
	if (fill_fqcsid_sess_mod_req(&pfcp_sess_mod_req, context)) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to fill FQ-CSID in Sess EST Req ERROR: %s\n",
				ERR_MSG,
				strerror(errno));
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
#endif /* USE_CSID */
	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg, INTERFACE);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
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
	resp->eps_bearer_id = default_bearer_id;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->gtpc_msg.mbr = *mb_req;

	/* Fill the MBR response and send back to SGW */
	set_modify_bearer_response(gtpc_mbr_tx,
			context->sequence, context, bearer, &resp->gtpc_msg.mbr);

	s5s8_recv_sockaddr.sin_addr.s_addr =
		htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);

	clLog(clSystemLog, eCLSeverityDebug, FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", ERR_MSG,
			inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

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
	uint8_t *buffer = NULL;
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


	raa.data.cp_raa.session_id.len = strnlen(pdn->gx_sess_id,MAX_LEN);
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
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len_total);
			//msg_len + sizeof(raa.msg_type) + sizeof(unsigned long));

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_RAA, SENT, GX);

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
		clLog(clSystemLog, eCLSeverityCritical,
			"%s:%d NO Session Entry Found for sess ID:%lu\n",
			__func__, __LINE__, sess_id);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,
			"%s:%d UE context not found %u\n",
			__func__, __LINE__,ret);

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

			gen_reauth_response(context, resp->eps_bearer_id - 5);

			delete_dedicated_bearers(context->pdns[bearer_id],
				resp->eps_bearer_ids, resp->bearer_count);

			resp->state = CONNECTED_STATE;
			resp->msg_type = GX_RAA_MSG;
			context->pdns[resp->eps_bearer_id - 5]->state = CONNECTED_STATE;

			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
			return 0;
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
process_pfcp_sess_upd_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint64_t sess_id = pfcp_sess_mod_rsp->header.seid_seqno.has_seid.seid;
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
	if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ebi_index = UE_BEAR_ID(sess_id) - 5;
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed to get pdn \n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;

	}
	return 0;
}

uint8_t
process_pfcp_sess_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint64_t sess_id = pfcp_sess_mod_rsp->header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d No Session Entry Found for sess ID:%lu\n",
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
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ebi_index = UE_BEAR_ID(sess_id) - 5;
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed to get pdn \n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

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
				context->sequence, context, bearer, &resp->gtpc_msg.mbr);
		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;

#ifdef USE_CSID
		if ((pfcp_config.cp_type != PGWC) && (pdn->proc == INITIAL_PDN_ATTACH_PROC)) {
			uint16_t old_csid =
				(context->up_fqcsid)->local_csid[(context->up_fqcsid)->num_csid - 1];
			fqcsid_t *tmp = NULL;
			fqcsid_t *fqcsid = NULL;
			fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (fqcsid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
						ERR_MSG);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			/* SGW FQ-CSID */
			if (pfcp_sess_mod_rsp->sgw_u_fqcsid.header.len) {
				if (pfcp_sess_mod_rsp->sgw_u_fqcsid.number_of_csids) {
					/* Stored the SGW CSID by SGW Node address */
					tmp = get_peer_addr_csids_entry(pfcp_sess_mod_rsp->sgw_u_fqcsid.node_address,
							ADD);

					if (tmp == NULL) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: peer csid entry not found %s %s %d\n", ERR_MSG,__func__
							,__LINE__,strerror(errno));
						return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
					}

					tmp->node_addr = pfcp_sess_mod_rsp->sgw_u_fqcsid.node_address;

					for(uint8_t itr = 0; itr < pfcp_sess_mod_rsp->sgw_u_fqcsid.number_of_csids; itr++) {
						uint8_t match = 0;
						for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
							if (tmp->local_csid[itr1] == pfcp_sess_mod_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr]) {
								match = 1;
							}
						}
						if (!match) {
							tmp->local_csid[tmp->num_csid++] =
								pfcp_sess_mod_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr];
						}
					}
					for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_rsp->sgw_u_fqcsid.number_of_csids; itr1++) {
							fqcsid->local_csid[fqcsid->num_csid++] =
								pfcp_sess_mod_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr1];
					}

					fqcsid->node_addr = pfcp_sess_mod_rsp->sgw_u_fqcsid.node_address;

					for (uint8_t itr2 = 0; itr2 < tmp->num_csid; itr2++) {
						if (tmp->local_csid[itr2] == old_csid) {
							for(uint8_t pos = itr2; pos < (tmp->num_csid - 1); pos++ ) {
								tmp->local_csid[pos] = tmp->local_csid[pos + 1];
							}
							tmp->num_csid--;
						}
					}
					///* Remove CSID From Peer Node entry if local CSID is not linked */
					//fqcsid_t *tmp = NULL;
					//csid_t *csid = NULL;


			//csid_key_t key_t = {0};
					//key_t.local_csid = old_csid;
					//key_t.node_addr = fqcsid->node_addr;

					//csid = get_peer_csid_entry(&key_t, SX_PORT_ID);
					//if (csid == NULL) {
					//	clLog(clSystemLog, eCLSeverityCritical,
					//					FORMAT"Error: %s \n", ERR_MSG,
					//					strerror(errno));
					//	return -1;
					//}
					//for (uint8_t itr3 = 0; itr3 < csid->num_csid; itr3++) {
					//	if (csid->local_csid[itr2] == ) {
					//		for(uint8_t pos = itr2; pos < (tmp->num_csid - 1); pos++ ) {
					//			tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					//		}
					//		tmp->num_csid--;
					//	}
					//}
				}
			}
			else{
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"context not found for FQ-CSID while session modification \n",ERR_MSG);
			}

			/* TODO: Add the handling if SGW or PGW not support Partial failure */
			/* Link peer node SGW or PGW csid with local csid */
			if (pfcp_config.cp_type != PGWC) {
				ret = update_peer_csid_link(fqcsid, context->sgw_fqcsid);
			}

			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: peer csid entry not found %s %s %d\n", ERR_MSG, __func__,
					__LINE__,strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Update the UP CSID in the context */
			context->up_fqcsid = fqcsid;

			/* Send the updated SGW CSID to peer node */
			if (pfcp_config.cp_type == SGWC) {
				uint16_t payload_length = 0;
				bzero(&s5s8_tx_buf, sizeof(s5s8_tx_buf));
				gtpv2c_header_t *gtpc_mbr_tx = (gtpv2c_header_t *)s5s8_tx_buf;

				/* Fill the MBReq with updated SGW CSID */
				if (set_mbr_upd_sgw_csid_req(gtpc_mbr_tx, pdn, UE_BEAR_ID(sess_id)) < 0) {
					/* TODO: Handling the error conditions */

				}

				s5s8_recv_sockaddr.sin_addr.s_addr =
					htonl(bearer->pdn->s5s8_pgw_gtpc_ipv4.s_addr);

				clLog(clSystemLog, eCLSeverityDebug, FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", ERR_MSG,
						inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

				payload_length = ntohs(gtpc_mbr_tx->gtpc.message_len)
					+ sizeof(gtpc_mbr_tx->gtpc);

				gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len, SENT);

				process_cp_li_msg_using_context(
					context, s5s8_tx_buf, payload_length,
					pfcp_config.s5s8_ip.s_addr, s5s8_recv_sockaddr.sin_addr.s_addr,
					pfcp_config.s5s8_port, s5s8_recv_sockaddr.sin_port);

			}
		}
#endif /* USE_CSID */
		/* Update the next hop IP address */
		if (PGWC != pfcp_config.cp_type) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		}

		return 0;

	} else if (resp->msg_type == GTP_CREATE_SESSION_RSP) {
		/* Fill the Create session response */
		set_create_session_response(
				gtpv2c_tx, context->sequence, context, bearer->pdn, bearer, 0);

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
	        ret = set_create_bearer_request(gtpv2c_tx, context->sequence, pdn,
				pdn->default_bearer_id, 0, resp, 0);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;

		if (SAEGWC == pfcp_config.cp_type) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		} else {
		    s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);
		}

		return ret;
#endif
	} else if (resp->msg_type == GTP_CREATE_BEARER_REQ) {
		ret = set_sgwc_create_bearer_request(gtpv2c_tx, context->sequence, pdn,
		resp->eps_bearer_id, 0, resp);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

		return ret;

	} else if (resp->msg_type == GTP_CREATE_BEARER_RSP) {

		if ((SAEGWC == pfcp_config.cp_type) || (PGWC == pfcp_config.cp_type)) {
#ifdef GX_BUILD
			gen_reauth_response(context, resp->eps_bearer_id - 5);

			resp->msg_type = GX_RAA_MSG;
			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			return 0;

#endif
		} else {
			bearer = context->eps_bearers[resp->eps_bearer_id - 5];
			set_create_bearer_response(
				gtpv2c_tx, context->sequence, pdn, resp->eps_bearer_id, 0, resp);

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

			clLog(clSystemLog, eCLSeverityDebug, "SGWC:%s: "
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

		clLog(clSystemLog, eCLSeverityDebug, "%s:%d s11_mme_sockaddr.sin_addr.s_addr :%s\n",
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

	clLog(clSystemLog, eCLSeverityDebug, "%s:%d s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
				__LINE__, inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	return 0;
}

uint8_t
process_pfcp_sess_mod_resp_for_mod_proc(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
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
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ebi_index = UE_BEAR_ID(sess_id) - 5;
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed to get pdn \n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if(SGWC == pfcp_config.cp_type){
		uint8_t flag_check = 0;

		if((context->second_rat_flag == TRUE) && (context->second_rat.irpgw == 0)) {

			/* Fill the modify bearer response */
			set_modify_bearer_response_handover(gtpv2c_tx,
					context->sequence, context, bearer, &resp->gtpc_msg.mbr);
			resp->state = CONNECTED_STATE;
			/* Update the UE state */
			pdn->state = CONNECTED_STATE;
			return 0;
		}

		check_for_uli_changes(&resp->gtpc_msg.mbr.uli, pdn->context, &flag_check);
		set_modify_bearer_request(gtpv2c_tx, pdn, bearer);

		s5s8_recv_sockaddr.sin_addr.s_addr =
			htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);

		resp->state = MBR_REQ_SNT_STATE;
		pdn->state = resp->state;
		context->uli_flag = FALSE;
		context->serving_nw_flag = FALSE;
		context->rat_type_flag = FALSE;
		context->ue_time_zone_flag = FALSE;
		context->uci_flag = FALSE;
		context->second_rat_flag = FALSE;
	}else{
		/* Fill the modify bearer response */
		set_modify_bearer_response_handover(gtpv2c_tx,
				context->sequence, context, bearer, &resp->gtpc_msg.mbr);

		if(SAEGWC == pfcp_config.cp_type){
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		}

		s5s8_recv_sockaddr.sin_addr.s_addr =
			htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);

		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;
	}
	return 0;
}

int
process_change_noti_request(change_noti_req_t *change_not_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn =  NULL;
	//struct resp_info *resp = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &change_not_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = change_not_req->lbi.ebi_ebi - 5;
	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;
	uint8_t flag_check = 0;

	if(change_not_req->imsi.header.len == 0) {

		clLog(clSystemLog, eCLSeverityCritical,
			"%s:%d IMSI NOT FOUND in Change Notification Message\n\n", __func__, __LINE__);

		uint8_t payload_length = 0;
		bzero(&tx_buf, sizeof(tx_buf));
		gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

		set_change_notification_response(gtpv2c_tx, pdn, FALSE);

		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		if(PGWC == pfcp_config.cp_type) {
			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);

			gtpv2c_send(s5s8_fd, tx_buf, payload_length,
					(struct sockaddr *) &s5s8_recv_sockaddr,
					s5s8_sockaddr_len, SENT);

			process_cp_li_msg_using_context(
				context, tx_buf, payload_length,
				pfcp_config.s5s8_ip.s_addr, s5s8_recv_sockaddr.sin_addr.s_addr,
				pfcp_config.s5s8_port, s5s8_recv_sockaddr.sin_port);

		} else if(SAEGWC == pfcp_config.cp_type) {

			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(pdn->context->s11_mme_gtpc_ipv4.s_addr);

			gtpv2c_send(s11_fd, tx_buf, payload_length,
					(struct sockaddr *) &s11_mme_sockaddr,
					s11_mme_sockaddr_len, SENT);

			process_cp_li_msg_using_context(
				context, tx_buf, payload_length,
				pfcp_config.s11_ip.s_addr, s11_mme_sockaddr.sin_addr.s_addr,
				pfcp_config.s11_port, s11_mme_sockaddr.sin_port);
		}

		pdn->state = CONNECTED_STATE;
		pdn->proc =  INITIAL_PDN_ATTACH_PROC;

	}

	//memcpy(&context->imsi, &(change_not_req->imsi.imsi_number_digits), change_not_req->imsi.header.len);

	context->imsi_len = change_not_req->imsi.header.len;

	context->sequence = change_not_req->header.teid.has_teid.seq;
	if(change_not_req->uli.header.len !=0) {
		check_for_uli_changes(&change_not_req->uli, pdn->context, &flag_check);
	}

	if(change_not_req->rat_type.header.len != 0) {
		context->rat_type.rat_type = change_not_req->rat_type.rat_type;
	}
	if(change_not_req->second_rat_count != 0 ) {
		/*Add to the CDR */
		uint8_t trigg_buff[] = "secondary_rat_usage";
		for(uint8_t i = 0; i <  change_not_req->second_rat_count; i++) {
			cdr second_rat_data = {0} ;
			struct timeval unix_start_time;
			struct timeval unix_end_time;

			second_rat_data.cdr_type = CDR_BY_SEC_RAT;
			second_rat_data.change_rat_type_flag = 1;
			/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
			second_rat_data.rat_type = (change_not_req->secdry_rat_usage_data_rpt[i].secdry_rat_type == 0) ? 10 : 0;
			second_rat_data.bearer_id = change_not_req->lbi.ebi_ebi;
			second_rat_data.seid = pdn->seid;
			second_rat_data.imsi = pdn->context->imsi;
			second_rat_data.start_time = change_not_req->secdry_rat_usage_data_rpt[i].start_timestamp;
			second_rat_data.end_time = change_not_req->secdry_rat_usage_data_rpt[i].end_timestamp;
			second_rat_data.data_volume_uplink = change_not_req->secdry_rat_usage_data_rpt[i].usage_data_ul;
			second_rat_data.data_volume_downlink = change_not_req->secdry_rat_usage_data_rpt[i].usage_data_dl;
			ntp_to_unix_time(&change_not_req->secdry_rat_usage_data_rpt[i].start_timestamp,&unix_start_time);
			ntp_to_unix_time(&change_not_req->secdry_rat_usage_data_rpt[i].end_timestamp,&unix_end_time);
			second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
			second_rat_data.data_start_time = 0;
			second_rat_data.data_end_time = 0;
			second_rat_data.total_data_volume = change_not_req->secdry_rat_usage_data_rpt[i].usage_data_ul +
			change_not_req->secdry_rat_usage_data_rpt[i].usage_data_dl;
			memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));
			generate_cdr_info(&second_rat_data);
		}
	}
#ifdef GX_BUILD
	if(flag_check != 0 || change_not_req->rat_type.header.len != 0) {
		ret = gen_ccru_request(pdn, bearer, flag_check);
		return 0;
	}
#endif /* GX_BUILD */
	/**/
	uint8_t payload_length = 0;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	set_change_notification_response(gtpv2c_tx, pdn, FALSE);

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	s5s8_recv_sockaddr.sin_addr.s_addr =
		htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);

	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
			(struct sockaddr *) &s5s8_recv_sockaddr,
			s5s8_sockaddr_len,SENT);

	process_cp_li_msg_using_context(
		context, tx_buf, payload_length,
		pfcp_config.s5s8_ip.s_addr, s5s8_recv_sockaddr.sin_addr.s_addr,
		pfcp_config.s5s8_port, s5s8_recv_sockaddr.sin_port);

	return 0;
}

int
process_change_noti_response(change_noti_rsp_t *change_not_rsp, gtpv2c_header_t *gtpv2c_tx)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int ret = 0;
	//uint8_t ebi_index = 0;

	change_noti_rsp_t change_notification_rsp = {0};

	ret = get_ue_context_by_sgw_s5s8_teid(change_not_rsp->header.teid.has_teid.teid, &context);
	if (ret < 0 || !context) {
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ret = get_bearer_by_teid(change_not_rsp->header.teid.has_teid.teid, &bearer);
	if(ret < 0) {
		fprintf(stderr, "%s:%d Entry not found for teid:%x...\n", __func__, __LINE__, change_not_rsp->header.teid.has_teid.teid);
		return -1;
	}

	//bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;

	set_gtpv2c_teid_header((gtpv2c_header_t *) &change_notification_rsp, GTP_CHANGE_NOTIFICATION_RSP,
		context->s11_mme_gtpc_teid, context->sequence, 0);

	//set_cause_accepted(&change_notification_rsp.cause, IE_INSTANCE_ZERO);
	set_cause_accepted(&change_notification_rsp.cause, IE_INSTANCE_ZERO);
	change_notification_rsp.cause.cause_value = change_not_rsp->cause.cause_value;

	memcpy(&change_notification_rsp.imsi.imsi_number_digits, &(context->imsi), context->imsi_len);
	set_ie_header(&change_notification_rsp.imsi.header, GTP_IE_IMSI, IE_INSTANCE_ZERO,
			context->imsi_len);

	s11_mme_sockaddr.sin_addr.s_addr =
		htonl(context->s11_mme_gtpc_ipv4.s_addr);

	uint16_t msg_len = 0;
	msg_len = encode_change_noti_rsp(&change_notification_rsp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	pdn->state =  CONNECTED_STATE;
	pdn->proc = INITIAL_PDN_ATTACH_PROC;
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

	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Context not found for given %s %d - "
				"Dropping packet\n",__func__,__LINE__);

		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ebi_index = del_req->lbi.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received Delete Session on non-existent EBI - "
				"Dropping packet\n");
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received Delete Session on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n");
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = bearer->pdn;

	bearer->eps_bearer_id = del_req->lbi.ebi_ebi;

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, pdn, pdn->eps_bearers,
			MAX_BEARERS);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg, INTERFACE);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	} else {
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
		clLog(clSystemLog, eCLSeverityCritical, "No Session Entry Found for sess ID : %lu at %s %d \n", context->pdns[ebi_index]->seid,__func__,__LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
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

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"%s:%d Error sending pfcp session delete request : %i\n", __func__, __LINE__, errno);
		return -1;
	} else  {

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
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed to get pdn \n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

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
	if (ret && ret!=-1)
		return ret;

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->pdns[ebi_index]->dp_seid;

	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical,
			"%s:%d Error sending Session Modification Request %i\n", __func__, __LINE__, errno);
			return -1;
	} else  {

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
		clLog(clSystemLog, eCLSeverityCritical,
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

			snprintf(rule_name.rule_name, RULE_NAME_LEN, "%s%d",
					ded_bearer->dynamic_rules[index]->rule_name, pdn->call_id);

			/* Delete rule name from hash */
			if (del_rule_name_entry(rule_name)) {
				/* TODO: Error handling rule not found */
				clLog(clSystemLog, eCLSeverityCritical,
						"%s:%d Failed to delete rule entry\n",__func__, __LINE__);
				return -1;
			}
		}

		/* Delete PDR, QER of bearer */
		if (del_rule_entries(pdn->context, ebi)) {
			/* TODO: Error message handling in case deletion failed */
			clLog(clSystemLog, eCLSeverityCritical,
					"%s:%d Failed to delete rule entries\n",__func__, __LINE__);
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

#ifdef USE_CSID
int8_t
cleanup_session_entries(uint16_t local_csid, ue_context *context)
{
	int ret = 0;
	/* Clean MME FQ-CSID */
	if (context->mme_fqcsid != NULL) {
		if ((context->mme_fqcsid)->num_csid) {
			csid_t *csid = NULL;
			csid_key_t key_t = {0};
			key_t.local_csid = (context->mme_fqcsid)->local_csid[(context->mme_fqcsid)->num_csid - 1];
			key_t.node_addr = (context->mme_fqcsid)->node_addr;

			if (pfcp_config.cp_type != PGWC)
				csid = get_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
			else
				csid = get_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);

			if (csid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						FORMAT"Error: MME csid is null %s \n", ERR_MSG,
						strerror(errno));

				return -1;
			}

			for (uint8_t itr1 = 0; itr1 < csid->num_csid; itr1++) {
				if (csid->local_csid[itr1] == local_csid) {
					for(uint8_t pos = itr1; pos < (csid->num_csid - 1); pos++ ) {
						csid->local_csid[pos] = csid->local_csid[pos + 1];
					}
					csid->num_csid--;
				}
			}

			if (!csid->num_csid) {
				if (pfcp_config.cp_type != PGWC)
					ret = del_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
				else
					ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							FORMAT"Error: unable to delete peer MME csid entry %s \n", ERR_MSG,
									strerror(errno));
					return -1;
				}
			}
		}
		if (context->mme_fqcsid != NULL)
			rte_free(context->mme_fqcsid);
	}

	/* Clean SGW FQ-CSID */
	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {
			csid_t *csid = NULL;
			csid_key_t key_t = {0};
			key_t.local_csid = (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1];
			key_t.node_addr = (context->sgw_fqcsid)->node_addr;

			if (pfcp_config.cp_type != PGWC)
				csid = get_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
			else
				csid = get_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
			if (csid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						FORMAT"Error: SGW FQ-CSID is null %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			for (uint8_t itr1 = 0; itr1 < csid->num_csid; itr1++) {
				if (csid->local_csid[itr1] == local_csid) {
					for(uint8_t pos = itr1; pos < (csid->num_csid - 1); pos++ ) {
						csid->local_csid[pos] = csid->local_csid[pos + 1];
					}
					csid->num_csid--;
				}
			}

			if (!csid->num_csid) {
				if (pfcp_config.cp_type != PGWC)
					ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				else
					ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								FORMAT"Error: unable to delete peer FQ-CSID entry%s \n", ERR_MSG,
									strerror(errno));
					return -1;
				}
			}
		}
		if (context->sgw_fqcsid != NULL)
			rte_free(context->sgw_fqcsid);
	}

	if (pfcp_config.cp_type != SAEGWC) {
		/* Clean PGW FQ-CSID */
		if (context->pgw_fqcsid != NULL) {
			if ((context->pgw_fqcsid)->num_csid) {
				csid_t *csid = NULL;
				csid_key_t key_t = {0};
				key_t.local_csid = (context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1];
				key_t.node_addr = (context->pgw_fqcsid)->node_addr;

				if (pfcp_config.cp_type != PGWC)
					csid = get_peer_csid_entry(&key_t, S5S8_SGWC_PORT_ID);
				else
					csid = get_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				if (csid == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							FORMAT"Error: PGW FQ-CSID entry is null %s \n", ERR_MSG, strerror(errno));
					return -1;
				}

				for (uint8_t itr1 = 0; itr1 < csid->num_csid; itr1++) {
					if (csid->local_csid[itr1] == local_csid) {
						for(uint8_t pos = itr1; pos < (csid->num_csid - 1); pos++ ) {
							csid->local_csid[pos] = csid->local_csid[pos + 1];
						}
						csid->num_csid--;
					}
				}

				if (!csid->num_csid) {
					if (pfcp_config.cp_type != PGWC)
						ret = del_peer_csid_entry(&key_t, S5S8_SGWC_PORT_ID);
					else
						ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: unable to delete peer PGW CSID entry  %s \n", ERR_MSG,
										strerror(errno));
						return -1;
					}
				}
			}
			if (context->pgw_fqcsid != NULL)
				rte_free(context->pgw_fqcsid);
		}
	}

	/* Clean UP FQ-CSID */
	if (context->up_fqcsid != NULL) {
		if ((context->up_fqcsid)->num_csid) {
			csid_t *csid = NULL;
			csid_key_t key_t = {0};
			key_t.local_csid = (context->up_fqcsid)->local_csid[(context->up_fqcsid)->num_csid - 1];
			key_t.node_addr = (context->up_fqcsid)->node_addr;

			csid = get_peer_csid_entry(&key_t, SX_PORT_ID);
			if (csid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
							FORMAT"Error: CSID is null %s \n", ERR_MSG,
								strerror(errno));
				return -1;
			}

			for (uint8_t itr1 = 0; itr1 < csid->num_csid; itr1++) {
				if (csid->local_csid[itr1] == local_csid) {
					for(uint8_t pos = itr1; pos < (csid->num_csid - 1); pos++ ) {
						csid->local_csid[pos] = csid->local_csid[pos + 1];
					}
					csid->num_csid--;
				}
			}

			if (!csid->num_csid) {
				ret = del_peer_csid_entry(&key_t, SX_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error while deleting CSID %s \n", ERR_MSG,
									strerror(errno));
					return -1;
				}
			}
		}
		if (context->up_fqcsid != NULL)
			rte_free(context->up_fqcsid);
	}
	return 0;
}
#endif /* USE_CSID */

int8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		gx_msg *ccr_request, uint16_t *msglen, uint64_t *uiImsi, int *li_sock_fd)
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
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO response Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_DEL_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
									__func__, __LINE__, teid);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Set IMSI for lawful interception */
	*uiImsi = context->imsi;

	/* Set Socket Fd for lawful interception */
	*li_sock_fd = context->li_sock_fd;

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
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
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

		clLog(clSystemLog, eCLSeverityDebug, "PGWC:%s:%d "
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

		if(context->num_pdns == 0) {
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
						FORMAT"Error on upflist_by_ue_hash deletion of IMSI \n",
						ERR_MSG);
			}
#endif /* USE_DNS_QUERY */
		}

#ifdef USE_CSID
		fqcsid_t *csids = context->pgw_fqcsid;
		/* Get the session ID by csid */
		for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
			sess_csid *tmp = NULL;

			tmp = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
			if (tmp == NULL)
				continue;

			/* Remove node from csid linked list */
			tmp = remove_sess_csid_data_node(tmp, sess_id);

			/* Update CSID Entry in table */
			ret = rte_hash_add_key_data(seids_by_csid_hash,
							&csids->local_csid[itr], tmp);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical,
						FORMAT"Failed to remove Session IDs entry for CSID = %u"
						"\n\tError= %s\n",
						ERR_MSG, csids->local_csid[itr],
						rte_strerror(abs(ret)));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			if(tmp == NULL) {
				ret = del_sess_csid_entry(csids->local_csid[itr]);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}

				/* TODO: Need to think */
				/* Cleanup Internal data structures */
				//csid_key_t key = {0};
				//key.local_csid = csids->local_csid[itr];
				//key.node_addr = csids->node_addr;
				//ret = del_peer_csid_entry(&key, S5S8_PGWC_PORT_ID);
				//if (ret) {
				//	clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				//					strerror(errno));
				//	return -1;
				//}

				ret = cleanup_session_entries(csids->local_csid[itr], context);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
			}

#endif /* USE_CSID */
			rte_free(context);
		}

		return 0;
	}


	/* Fill gtpv2c structure for sending on s11 interface */
	set_gtpv2c_teid_header((gtpv2c_header_t *) &del_resp, GTP_DELETE_SESSION_RSP,
			context->s11_mme_gtpc_teid, context->sequence, 0);
	set_cause_accepted_ie((gtpv2c_header_t *) &del_resp, IE_INSTANCE_ZERO);

	del_resp.cause.header.len = ntohs(del_resp.cause.header.len);

	/*Encode the S11 delete session response message. */
	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(clSystemLog, eCLSeverityDebug, "SAEGWC:%s:%d"
			"s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__, __LINE__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));


	/* Delete entry from session entry */
	if (del_sess_entry(sess_id) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for Key sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (del_rule_entries(context, ebi_index) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s %s - Error on delete rule entries\n",__file__,
				strerror(ret));
	}

	ret = delete_sgwc_context(teid, &context, &sess_id);
	if (ret)
		return ret;

	if(context->num_pdns == 0) {
		/* Delete UE context entry from UE Hash */
		if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0){
			clLog(clSystemLog, eCLSeverityCritical,
					"%s %s - Error on ue_context_by_fteid_hash del\n",__file__,
					strerror(ret));
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
#ifdef USE_DNS_QUERY
		/* Delete UPFList entry from UPF Hash */
		if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi))) < 0){
			clLog(clSystemLog, eCLSeverityCritical,
						FORMAT"Error on upflist_by_ue_hash deletion of IMSI \n",
						ERR_MSG);
		}
#endif /* USE_DNS_QUERY */

#ifdef USE_CSID
		fqcsid_t *csids = context->sgw_fqcsid;

		/* Get the session ID by csid */
		for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
			sess_csid *tmp = NULL;

			tmp = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
			if (tmp == NULL)
				continue;

			/* Remove node from csid linked list */
			tmp = remove_sess_csid_data_node(tmp, sess_id);

			/* Update CSID Entry in table */
			ret = rte_hash_add_key_data(seids_by_csid_hash,
							&csids->local_csid[itr], tmp);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add Session IDs entry for CSID = %u"
						"\n\tError= %s\n",
						ERR_MSG, csids->local_csid[itr],
						rte_strerror(abs(ret)));
				return -1;
			}

			if(tmp == NULL) {
				ret = del_sess_csid_entry(csids->local_csid[itr]);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					//return -1;
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}

				ret = cleanup_session_entries(csids->local_csid[itr], context);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
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
fill_pfcp_sess_mod_req_delete(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;
	eps_bearer *bearer;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
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

	/*SP: Adding FAR IE*/
	pfcp_sess_mod_req->update_far_count = 0;
	for (int index = 0; index < bearer_cntr; index++){
		bearer = bearers[index];
		if(bearer != NULL){
			for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
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
	if(pfcp_sess_mod_req->update_far_count){
			for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count; itr1++) {
				pfcp_sess_mod_req->update_far[itr1].apply_action.drop = PRESENT;
		}
	}
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
		clLog(clSystemLog, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
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
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
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
	         return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the UE state */
	ret = update_ue_state(context->pdns[ebi_index]->s5s8_pgw_gtpc_teid,
			PFCP_SESS_MOD_RESP_RCVD_STATE ,ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State for teid: %u\n", __func__,
				context->pdns[ebi_index]->s5s8_pgw_gtpc_teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n");
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	/* Fill the modify bearer response */

	set_modify_bearer_response_handover(gtpv2c_tx,
			context->sequence, context, bearer, &resp->gtpc_msg.mbr);

	/* Update the session state */
	resp->state = CONNECTED_STATE;
	bearer->pdn->state = CONNECTED_STATE;
	/* Update the UE state */
	ret = update_ue_state(context->s11_sgw_gtpc_teid,
			CONNECTED_STATE,ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State.\n", __func__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	s5s8_recv_sockaddr.sin_addr.s_addr =
		htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);

	clLog(clSystemLog, eCLSeverityDebug, "%s: s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));
	return 0;
}


int
process_pfcp_sess_mod_resp_cs_cbr_request(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);
	gtpv2c_header_t *gtpv2c_cbr_t = NULL;
	uint16_t msg_len = 0;

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
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed to get pdn \n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if(resp->msg_type == GTP_MODIFY_BEARER_REQ){
		/*send mbr resp to mme and create brearer resp to pgw*/

		set_modify_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer, &resp->gtpc_msg.mbr);
		s11_mme_sockaddr.sin_addr.s_addr =
			htonl(context->s11_mme_gtpc_ipv4.s_addr);

		if ((SAEGWC == pfcp_config.cp_type)) {
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
				gtpv2c_tx, context->sequence, pdn, resp->eps_bearer_id, 0, resp);

			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[0]->s5s8_pgw_gtpc_ipv4.s_addr);

			return 0;
		}

	}else{

	/* Fill the create session  response */

	msg_len = set_create_session_response(
				gtpv2c_tx, context->sequence, context, bearer->pdn, bearer, 1);
	gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + msg_len);

	/* Fill the Create bearer request*/
	ret = set_sgwc_create_bearer_request(gtpv2c_cbr_t, context->sequence, pdn,
		resp->eps_bearer_id, 0, resp);


	s11_mme_sockaddr.sin_addr.s_addr =
		htonl(context->s11_mme_gtpc_ipv4.s_addr);
	resp->state = CREATE_BER_REQ_SNT_STATE;
	pdn->state = CREATE_BER_REQ_SNT_STATE;


	}
/*
	resp->state = CONNECTED_STATE;
	pdn->state = CONNECTED_STATE;
	resp->state = CREATE_BER_REQ_SNT_STATE;
	pdn->state = CREATE_BER_REQ_SNT_STATE;*/

	clLog(clSystemLog, eCLSeverityDebug, "%s: s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));
	return 0;
}


int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt)
{

	return pdn_cntxt->num_bearer;
}

void
send_pfcp_sess_mod_req_for_li(struct li_df_config_t *li_config)
{
	int ret = 0;
	uint32_t seq = 0;
	eps_bearer *bearer;
	uint8_t ebi_index = 0;
	pdr_t *pdr_ctxt = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_ctx = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req;

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &li_config->uiImsi,
			(void **) &(context));
	if (ret == -ENOENT){
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d No data found for %x imsi\n"
				, __func__, __LINE__, li_config->uiImsi);
		return;
	}

	if (NULL == context) {
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%dUE context is NULL\n" , __func__, __LINE__);
		return;
	}

	if (context->li_sock_fd <= 0) {
		if (li_config->uiAction == EVENT_BASED ||
				li_config->uiAction == CC_EVENT_BASED) {
			context->li_sock_fd = get_tcp_tunnel(li_config->ddf2_ip.s_addr,
					li_config->uiDDf2Port,
					TCP_CREATE);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
				"%s:%dLI for this UE is not enabled \n", __func__, __LINE__);
			return;
		}

		context->dupl = PRESENT;
	} else {
		/* Stop event and start CC / stop li */
		if ((CC_BASED == li_config->uiAction) ||
				(CC_EVENT_DELETE == li_config->uiAction)) {
			Cleanup_sock_ddf_ip_hash(li_config->ddf2_ip.s_addr, li_config->uiDDf2Port);

			/* Close TCP client */
			close(context->li_sock_fd);
			context->li_sock_fd = NOT_PRESENT;

			if (CC_EVENT_DELETE == li_config->uiAction) {
				context->dupl = NOT_PRESENT;
			}
		}
	}

	pdn = context->pdns[ebi_index];

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	memset(&pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn->seid, node_value);

	pfcp_sess_mod_req.update_far_count = NOT_PRESENT;
	for (int index = 0; index < pdn->num_bearer; index++){
		bearer = pdn->eps_bearers[index];
		if(bearer){
			for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					updating_far(&(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count]));

					pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
							pdr_ctxt->far.far_id_value;

					pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl =
							GET_DUP_STATUS(pdn->context);
					pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;


					if (PRESENT == pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl) {
						pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].upd_dupng_parms_count = PRESENT;
						uint16_t len = fill_upd_dup_param(
								&(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].upd_dupng_parms[0]),
								li_config->ddf2_ip.s_addr,
								li_config->uiDDf2Port,
								li_config->uiAction);

						pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].header.len += len;
					}

					pfcp_sess_mod_req.update_far_count++;
				}
			}
			ebi_index = bearer->eps_bearer_id - 5 ;
		}
	}

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg, INTERFACE);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	} else {
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
				&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
	}
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
