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
#include "teid.h"

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
#include "gtpv2c_error_rsp.h"
#include "debug_str.h"

extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

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
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req, uint8_t cp_mode)
{
	uint32_t seq = 1;

	memset(pfcp_sess_del_req, 0, sizeof(pfcp_sess_del_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_DELETION_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_req->header),
		PFCP_SESSION_DELETION_REQUEST, HAS_SEID, seq, cp_mode);

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
			PFCP_SESSION_SET_DELETION_REQUEST, HAS_SEID, seq, NO_CP_MODE_REQUIRED);

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
	set_fq_csid( &(pfcp_sess_set_del_req->up_fqcsid), sgwu_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwu_addr, INET_ADDRSTRLEN);
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->up_fqcsid), pgwu_value);

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

void add_pdr_qer_for_rule(eps_bearer *bearer, bool prdef_rule)
{

	if (bearer == NULL || bearer->pdr_count == 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" No PDR found in the "
			"bearer, so can't increase it \n", LOG_VALUE);
	}

	for(int itr = 0; itr < NUMBER_OF_PDR_PER_RULE; itr++){
		pdr_t *pdr_ctxt = NULL;
		pdr_ctxt = rte_zmalloc_socket(NULL, sizeof(pdr_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (pdr_ctxt == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for PDR structure, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			return;
		}
		memcpy(pdr_ctxt, bearer->pdrs[itr], sizeof(pdr_t));
		pdr_ctxt->urr_id_count = 1;
		pdr_ctxt->rule_id =  generate_pdr_id();
		pdr_ctxt->urr.urr_id_value =  generate_urr_id();
		bearer->pdrs[bearer->pdr_count++] = pdr_ctxt;
		pdr_ctxt->create_far = NOT_PRESENT;
		pdr_ctxt->create_urr = PRESENT;

		int ret = add_pdr_entry(pdr_ctxt->rule_id, pdr_ctxt);
		if ( ret != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error while adding "
				"PDR entry for Rule ID %d \n", LOG_VALUE, pdr_ctxt->rule_id);
			return;
		}

	}

	if (bearer->pdn->context->cp_mode != SGWC){
		if(!prdef_rule){
			for(uint8_t itr=bearer->qer_count; itr < bearer->qer_count + NUMBER_OF_QER_PER_RULE; itr++){
				bearer->qer_id[itr].qer_id = generate_qer_id();
				fill_qer_entry(bearer->pdn, bearer, itr);
			}
			bearer->qer_count += NUMBER_OF_QER_PER_RULE;
		}
	}
	return;
}

void
fill_pfcp_gx_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, uint16_t action, struct resp_info *resp)
{

	int ret = 0;
	uint32_t seq = 0;
	eps_bearer *bearer = NULL;
	upf_context_t *upf_ctx = NULL;
	ue_context *context = NULL;
	int tmp_bearer_idx = 0;
	dynamic_rule_t rule = {0};
	//uint8_t itr = 0 ;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Error while extracting "
			"upf context: %d \n", LOG_VALUE, ret);
		return;
	}

	memset(pfcp_sess_mod_req,0,sizeof(pfcp_sess_mod_req_t));
	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq, pdn->context->cp_mode);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	if ((pdn->context->cp_mode == PGWC) ||
			(SAEGWC == pdn->context->cp_mode))
	{
		for (int idx=0; idx <  pdn->policy.count; idx++)
		{
			if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_ADD &&
					action == RULE_ACTION_ADD)	{

				if(pdn->policy.pcc_rule[idx].predefined_rule){
					bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].pdef_rule.qos);
				}else{
					bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].dyn_rule.qos);
				}
				if(bearer == NULL) {

					/*
					 * create dedicated bearer
					 */
					bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
					if(bearer == NULL) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failure to allocate bearer "
								"structure: %s (%s:%d)\n",LOG_VALUE,
								rte_strerror(rte_errno),
								__FILE__,  __LINE__);
						return;
					}

					tmp_bearer_idx = (resp->bearer_count + MAX_BEARERS + 1);
					resp->eps_bearer_ids[resp->bearer_count++] = tmp_bearer_idx;
					int ebi_index = GET_EBI_INDEX(tmp_bearer_idx);
					if (ebi_index == -1) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
						return;
					}
					bzero(bearer,  sizeof(eps_bearer));
					bearer->pdn = pdn;
					bearer->eps_bearer_id = tmp_bearer_idx;
					pdn->eps_bearers[ebi_index] = bearer;
					pdn->context->eps_bearers[ebi_index] = bearer;
					pdn->num_bearer++;

					fill_dedicated_bearer_info(bearer, pdn->context, pdn, pdn->policy.pcc_rule[idx].predefined_rule);
				}else{
					add_pdr_qer_for_rule(bearer, pdn->policy.pcc_rule[idx].predefined_rule);
				}

				/*fill predefine rule*/
				if(pdn->policy.pcc_rule[idx].predefined_rule){

					memcpy(&(bearer->qos), &(pdn->policy.pcc_rule[idx].pdef_rule.qos), sizeof(bearer_qos_ie));
					memcpy(&rule, &pdn->policy.pcc_rule[idx].pdef_rule, sizeof(dynamic_rule_t));

					bearer->prdef_rules[bearer->num_prdef_filters] =
						rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
								RTE_CACHE_LINE_SIZE, rte_socket_id());

					if (bearer->prdef_rules[bearer->num_prdef_filters] == NULL)
					{
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to "
								"allocate failure rule memory structure: %s\n",LOG_VALUE,
								rte_strerror(rte_errno));
						return;
					}
					memcpy((bearer->prdef_rules[bearer->num_prdef_filters]),
							&(pdn->policy.pcc_rule[idx].pdef_rule),
							sizeof(dynamic_rule_t));
				} else {

					memcpy(&(bearer->qos), &(pdn->policy.pcc_rule[idx].dyn_rule.qos), sizeof(bearer_qos_ie));
					memcpy(&rule, &pdn->policy.pcc_rule[idx].dyn_rule, sizeof(dynamic_rule_t));

					bearer->dynamic_rules[bearer->num_dynamic_filters] =
						rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
								RTE_CACHE_LINE_SIZE, rte_socket_id());

					if (bearer->dynamic_rules[bearer->num_dynamic_filters] == NULL) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failure to allocate dynamic rule memory "
								"structure: %s (%s:%d)\n",LOG_VALUE,
								rte_strerror(rte_errno),
								__FILE__, __LINE__);
						return;
					}

					memcpy( (bearer->dynamic_rules[bearer->num_dynamic_filters]),
							&(pdn->policy.pcc_rule[idx].dyn_rule),
							sizeof(dynamic_rule_t));
				}
				fill_pfcp_entry(bearer, &rule);

				ret = get_ue_context(UE_SESS_ID(pdn->seid), &context);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
						"get UE Context for teid : %d \n", LOG_VALUE,
						UE_SESS_ID(pdn->seid));
					return;
				}

				fill_create_pfcp_info(pfcp_sess_mod_req, &rule, context, pdn->generate_cdr);

				if(pdn->policy.pcc_rule[idx].predefined_rule)
					bearer->num_prdef_filters++;
				else
					bearer->num_dynamic_filters++;

			} else {
				if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_DELETE &&
						action == RULE_ACTION_DELETE) {

					rule_name_key_t rule_name = {0};
					memset(rule_name.rule_name, '\0', sizeof(rule_name.rule_name));

					if(pdn->policy.pcc_rule[idx].predefined_rule){
						snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s",pdn->policy.pcc_rule[idx].pdef_rule.rule_name);
					}else{
						snprintf(rule_name.rule_name, RULE_NAME_LEN, "%s%d",
								pdn->policy.pcc_rule[idx].dyn_rule.rule_name, pdn->call_id);
					}
					int8_t bearer_id = get_rule_name_entry(rule_name);
					if (-1 == bearer_id) {

						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
								"get bearer for rule_name : %s \n", LOG_VALUE,
								rule_name.rule_name);
						return;
					}
					resp->eps_bearer_ids[resp->bearer_count++] = bearer_id + NUM_EBI_RESERVED;
					if ((bearer_id + 1) == pdn->default_bearer_id) {
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
}

static int
predef_pfcp_actvt_predef_rules_ie_t(pfcp_actvt_predef_rules_ie_t *actvt_predef_rules,
		dynamic_rule_t *pdef_rules)
{
	int len = 0;
	len = strnlen((char *)(&pdef_rules->rule_name), RULE_NAME_LEN);
	memcpy(&actvt_predef_rules->predef_rules_nm, &pdef_rules->rule_name, len);

	pfcp_set_ie_header(
			&(actvt_predef_rules->header), PFCP_IE_ACTVT_PREDEF_RULES, len);

	return (len + sizeof(pfcp_ie_header_t));
}

static int
fill_predef_rules_pdr(pfcp_create_pdr_ie_t *create_pdr,
	dynamic_rule_t *pdef_rules, int pdr_counter, uint8_t rule_indx)
{
		if (pdef_rules == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Predefined SDF rules is NULL\n", LOG_VALUE);
			return -1;
		}

		/* Fill the appropriate predence value into PDR*/
		create_pdr[pdr_counter].precedence.prcdnc_val = pdef_rules->precedence;

		if((create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
		        ((pdef_rules->flow_desc[rule_indx].flow_direction == TFT_DIRECTION_UPLINK_ONLY) ||
			    (pdef_rules->flow_desc[rule_indx].flow_direction == TFT_DIRECTION_BIDIRECTIONAL))) {
				/* Fill the Rule Name in the Active Predefined Rules*/
				uint8_t len = predef_pfcp_actvt_predef_rules_ie_t(
					&create_pdr[pdr_counter].actvt_predef_rules[rule_indx],
					pdef_rules);
				create_pdr[pdr_counter].actvt_predef_rules_count++;
				create_pdr[pdr_counter].header.len += len;

		}else if((create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
		        ((pdef_rules->flow_desc[rule_indx].flow_direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
			    (pdef_rules->flow_desc[rule_indx].flow_direction == TFT_DIRECTION_BIDIRECTIONAL))) {
				/* Fill the Rule Name in the Active Predefined Rules*/
				uint8_t len = predef_pfcp_actvt_predef_rules_ie_t(
					&create_pdr[pdr_counter].actvt_predef_rules[rule_indx],
					pdef_rules);

				create_pdr[pdr_counter].actvt_predef_rules_count++;
				create_pdr[pdr_counter].header.len += len;
		}
	return 0;
}

int
fill_create_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
		ue_context *context, uint8_t gen_cdr)
{
	int ret = 0;
	uint16_t len = 0;
	imsi_id_hash_t *imsi_id_config = NULL;

	pfcp_create_pdr_ie_t *pdr = NULL;
	pfcp_create_urr_ie_t *urr = NULL;
	pfcp_create_far_ie_t *far = NULL;
	pfcp_create_qer_ie_t *qer = NULL;

	/* get user level packet copying token or id using imsi */
	ret = get_id_using_imsi(context->imsi, &imsi_id_config);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Not applicable for li\n",
				LOG_VALUE);
	}

	for(int i=0; i<NUMBER_OF_PDR_PER_RULE; i++)
	{
		int idx = pfcp_sess_mod_req->create_pdr_count;
		pdr = &(pfcp_sess_mod_req->create_pdr[idx]);
		urr = &(pfcp_sess_mod_req->create_urr[idx]);
		far = &(pfcp_sess_mod_req->create_far[idx]);
		if (gen_cdr) {
			pdr->urr_id_count = 1; //NK:per PDR there is one URR
			set_create_urr(urr, dyn_rule->pdr[i]);
		}

		if(!dyn_rule->predefined_rule){
			qer = &(pfcp_sess_mod_req->create_qer[idx]);
			pdr->qer_id_count = 1;
		}
		set_create_pdr(pdr, dyn_rule->pdr[i], context->cp_mode);

		if(!dyn_rule->predefined_rule){

		fill_create_pdr_sdf_rules(pfcp_sess_mod_req->create_pdr,
						dyn_rule, idx);
		} else {
			int itr = 0;
			fill_predef_rules_pdr(pdr, dyn_rule, itr, itr);

		}

		/* Condition check because for new rule
		 * no need to create new FAR */
		if(dyn_rule->pdr[i]->create_far == PRESENT) {

			/*Just need to forward the packets that's why disabling
			 * all other supported action*/
			dyn_rule->pdr[i]->far.actions.forw = PRESENT;
			dyn_rule->pdr[i]->far.actions.dupl = 0;
			dyn_rule->pdr[i]->far.actions.drop = 0;
			set_create_far(far, &dyn_rule->pdr[i]->far);
			len = set_destination_interface(&(far->frwdng_parms.dst_intfc),
									dyn_rule->pdr[i]->far.dst_intfc.interface_value);
		pfcp_set_ie_header(&(far->frwdng_parms.header),
				IE_FRWDNG_PARMS, len);

		far->frwdng_parms.header.len = len;

		len += UPD_PARAM_HEADER_SIZE;

		far->header.len += len;

		far->apply_action.forw = PRESENT;
		far->apply_action.dupl = GET_DUP_STATUS(context);
		len = 0;

			if ((context != NULL) && (imsi_id_config != NULL) && (imsi_id_config->cntr > 0)){

				update_li_info_in_dup_params(imsi_id_config, context, far);
			}
		}

		if(!dyn_rule->predefined_rule){
			set_create_qer(qer, &(dyn_rule->pdr[i]->qer));
			qer->qer_id.qer_id_value  = dyn_rule->pdr[i]->qer.qer_id;
			pfcp_sess_mod_req->create_qer_count++;
		}

		pfcp_sess_mod_req->create_pdr_count++;
		pfcp_sess_mod_req->create_urr_count++;
		pfcp_sess_mod_req->create_far_count++;
	}
	return 0;
}

int
fill_remove_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer)
{
	pfcp_update_far_ie_t *far = NULL;

	for(int i=0; i<NUMBER_OF_PDR_PER_RULE; i++)
	{
		far = &(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]);

		/*Just need to Drop the packets that's why disabling
		 * all other supported action*/
		bearer->pdrs[i]->far.actions.forw = 0;
		bearer->pdrs[i]->far.actions.dupl = 0;
		bearer->pdrs[i]->far.actions.drop = PRESENT;
		set_update_far(far, &bearer->pdrs[i]->far);

		pfcp_sess_mod_req->update_far_count++;
	}
	return 0;
}

int fill_update_pdr_sdf_rule(pfcp_update_pdr_ie_t* update_pdr,
								dynamic_rule_t *dyn_rule, int pdr_counter){
    int sdf_filter_count = 0;

    update_pdr[pdr_counter].precedence.prcdnc_val = dyn_rule->precedence;
    /* itr is for flow information counter */
    /* sdf_filter_count is for SDF information counter */
    for(int itr = 0; itr < dyn_rule->num_flw_desc; itr++) {

        if(dyn_rule->flow_desc[itr].sdf_flow_description != NULL) {

            if((update_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
                ((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
                (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

                int len = sdf_pkt_filter_add(&update_pdr[pdr_counter].pdi, dyn_rule,
									sdf_filter_count, itr, TFT_DIRECTION_UPLINK_ONLY);
				update_pdr[pdr_counter].header.len += len;
                sdf_filter_count++;
            }else if((update_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
                ((dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
                (dyn_rule->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

	                int len = sdf_pkt_filter_add(&update_pdr[pdr_counter].pdi, dyn_rule,
						sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);
						update_pdr[pdr_counter].header.len += len;
	                sdf_filter_count++;
            }

        } else {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "No SDF rules found "
				"while updating PDR sdf rule\n", LOG_VALUE);
        }
    }

	update_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

    return 0;
}

void
remove_pdr_from_bearer(eps_bearer *bearer, uint16_t pdr_id_value){

	int flag = 0;
	for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
		if(bearer->pdrs[itr]->rule_id == pdr_id_value){
			flag = 1;
		}

		if(flag == 1 && itr != bearer->pdr_count - 1){
			bearer->pdrs[itr] = bearer->pdrs[itr + 1];
		}
	}

	if(flag == 1){
		bearer->pdrs[bearer->pdr_count] = NULL;
		bearer->pdr_count--;
	}
	return;
}

void
remove_qer_from_bearer(eps_bearer *bearer, uint16_t qer_id_value){

	int flag = 0;
	for(uint8_t itr = 0; itr < bearer->qer_count ; itr++) {
		if(bearer->qer_id[itr].qer_id == qer_id_value){
			flag = 1;
		}

		if(flag == 1 && itr != bearer->qer_count - 1){
			bearer->qer_id[itr] = bearer->qer_id[itr + 1];

		}
	}

	if(flag == 1){
		bearer->qer_id[bearer->qer_count].qer_id = 0;
		bearer->qer_count--;
	}
	return;
}

int
delete_pdr_qer_for_rule(eps_bearer *bearer, uint16_t pdr_id_value) {
	pdr_t *pdr_ctx =  NULL;

	/*Delete all pdr, qer entry from table */
	for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
		pdr_ctx = bearer->pdrs[itr];
		if(pdr_ctx != NULL && pdr_ctx->rule_id == pdr_id_value) {

			rule_name_key_t key = {0};
			snprintf(key.rule_name, RULE_NAME_LEN, "%s%d",
					pdr_ctx->rule_name, (bearer->pdn)->call_id);

			if(bearer->eps_bearer_id ==
					get_rule_name_entry(key) + NUM_EBI_RESERVED){

				if (del_rule_name_entry(key) != 0) {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT" Error while deleting rule name entries\n",
						LOG_VALUE);
				}
			}

			remove_pdr_from_bearer(bearer, pdr_id_value);
			if( del_pdr_entry(pdr_ctx->rule_id) != 0 ){
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Error while deleting PDR entry for Rule id : %d\n",
					LOG_VALUE, pdr_ctx->rule_id);
			}
			if (pfcp_config.use_gx) {
				remove_qer_from_bearer(bearer, pdr_ctx->qer.qer_id);
				if(del_qer_entry(pdr_ctx->qer.qer_id) != 0 ){
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Error while deleting QER entry for QER id : %d\n",
						LOG_VALUE, pdr_ctx->qer.qer_id);
				}
			}
			return 0;
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"No PDR entry found while deleting pdr\n", LOG_VALUE);
		}
	}
	return -1;
}

void
fill_update_bearer_sess_mod(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer){

	pdn_connection *pdn = bearer->pdn;
	for(int idx = 0; idx < pdn->policy.count; idx++){

		for(int idx2 = 0; idx2 < bearer->pdr_count; idx2++){

			if((pdn->policy.pcc_rule[idx].action == bearer->action) &&
				(strncmp(pdn->policy.pcc_rule[idx].dyn_rule.rule_name,
					bearer->pdrs[idx2]->rule_name, RULE_NAME_LEN) == 0)){

				if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY){


					if(bearer->flow_desc_check == PRESENT) {

						int index = pfcp_sess_mod_req->update_pdr_count;
						set_update_pdr(&(pfcp_sess_mod_req->update_pdr[index]),
								bearer->pdrs[idx2], pdn->context->cp_mode );
						fill_update_pdr_sdf_rule(pfcp_sess_mod_req->update_pdr,
												&pdn->policy.pcc_rule[idx].dyn_rule, index);
						pfcp_sess_mod_req->update_pdr_count++;

					}

					if(bearer->qos_bearer_check == PRESENT) {

						int index2 = pfcp_sess_mod_req->update_qer_count;
			            set_update_qer(&(pfcp_sess_mod_req->update_qer[index2]),
														&bearer->pdrs[idx2]->qer);

					    pfcp_sess_mod_req->update_qer_count++;
					}

				}else if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_ADD_RULE){

					/* A new rule to be added to Bearer already present */
					int index = pfcp_sess_mod_req->create_pdr_count;
					int index2 = pfcp_sess_mod_req->create_qer_count;
					pfcp_sess_mod_req->create_pdr[index].qer_id_count = 1;
					if (pdn->generate_cdr) {
						pfcp_sess_mod_req->create_pdr[index].urr_id_count = 1;
						set_create_urr(&pfcp_sess_mod_req->create_urr[index],
										bearer->pdrs[idx2]);

						pfcp_sess_mod_req->create_urr_count++;
					}
					set_create_pdr(&pfcp_sess_mod_req->create_pdr[index],
								bearer->pdrs[idx2], pdn->context->cp_mode);

					fill_create_pdr_sdf_rules(pfcp_sess_mod_req->create_pdr,
												&pdn->policy.pcc_rule[idx].dyn_rule,
												index);
					set_create_qer(&pfcp_sess_mod_req->create_qer[index2],
										&(bearer->pdrs[idx2]->qer));
					pfcp_sess_mod_req->create_pdr_count++;
					pfcp_sess_mod_req->create_qer_count++;

					/* ADDING the rule in rule_bearer_id hash */
					rule_name_key_t rule_name = {0};
					memset(rule_name.rule_name, '\0', sizeof(rule_name.rule_name));
					snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s%d",
							pdn->policy.pcc_rule[idx].dyn_rule.rule_name, pdn->call_id);

					bearer_id_t *id;
					id = malloc(sizeof(bearer_id_t));
					memset(id, 0 , sizeof(bearer_id_t));

					int ebi_index = GET_EBI_INDEX(bearer->eps_bearer_id);
					if (ebi_index == -1) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
						return;
					}

					id->bearer_id = ebi_index;

					/* Adding rule to Hash as Rule End in Update bearer */
					if (add_rule_name_entry(rule_name, id) != 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Error while adding rule name entry\n",
							LOG_VALUE);
						return;
					}

				}else if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_REMOVE_RULE){

					/* A rule to be remove from Bearer already present */
					int index = pfcp_sess_mod_req->remove_pdr_count;
					set_remove_pdr(&(pfcp_sess_mod_req->remove_pdr[index]),
														bearer->pdrs[idx2]->rule_id);
					pfcp_sess_mod_req->remove_pdr_count++;

				}
			}
		}
	}
	/* Reset these variable as for current rule all the action is taken*/
	bearer->flow_desc_check = NOT_PRESENT;
	bearer->qos_bearer_check = NOT_PRESENT;
	return;
}

void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, eps_bearer **bearer,
		pdn_connection *pdn, pfcp_update_far_ie_t update_far[],
		uint8_t endmarker_flag, uint8_t bearer_count, ue_context *context)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	int ret = 0;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr, &upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Error while extracting "
			"upf context: %d \n", LOG_VALUE, ret);
		return;
	}

	if( header != NULL)
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"header is null TEID[%d]\n",
		 LOG_VALUE, header->teid.has_teid.teid);

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq, context->cp_mode);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	/* TODO modify this hard code to generic */
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	/* This depends on condition in pcrf data(pcrf will send bar_rule_id if it needs to be delated). Need to handle after pcrf integration*/
	/* removing_bar(&(pfcp_sess_mod_req->remove_bar)); */

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
	for (int iCnt= 0; iCnt < bearer_count; iCnt++ ) {

		uint8_t pdr_idx = 0;
		if (pfcp_sess_mod_req->create_pdr_count) {
			fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req, bearer[iCnt], context,
														iCnt*NUMBER_OF_PDR_PER_RULE);

		/* This depends on condition  if the CP function requests the UP function to create a new BAR
		  Need to add condition to check if CP needs creation of BAR*/
			for( int itr = pfcp_sess_mod_req->create_pdr_count - NUMBER_OF_PDR_PER_RULE;
					itr < pfcp_sess_mod_req->create_pdr_count; itr++) {
				if((pfcp_sess_mod_req->create_pdr[itr].header.len)
							&& (pfcp_sess_mod_req->create_pdr[itr].far_id.header.len)) {

					for( int j = 0; j < pfcp_sess_mod_req->create_far_count ; j++) {

						if(pfcp_sess_mod_req->create_far[itr].bar_id.header.len) {
							/* TODO: Pass bar_id from pfcp_session_mod_req->create_far[i].bar_id.bar_id_value
							   to set bar_id*/
							creating_bar(&(pfcp_sess_mod_req->create_bar));
						}

					}

				}

				if (context->cp_mode == SGWC || context->cp_mode == SAEGWC) {
					pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.teid =
						bearer[iCnt]->pdrs[pdr_idx]->pdi.local_fteid.teid ;
					/* TODO: Revisit this for change in yang */
					pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address =
						bearer[iCnt]->pdrs[pdr_idx]->pdi.ue_addr.ipv4_address;
					pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.ipv4_address =
						bearer[iCnt]->pdrs[pdr_idx]->pdi.local_fteid.ipv4_address;
					pfcp_sess_mod_req->create_pdr[itr].pdi.src_intfc.interface_value =
						bearer[iCnt]->pdrs[pdr_idx]->pdi.src_intfc.interface_value;
				}
				pdr_idx++;
			}
		}

		/*Adding FAR IE*/
		for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count ; itr1++) {

			set_update_far(&(pfcp_sess_mod_req->update_far[itr1]), NULL);
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

			if(endmarker_flag) {

				set_pfcpsmreqflags(&(pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.pfcpsmreq_flags));
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.pfcpsmreq_flags.sndem = 1;
				pfcp_sess_mod_req->update_far[itr1].header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);

			}

		}

	}/*end of for loop*/

	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	/* This IE is included if one of DROBU and QAURR flag is set,
	      excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}

	/* This IE is included if QAURR flag is set (this flag is in PFCPSMReq-Flags IE) or Query URR IE is present,
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
		eps_bearer *bearer, ue_context *context, uint8_t create_pdr_counter)
{
	int ret = 0;
	int itr2 = create_pdr_counter;
	for(int i = 0; i < NUMBER_OF_PDR_PER_RULE; i++) {

		if ((pfcp_config.use_gx) &&
			(context->cp_mode == PGWC || context->cp_mode == SAEGWC)){
			pfcp_sess_mod_req->create_pdr[itr2].qer_id_count = 1;
		}

		if (bearer->pdn->generate_cdr) {
			pfcp_sess_mod_req->create_pdr[itr2].urr_id_count = 1;
			pfcp_sess_mod_req->create_urr_count++;
			set_create_urr(&(pfcp_sess_mod_req->create_urr[itr2]), bearer->pdrs[i]);
		}
		//pfcp_sess_mod_req->create_pdr[i].qer_id_count = bearer->qer_count;
		set_create_pdr(&(pfcp_sess_mod_req->create_pdr[itr2]), bearer->pdrs[i],
				context->cp_mode);
		pfcp_sess_mod_req->create_far_count++;
		/*Just need to Forward the packets that's why disabling
		 * all other supported action*/
		bearer->pdrs[i]->far.actions.forw = PRESENT;
		bearer->pdrs[i]->far.actions.dupl = 0;
		bearer->pdrs[i]->far.actions.drop = 0;
		set_create_far(&(pfcp_sess_mod_req->create_far[itr2]), &bearer->pdrs[i]->far);

		itr2++;
	}

	/* get user level packet copying token or id using imsi */
	imsi_id_hash_t *imsi_id_config = NULL;
	ret = get_id_using_imsi(context->imsi, &imsi_id_config);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Not applicable for li\n",
				LOG_VALUE);
	}

	itr2 =  create_pdr_counter;
	for(int itr = 0; itr < NUMBER_OF_PDR_PER_RULE; itr++) {

		if ((context->cp_mode == PGWC) || (SAEGWC == context->cp_mode)) {
			if (pfcp_sess_mod_req->create_far[itr2].apply_action.forw == PRESENT) {

				uint16_t len = 0;

				if ((SAEGWC == context->cp_mode) ||
					(SOURCE_INTERFACE_VALUE_ACCESS ==
						 bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {

					len = set_destination_interface(&(pfcp_sess_mod_req->create_far[itr2].frwdng_parms.dst_intfc),
													bearer->pdrs[itr]->far.dst_intfc.interface_value);
					pfcp_set_ie_header(&(pfcp_sess_mod_req->create_far[itr2].frwdng_parms.header),
							IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

					pfcp_sess_mod_req->create_far[itr2].frwdng_parms.header.len = len;

					len += UPD_PARAM_HEADER_SIZE;

					pfcp_sess_mod_req->create_far[itr2].header.len += len;

				}
			}
		} else {
			if ((SGWC == context->cp_mode) &&
				(DESTINATION_INTERFACE_VALUE_CORE ==
				 bearer->pdrs[itr]->far.dst_intfc.interface_value) &&
				(bearer->s5s8_pgw_gtpu_teid != 0) &&
				(bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0)) {

				uint16_t len = 0;
				len += set_forwarding_param(&(pfcp_sess_mod_req->create_far[itr2].frwdng_parms),
											bearer->pdrs[itr]->far.outer_hdr_creation.ipv4_address,
											bearer->pdrs[itr]->far.outer_hdr_creation.teid,
											bearer->pdrs[itr]->far.dst_intfc.interface_value);
				pfcp_sess_mod_req->create_far[itr2].header.len += len;

			}
		}

		if ((context != NULL) && (imsi_id_config != NULL) && (imsi_id_config->cntr > 0)){

			update_li_info_in_dup_params(imsi_id_config, context,
					&(pfcp_sess_mod_req->create_far[itr2]));
		}
		itr2++;
	} /*for loop*/

	if ((pfcp_config.use_gx) &&
		(context->cp_mode == PGWC || context->cp_mode == SAEGWC)) {
		pfcp_sess_mod_req->create_qer_count = bearer->qer_count;
		qer_t *qer_context = NULL;
		for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_qer_count ; itr1++) {
			qer_context = get_qer_entry(bearer->qer_id[itr1].qer_id);
			/* Assign the value from the PDR */
			if(qer_context) {
				set_create_qer(&(pfcp_sess_mod_req->create_qer[itr1]), qer_context);
			}
		}

		for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_pdr_count ; itr1++) {
			for(int index = 0; index < bearer->num_dynamic_filters; index++)
				fill_create_pdr_sdf_rules(pfcp_sess_mod_req->create_pdr,
											bearer->dynamic_rules[index],
																	itr1);
		}
	}
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

	/*updated the header len of pdi as sdf rules has been added*/
	pdi->header.len += (len + sizeof(pfcp_ie_header_t));
	return (len + sizeof(pfcp_ie_header_t));
}

int fill_create_pdr_sdf_rules(pfcp_create_pdr_ie_t *create_pdr,
	dynamic_rule_t *dynamic_rules,	int pdr_counter)
{
	int ret = 0;
	int sdf_filter_count = 0;
	/*convert pkt_filter_strucutre to char string*/

	create_pdr[pdr_counter].precedence.prcdnc_val = dynamic_rules->precedence;
	/*itr is for flow information counter*/
	/*sdf_filter_count is for SDF information counter*/
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

			} else if((create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
					((dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
					 (dynamic_rules->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

				int len = sdf_pkt_filter_add(
								&create_pdr[pdr_counter].pdi, dynamic_rules,
								sdf_filter_count, itr, TFT_DIRECTION_DOWNLINK_ONLY);

				create_pdr[pdr_counter].header.len += len;
				sdf_filter_count++;
			}

		} else {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "No SDF rules found "
				"while creating PDR sdf rule\n", LOG_VALUE);
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory for QER structure, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error while adding "
			"QER entry \n", LOG_VALUE);
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory for QER structure, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error while adding "
			"QER entry \n", LOG_VALUE);
		return ret;
	}


	return ret;
}

void
fill_pdr_sdf_qer(pdr_t *pdr_ctxt, dynamic_rule_t *dyn_rule){

	int i = pdr_ctxt->pdi.src_intfc.interface_value;
	uint16_t flow_len = 0;
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
		} else {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "No SDF rules found "
				"while filling PDR sdf rule\n", LOG_VALUE);
		}
	}

	pdr_ctxt->qer.max_bitrate.ul_mbr = dyn_rule->qos.ul_mbr;
	pdr_ctxt->qer.max_bitrate.dl_mbr = dyn_rule->qos.dl_mbr;
	pdr_ctxt->qer.guaranteed_bitrate.ul_gbr = dyn_rule->qos.ul_gbr;
	pdr_ctxt->qer.guaranteed_bitrate.dl_gbr = dyn_rule->qos.dl_gbr;

	return;

}

int fill_pfcp_entry(eps_bearer *bearer, dynamic_rule_t *dyn_rule)
{

	pdn_connection *pdn = bearer->pdn;
	int ret;
	int idx = bearer->pdr_count - NUMBER_OF_PDR_PER_RULE;

	for(int i = 0;	i < NUMBER_OF_PDR_PER_RULE; i++) {

		pdr_t *pdr_ctxt = NULL;
		pdr_ctxt = bearer->pdrs[idx];

		pdr_ctxt->prcdnc_val =  dyn_rule->precedence;
		pdr_ctxt->session_id = pdn->seid;

		/*to be filled in fill_sdf_rule*/
		pdr_ctxt->pdi.sdf_filter_cnt = 0;
		dyn_rule->pdr[i] = pdr_ctxt;
		if(!dyn_rule->predefined_rule) {
			strncpy(pdr_ctxt->rule_name, dyn_rule->rule_name, RULE_NAME_LEN);
			pdr_ctxt->pdi.src_intfc.interface_value = i;
			pdr_ctxt->qer.qer_id = bearer->qer_id[idx].qer_id;
			pdr_ctxt->qer_id[0].qer_id = pdr_ctxt->qer.qer_id;
			pdr_ctxt->qer.session_id = pdn->seid;

			fill_pdr_sdf_qer(pdr_ctxt, dyn_rule);

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
		idx++;
	} /* FOR Loop */
	return 0;
}

pdr_t *
fill_pdr_entry(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, uint8_t iface, uint8_t itr)
{

	uint8_t tmp_pdr_rule_id = 0;
	uint8_t tmp_far_id = 0;
	uint8_t tmp_urr_id = 0;

	char mnc[MCC_MNC_LEN] = {0};
	char mcc[MCC_MNC_LEN] = {0};
	char nwinst[PFCP_NTWK_INST_LEN] = {0};
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

	snprintf(nwinst, PFCP_NTWK_INST_LEN,"mnc%s.mcc%s", mnc, mcc);

	if (bearer->pdr_count) {
		if (bearer->pdrs[itr] != NULL) {
			pdr_ctxt = get_pdr_entry((bearer->pdrs[itr])->rule_id);
		}
	}
	if (pdr_ctxt == NULL) {
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
		memset(pdr_ctxt, 0, sizeof(pdr_t));
		pdr_ctxt->rule_id =  generate_pdr_id();
		pdr_ctxt->far.far_id_value = generate_far_id();
		pdr_ctxt->urr.urr_id_value = generate_urr_id();
	} else {
		/* Handover/Promotion scenario */
		/* TODO */
		tmp_pdr_rule_id = pdr_ctxt->rule_id;
		tmp_far_id = pdr_ctxt->far.far_id_value;
		tmp_urr_id = pdr_ctxt->far.far_id_value;
		/* Flush exisiting PDR Info */
		memset(pdr_ctxt, 0, sizeof(pdr_t));
		pdr_ctxt->rule_id = tmp_pdr_rule_id;
		pdr_ctxt->far.far_id_value = tmp_far_id;
		pdr_ctxt->urr.urr_id_value = tmp_urr_id;
	}
	pdr_ctxt->prcdnc_val =  1;
	pdr_ctxt->create_far = PRESENT;
	pdr_ctxt->create_urr = PRESENT;
	/*
	 *   per pdr there is one URR
	 *   hence hardcoded urr count to one
	 */
	pdr_ctxt->urr_id_count = URR_PER_PDR;


	pdr_ctxt->session_id = pdn->seid;
	pdr_ctxt->pdi.src_intfc.interface_value = iface;
	strncpy((char * )pdr_ctxt->pdi.ntwk_inst.ntwk_inst, (char *)nwinst, PFCP_NTWK_INST_LEN);

	/* TODO: NS Add this changes after DP related changes of VS
	 * if(context->cp_mode != SGWC){
	 * pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;
	 * }
	 */
	if(pdn->policy.pcc_rule[itr].predefined_rule){
		pdr_ctxt->actvt_predef_rules_count += 1;
	}else{
		/*to be filled in fill_sdf_rule*/
		pdr_ctxt->pdi.sdf_filter_cnt += 1;
		if (context->cp_mode == PGWC || context->cp_mode == SAEGWC){
			/* TODO Hardcode 1 set because one PDR contain only 1 QER entry
			 * Revist again in case of multiple rule support
			 */
			pdr_ctxt->qer_id_count = 1;

		}
	}

	pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;

	if (iface == SOURCE_INTERFACE_VALUE_ACCESS) {

		pdr_ctxt->pdi.local_fteid.teid = bearer->s1u_sgw_gtpu_teid;
		pdr_ctxt->pdi.local_fteid.ipv4_address = 0;

		if ((SGWC == context->cp_mode) &&
				(bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0) &&
				(bearer->s5s8_pgw_gtpu_teid != 0)) {
			/*Just need to Forward the packets that's why disabling
			 * all other supported action*/
			pdr_ctxt->far.actions.forw = PRESENT;
			pdr_ctxt->far.actions.dupl = 0;
			pdr_ctxt->far.actions.drop = 0;
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
			pdr_ctxt->far.outer_hdr_creation.ipv4_address =
				bearer->s5s8_pgw_gtpu_ipv4.s_addr;
			pdr_ctxt->far.outer_hdr_creation.teid =
				bearer->s5s8_pgw_gtpu_teid;
		} else {
			pdr_ctxt->far.actions.forw = 0;
			pdr_ctxt->far.actions.dupl = 0;
			pdr_ctxt->far.actions.drop = 0;
		}

		if ((context->cp_mode == PGWC) ||
				(SAEGWC == context->cp_mode)) {
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		} else if ((context->cp_mode == SGWC) && (context->indication_flag.oi != 0)){
			pdr_ctxt->far.outer_hdr_creation.ipv4_address =
				bearer->s5s8_pgw_gtpu_ipv4.s_addr;
			pdr_ctxt->far.outer_hdr_creation.teid =
				bearer->s5s8_pgw_gtpu_teid;
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		}

	} else{
		if(context->cp_mode == SGWC){
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
			pdr_ctxt->far.actions.dupl = 0;
			pdr_ctxt->far.actions.drop = 0;
			if(context->cp_mode == PGWC){
				pdr_ctxt->far.outer_hdr_creation.ipv4_address =
					bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				pdr_ctxt->far.outer_hdr_creation.teid =
					bearer->s5s8_sgw_gtpu_teid;
				pdr_ctxt->far.dst_intfc.interface_value =
					DESTINATION_INTERFACE_VALUE_ACCESS;
			}
		}
	}

	/* Measurement method set to volume as well as time as a default*/
	pdr_ctxt->urr.mea_mt.volum = PRESENT;
	pdr_ctxt->urr.mea_mt.durat = PRESENT;

	if(pdn->apn_in_use->trigger_type == VOL_BASED) {
		pdr_ctxt->urr.rept_trigg.volth = PRESENT;
		if (iface == SOURCE_INTERFACE_VALUE_ACCESS) {
			pdr_ctxt->urr.vol_th.uplink_volume =
				pdn->apn_in_use->uplink_volume_th;
		} else {
			pdr_ctxt->urr.vol_th.downlink_volume =
				pdn->apn_in_use->downlink_volume_th;
		}

	} else if (pdn->apn_in_use->trigger_type == TIME_BASED) {
		pdr_ctxt->urr.rept_trigg.timth = PRESENT;
		pdr_ctxt->urr.time_th.time_threshold =
			pdn->apn_in_use->time_th;
	} else {
		pdr_ctxt->urr.rept_trigg.volth = PRESENT;
		pdr_ctxt->urr.rept_trigg.timth = PRESENT;
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error while adding "
			"pdr entry\n", LOG_VALUE);
		return NULL;
	}
	return pdr_ctxt;
}

eps_bearer* get_default_bearer(pdn_connection *pdn)
{
	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return NULL;
	}

	return pdn->eps_bearers[ebi_index];

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
			LOG_FORMAT"Comparing default bearer qci with the rule qci\n", LOG_VALUE);
		return -1;
	}

	if(default_bearer_qos->arp.preemption_vulnerability != rule_qos->arp.preemption_vulnerability) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Comparing default bearer qos arp preemption vulnerablity\n",
			LOG_VALUE);
		return -1;
	}

	if(default_bearer_qos->arp.priority_level != rule_qos->arp.priority_level) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Comparing default bearer qos arp priority level\n", LOG_VALUE);
		return -1;
	}
	if(default_bearer_qos->arp.preemption_capability != rule_qos->arp.preemption_capability) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Comparing default bearer qos arp preemption vulnerablity\n",
			LOG_VALUE);
		return -1;
	}
	return 0;

}

uint16_t
fill_dup_param(pfcp_dupng_parms_ie_t *dup_params, uint8_t li_policy[],
		uint8_t li_policy_len)
{
	uint16_t len = 0;

	set_duplicating_param(dup_params);

	/* Set forwarding policy IE */
	memset(dup_params->frwdng_plcy.frwdng_plcy_ident, 0, MAX_LI_POLICY_LIMIT);
	memcpy(dup_params->frwdng_plcy.frwdng_plcy_ident, li_policy, li_policy_len);
	len += li_policy_len * sizeof(uint8_t);
	dup_params->frwdng_plcy.frwdng_plcy_ident_len = li_policy_len;
	len += sizeof(uint8_t);

	/* Forwarding policy header */
	dup_params->frwdng_plcy.header.len = len;
	len += UPD_PARAM_HEADER_SIZE;

	/* Duplicating parameter header */
	dup_params->header.len = len;
	len += UPD_PARAM_HEADER_SIZE;

	/* IE's which are not require. Set their header length to 0 */
	dup_params->dst_intfc.header.len = 0;
	dup_params->outer_hdr_creation.header.len = 0;

	/* Return value to update create far header */
	return len;
	/* End : Need to add condition and all stuff must be in function */
}

uint16_t
fill_upd_dup_param(pfcp_upd_dupng_parms_ie_t *dup_params, uint8_t li_policy[],
		uint8_t li_policy_len)
{
	uint16_t len = 0;

	set_upd_duplicating_param(dup_params);

	if (0 != li_policy_len) {

		/* Set forwarding policy IE */
		memset(dup_params->frwdng_plcy.frwdng_plcy_ident, 0,
				MAX_LI_POLICY_LIMIT);
		memcpy(dup_params->frwdng_plcy.frwdng_plcy_ident, li_policy,
				li_policy_len);
		len += li_policy_len * sizeof(uint8_t);
		dup_params->frwdng_plcy.frwdng_plcy_ident_len = li_policy_len;
		len += sizeof(uint8_t);

		/* Forwarding policy header */
		dup_params->frwdng_plcy.header.len = len;
		len += UPD_PARAM_HEADER_SIZE;
	}

	/* Duplicating parameter header */
	dup_params->header.len = len;
	len += UPD_PARAM_HEADER_SIZE;

	/* IE's which are not require. Set their header length to 0 */
	dup_params->dst_intfc.header.len = 0;
	dup_params->outer_hdr_creation.header.len = 0;

	/* Return value to update update far header */
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
	uint8_t pdr_idx =0;
	uint8_t bearer_id = 0;
	eps_bearer *bearer = NULL;
	upf_context_t *upf_ctx = NULL;
	qer_t *qer_context = NULL;
	bearer_qos_ie *default_bearer_qos = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr, &upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error while extracting "
			"upf context UPF ip : %u \n", LOG_VALUE, pdn->upf_ipv4.s_addr);
		return;
	}

	memset(pfcp_sess_est_req,0,sizeof(pfcp_sess_estab_req_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req->header), PFCP_SESSION_ESTABLISHMENT_REQUEST,
			HAS_SEID, seq, context->cp_mode);

	pfcp_sess_est_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(pAddr);

	set_node_id(&(pfcp_sess_est_req->node_id), node_value);

	set_user_id(&(pfcp_sess_est_req->user_id), context->imsi);

	set_fseid(&(pfcp_sess_est_req->cp_fseid), pdn->seid, node_value);

	if ((context->cp_mode == PGWC) ||
		(SAEGWC == context->cp_mode))
	{
		pfcp_sess_est_req->create_pdr_count = pdn->policy.num_charg_rule_install * NUMBER_OF_PDR_PER_RULE;
		/*
		 * For pgw create pdf, far and qer while handling pfcp messages
		 */
		for (int idx=0; idx <  pdn->policy.num_charg_rule_install; idx++)
		{
			bearer = NULL;
			if (pdn->policy.pcc_rule[idx].predefined_rule) {
				default_bearer_qos = &pdn->policy.pcc_rule[idx].pdef_rule.qos;

			} else {
				default_bearer_qos = &pdn->policy.pcc_rule[idx].dyn_rule.qos;
			}
			if(compare_default_bearer_qos(&pdn->policy.default_bearer_qos,
						default_bearer_qos) == 0) {
				/* This means rule going to install in default bearer */
				bearer = get_default_bearer(pdn);
				if (bearer == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"bearer object is NULL\n", LOG_VALUE);
					return;
				}
			} else {
				/* dedicated bearer */
				bearer = get_bearer(pdn, default_bearer_qos);
				if(bearer == NULL) {
					/* create dedicated bearer */
					bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
					if(bearer == NULL) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure "
							"to allocate bearer structure: %s\n",
							LOG_VALUE, rte_strerror(rte_errno));
						return;
					}
					bearer->pdn = pdn;
					bearer_id = get_new_bearer_id(pdn);
					pdn->eps_bearers[bearer_id] = bearer;
					pdn->context->eps_bearers[bearer_id] = bearer;
					pdn->num_bearer++;
					fill_dedicated_bearer_info(bearer, pdn->context, pdn, pdn->policy.pcc_rule[idx].predefined_rule);
					memcpy(&(bearer->qos),
							default_bearer_qos,
							sizeof(bearer_qos_ie));
				}

			}
			if(pdn->policy.pcc_rule[idx].predefined_rule){
				bearer->prdef_rules[bearer->num_prdef_filters] =
					rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
							RTE_CACHE_LINE_SIZE, rte_socket_id());

				if (bearer->prdef_rules[bearer->num_prdef_filters] == NULL)
				{
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to "
							"allocate failure rule memory structure: %s\n",LOG_VALUE,
							rte_strerror(rte_errno));
					return;
				}
				memcpy((bearer->prdef_rules[bearer->num_prdef_filters]),
						&(pdn->policy.pcc_rule[idx].pdef_rule),
						sizeof(dynamic_rule_t));

				for(int itr = 0; itr < NUMBER_OF_PDR_PER_RULE; itr++){
					bearer->prdef_rules[bearer->num_prdef_filters]->pdr[itr] = bearer->pdrs[itr];
				}
				bearer->num_prdef_filters++;

			} else {
				bearer->dynamic_rules[bearer->num_dynamic_filters] = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
				if (bearer->dynamic_rules[bearer->num_dynamic_filters] == NULL)
				{
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to "
							"allocate dynamic rule memory structure: %s\n",LOG_VALUE,
							rte_strerror(rte_errno));
					return;
				}
				memcpy( (bearer->dynamic_rules[bearer->num_dynamic_filters]),
						&(pdn->policy.pcc_rule[idx].dyn_rule),
						sizeof(dynamic_rule_t));

				for(int itr = 0; itr < NUMBER_OF_PDR_PER_RULE; itr++){
					strncpy(bearer->pdrs[itr]->rule_name,pdn->policy.pcc_rule[idx].dyn_rule.rule_name, RULE_NAME_LEN);
					bearer->dynamic_rules[bearer->num_dynamic_filters]->pdr[itr] = bearer->pdrs[itr];
					enum flow_status f_status =
						bearer->dynamic_rules[bearer->num_dynamic_filters]->flow_status; // consider dynamic rule is 1 only /*TODO*/
					fill_gate_status(pfcp_sess_est_req, itr + 1, f_status);
				}
				bearer->num_dynamic_filters++;
			}

		}
	} else {
		bearer = get_default_bearer(pdn);
		pfcp_sess_est_req->create_pdr_count = pdn->context->bearer_count * NUMBER_OF_PDR_PER_RULE;

	}

	/* get user level packet copying token or id using imsi */
	imsi_id_hash_t *imsi_id_config = NULL;
	ret = get_id_using_imsi(context->imsi, &imsi_id_config);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Not applicable for li\n",
				LOG_VALUE);
	}
	uint8_t itr = 0;
	for(uint8_t i = 0; i < MAX_BEARERS; i++) {

		bearer = pdn->eps_bearers[i];
		if(bearer != NULL)
		{
			for(uint8_t idx = 0; idx < bearer->pdr_count; idx++)
			{
				for (uint8_t idx1 = 0; idx1 < bearer->num_dynamic_filters; idx1++) {
					if (!(pdn->policy.pcc_rule[itr].predefined_rule)) {
						if (context->cp_mode == PGWC || context->cp_mode == SAEGWC){
							pfcp_sess_est_req->create_pdr[pdr_idx].qer_id_count = 1;
						}
					}
				}

				/*Just need to Forward the packets that's why disabling
				 * all other supported action*/
				bearer->pdrs[idx]->far.actions.forw = PRESENT;
				bearer->pdrs[idx]->far.actions.dupl = 0;
				bearer->pdrs[idx]->far.actions.drop = 0;
				if (pdn->generate_cdr) {
					pfcp_sess_est_req->create_pdr[pdr_idx].urr_id_count = 1;
					pfcp_sess_est_req->create_urr_count++;
					set_create_urr(&(pfcp_sess_est_req->create_urr[pdr_idx]), bearer->pdrs[idx]);
				}
				set_create_pdr(&(pfcp_sess_est_req->create_pdr[pdr_idx]), bearer->pdrs[idx], context->cp_mode);
				pfcp_sess_est_req->create_far_count++;
				set_create_far(&(pfcp_sess_est_req->create_far[pdr_idx]), &bearer->pdrs[idx]->far);

				if (( SGWC == context->cp_mode ) &&
						(context->indication_flag.oi == 0)) {

					if (SOURCE_INTERFACE_VALUE_ACCESS ==
							bearer->pdrs[idx]->pdi.src_intfc.interface_value) {
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.buff = PRESENT;
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = NOT_PRESENT;

					} else {
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.nocp = PRESENT;
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.buff = PRESENT;
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = NOT_PRESENT;
					}
				}

				/* SGW Relocation*/
				if(pdn->context->indication_flag.oi != 0) {
					uint8_t len  = 0;
					if(pdr_idx%2)
					{
						len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms),
																		bearer->s1u_enb_gtpu_ipv4.s_addr,
																		bearer->s1u_enb_gtpu_teid,
																		DESTINATION_INTERFACE_VALUE_ACCESS);
						pfcp_sess_est_req->create_far[pdr_idx].header.len += len;

					} else {
						pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
						len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms),
																		bearer->s5s8_pgw_gtpu_ipv4.s_addr,
																		bearer->s5s8_pgw_gtpu_teid,
																		DESTINATION_INTERFACE_VALUE_CORE);
						pfcp_sess_est_req->create_far[pdr_idx].header.len += len;
					}
				}

				if ((context != NULL) && (imsi_id_config != NULL) && (imsi_id_config->cntr > 0)) {

					update_li_info_in_dup_params(imsi_id_config, context,
							&(pfcp_sess_est_req->create_far[pdr_idx]));
				}

				if ((context->cp_mode == PGWC) || (SAEGWC == context->cp_mode)) {

					pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = PRESENT;
					if (pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw == PRESENT) {
						uint16_t len = 0;

						if (SOURCE_INTERFACE_VALUE_ACCESS == bearer->pdrs[idx]->pdi.src_intfc.interface_value) {


							len = set_destination_interface(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.dst_intfc),
									bearer->pdrs[idx]->far.dst_intfc.interface_value);
							pfcp_set_ie_header(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.header),
									IE_FRWDNG_PARMS, len);


							pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms.header.len = len;

							len += UPD_PARAM_HEADER_SIZE;
							pfcp_sess_est_req->create_far[pdr_idx].header.len += len;
						} else {
							if (context->cp_mode == PGWC) {
								len += set_forwarding_param(&(pfcp_sess_est_req->create_far[pdr_idx].frwdng_parms),
										bearer->pdrs[idx]->far.outer_hdr_creation.ipv4_address,
										bearer->pdrs[idx]->far.outer_hdr_creation.teid,
										bearer->pdrs[idx]->far.dst_intfc.interface_value);
							} else {
								pfcp_sess_est_req->create_far[pdr_idx].apply_action.nocp = PRESENT;
								pfcp_sess_est_req->create_far[pdr_idx].apply_action.buff = PRESENT;
								pfcp_sess_est_req->create_far[pdr_idx].apply_action.forw = NOT_PRESENT;

							}

							pfcp_sess_est_req->create_far[pdr_idx].header.len += len;
						}
					}
					if(!pdn->policy.pcc_rule[itr].predefined_rule){
						qer_context = get_qer_entry(bearer->qer_id[idx].qer_id);
						/* Assign the value from the PDR */
						if(qer_context){
							set_create_qer(&(pfcp_sess_est_req->create_qer[pdr_idx]), qer_context);
						}
					}
				}

				pdr_idx++;
			}

			if(!(pdn->policy.pcc_rule[itr].predefined_rule)){
				pfcp_sess_est_req->create_qer_count += bearer->qer_count;
			}
		}
	}

	pdr_idx = 0;
	for(int itr1 = 0; itr1 <  pdn->policy.num_charg_rule_install; itr1++) {
		if (pdn->policy.pcc_rule[itr1].predefined_rule) {
			/*
			 * call fill_create_pdr_activate_predef_rules twice because one rule create 2 PDRs
			 */
			fill_predef_rules_pdr(
					pfcp_sess_est_req->create_pdr, &pdn->policy.pcc_rule[itr1].pdef_rule, pdr_idx, 0);
			pdr_idx++;

			fill_predef_rules_pdr(
					pfcp_sess_est_req->create_pdr, &pdn->policy.pcc_rule[itr1].pdef_rule, pdr_idx, 0);
			pdr_idx++;
		} else {
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
	}

	/* Set the pdn connection type */
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
int
fill_context_info(create_sess_req_t *csr, ue_context *context, pdn_connection *pdn)
{
	if (csr->mei.header.len)
		memcpy(&context->mei, &csr->mei.mei, csr->mei.header.len);

	memcpy(&context->msisdn, &csr->msisdn.msisdn_number_digits, csr->msisdn.header.len);

	if ((context->cp_mode == SGWC) || (context->cp_mode == SAEGWC)) {

		context->s11_sgw_gtpc_ipv4.s_addr = pfcp_config.s11_ip.s_addr;
		context->s11_mme_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;
		s11_mme_sockaddr.sin_addr.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;

		if(csr->indctn_flgs.header.len != 0) {
			context->indication_flag.oi = csr->indctn_flgs.indication_oi;
			context->indication_flag.crsi = csr->indctn_flgs.indication_crsi;
			context->indication_flag.sgwci= csr->indctn_flgs.indication_sgwci;
			context->indication_flag.hi = csr->indctn_flgs.indication_hi;
			context->indication_flag.ccrsi = csr->indctn_flgs.indication_ccrsi;
			context->indication_flag.cprai = csr->indctn_flgs.indication_cprai;
			context->indication_flag.clii = csr->indctn_flgs.indication_clii;
			context->indication_flag.dfi = csr->indctn_flgs.indication_dfi;
			if (context->indication_flag.oi)
				context->procedure = SGW_RELOCATION_PROC;
		}

	}

	/* It's senders TEID
	 * MME TEID for MME -> SGW
	 * SGW TEID for SGW -> PGW
	 */
	context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;

	/* Stored the serving network information in UE context */
	context->serving_nw.mnc_digit_1 = csr->serving_network.mnc_digit_1;
	context->serving_nw.mnc_digit_2 = csr->serving_network.mnc_digit_2;
	context->serving_nw.mnc_digit_3 = csr->serving_network.mnc_digit_3;
	context->serving_nw.mcc_digit_1 = csr->serving_network.mcc_digit_1;
	context->serving_nw.mcc_digit_2 = csr->serving_network.mcc_digit_2;
	context->serving_nw.mcc_digit_3 = csr->serving_network.mcc_digit_3;

	if (csr->uci.header.len != 0) {

		context->uci_flag = true;
		context->uci.mnc_digit_1 = csr->uci.mnc_digit_1;
		context->uci.mnc_digit_2 = csr->uci.mnc_digit_2;
		context->uci.mnc_digit_3 = csr->uci.mnc_digit_3;
		context->uci.mcc_digit_1 = csr->uci.mcc_digit_1;
		context->uci.mcc_digit_2 = csr->uci.mcc_digit_2;
		context->uci.mcc_digit_3 = csr->uci.mcc_digit_3;
		context->uci.csg_id = csr->uci.csg_id;
		context->uci.csg_id2 = csr->uci.csg_id2;
		context->uci.access_mode = csr->uci.access_mode;
		context->uci.lcsg = csr->uci.lcsg;
		context->uci.cmi = csr->uci.cmi;

	}

	if (csr->ue_time_zone.header.len != 0) {
		context->ue_time_zone_flag = true;
		context->tz.tz = csr->ue_time_zone.time_zone;
		context->tz.dst = csr->ue_time_zone.daylt_svng_time;
	}

	if( csr->mo_exception_data_cntr.header.len != 0) {
		context->mo_exception_data_counter.timestamp_value =  csr->mo_exception_data_cntr.timestamp_value;
		context->mo_exception_data_counter.counter_value = csr->mo_exception_data_cntr.counter_value;
		context->mo_exception_flag = true;
	}

	/* Stored the RAT TYPE information in UE context */
	if (csr->rat_type.header.len != 0) {
		context->rat_type.rat_type = csr->rat_type.rat_type;
		context->rat_type.len = csr->rat_type.header.len;
	}

	/* Stored the UP selection flag*/
	if(csr->up_func_sel_indctn_flgs.header.len != 0) {
		context->up_selection_flag = TRUE;
		context->dcnr_flag = csr->up_func_sel_indctn_flgs.dcnr;
	}

	/* Stored the RAT TYPE information in UE context */
	if (csr->uli.header.len != 0) {
		fill_uli_info(&csr->uli, context);
	}

	/* Maintain the sequence number of CSR */
	if(csr->header.gtpc.teid_flag == 1) {
		context->sequence = pdn->csr_sequence = csr->header.teid.has_teid.seq;
	} else {
		context->sequence = pdn->csr_sequence = csr->header.teid.no_teid.seq;
	}

	return 0;
}

/**
 * @brief  : Fill pdn info from data in incoming csr
 * @param  : csr holds data in csr
 * @param  : pdn , pointer to pdn connction structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_pdn_info(create_sess_req_t *csr, pdn_connection *pdn,
		ue_context *context, eps_bearer *bearer)
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

	if ((context->cp_mode == SGWC) || ( context->cp_mode == SAEGWC)) {
		if (!pdn->s5s8_sgw_gtpc_teid) {
			pdn->s5s8_sgw_gtpc_teid = get_s5s8_sgw_gtpc_teid();
		}
		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.s5s8_ip;

		if(context->cp_mode == SGWC) {
			pdn->s5s8_pgw_gtpc_ipv4.s_addr =
				csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address;

		} else {
			pdn->s5s8_pgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
			/* Allocate the TEID in case of promotion and demotion case */
			/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_teid */
			pdn->s5s8_pgw_gtpc_teid = context->s11_sgw_gtpc_teid;

		}

	} else if (context->cp_mode == PGWC) {
		pdn->s5s8_pgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;

		/* Note: s5s8_pgw_gtpc_teid generated from
		 * s5s8_pgw_gtpc_base_teid and incremented
		 * for each pdn connection, similar to
		 * s11_sgw_gtpc_teid
		 */
		pdn->s5s8_pgw_gtpc_teid = context->s11_sgw_gtpc_teid;
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;

		/* Maitain the fqdn into table */
		memcpy(pdn->fqdn, (char *)csr->sgw_u_node_name.fqdn,
						csr->sgw_u_node_name.header.len);


	}

	if (csr->indctn_flgs.header.len != 0 && context->indication_flag.oi) {
		memcpy(&(pdn->ipv4.s_addr) ,&(csr->paa.pdn_addr_and_pfx), IPV4_SIZE);
		pdn->s5s8_pgw_gtpc_teid = csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key;
	}

	/* Promotion Case */
	if (!pdn->dp_seid) {
		pdn->dp_seid = 0;
		pdn->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	}
	pdn->context = context;

	if (context->cp_mode == SGWC) {
		s5s8_recv_sockaddr.sin_addr.s_addr =
				csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address;

		/* Check for wheather to Generate CDR or NOT */
		if(pfcp_config.generate_sgw_cdr == SGW_CC_CHECK){
			if(pfcp_config.sgw_cc == csr->chrgng_char.chrgng_char_val){
				pdn->generate_cdr = PRESENT;
			}else{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" %s CC value Missmatched\n",
																					LOG_VALUE);
				pdn->generate_cdr = NOT_PRESENT;
			}

		}else{
			pdn->generate_cdr = pfcp_config.generate_sgw_cdr;
		}
	}else {

		/* Check for wheather to Generate CDR or NOT */
		pdn->generate_cdr = pfcp_config.generate_cdr;
	}

	/* Stored the mapped ue usage type information in PDN */
	if (csr->mapped_ue_usage_type.header.len != 0) {
		pdn->mapped_ue_usage_type = csr->mapped_ue_usage_type.mapped_ue_usage_type;
	} else {
		pdn->mapped_ue_usage_type = -1;
	}

	return 0;
}

int
check_interface_type(uint8_t iface, uint8_t  cp_type){
	switch(iface){
		case GTPV2C_IFTYPE_S1U_ENODEB_GTPU:
			if ((cp_type == SGWC) || (cp_type == SAEGWC)) {
				return DESTINATION_INTERFACE_VALUE_ACCESS;
			}
			break;
		case GTPV2C_IFTYPE_S5S8_SGW_GTPU:
			if (cp_type == PGWC){
				return DESTINATION_INTERFACE_VALUE_ACCESS;
			}
			break;
		case GTPV2C_IFTYPE_S5S8_PGW_GTPU:
			if (cp_type == SGWC){
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
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid interface "
				"type\n", LOG_VALUE);
			return -1;
			break;
	}
	return -1;
}

int
fill_dedicated_bearer_info(eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn, bool prdef_rule)
{
	int ret = 0;
	upf_context_t *upf_ctx = NULL;
	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	bearer->s5s8_sgw_gtpu_ipv4.s_addr = context->eps_bearers[ebi_index]->s5s8_sgw_gtpu_ipv4.s_addr;
#ifdef CP_BUILD
	if(!prdef_rule && (pfcp_config.use_gx)){
		/* TODO: Revisit this for change in yang*/
		if (context->cp_mode != SGWC){
			for(uint8_t itr=bearer->qer_count;
				itr < bearer->qer_count + NUMBER_OF_QER_PER_RULE;
				itr++){

				bearer->qer_id[itr].qer_id = generate_qer_id();
				fill_qer_entry(pdn, bearer,itr);
			}
			bearer->qer_count += NUMBER_OF_QER_PER_RULE;
		}
	}
#endif /* CP_BUILD */

	/*SP: As per discussion Per bearer two pdrs and fars will be there*/
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         2      s5s8 PGWU          NA
	 SAEGWC       2      s1u SAEGWU         NA
	 ************************************************/

	for(uint8_t itr=bearer->pdr_count;
		itr < bearer->pdr_count + NUMBER_OF_PDR_PER_RULE;
		itr++){

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
	bearer->pdr_count += NUMBER_OF_PDR_PER_RULE;

	bearer->pdn = pdn;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ipv4.s_addr),
			(void **) &(upf_ctx));
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NO ENTRY FOUND IN UPF "
			"HASH [%u]\n", LOG_VALUE, (pdn->upf_ipv4.s_addr));
		return GTPV2C_CAUSE_INVALID_PEER;
	}

	if (context->cp_mode == SGWC) {
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_sgwu_ip;
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		bearer->s1u_sgw_gtpu_teid = get_s1u_sgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
												context->cp_mode, &upf_teid_info_head);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip,
												SOURCE_INTERFACE_VALUE_ACCESS);

		bearer->s5s8_sgw_gtpu_teid = get_s5s8_sgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
												context->cp_mode, &upf_teid_info_head);
		update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip,
												SOURCE_INTERFACE_VALUE_CORE);

	}else if (context->cp_mode == SAEGWC) {
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		bearer->s1u_sgw_gtpu_teid = get_s1u_sgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
							context->cp_mode, &upf_teid_info_head);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip,
					SOURCE_INTERFACE_VALUE_ACCESS);

		/* Suppport the promotion and demotion */
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_pgwu_ip;
		bearer->s5s8_pgw_gtpu_teid =  bearer->s1u_sgw_gtpu_teid;

	} else {

		bearer->s5s8_pgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_pgwu_ip;

		bearer->s5s8_pgw_gtpu_teid = get_s5s8_pgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
											context->cp_mode, &upf_teid_info_head);
		update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, upf_ctx->s5s8_pgwu_ip,
											SOURCE_INTERFACE_VALUE_ACCESS);
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
 * @param  : index, index of an array
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_bearer_info(create_sess_req_t *csr, eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn, int index )
{

	/* Need to re-vist this ARP[Allocation/Retention priority] handling portion */
	bearer->qos.arp.priority_level =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.pl;
	bearer->qos.arp.preemption_capability =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.pci;
	bearer->qos.arp.preemption_vulnerability =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.pvi;

	/* TODO: Implement TFTs on default bearers
	 * if (create_session_request.bearer_tft_ie) {
	 * }**/

	/* Fill the QCI value */
	bearer->qos.qci =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.qci;
	bearer->qos.ul_mbr =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.max_bit_rate_uplnk;
	bearer->qos.dl_mbr =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.max_bit_rate_dnlnk;
	bearer->qos.ul_gbr =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.guarntd_bit_rate_uplnk;
	bearer->qos.dl_gbr =
		csr->bearer_contexts_to_be_created[index].bearer_lvl_qos.guarntd_bit_rate_dnlnk;

	bearer->s1u_sgw_gtpu_teid = 0;
	bearer->s5s8_sgw_gtpu_teid = 0;

	if (context->cp_mode == PGWC){
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created[index].s5s8_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid = csr->bearer_contexts_to_be_created[index].s5s8_u_sgw_fteid.teid_gre_key;
	}

	if (csr->indctn_flgs.header.len != 0 && context->indication_flag.oi) {
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created[index].s5s8_u_pgw_fteid.ipv4_address;
		bearer->s5s8_pgw_gtpu_teid = csr->bearer_contexts_to_be_created[index].s5s8_u_pgw_fteid.teid_gre_key;
		bearer->s1u_enb_gtpu_teid = csr->bearer_contexts_to_be_created[index].s1u_enb_fteid.teid_gre_key;
		bearer->s1u_enb_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created[index].s1u_enb_fteid.ipv4_address;
	}

	/*SP: As per discussion Per bearer two pdrs and fars will be there*/
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         2      s5s8 PGWU          NA
	 SAEGWC       2      s1u SAEGWU         NA
	 ************************************************/

	for(uint8_t itr = bearer->pdr_count;
			itr < bearer->pdr_count + NUMBER_OF_PDR_PER_RULE;
			itr++){

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
	bearer->pdr_count += NUMBER_OF_PDR_PER_RULE;

	bearer->pdn = pdn;

	RTE_SET_USED(context);
	return 0;
}

/**
 * @brief  : Generate ccr request
 * @param  : context, ue context
 * @param  : ebi_index
 * @param  : csr, create session request data
 * @return : Returns 0 on success, -1 otherwise
 */
static int
gen_ccr_request(ue_context *context, int ebi_index , create_sess_req_t *csr)
{
	/* VS: Initialize the Gx Parameters */
	uint8_t ret = 0;
	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;
	pdn_connection *pdn = NULL;

	pdn = GET_PDN(context, ebi_index);
	/* VS: Generate unique call id per PDN connection */
	pdn->call_id = generate_call_id();

	/** Allocate the memory for Gx Context
	 */
	gx_context = rte_malloc_socket(NULL,
			sizeof(gx_context_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (gx_context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to allocate gx "
			"context structure: %s \n", LOG_VALUE, rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Generate unique session id for communicate over the Gx interface */
	if (gen_sess_id_for_ccr(gx_context->gx_sess_id,
				pdn->call_id)) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: Failed to "
			"to generate unnique session id %s \n", LOG_VALUE,strerror(errno));
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Maintain the gx session id in context */
	memcpy(pdn->gx_sess_id, gx_context->gx_sess_id, sizeof(pdn->gx_sess_id));

	/* Maintain the PDN mapping with call id */
	if ((ret = add_pdn_conn_entry(pdn->call_id, pdn) )!= 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add pdn "
			"entry with call id\n", LOG_VALUE);
		return ret;
	}

	/* Set up the CP Mode */
	gx_context->cp_mode = context->cp_mode;

	/* Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = INITIAL_REQUEST ;

	/* Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = ESTABLISHMENT ;

	/* Set bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT ;
	ccr_request.data.ccr.bearer_identifier.len =
		(1 + (uint32_t)log10((context->eps_bearers[ebi_index])->eps_bearer_id));

	if (ccr_request.data.ccr.bearer_identifier.len >= GX_BEARER_IDENTIFIER_LEN) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Insufficient memory to copy bearer identifier\n",LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	} else {
		strncpy((char *)ccr_request.data.ccr.bearer_identifier.val,
				(char *)&(context->eps_bearers[ebi_index])->eps_bearer_id,
				ccr_request.data.ccr.bearer_identifier.len);
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

	/* Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, context,
				ebi_index, gx_context->gx_sess_id, 0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to fill "
			"CCR request\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton(CLI_GX_IP, &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_INITIAL, SENT, GX);


	/* Update UE State */
	pdn->state = CCR_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = CCR_SNT_STATE;
	gx_context->proc = pdn->proc;

	/* Maintain the Gx context mapping with Gx Session id */
	if ((ret = gx_context_entry_add(gx_context->gx_sess_id, gx_context)) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
			"gx context entry : %s \n", LOG_VALUE, strerror(errno));
		return ret;
	}

	/* Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	ccr_request.msg_len = msg_len + GX_HEADER_LEN;

	buffer = rte_zmalloc_socket(NULL, msg_len + GX_HEADER_LEN,
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to allocate "
			"CCR Buffer memory structure: %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
	memcpy(buffer + sizeof(ccr_request.msg_type),
							&ccr_request.msg_len,
					sizeof(ccr_request.msg_len));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + GX_HEADER_LEN), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR in Packing "
			"CCR Buffer\n", LOG_VALUE);

		rte_free(buffer);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;

	}

	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + GX_HEADER_LEN);

	rte_free(buffer);
	if (ccr_request.data.ccr.subscription_id.list != NULL) {
		free(ccr_request.data.ccr.subscription_id.list);
		ccr_request.data.ccr.subscription_id.list = NULL;
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
			"subscription id list is successfully free\n",
			LOG_VALUE);
	}
	RTE_SET_USED(csr);
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

/* @brief  : Store rule index in array if it not previously
 *         : stored.Useful to identify rule name.
 * @param  : rule_index, index at which rule is stored in bearer
 * @param  : rule_report_arr, sructure to store rule idex & num
 *         : of packet filter.
 * @return : nothing.
 */

static void
store_rule_report_index(uint8_t rule_index,
				rule_report_index_t *rule_report_arr) {

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Received rule_index : %d\n",
			LOG_VALUE, rule_index);

	for(int cnt = 0; cnt < rule_report_arr->rule_cnt; cnt++) {
		if(rule_index == rule_report_arr->rule_report[cnt]) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"rule_match\n", LOG_VALUE);
			rule_report_arr->num_fltr[cnt] += 1;
			return ;
		}
	}

	rule_report_arr->rule_report[(rule_report_arr->rule_cnt)] = rule_index;
	rule_report_arr->num_fltr[(rule_report_arr->rule_cnt)] += 1;
	rule_report_arr->rule_cnt++;
	clLog(clSystemLog, eCLSeverityDebug,
			"Increment rule count\n");
	return ;
}

/* @brief  : Free dynamically allocated memory in ccr request
 * @param  : ccr_request, ptr to ccr msg structure in which
 *         : memory is allocated.
 * @return : nothing.
 */
static void
free_dynamically_alloc_memory(gx_msg *ccr_request) {

	if(ccr_request->data.ccr.presence.subscription_id == PRESENT) {

		free(&ccr_request->data.ccr.subscription_id.list[0]);
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Subscription id cleanup succesfully\n", LOG_VALUE);
	}

	if(ccr_request->data.ccr.presence.packet_filter_information == PRESENT) {

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"packet_filter_information.count : %d\n",
				LOG_VALUE, ccr_request->data.ccr.packet_filter_information.count);

		rte_free(&ccr_request->data.ccr.packet_filter_information.list[0]);
		clLog(clSystemLog, eCLSeverityDebug,
				"Free packet filter information : \n", LOG_VALUE);
	}

	if(ccr_request->data.ccr.presence.charging_rule_report == PRESENT) {

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"charging rule report .count : %d\n",
				LOG_VALUE, ccr_request->data.ccr.charging_rule_report.count);

		for(int cnt = 0; cnt < ccr_request->data.ccr.charging_rule_report.count; cnt++) {

			if(ccr_request->data.ccr.charging_rule_report.list[cnt].presence.charging_rule_name == PRESENT) {
				for(int iCnt = 0; iCnt < ccr_request->data.ccr.charging_rule_report.list[cnt].charging_rule_name.count; iCnt++) {
					rte_free(&ccr_request->data.ccr.charging_rule_report.list[cnt].charging_rule_name.list[iCnt]);

				}
			}

		}
		rte_free(&ccr_request->data.ccr.charging_rule_report.list[0]);
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Free Charging rule report : \n", LOG_VALUE);
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Cleanup Succesfully\n", LOG_VALUE);
}



/**
 * @brief  : Generate CCR-U request for BRC
 * @param  : bearer_rsrc_cmd , pointer to received bearer resource cmd
 * @param  : ccr_request , pointer to ccr_request
 * @return : Returns 0 in case of success , error code otherwise
 */
static int
ccru_req_for_bearer_rsrc_mod(bearer_rsrc_cmd_t *bearer_rsrc_cmd,
								gx_msg *ccr_request, eps_bearer *bearer)
{
	int ret = 0;

	uint8_t tft_op_code = (((bearer_rsrc_cmd->tad.traffic_agg_desc) >> TFT_OP_CODE_SHIFT ) & TFT_OP_CODE_MASK);

	/*  Set Credit Control Bearer opertaion type */
	ccr_request->data.ccr.presence.bearer_operation = PRESENT;


	switch(tft_op_code) {

		case TFT_OP_CREATE_NEW :
			ret = fill_create_new_tft_avp(ccr_request, bearer_rsrc_cmd);
			break;

		case TFT_OP_DELETE_EXISTING :
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"ERROR :Unsupported TFT OPCODE \n", LOG_VALUE);
			/*Unsupported TFT code*/
			ret = GTPV2C_CAUSE_SEMANTIC_ERR_IN_TAD_OP;
			break;

		case TFT_OP_DELETE_FILTER_EXISTING :
			ret = fill_delete_existing_filter_tft_avp(ccr_request, bearer_rsrc_cmd, bearer);
			break;

		case TFT_OP_ADD_FILTER_EXISTING :
			ret = fill_add_filter_existing_tft_avp(ccr_request, bearer_rsrc_cmd, bearer);
			break;

		case TFT_OP_REPLACE_FILTER_EXISTING :
			ret = fill_replace_filter_existing_tft_avp(ccr_request, bearer_rsrc_cmd, bearer);
			break;

		case TFT_OP_NO_OP :
			ret = fill_no_tft_avp(ccr_request, bearer_rsrc_cmd, bearer);
			break;

		case TFT_OP_IGNORE :
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"ERROR :Unsupported TFT OPCODE \n", LOG_VALUE);
			/*Unsupported TFT code*/
			ret = GTPV2C_CAUSE_SEMANTIC_ERR_IN_TAD_OP;
			break;

		default :
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"ERROR :Invalid TFT OPCODE \n", LOG_VALUE);
			/*Invalid TFT opcode*/
			ret = GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
			break;
	}

	return ret;
}

int
fill_no_tft_avp(gx_msg *ccr_request,
			bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer) {

	if(bearer_rsrc_cmd->flow_qos.header.len == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Flow QoS IE is "
				"not present for no TFT opcode \n",LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	} else {
		fill_qos_avp_bearer_resource_cmd(ccr_request, bearer_rsrc_cmd);
	}

	/*Check E bit is 1 or not for parameter list*/
	if ((((bearer_rsrc_cmd->tad.traffic_agg_desc) >> 4) & (E_BIT_MASK)) != 1 ){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Parameter list "
				"is not included, "
				"E bit is not set \n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	uint8_t pkt_flt_cnt = 0;
	pkt_flt_cnt = ((bearer_rsrc_cmd->tad.traffic_agg_desc) & NUM_OF_PKT_FLTR_MASK);
	if (pkt_flt_cnt != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Packet filter list "
				"should not present when TFT op code is "
				"no TFT\n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	uint8_t num_param_list = 0;
	uint8_t pkt_indx = 0;
	rule_report_index_t rule_report = {0};
	int rule_index = -1;
	num_param_list = ((bearer_rsrc_cmd->tad.header.len - 1) / 3) ;

	if(num_param_list <= 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Parameter list "
				"is empty for TFT op code "
				"no TFT\n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	/*Check received packet filter id in BRC is exist in
	 * bearer or not,if exist then store rule index
	 */
	for(int cnt = 0; cnt < num_param_list; cnt++) {
		param_list param_lst = {0};
		parse_parameter_list(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &param_lst);
		pkt_indx += 3;

		rule_index = check_pckt_fltr_id_in_rule(param_lst.packet_id, bearer);

		if(rule_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error : Packet filter identifier"
					"is not exist in given bearer\n",LOG_VALUE);
			return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
		}
		store_rule_report_index(rule_index, &rule_report);
	}

	/*Include rule name for affected rule in AVP*/
	ccr_request->data.ccr.presence.charging_rule_report = PRESENT;
	ccr_request->data.ccr.charging_rule_report.count = rule_report.rule_cnt;

	ccr_request->data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleReport)*(rule_report.rule_cnt)), RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.charging_rule_report.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Charging rule report information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	for(int id = 0; id < rule_report.rule_cnt; id++) {

		ccr_request->data.ccr.charging_rule_report.list[id].presence.charging_rule_name = PRESENT;
		ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.count = 1;
		ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list = rte_malloc_socket(NULL,
				(sizeof(GxChargingRuleNameOctetString)*(rule_report.rule_cnt)),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					"allocate memory for Charging rule name avp : %s", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].len =
			strnlen(bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, RULE_NAME_LEN);

		memcpy(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].val,
				bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, strlen(bearer->dynamic_rules[0]->rule_name));

		ccr_request->data.ccr.charging_rule_report.list[id].presence.pcc_rule_status = PRESENT;
		ccr_request->data.ccr.charging_rule_report.list[id].pcc_rule_status = ACTIVE;

		ccr_request->data.ccr.charging_rule_report.list[id].presence.rule_failure_code = PRESENT;
		ccr_request->data.ccr.charging_rule_report.list[id].rule_failure_code = NO_BEARER_BOUND;
	}


	ccr_request->data.ccr.bearer_operation = MODIFICATION;
	ccr_request->data.ccr.presence.packet_filter_operation = PRESENT;
	ccr_request->data.ccr.packet_filter_operation = MODIFICATION;
	ccr_request->data.ccr.presence.packet_filter_information = PRESENT;

	/*As per spec 29.212 only one Packet-Filter-Information AVP should present*/
	ccr_request->data.ccr.packet_filter_information.count = num_param_list;

	ccr_request->data.ccr.packet_filter_information.list = rte_malloc_socket(NULL,
			(sizeof(GxPacketFilterInformation)*num_param_list),RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.packet_filter_information.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to"
				"allocate Packet filter Buffer : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pkt_indx = 0;

	for (int idx = 0; idx < num_param_list; idx++) {
		/* TODO : remove hardcode value */
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_identifier = PRESENT;

		param_list param_lst = {0};
		parse_parameter_list(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &param_lst);
		pkt_indx += 3;

		memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.val,
				&param_lst.packet_id,1);
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.len = 1;
	}

	return 0;
}

int
fill_create_new_tft_avp(gx_msg *ccr_request, bearer_rsrc_cmd_t *bearer_rsrc_cmd) {

	ccr_request->data.ccr.bearer_operation = ESTABLISHMENT;

	ccr_request->data.ccr.presence.packet_filter_operation = PRESENT;
	ccr_request->data.ccr.packet_filter_operation = ADDITION;
	ccr_request->data.ccr.presence.packet_filter_information = PRESENT;

	if(bearer_rsrc_cmd->flow_qos.header.len != 0)
		fill_qos_avp_bearer_resource_cmd(ccr_request, bearer_rsrc_cmd);
	else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Flow QoS IE "
				"is Missing for create new TFT opcode\n", LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	uint8_t idx = 0;
	uint8_t pkt_flt_cnt = 0;
	pkt_flt_cnt = ((bearer_rsrc_cmd->tad.traffic_agg_desc) & NUM_OF_PKT_FLTR_MASK);

	if(pkt_flt_cnt == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Packet filter "
				"is Missing while creating new TFT AVp \n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	/*no.of packet filter present BRC inside TAD IE*/
	ccr_request->data.ccr.packet_filter_information.count = pkt_flt_cnt;

	ccr_request->data.ccr.packet_filter_information.list = rte_malloc_socket(NULL,
			(sizeof(GxPacketFilterInformation)*pkt_flt_cnt),RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.packet_filter_information.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Packet filter information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	struct in_addr src_ip_addr;
	struct in_addr dst_ip_addr;
	uint8_t pkt_indx = 0;

	for( idx = 0; idx < pkt_flt_cnt; idx++ ) {

		char dest_addr_buff[ADDR_BUF_SIZE]= {0};
		char src_addr_buff[ADDR_BUF_SIZE]= {0};
		char pkt_buff[PCKT_BUF_SIZE] = {0};

		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_content = PRESENT;
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_identifier = PRESENT;
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.flow_direction = PRESENT;
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.precedence = PRESENT;

		tad_pkt_fltr_t tad_pkt_fltr = {0};
		fill_gx_packet_filter_info(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &tad_pkt_fltr);

		pkt_indx = (bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx + PKT_FLTR_LEN_INDEX]) + PKT_FLTR_CONTENT_INDEX;

		memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.val,
				&tad_pkt_fltr.pckt_fltr_id,1);
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.len = 1;
		ccr_request->data.ccr.packet_filter_information.list[idx].flow_direction = tad_pkt_fltr.pckt_fltr_dir;
		memcpy(&ccr_request->data.ccr.packet_filter_information.list[idx].precedence,
				&tad_pkt_fltr.precedence,1);

		src_ip_addr.s_addr = tad_pkt_fltr.local_ip_addr;
		dst_ip_addr.s_addr = tad_pkt_fltr.remote_ip_addr;
		snprintf(src_addr_buff,ADDR_BUF_SIZE,"%s",inet_ntoa(src_ip_addr));
		snprintf(dest_addr_buff,ADDR_BUF_SIZE,"%s",inet_ntoa(dst_ip_addr));

		snprintf(pkt_buff,PCKT_BUF_SIZE,"%s %s/%d %u-%u to %s/%d %u-%u ","permit out ip from",
				inet_ntoa(src_ip_addr),tad_pkt_fltr.local_ip_mask,tad_pkt_fltr.local_port_low,
				tad_pkt_fltr.local_port_high,dest_addr_buff,tad_pkt_fltr.remote_ip_mask,
				tad_pkt_fltr.remote_port_low,tad_pkt_fltr.remote_port_high);
		memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_content.val,
				pkt_buff,strlen(pkt_buff));
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_content.len = strlen(pkt_buff);

	}


	return 0;
}

int
fill_replace_filter_existing_tft_avp(gx_msg *ccr_request,
										bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer) {

	ccr_request->data.ccr.bearer_operation = MODIFICATION;
	ccr_request->data.ccr.presence.packet_filter_operation = PRESENT;
	ccr_request->data.ccr.packet_filter_operation = MODIFICATION;
	ccr_request->data.ccr.presence.packet_filter_information = PRESENT;

	uint8_t idx = 0;
	uint8_t pkt_flt_cnt = 0;
	uint8_t pkt_indx = 0;
	rule_report_index_t rule_report = {0};
	int rule_index = -1;
	pkt_flt_cnt = ((bearer_rsrc_cmd->tad.traffic_agg_desc) & NUM_OF_PKT_FLTR_MASK);

	if(pkt_flt_cnt == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Packet filter "
				"is Missing while replacing TFT AVP\n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	/*Check received packet filter id in BRC is exist in bearer or not
	 *If exist, then include store rule index & add rule name in
	 *Charging-Rule-Report AVP
	 */
	for (int cnt = 0; cnt < pkt_flt_cnt; cnt++) {
		tad_pkt_fltr_t tad_pkt_fltr = {0};
		fill_gx_packet_filter_info(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &tad_pkt_fltr);
		pkt_indx = (bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx + PKT_FLTR_LEN_INDEX]) + PKT_FLTR_CONTENT_INDEX;
		rule_index = check_pckt_fltr_id_in_rule(tad_pkt_fltr.pckt_fltr_id, bearer);

		if(rule_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error : Packet filter identifier"
					"is not exist in given bearer\n",LOG_VALUE);
			return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
		}
		store_rule_report_index(rule_index, &rule_report);
	}

	ccr_request->data.ccr.presence.charging_rule_report = PRESENT;
	ccr_request->data.ccr.charging_rule_report.count = rule_report.rule_cnt;

	ccr_request->data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleReport)*(rule_report.rule_cnt)), RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.charging_rule_report.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Charging rule report information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	for(int id = 0; id < rule_report.rule_cnt; id++) {

		ccr_request->data.ccr.charging_rule_report.list[id].presence.charging_rule_name = PRESENT;
		ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.count = 1;
		ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list = rte_malloc_socket(NULL,
				(sizeof(GxChargingRuleNameOctetString)*(rule_report.rule_cnt)),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					"allocate memory for Charging rule name avp : %s", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].len =
			strnlen(bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, RULE_NAME_LEN);

		memcpy(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].val,
				bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, strlen(bearer->dynamic_rules[0]->rule_name));

		ccr_request->data.ccr.charging_rule_report.list[id].presence.pcc_rule_status = PRESENT;
		ccr_request->data.ccr.charging_rule_report.list[id].pcc_rule_status = ACTIVE;

		ccr_request->data.ccr.charging_rule_report.list[id].presence.rule_failure_code = PRESENT;
		ccr_request->data.ccr.charging_rule_report.list[id].rule_failure_code = NO_BEARER_BOUND;
	}

	/*no.of packet filter present BRC inside TAD IE*/
	ccr_request->data.ccr.packet_filter_information.count = pkt_flt_cnt;

	ccr_request->data.ccr.packet_filter_information.list = rte_malloc_socket(NULL,
			(sizeof(GxPacketFilterInformation)*pkt_flt_cnt),RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.packet_filter_information.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Packet filter information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	struct in_addr src_ip_addr;
	struct in_addr dst_ip_addr;
	pkt_indx = 0;
	for( idx = 0; idx < pkt_flt_cnt; idx++ ) {

		char dest_addr_buff[ADDR_BUF_SIZE]= {0};
		char src_addr_buff[ADDR_BUF_SIZE]= {0};
		char pkt_buff[PCKT_BUF_SIZE] = {0};

		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_content = PRESENT;
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_identifier = PRESENT;
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.flow_direction = PRESENT;
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.precedence = PRESENT;

		tad_pkt_fltr_t tad_pkt_fltr = {0};
		fill_gx_packet_filter_info(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &tad_pkt_fltr);

		pkt_indx = (bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx + PKT_FLTR_LEN_INDEX]) + PKT_FLTR_CONTENT_INDEX;

		memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.val,
				&tad_pkt_fltr.pckt_fltr_id,1);
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.len = 1;
		ccr_request->data.ccr.packet_filter_information.list[idx].flow_direction = tad_pkt_fltr.pckt_fltr_dir;
		memcpy(&ccr_request->data.ccr.packet_filter_information.list[idx].precedence,
				&tad_pkt_fltr.precedence,1);

		src_ip_addr.s_addr = tad_pkt_fltr.local_ip_addr;
		dst_ip_addr.s_addr = tad_pkt_fltr.remote_ip_addr;
		snprintf(src_addr_buff,ADDR_BUF_SIZE,"%s",inet_ntoa(src_ip_addr));
		snprintf(dest_addr_buff,ADDR_BUF_SIZE,"%s",inet_ntoa(dst_ip_addr));

		snprintf(pkt_buff,PCKT_BUF_SIZE,"%s %s/%d %u-%u to %s/%d %u-%u ","permit out ip from",
				inet_ntoa(src_ip_addr),tad_pkt_fltr.local_ip_mask,tad_pkt_fltr.local_port_low,
				tad_pkt_fltr.local_port_high,dest_addr_buff,tad_pkt_fltr.remote_ip_mask,
				tad_pkt_fltr.remote_port_low,tad_pkt_fltr.remote_port_high);
		memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_content.val,
				pkt_buff,strlen(pkt_buff));
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_content.len = strlen(pkt_buff);

	}

	/*If qos is requested to modify*/
	if(bearer_rsrc_cmd->flow_qos.header.len != 0)
		fill_qos_avp_bearer_resource_cmd(ccr_request, bearer_rsrc_cmd);

	return 0;
}


int
fill_add_filter_existing_tft_avp(gx_msg *ccr_request,
									bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer) {

	/*Check E bit is 1 or not for parameter list*/
	if ((((bearer_rsrc_cmd->tad.traffic_agg_desc) >> 4) & (E_BIT_MASK)) != 1 ){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Parameter list "
				"is not included \n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	ccr_request->data.ccr.bearer_operation = MODIFICATION;
	ccr_request->data.ccr.presence.packet_filter_operation = PRESENT;
	ccr_request->data.ccr.packet_filter_operation = ADDITION;
	ccr_request->data.ccr.presence.packet_filter_information = PRESENT;

	int ret = 0;
	uint8_t idx = 0;
	uint8_t pkt_flt_cnt = 0;
	uint16_t total_len = bearer_rsrc_cmd->tad.header.len;
	pkt_flt_cnt = ((bearer_rsrc_cmd->tad.traffic_agg_desc) & NUM_OF_PKT_FLTR_MASK);

	if(pkt_flt_cnt == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Packet filter "
				"is Missing while adding filter to existing TFT AVP\n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	param_list param_lst = {0};
	int id = 0;
	/*Get index of parameter list in TAD IE*/
	uint8_t param_lst_index = bearer_rsrc_cmd->tad.header.len - PARAM_LIST_INDEX;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"param_lst_index : %d\n",
													LOG_VALUE, param_lst_index);

	ret = parse_parameter_list(&bearer_rsrc_cmd->tad.pkt_fltr_buf[param_lst_index], &param_lst);
	if(ret!=0)
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;

	int rule_index = -1;
	/*Check received packet filter id in BRC is exist or not*/
	rule_index = check_pckt_fltr_id_in_rule(param_lst.packet_id, bearer);

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"rule_index : %d\n\n",
			LOG_VALUE, rule_index);

	if(rule_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Packet filter id "
				"is not found in bearer TFT\n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	/*Include affted charging rule name in Charging-Rule-Report AVP*/
	ccr_request->data.ccr.presence.charging_rule_report = PRESENT;
	ccr_request->data.ccr.charging_rule_report.count = 1;

	ccr_request->data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleReport)), RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.charging_rule_report.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Charging rule report information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}


	ccr_request->data.ccr.charging_rule_report.list[id].presence.charging_rule_name = PRESENT;
	ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.count = 1;
	ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleNameOctetString)), RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Charging rule name avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].len =
		strnlen(bearer->dynamic_rules[rule_index]->rule_name, RULE_NAME_LEN);

	memcpy(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].val,
			bearer->dynamic_rules[rule_index]->rule_name, strlen(bearer->dynamic_rules[rule_index]->rule_name));

	ccr_request->data.ccr.charging_rule_report.list[id].presence.pcc_rule_status = PRESENT;
	ccr_request->data.ccr.charging_rule_report.list[id].pcc_rule_status = ACTIVE;

	ccr_request->data.ccr.charging_rule_report.list[id].presence.rule_failure_code = PRESENT;
	ccr_request->data.ccr.charging_rule_report.list[id].rule_failure_code = NO_BEARER_BOUND;

	/*no.of packet filter present BRC inside TAD IE*/
	ccr_request->data.ccr.packet_filter_information.count = pkt_flt_cnt + 1;

	/*Assumption : only one parameter list will be present*/
	ccr_request->data.ccr.packet_filter_information.list = rte_malloc_socket(NULL,
			(sizeof(GxPacketFilterInformation)*(pkt_flt_cnt + 1)),RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.packet_filter_information.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Packet filter information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	struct in_addr src_ip_addr;
	struct in_addr dst_ip_addr;
	uint8_t pkt_indx = 0;
	uint16_t total_decoded = 1;

	while (total_decoded < total_len) {

		for( idx = 0; idx < pkt_flt_cnt; idx++ ) {

			char dest_addr_buff[ADDR_BUF_SIZE]= {0};
			char src_addr_buff[ADDR_BUF_SIZE]= {0};
			char pkt_buff[PCKT_BUF_SIZE] = {0};

			ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_content = PRESENT;
			ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_identifier = PRESENT;
			ccr_request->data.ccr.packet_filter_information.list[idx].presence.flow_direction = PRESENT;
			ccr_request->data.ccr.packet_filter_information.list[idx].presence.precedence = PRESENT;

			tad_pkt_fltr_t tad_pkt_fltr = {0};
			fill_gx_packet_filter_info(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &tad_pkt_fltr);

			pkt_indx += (bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx + PKT_FLTR_LEN_INDEX]) + PKT_FLTR_CONTENT_INDEX;
			total_decoded += pkt_indx;

			memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.val,
					&tad_pkt_fltr.pckt_fltr_id,1);
			ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.len = 1;
			ccr_request->data.ccr.packet_filter_information.list[idx].flow_direction = tad_pkt_fltr.pckt_fltr_dir;
			memcpy(&ccr_request->data.ccr.packet_filter_information.list[idx].precedence,
					&tad_pkt_fltr.precedence,1);

			src_ip_addr.s_addr = tad_pkt_fltr.local_ip_addr;
			dst_ip_addr.s_addr = tad_pkt_fltr.remote_ip_addr;
			snprintf(src_addr_buff,ADDR_BUF_SIZE,"%s",inet_ntoa(src_ip_addr));
			snprintf(dest_addr_buff,ADDR_BUF_SIZE,"%s",inet_ntoa(dst_ip_addr));

			snprintf(pkt_buff,PCKT_BUF_SIZE,"%s %s/%d %u-%u to %s/%d %u-%u ","permit out ip from",
					inet_ntoa(src_ip_addr),tad_pkt_fltr.local_ip_mask,tad_pkt_fltr.local_port_low,
					tad_pkt_fltr.local_port_high,dest_addr_buff,tad_pkt_fltr.remote_ip_mask,
					tad_pkt_fltr.remote_port_low,tad_pkt_fltr.remote_port_high);
			memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_content.val,
					pkt_buff,strlen(pkt_buff));
			ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_content.len = strlen(pkt_buff);

		}

		param_list param_lst = {0};
		ret = parse_parameter_list(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &param_lst);
		if(ret!=0)
			return -1;
		pkt_indx += PARAMETER_LIST_LEN;
		total_decoded += PARAMETER_LIST_LEN;

		/*Fill only packet-filter-identifier in packet-filter-information AVP using param list*/
		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_identifier = PRESENT;

		memcpy(ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.val,
				&param_lst.packet_id,1);
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.len = 1;
		idx++;
	}

	if(bearer_rsrc_cmd->flow_qos.header.len != 0)
		fill_qos_avp_bearer_resource_cmd(ccr_request, bearer_rsrc_cmd);

	return 0;
}

int
fill_delete_existing_filter_tft_avp(gx_msg *ccr_request,
									bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer) {

	ccr_request->data.ccr.presence.packet_filter_operation = PRESENT;
	ccr_request->data.ccr.packet_filter_operation = DELETION;
	ccr_request->data.ccr.presence.packet_filter_information = PRESENT;

	uint8_t idx = 0;
	uint8_t pkt_indx = 0;
	uint8_t pkt_flt_cnt = 0;
	rule_report_index_t rule_report = {0};
	int rule_index = -1;
	pkt_flt_cnt = ((bearer_rsrc_cmd->tad.traffic_agg_desc) & NUM_OF_PKT_FLTR_MASK);

	if(pkt_flt_cnt == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Packet filter "
				"is Missing while deleting existing filter TFT AVP \n",LOG_VALUE);
		return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"pkt_flt_cnt rcvd in BRC: %d\n",
			LOG_VALUE, pkt_flt_cnt);

	/*Check UE sends valid packet filter count or not
	 *if valid then store rule index in structure
	 */
	for(int cnt = 0; cnt < pkt_flt_cnt; cnt++ ) {
		delete_pkt_filter pkt_id = {0};
		fill_gx_packet_filter_id(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &pkt_id);
		pkt_indx += 1;
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"pkt flt id : %d\n",
				LOG_VALUE, pkt_id.pkt_filter_id);

		rule_index = check_pckt_fltr_id_in_rule(pkt_id.pkt_filter_id, bearer);
		if(rule_index == -1){
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error : Packet filter "
					"is Missing while deleting existing filter TFT AVP \n",LOG_VALUE);
			return GTPV2C_CAUSE_SYNTACTIC_ERR_IN_TAD_OP;
		}
		store_rule_report_index(rule_index, &rule_report);
	}

	uint8_t total_no_of_pckt_fltr = 0;

		for ( int cnt=0 ; cnt < bearer->num_dynamic_filters ; cnt++ ) {
			total_no_of_pckt_fltr += bearer->dynamic_rules[cnt]->num_flw_desc;
		}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"total_no_of_pckt_fltr : %d\n"
													"&  pkt_flt_cnt in brc : %d\n",
									LOG_VALUE, total_no_of_pckt_fltr, pkt_flt_cnt);

	/* If bearer containt num of packet filter which is equal to
	 * num of packet filter id received in BRC then delete that bearer
	 * else update
	 */
	if(total_no_of_pckt_fltr == pkt_flt_cnt) {
		ccr_request->data.ccr.bearer_operation = TERMINATION;
		ccr_request->data.ccr.presence.charging_rule_report = PRESENT;
		ccr_request->data.ccr.charging_rule_report.count = rule_report.rule_cnt;


		ccr_request->data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
				(sizeof(GxChargingRuleReport)*(rule_report.rule_cnt)), RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(ccr_request->data.ccr.charging_rule_report.list == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					"allocate memory for Charging rule report information avp : %s", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		for(int id = 0; id < rule_report.rule_cnt; id++) {

			ccr_request->data.ccr.charging_rule_report.list[id].presence.charging_rule_name = PRESENT;
			ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.count = 1;
			ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list = rte_malloc_socket(NULL,
					(sizeof(GxChargingRuleNameOctetString)), RTE_CACHE_LINE_SIZE, rte_socket_id());

			if(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
						"allocate memory for Charging rule name avp : %s", LOG_VALUE,
						rte_strerror(rte_errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].len =
				strnlen(bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, RULE_NAME_LEN);

			memcpy(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].val,
					bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, strlen(bearer->dynamic_rules[0]->rule_name));

			ccr_request->data.ccr.charging_rule_report.list[id].presence.pcc_rule_status = PRESENT;
			ccr_request->data.ccr.charging_rule_report.list[id].pcc_rule_status = INACTIVE;

			ccr_request->data.ccr.charging_rule_report.list[id].presence.rule_failure_code = PRESENT;
			ccr_request->data.ccr.charging_rule_report.list[id].rule_failure_code = NO_BEARER_BOUND;
		}


	} else {
		ccr_request->data.ccr.bearer_operation = MODIFICATION;

		ccr_request->data.ccr.presence.charging_rule_report = PRESENT;
		ccr_request->data.ccr.charging_rule_report.count = rule_report.rule_cnt;

		ccr_request->data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
				(sizeof(GxChargingRuleReport)*(rule_report.rule_cnt)), RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(ccr_request->data.ccr.charging_rule_report.list == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					"allocate memory for Charging rule report information avp : %s", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		/*Include Charging-Rule-Report IE for each affected rule*/
		for(int id = 0; id < rule_report.rule_cnt; id++) {

			ccr_request->data.ccr.charging_rule_report.list[id].presence.charging_rule_name = PRESENT;
			ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.count = 1;
			ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list = rte_malloc_socket(NULL,
					(sizeof(GxChargingRuleNameOctetString)*(rule_report.rule_cnt)),
												RTE_CACHE_LINE_SIZE, rte_socket_id());

			if(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
						"allocate memory for Charging rule name avp : %s", LOG_VALUE,
						rte_strerror(rte_errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].len =
				strnlen(bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, RULE_NAME_LEN);

			memcpy(ccr_request->data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].val,
					bearer->dynamic_rules[rule_report.rule_report[id]]->rule_name, strlen(bearer->dynamic_rules[0]->rule_name));

			ccr_request->data.ccr.charging_rule_report.list[id].presence.pcc_rule_status = PRESENT;

			/*If all packet filter in rule is removed then set status to INACTIVE else ACTIVE*/
			if(bearer->dynamic_rules[rule_report.rule_report[id]]->num_flw_desc == rule_report.num_fltr[id]) {
				ccr_request->data.ccr.charging_rule_report.list[id].pcc_rule_status = INACTIVE;
			} else {
				ccr_request->data.ccr.charging_rule_report.list[id].pcc_rule_status = ACTIVE;
			}

			ccr_request->data.ccr.charging_rule_report.list[id].presence.rule_failure_code = PRESENT;
			ccr_request->data.ccr.charging_rule_report.list[id].rule_failure_code = NO_BEARER_BOUND;
		}
	}

	/*no.of packet filter identifier present BRC inside TAD IE*/
	ccr_request->data.ccr.packet_filter_information.count = pkt_flt_cnt;

	ccr_request->data.ccr.packet_filter_information.list = rte_malloc_socket(NULL,
			(sizeof(GxPacketFilterInformation)*pkt_flt_cnt),RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request->data.ccr.packet_filter_information.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Packet filter information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pkt_indx = 0;
	for( idx = 0; idx < pkt_flt_cnt; idx++ ) {

		ccr_request->data.ccr.packet_filter_information.list[idx].presence.packet_filter_identifier = PRESENT;

		delete_pkt_filter pkt_id = {0};
		fill_gx_packet_filter_id(&bearer_rsrc_cmd->tad.pkt_fltr_buf[pkt_indx], &pkt_id);

		pkt_indx += 1;

		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.val[0] = pkt_id.pkt_filter_id;
		ccr_request->data.ccr.packet_filter_information.list[idx].packet_filter_identifier.len = 1;
	}

	if(bearer_rsrc_cmd->flow_qos.header.len != 0)
		fill_qos_avp_bearer_resource_cmd(ccr_request, bearer_rsrc_cmd);

	return 0;
}


int
fill_delete_existing_tft_avp(gx_msg *ccr_request) {

		ccr_request->data.ccr.bearer_operation = TERMINATION;
		ccr_request->data.ccr.presence.packet_filter_operation = PRESENT;
		ccr_request->data.ccr.packet_filter_operation = DELETION;

	return 0;
}

int
parse_parameter_list(uint8_t pkt_fltr_buf[], param_list *param_lst) {

	param_lst->param_id = pkt_fltr_buf[0];
	param_lst->len = pkt_fltr_buf[1];

	if(param_lst->param_id == 0x03) {
		param_lst->packet_id = pkt_fltr_buf[2];
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error : Parameter identifier in"
				"parameter list is not supported \n",LOG_VALUE);
		return -1;
	}

	return 0;
}

int
fill_qos_avp_bearer_resource_cmd(gx_msg *ccr_request, bearer_rsrc_cmd_t *bearer_rsrc_cmd) {

	ccr_request->data.ccr.presence.qos_information = PRESENT;
	ccr_request->data.ccr.qos_information.presence.qos_class_identifier = PRESENT;
	ccr_request->data.ccr.qos_information.presence.guaranteed_bitrate_ul = PRESENT;
	ccr_request->data.ccr.qos_information.presence.guaranteed_bitrate_dl = PRESENT;


	ccr_request->data.ccr.qos_information.qos_class_identifier =
		bearer_rsrc_cmd->flow_qos.qci;
	ccr_request->data.ccr.qos_information.guaranteed_bitrate_ul =
		bearer_rsrc_cmd->flow_qos.guarntd_bit_rate_uplnk;
	ccr_request->data.ccr.qos_information.guaranteed_bitrate_dl =
		bearer_rsrc_cmd->flow_qos.guarntd_bit_rate_dnlnk;
	return 0;
}

int
fill_gx_packet_filter_id(uint8_t *pkt_fltr_buf, delete_pkt_filter *pkt_id) {

	pkt_id->pkt_filter_id = (*pkt_fltr_buf & 0x0f);

	return 0;
}


int
fill_gx_packet_filter_info(uint8_t pkt_fltr_buf[], tad_pkt_fltr_t *tad_pkt_fltr) {

	int index = 0;
	int itr = 0 ;
	uint8_t total_pkt_fltr_len = pkt_fltr_buf[2] + 2;

	for(index = 0; index< total_pkt_fltr_len; index++) {

		if(index == 0) {
			tad_pkt_fltr->pckt_fltr_id = ((pkt_fltr_buf[0]) & 0x0f);
			tad_pkt_fltr->pckt_fltr_dir = ((pkt_fltr_buf[0] >> 4) & 0x03);
			continue;
		}

		if(index == 1) {
			tad_pkt_fltr->precedence = pkt_fltr_buf[1];
			continue;
		}

		if (pkt_fltr_buf[index] == TFT_IPV4_SRC_ADDR_TYPE) {
			memcpy(&tad_pkt_fltr->local_ip_addr,&pkt_fltr_buf[index+1],PKT_FLTR_COMP_TYPE_ID_LEN);
			index = index + PKT_FLTR_COMP_TYPE_ID_LEN + 1;
			for ( itr = index; itr < (index+PKT_FLTR_COMP_TYPE_ID_LEN); itr++) {
				if(pkt_fltr_buf[itr] == 0xff)
					tad_pkt_fltr->local_ip_mask += IP_MASK;
			}
			index = index + NEXT_PKT_FLTR_COMP_INDEX;
			continue;
		}

		if (pkt_fltr_buf[index] == TFT_IPV4_REMOTE_ADDR_TYPE) {
			memcpy(&tad_pkt_fltr->remote_ip_addr,&pkt_fltr_buf[index+1],PKT_FLTR_COMP_TYPE_ID_LEN);
			index = index + PKT_FLTR_COMP_TYPE_ID_LEN + 1;
			for ( itr = index; itr < (index+PKT_FLTR_COMP_TYPE_ID_LEN); itr++) {
				if(pkt_fltr_buf[itr] == 0xff)
					tad_pkt_fltr->remote_ip_mask += IP_MASK;
			}
			index = index + NEXT_PKT_FLTR_COMP_INDEX;
			continue;
		}

		if (pkt_fltr_buf[index] == TFT_PROTO_IDENTIFIER_NEXT_HEADER_TYPE) {
			memcpy(&tad_pkt_fltr->proto_id,&pkt_fltr_buf[index+1],1);
			index = index + 1;
			continue;
		}

		if (pkt_fltr_buf[index] == TFT_DEST_PORT_RANGE_TYPE) {
			memcpy(&tad_pkt_fltr->local_port_low,&pkt_fltr_buf[index+1],PORT_LEN);
			index = index + PORT_LEN;
			memcpy(&tad_pkt_fltr->local_port_high,&pkt_fltr_buf[index+1],PORT_LEN);
			index = index + PORT_LEN;
			tad_pkt_fltr->local_port_low = ntohs(tad_pkt_fltr->local_port_low);
			tad_pkt_fltr->local_port_high = ntohs(tad_pkt_fltr->local_port_high);
			continue;
		}

		if (pkt_fltr_buf[index] == TFT_SRC_PORT_RANGE_TYPE) {
			memcpy(&tad_pkt_fltr->remote_port_low,&pkt_fltr_buf[index+1],PORT_LEN);
			index = index + PORT_LEN;
			memcpy(&tad_pkt_fltr->remote_port_high,&pkt_fltr_buf[index+1],PORT_LEN);
			index = index + PORT_LEN;
			tad_pkt_fltr->remote_port_low = ntohs(tad_pkt_fltr->remote_port_low);
			tad_pkt_fltr->remote_port_high = ntohs(tad_pkt_fltr->remote_port_high);
			continue;
		}

		if(pkt_fltr_buf[index] == TFT_SINGLE_REMOTE_PORT_TYPE) {
			memcpy(&tad_pkt_fltr->remote_port_low,&pkt_fltr_buf[index+1],PORT_LEN);
			memcpy(&tad_pkt_fltr->remote_port_high,&pkt_fltr_buf[index+1],PORT_LEN);
			tad_pkt_fltr->remote_port_low = ntohs(tad_pkt_fltr->remote_port_low);
			tad_pkt_fltr->remote_port_high = ntohs(tad_pkt_fltr->remote_port_high);
			index = index + PORT_LEN;
			continue;
		}

		if(pkt_fltr_buf[index] == TFT_SINGLE_SRC_PORT_TYPE) {
			memcpy(&tad_pkt_fltr->local_port_low,&pkt_fltr_buf[index+1],PORT_LEN);
			memcpy(&tad_pkt_fltr->local_port_high,&pkt_fltr_buf[index+1],PORT_LEN);
			tad_pkt_fltr->local_port_low = ntohs(tad_pkt_fltr->local_port_low);
			tad_pkt_fltr->local_port_high = ntohs(tad_pkt_fltr->local_port_high);
			index = index + PORT_LEN;
			continue;
		}
	}

	return 0;
}
/**
 * @brief  : Generate ccru request
 * @param  : pdn, pdn connection data
 * @param  : bearer, bearer information
 * @param  : flag_check
 * @param  : bearer resource command
 * @return : Returns 0 on success, -1 otherwise
 */
int
gen_ccru_request(ue_context *context, eps_bearer *bearer,
		bearer_rsrc_cmd_t *bearer_rsrc_cmd)
{
	/*
	 * TODO:
	 * Passing bearer as parameter is a BAD IDEA
	 * because what if multiple bearer changes?
	 * code SHOULD anchor only on pdn.
	 */
	/* Initialize the Gx Parameters */

	uint16_t msg_len = 0;
	uint8_t bearer_resource_mod_flow_flag = 0;
	gx_msg ccr_request = {0};
	uint8_t *buffer = NULL;
	gx_context_t *gx_context = NULL;
	pdn_connection *pdn = NULL;

	pdn = bearer->pdn;

	if( pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"PDN not found while generating CCR-UPDATE\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	int ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"ERROR :NO ENTRY FOUND IN Gx HASH [%s]\n",
				LOG_VALUE,pdn->gx_sess_id);

			    return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = UPDATE_REQUEST ;

	if (bearer_rsrc_cmd == NULL) {
		/* Set Credit Control Bearer opertaion type */
		ccr_request.data.ccr.presence.bearer_operation = PRESENT;
		ccr_request.data.ccr.bearer_operation = MODIFICATION;

	} else {
		bearer_resource_mod_flow_flag = 1;
		ret = ccru_req_for_bearer_rsrc_mod(bearer_rsrc_cmd,
											&ccr_request, bearer);
		if( ret!= 0 )
			return ret;
	}

	/* Set bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT;

	if(bearer_resource_mod_flow_flag == 1) {
		if (bearer_rsrc_cmd->eps_bearer_id.ebi_ebi != 0) {
			ccr_request.data.ccr.bearer_identifier.len =
				(1 + (uint32_t)log10(bearer->eps_bearer_id));
		} else {
			ccr_request.data.ccr.bearer_identifier.len =
				(1 + (uint32_t)log10(EBI_ABSENT));
		}
	} else {
		ccr_request.data.ccr.bearer_identifier.len =
			(1 + (uint32_t)log10(bearer->eps_bearer_id));
	}

	if (ccr_request.data.ccr.bearer_identifier.len >= GX_BEARER_IDENTIFIER_LEN) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Insufficient memory to copy bearer identifier\n",
				LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	} else {
		strncpy((char *)ccr_request.data.ccr.bearer_identifier.val,
				(char *)&bearer->eps_bearer_id,
				ccr_request.data.ccr.bearer_identifier.len);
	}

	/* Subscription-Id */
	if(context->imsi  || context->msisdn)
	{
		uint8_t idx = 0;
		ccr_request.data.ccr.presence.subscription_id = PRESENT;
		ccr_request.data.ccr.subscription_id.count = 2; // IMSI & MSISDN
		ccr_request.data.ccr.subscription_id.list  = rte_malloc_socket(NULL,
				(sizeof(GxSubscriptionId)*2),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		/* Fill IMSI */
		if(context->imsi != 0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].
							subscription_id_type = END_USER_IMSI;
			ccr_request.data.ccr.subscription_id.list[idx].
							subscription_id_data.len = pdn->context->imsi_len;
			memcpy(ccr_request.data.ccr.subscription_id.list[idx].subscription_id_data.val,
					&context->imsi,
					context->imsi_len);
			idx++;
		}

		/* Fill MSISDN */
		if(context->msisdn !=0)
		{
			ccr_request.data.ccr.subscription_id.list[idx].
								subscription_id_type = END_USER_E164;
			ccr_request.data.ccr.subscription_id.list[idx].
								subscription_id_data.len =  pdn->context->msisdn_len;

			memcpy(ccr_request.data.ccr.subscription_id.list[idx].
					subscription_id_data.val, &context->msisdn,
				    context->msisdn_len);
		}
	}

	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	int index = 0;
	int len = 0;

	uint8_t evnt_tigger_list[EVENT_TRIGGER_LIST] = {0};

	ccr_request.data.ccr.presence.event_trigger = PRESENT ;
	ccr_request.data.ccr.event_trigger.count = 0 ;

	if(bearer_resource_mod_flow_flag == 1 ) {
		evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = RESOURCE_MODIFICATION_REQUEST;
	}

	if(context->rat_type_flag != FALSE) {

		evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = RAT_EVENT_TRIGGER;
	}
	if(context->uli_flag != FALSE) {

		if((context->event_trigger & (1 << ULI_EVENT_TRIGGER)) != 0) {

			evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = ULI_EVENT_TRIGGER;

		}

		if(context->uli_flag  == ECGI_AND_TAI_PRESENT) {

			if(((context->event_trigger & (1 << TAI_EVENT_TRIGGER)) != 0)
				&& ((context->event_trigger &
						(1 << ECGI_EVENT_TRIGGER)) != 0)) {

				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = ECGI_EVENT_TRIGGER;
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = TAI_EVENT_TRIGGER;

			}

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_ECGI_AND_TAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len =index ;
			len = fill_tai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(context->uli.tai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;
			len  = fill_ecgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[len + 1]),
						&(context->uli.ecgi2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((context->uli_flag & (1<< 0)) == TAI_PRESENT) ) {

			if(((context->event_trigger & (1 << TAI_EVENT_TRIGGER)) != 0)) {
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = TAI_EVENT_TRIGGER;
			}

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_TAI_TYPE;

			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len = fill_tai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
							&(context->uli.tai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((context->uli_flag & (1 << 4)) == ECGI_PRESENT)) {

			if(((context->event_trigger & (1 << ECGI_EVENT_TRIGGER)) != 0)) {
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = ECGI_EVENT_TRIGGER;
			}
			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_ECGI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_ecgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
													&(context->uli.ecgi2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((context->uli_flag & (1 << 2)) == SAI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_SAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_sai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
													&(context->uli.sai2));
			ccr_request.data.ccr.tgpp_user_location_info.len += len;
		} else if (((context->uli_flag & (1 << 3)) == RAI_PRESENT)) {

			if(((pdn->context->event_trigger & (1 << RAI_EVENT_TRIGGER)) != 0)) {
				evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = RAI_EVENT_TRIGGER;
			}
			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_RAI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_rai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(context->uli.rai2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((context->uli_flag & (1 << 1)) == CGI_PRESENT)) {

			ccr_request.data.ccr.presence.tgpp_user_location_info = PRESENT;
			ccr_request.data.ccr.tgpp_user_location_info.val[index++] = GX_CGI_TYPE;
			ccr_request.data.ccr.tgpp_user_location_info.len = index ;
			len  = fill_cgi(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(context->uli.cgi2));

			ccr_request.data.ccr.tgpp_user_location_info.len += len;

		} else if (((context->uli_flag & (1 << 6)) == 1)) {

			len = fill_lai(&(ccr_request.data.ccr.tgpp_user_location_info.val[index]),
						&(context->old_uli.lai2));
		}
		context->uli_flag = FALSE;
	}

	if( context->ue_time_zone_flag != FALSE ) {

		evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] = UE_TIMEZONE_EVT_TRIGGER;
		index = 0;
		ccr_request.data.ccr.presence.tgpp_ms_timezone = PRESENT;
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = ((context->tz.tz) & 0xff);
		ccr_request.data.ccr.tgpp_ms_timezone.val[index++] = ((context->tz.dst) & 0xff);
		ccr_request.data.ccr.tgpp_ms_timezone.len = index;
	}

	context->ue_time_zone_flag =  FALSE;
	ccr_request.data.ccr.event_trigger.list = (int32_t *)malloc(ccr_request.data.ccr.
												event_trigger.count * sizeof(int32_t));

	for(uint8_t count = 0; count < ccr_request.data.ccr.event_trigger.count; count++ ) {
		*(ccr_request.data.ccr.event_trigger.list + count) = evnt_tigger_list[count];
	}

	int ebi_index =  GET_EBI_INDEX(bearer->eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	/* Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, context,
				ebi_index, pdn->gx_sess_id, bearer_resource_mod_flow_flag) != 0) {

		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed CCR request filling process\n", LOG_VALUE);
		return -1;
	}

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton(CLI_GX_IP, &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_UPDATE, SENT, GX);


	/* Update UE State */
	pdn->state = CCRU_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = CCRU_SNT_STATE;
	gx_context->proc = pdn->proc;

	/* Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	ccr_request.msg_len = msg_len + GX_HEADER_LEN;

	buffer = rte_zmalloc_socket(NULL, msg_len + GX_HEADER_LEN,
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failure to allocate CCR Buffer memory"
				"structure: %s \n",LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
	memcpy(buffer + sizeof(ccr_request.msg_type),
					&ccr_request.msg_len,
					sizeof(ccr_request.msg_len));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + GX_HEADER_LEN), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR in Packing CCR "
			"Buffer\n", LOG_VALUE);
		rte_free(buffer);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + GX_HEADER_LEN);
	rte_free(buffer);
	if(ccr_request.data.ccr.event_trigger.list != NULL)
		free(ccr_request.data.ccr.event_trigger.list);
	free_dynamically_alloc_memory(&ccr_request);

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
	/* Initialize the Gx Parameters */
	int ret = 0;
	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN Gx "
			"HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
	return -1;
	}
	/* Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = UPDATE_REQUEST ;

	/* Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = TERMINATION;

	uint8_t indx_bearer = bearer->eps_bearer_id;
	/* Set bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT;
	ccr_request.data.ccr.bearer_identifier.len =
		(1 + (uint32_t)log10(indx_bearer));

	if (ccr_request.data.ccr.bearer_identifier.len >= GX_BEARER_IDENTIFIER_LEN) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Insufficient memory to copy bearer identifier\n", LOG_VALUE);
		return -1;
	} else {
		strncpy((char *)ccr_request.data.ccr.bearer_identifier.val,
				(char *)&indx_bearer,
				ccr_request.data.ccr.bearer_identifier.len);
	}
	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	int idx = 0;
	ccr_request.data.ccr.presence.charging_rule_report = PRESENT;
	ccr_request.data.ccr.charging_rule_report.count = 1;
	ccr_request.data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleReportList)*1),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (ccr_request.data.ccr.charging_rule_report.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
			"Failure to allocate charging rule report list memory\n",
			LOG_VALUE);
		return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
	}

	ccr_request.data.ccr.charging_rule_report.list[idx].presence.charging_rule_name = PRESENT;
	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleNameOctetString)*1),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (ccr_request.data.ccr.charging_rule_report.list[idx]
		.charging_rule_name.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
			"Failure to allocate charging rule report"
			" list memory\n", LOG_VALUE);
		return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
	}

	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.count = 1;
	ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list[idx].len = strnlen(bearer->dynamic_rules[idx]->rule_name,RULE_NAME_LEN);

	for(uint16_t i = 0 ; i<strnlen(bearer->dynamic_rules[idx]->rule_name,RULE_NAME_LEN); i++){
		ccr_request.data.ccr.charging_rule_report.list[idx].charging_rule_name.list[idx].val[i] =
			bearer->dynamic_rules[idx]->rule_name[i];
	}

	ccr_request.data.ccr.charging_rule_report.list[idx].presence.pcc_rule_status = PRESENT;
	ccr_request.data.ccr.charging_rule_report.list[idx].pcc_rule_status = INACTIVE;

	ccr_request.data.ccr.charging_rule_report.list[idx].presence.rule_failure_code = PRESENT;
	ccr_request.data.ccr.charging_rule_report.list[idx].rule_failure_code = NO_BEARER_BOUND;

	char *temp = inet_ntoa(pdn->ipv4);
	memcpy(ccr_request.data.ccr.framed_ip_address.val, &temp, strnlen(temp,(GX_FRAMED_IP_ADDRESS_LEN + 1)));

	int ebi_index = GET_EBI_INDEX(bearer->eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	/* Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, pdn->context,
						ebi_index,pdn->gx_sess_id, 0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in CCR request "
			"filling process\n", LOG_VALUE);
		return -1;
	}

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton(CLI_GX_IP, &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_UPDATE, SENT, GX);


	/* Update UE State */
	pdn->state = CCRU_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = CCRU_SNT_STATE;
	gx_context->proc = pdn->proc;
	/* Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	ccr_request.msg_len = msg_len + GX_HEADER_LEN;

	buffer = rte_zmalloc_socket(NULL, msg_len + GX_HEADER_LEN,
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to allocate "
				"CCR-TERMINATION Buffer memory structure: %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
		return -1;
	}

	/* Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
	memcpy(buffer + sizeof(ccr_request.msg_type),
							&ccr_request.msg_len,
					sizeof(ccr_request.msg_len));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + GX_HEADER_LEN), msg_len) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in Packing "
			"CCR-TERMINATION Buffer\n", LOG_VALUE);
		rte_free(buffer);
		return -1;

	}

	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + GX_HEADER_LEN);
	rte_free(buffer);

	if(ccr_request.data.ccr.charging_rule_report.list[idx]
			.charging_rule_name.list != NULL) {
		rte_free(ccr_request.data.ccr.charging_rule_report.list[idx]
				.charging_rule_name.list);
		ccr_request.data.ccr.charging_rule_report.list[idx]
			.charging_rule_name.list = NULL;
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
			"charging rule name list memory is successfully free\n",
			LOG_VALUE);
	}

	if (ccr_request.data.ccr.charging_rule_report.list != NULL) {
		rte_free(ccr_request.data.ccr.charging_rule_report.list);
		ccr_request.data.ccr.charging_rule_report.list = NULL;
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
			"charging rule report list memory is successfully free\n",
			LOG_VALUE);
	}

	if (ccr_request.data.ccr.subscription_id.list != NULL) {
		free(ccr_request.data.ccr.subscription_id.list);
		ccr_request.data.ccr.subscription_id.list = NULL;
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
				"subscription id list is successfully free\n", LOG_VALUE);
	}

	store_rule_status_for_del_bearer_cmd(&pro_ack_rule_array, bearer);

	return 0;
}

int
store_rule_status_for_del_bearer_cmd(pro_ack_rule_array_t *pro_ack_rule_array,
										eps_bearer *bearer) {
	if(bearer == NULL) {
		return -1;
	}
	for(int cnt=0; cnt< bearer->num_dynamic_filters; cnt++) {
		if( bearer->dynamic_rules[cnt] != NULL) {
			strncpy(pro_ack_rule_array->rule[cnt].rule_name,
					bearer->dynamic_rules[cnt]->rule_name,
					strlen(bearer->dynamic_rules[cnt]->rule_name));
			pro_ack_rule_array->rule[cnt].rule_status = INACTIVE;
			pro_ack_rule_array->rule_cnt++;
		}
	}
	return 0;
}

void
fill_rule_and_qos_inform_in_pdn(pdn_connection *pdn)
{
	dynamic_rule_t *dynamic_rule = dynamic_rule = &pdn->policy.pcc_rule[0].dyn_rule;
	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return;
	}

	eps_bearer *bearer = pdn->eps_bearers[ebi_index];

	pdn->policy.default_bearer_qos_valid = TRUE;
	bearer_qos_ie *def_qos = &pdn->policy.default_bearer_qos;

	pdn->policy.num_charg_rule_install = DEFAULT_RULE_COUNT;
	def_qos->qci = QCI_VALUE;
	def_qos->arp.priority_level = GX_PRIORITY_LEVEL;
	def_qos->arp.preemption_capability = PREEMPTION_CAPABILITY_DISABLED;
	def_qos->arp.preemption_vulnerability = PREEMPTION_VALNERABILITY_ENABLED;

	bearer->qos.qci = QCI_VALUE;
	bearer->qos.arp.priority_level = GX_PRIORITY_LEVEL;
	bearer->qos.arp.preemption_capability = PREEMPTION_CAPABILITY_DISABLED;
	bearer->qos.arp.preemption_vulnerability = PREEMPTION_VALNERABILITY_ENABLED;

	memset(dynamic_rule->rule_name, '\0', sizeof(dynamic_rule->rule_name));
	strncpy(dynamic_rule->rule_name, RULE_NAME, RULE_LENGTH );

	dynamic_rule->online = ENABLE_ONLINE;
	dynamic_rule->offline = DISABLE_OFFLINE;
	dynamic_rule->flow_status = GX_ENABLE;
	dynamic_rule->precedence = PRECEDENCE;
	dynamic_rule->service_id = SERVICE_INDENTIFIRE;
	dynamic_rule->rating_group = RATING_GROUP;
	dynamic_rule->num_flw_desc = GX_FLOW_COUNT;

	for(uint8_t idx = 0; idx < GX_FLOW_COUNT; idx++) {
		dynamic_rule->flow_desc[idx].flow_direction = BIDIRECTIONAL;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.proto_id = PROTO_ID;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.local_ip_mask = LOCAL_IP_MASK;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.local_ip_addr.s_addr = LOCAL_IP_ADDR;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.local_port_low = PORT_LOW;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.local_port_high = PORT_HIGH;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.remote_ip_mask = REMOTE_IP_MASK;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.remote_ip_addr.s_addr = REMOTE_IP_ADDR;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.remote_port_low = PORT_LOW;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.remote_port_high = PORT_HIGH;
		dynamic_rule->flow_desc[idx].sdf_flw_desc.direction = TFT_DIRECTION_BIDIRECTIONAL;
	}

	dynamic_rule->qos.qci = QCI_VALUE;
	dynamic_rule->qos.arp.priority_level = GX_PRIORITY_LEVEL;
	dynamic_rule->qos.arp.preemption_capability = PREEMPTION_CAPABILITY_DISABLED;
	dynamic_rule->qos.arp.preemption_vulnerability = PREEMPTION_VALNERABILITY_ENABLED;
	dynamic_rule->qos.ul_mbr =  REQUESTED_BANDWIDTH_UL;
	dynamic_rule->qos.dl_mbr =  REQUESTED_BANDWIDTH_DL;
	dynamic_rule->qos.ul_gbr =  GURATEED_BITRATE_UL;
	dynamic_rule->qos.dl_gbr =  GURATEED_BITRATE_DL;

}

int
process_create_sess_req(create_sess_req_t *csr,
		ue_context **_context, struct in_addr *upf_ipv4,
		uint8_t cp_type)
{
	int ret = 0;
	struct in_addr ue_ip = {0};
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	int ebi_index = 0;
	uint8_t check_if_ue_hash_exist = 0;
	uint64_t imsi = UINT64_MAX;
	imsi_id_hash_t *imsi_id_config = NULL;

	apn *apn_requested = get_apn((char *)csr->apn.apn, csr->apn.header.len);

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	/* Checking Received CSR is for context replcement or not */
	ret = gtpc_context_replace_check(csr, cp_type, apn_requested);
	if (ret != 0) {

		if (ret == GTPC_CONTEXT_REPLACEMENT) {

			return GTPC_CONTEXT_REPLACEMENT;
		}

		if (ret != -1){

			memcpy(&imsi, &csr->imsi.imsi_number_digits, csr->imsi.header.len);
			rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi, (void **) &context);

			if(context != NULL ) {
				*_context = context;
			}

			return ret;
		}

		return ret;
	}

	if(csr->mapped_ue_usage_type.header.len > 0) {
		apn_requested->apn_usage_type = csr->mapped_ue_usage_type.mapped_ue_usage_type;
	}

	/* In the case of Promotion get the exsiting session info */
	if ((cp_type == SAEGWC) &&
			(csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key != 0)) {
		if (csr->indctn_flgs.indication_oi) {
			rte_hash_lookup_data(ue_context_by_fteid_hash,
					&csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key,
					(void **)&context);

			if (context != NULL) {
				/* Parse handover CSR and Fill the PFCP Session Modification Request */
				if (promotion_parse_cs_req(csr, context, cp_type) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to parse CSR in promotion case\n",
							LOG_VALUE);
					return -1;
				}
				context->promotion_flag = TRUE;
				*_context = context;
				return 0;
			}
		}
	}

	for(uint8_t i = 0; i< csr->bearer_count ; i++) {

		if (!csr->bearer_contexts_to_be_created[i].header.len) {
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		ebi_index = GET_EBI_INDEX(csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n",
				LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (cp_type != SGWC) {
			ret = acquire_ip(&ue_ip);
			if (ret)
				return ret;
		}

		/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
		ret = create_ue_context(&csr->imsi.imsi_number_digits, csr->imsi.header.len,
				csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi, &context, apn_requested,
				CSR_SEQUENCE(csr), &check_if_ue_hash_exist, cp_type);
		if (ret)
			return ret;

		*_context = context;

		if (cp_type != 0) {
			context->cp_mode = cp_type;
		}else {
			return -1;
		}

		/* Retrive procedure of CSR */
		pdn = GET_PDN(context, ebi_index);
		if (pdn == NULL){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
				"get pdn for ebi_index %d \n", LOG_VALUE, ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		bearer = context->eps_bearers[ebi_index];

		if (csr->linked_eps_bearer_id.ebi_ebi) {
			pdn->default_bearer_id = csr->linked_eps_bearer_id.ebi_ebi;
		}

		if (pdn->default_bearer_id == csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi) {

			if(fill_context_info(csr, context, pdn) != 0)
				return -1;

			pdn->proc = get_csr_proc(csr);

			/* Store upf ipv4 in pdn structure */
			pdn->upf_ipv4 = *upf_ipv4;
			if (context->cp_mode != SGWC)
				pdn->ipv4.s_addr = ntohl(ue_ip.s_addr);

			if (fill_pdn_info(csr, pdn, context, bearer) != 0)
				return -1;

		} /*Check UE Exist*/

		/* To minimize lookup of hash for LI */
		if ((NULL == imsi_id_config) && (NULL != context)) {

			if (NULL == imsi_id_config) {

				/* Get User Level Packet Copying Token or Id Using Imsi */
				ret = get_id_using_imsi(context->imsi, &imsi_id_config);
				if (ret < 0) {

					clLog(clSystemLog, eCLSeverityDebug, "[%s]:[%s]:[%d] Not applicable for li\n",
							__file__, __func__, __LINE__);
				}
			}

			if (NULL != imsi_id_config) {

				/* Fillup context from li hash */
				fill_li_config_in_context(context, imsi_id_config);
			}
		}

		if (fill_bearer_info(csr, bearer, context, pdn, i) != 0)
			return -1;

		pdn->context = context;

	} /*for loop*/

	if ((context->cp_mode == PGWC) || (context->cp_mode == SAEGWC)) {

		if (pfcp_config.use_gx) {
			ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n",
					LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			if ((ret = gen_ccr_request(context, ebi_index, csr)) != 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
						"generate CCR-INITIAL requset : %s\n", LOG_VALUE, strerror(errno));
				return ret;
			}
		} else {
			fill_rule_and_qos_inform_in_pdn(pdn);
		}
	}

#ifdef USE_CSID
	/* Parse and stored MME and SGW FQ-CSID in the context */
	fqcsid_t *tmp = NULL;

	/* Allocate the memory for each session */
	if (context != NULL) {
		context->mme_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		context->sgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		context->pgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if ((context->mme_fqcsid == NULL) || (context->sgw_fqcsid == NULL)
				|| (context->pgw_fqcsid == NULL)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate the "
					"memory for fqcsids entry\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Context not found "
				"while processing Create Session Request \n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* MME FQ-CSID */
	if (csr->mme_fqcsid.header.len) {
		/* Remove Exsiting MME CSID linked with session */
		if ((context->mme_fqcsid)->num_csid) {
			memset(context->mme_fqcsid, 0, sizeof(fqcsid_t));
		}
		ret = add_fqcsid_entry(&csr->mme_fqcsid, context->mme_fqcsid);
		if(ret)
			return ret;

	} else {
		/* Stored the MME CSID by MME Node address */
		tmp = get_peer_addr_csids_entry(context->s11_mme_gtpc_ipv4.s_addr,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
					"Add the MME CSID by MME Node address, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = context->s11_mme_gtpc_ipv4.s_addr;
		(context->mme_fqcsid)->node_addr = context->s11_mme_gtpc_ipv4.s_addr;
	}

	/* SGW FQ-CSID -- PGWC */
	if (csr->sgw_fqcsid.header.len) {
		/* Remove Exsiting SGW CSID linked with session */
		if ((context->sgw_fqcsid)->num_csid) {
			memset(context->sgw_fqcsid, 0, sizeof(fqcsid_t));
		}
		/* Stored the SGW CSID by SGW Node address */
		ret = add_fqcsid_entry(&csr->sgw_fqcsid, context->sgw_fqcsid);
		if(ret)
			return ret;

	} else {
		if ((context->cp_mode == SGWC) || (context->cp_mode == SAEGWC)) {
			tmp = get_peer_addr_csids_entry(context->s11_sgw_gtpc_ipv4.s_addr,
					ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed "
						"to Add the SGW CSID by SGW Node address, Error : %s \n", LOG_VALUE,
						strerror(errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			tmp->node_addr = context->s11_sgw_gtpc_ipv4.s_addr;
			(context->sgw_fqcsid)->node_addr = context->s11_sgw_gtpc_ipv4.s_addr;
		}
	}

	/* PGW FQ-CSID */
	if (context->cp_mode == PGWC) {
		tmp = get_peer_addr_csids_entry(pdn->s5s8_pgw_gtpc_ipv4.s_addr,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
					"Add the PGW CSID by PGW Node address, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		(context->pgw_fqcsid)->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	}
#endif /* USE_CSID */

	/* Store the context of ue in pdn */

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
	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if(context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Context not found "
			"while processing PFCP Session Establishment Request \n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	sequence = get_pfcp_sequence_number(PFCP_SESSION_ESTABLISHMENT_REQUEST, sequence);

	for(uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = pdn->eps_bearers[i];
		if(bearer == NULL)
			continue;

		if (context->cp_mode == SGWC) {
			/*Generating TEID for S1U interface*/
			bearer->s1u_sgw_gtpu_teid = get_s1u_sgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
												context->cp_mode, &upf_teid_info_head);
			update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid,
							upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);

			/* Generating TEID for SGW S5S8 interface */
			bearer->s5s8_sgw_gtpu_teid = get_s5s8_sgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
													context->cp_mode, &upf_teid_info_head);
			update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid,
							upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);

			bearer->s5s8_sgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_sgwu_ip;
			bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		} else if (context->cp_mode == SAEGWC) {
			/*Generating TEID for S1U interface*/
			bearer->s1u_sgw_gtpu_teid = get_s1u_sgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
													context->cp_mode, &upf_teid_info_head);
			update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid,
							upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);

			bearer->s5s8_sgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_sgwu_ip;
			bearer->s1u_sgw_gtpu_ipv4.s_addr  = upf_ctx->s1u_ip;
			bearer->s5s8_pgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_pgwu_ip;
			bearer->s5s8_pgw_gtpu_teid =  bearer->s1u_sgw_gtpu_teid;

		} else {
			/* Generating TEID for PGW S5S8 interface */
			bearer->s5s8_pgw_gtpu_teid = get_s5s8_pgw_gtpu_teid(bearer->pdn->upf_ipv4.s_addr,
													context->cp_mode, &upf_teid_info_head);
			update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid,
						upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);

			/* Update the PGWU IP address */
			bearer->s5s8_pgw_gtpu_ipv4.s_addr =
				upf_ctx->s5s8_pgwu_ip;
			/* Filling PDN structure*/
			pfcp_sess_est_req.pdn_type.header.type = PFCP_IE_PDN_TYPE;
			pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
			pfcp_sess_est_req.pdn_type.pdn_type_spare = 0;
			pfcp_sess_est_req.pdn_type.pdn_type =  1;
		}
		if(!pdn->policy.pcc_rule[pdn->policy.count].predefined_rule){
			if (context->cp_mode != SGWC){
				for(uint8_t itr=bearer->qer_count; itr < bearer->qer_count + NUMBER_OF_QER_PER_RULE;
					itr++){

					bearer->qer_id[itr].qer_id = generate_qer_id();
					fill_qer_entry(pdn, bearer,itr);
				}
				bearer->qer_count += NUMBER_OF_QER_PER_RULE;

				for(uint8_t itr=0; itr < bearer->pdr_count; itr++){
					bearer->pdrs[itr]->qer_id[0].qer_id = bearer->qer_id[itr].qer_id;
				}
			}

		}
	}
	fill_pfcp_sess_est_req(&pfcp_sess_est_req, pdn, sequence, context);

#ifdef USE_CSID

	/*Pointing bearer t the default bearer*/
	bearer = pdn->eps_bearers[ebi_index];
	if(bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Bearer not "
			"found for EBI ID : %d\n",LOG_VALUE, pdn->default_bearer_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Get the copy of existing SGW CSID */
	fqcsid_t tmp_csid_t = {0};
	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {
			memcpy(&tmp_csid_t, context->sgw_fqcsid, sizeof(fqcsid_t));
		}
	}
	/* Add the entry for peer nodes */
	if (fill_peer_node_info(pdn, bearer)) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill peer node info and assignment of the "
				"CSID Error: %s\n", LOG_VALUE, strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if (context->cp_mode != PGWC) {
		uint8_t tmp_csid = 0;
		/* Validate the exsiting CSID or allocated new one */
		for (uint8_t inx1 = 0; inx1 < tmp_csid_t.num_csid; inx1++) {
			if ((context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1] ==
					tmp_csid_t.local_csid[inx1]) {
				tmp_csid = tmp_csid_t.local_csid[inx1];
				break;
			}
		}

		if (!tmp_csid) {
			for (uint8_t inx = 0; inx <tmp_csid_t.num_csid; inx++) {
				/* Remove the session link from old CSID */
				sess_csid *tmp1 = NULL;
				tmp1 = get_sess_csid_entry(tmp_csid_t.local_csid[inx], REMOVE_NODE);

				if (tmp1 != NULL) {
					/* Remove node from csid linked list */
					tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

					int8_t ret = 0;
					/* Update CSID Entry in table */
					ret = rte_hash_add_key_data(seids_by_csid_hash,
									&tmp_csid_t.local_csid[inx], tmp1);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
								"\n\tError= %s\n",
								LOG_VALUE, tmp_csid_t.local_csid[inx],
								rte_strerror(abs(ret)));
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}
					if (tmp1 == NULL) {
						/* Removing temporary local CSID associated with MME */
						remove_peer_temp_csid(context->mme_fqcsid, tmp_csid_t.local_csid[inx],
								S11_SGW_PORT_ID);

						/* Removing temporary local CSID assocoated with PGWC */
						remove_peer_temp_csid(context->pgw_fqcsid, tmp_csid_t.local_csid[inx],
								S5S8_SGWC_PORT_ID);
					}
					/* Delete CSID from the context */
					for (uint8_t itr1 = 0; itr1 < (context->sgw_fqcsid)->num_csid; itr1++) {
						if ((context->sgw_fqcsid)->local_csid[itr1] == tmp_csid_t.local_csid[inx]) {
							for(uint8_t pos = itr1; pos < ((context->sgw_fqcsid)->num_csid - 1); pos++ ) {
								(context->sgw_fqcsid)->local_csid[pos] = (context->sgw_fqcsid)->local_csid[pos + 1];
							}
							(context->sgw_fqcsid)->num_csid--;
						}
					}
				} else {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to "
							"get Session ID entry for CSID:%u\n", LOG_VALUE,
							tmp_csid_t.local_csid[inx]);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}

				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Remove session link from Old CSID:%u\n",
						LOG_VALUE, tmp_csid_t.local_csid[inx]);
			}
		}
	}

	/* Add entry for cp session id with link local csid */
	sess_csid *tmp = NULL;
	if ((context->cp_mode == SGWC) || (context->cp_mode == SAEGWC)) {
		tmp = get_sess_csid_entry(
				(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1], ADD_NODE);
	} else {
		/* PGWC */
		tmp = get_sess_csid_entry(
				(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1], ADD_NODE);
	}

	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get CSID "
			"entry, Error: %s \n", LOG_VALUE,strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Link local csid with session id */
	/* Check head node created ot not */
	if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
		sess_csid *new_node = NULL;
		/* Add new node into csid linked list */
		new_node = add_sess_csid_data_node(tmp);
		if(new_node == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to ADD new "
				"node into CSID linked list : %s\n", LOG_VALUE);
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
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to fill FQ-CSID "
			"in Session Establishment Request, Error: %s\n", LOG_VALUE,
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

	resp->linked_eps_bearer_id = pdn->default_bearer_id;
	resp->msg_type = GTP_CREATE_SESSION_REQ;
	resp->state = PFCP_SESS_EST_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	resp->cp_mode = context->cp_mode;

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in sending "
			" PFCP Session Establishment Request, Error : %i\n", LOG_VALUE, errno);
		return -1;
	} else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	if (add_sess_entry(pdn->seid, resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add response "
			"structure entry in SM_HASH\n", LOG_VALUE);
		return -1;
	}
	return 0;
}

int8_t
process_pfcp_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp,
		gtpv2c_header_t *gtpv2c_tx, uint8_t is_piggybacked)
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
	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"while PFCP Session Establishment Response for "
			"session ID:%lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"Context for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	//*cp_type = context->cp_mode;

	/*TODO need to think on eps_bearer_id*/
	int ebi_index = GET_EBI_INDEX(resp->linked_eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn for "
			"ebi_index %d \n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	bearer = context->eps_bearers[ebi_index];

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	fqcsid_t *fqcsid = NULL;
	fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate the "
			"memory for fqcsids entry\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* UP FQ-CSID */
	if (pfcp_sess_est_rsp->up_fqcsid.header.len) {
		if (pfcp_sess_est_rsp->up_fqcsid.number_of_csids) {
			/* Stored the UP CSID by UP Node address */
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->up_fqcsid.node_address,
					ADD_NODE);

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Add the "
					"SGW-U CSID by SGW Node address, Error : %s \n",
					LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			tmp->node_addr = pfcp_sess_est_rsp->up_fqcsid.node_address;

			for(uint8_t itr = 0; itr < pfcp_sess_est_rsp->up_fqcsid.number_of_csids; itr++) {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] == pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[itr]) {
						match = 1;
						break;
					}
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[itr];
				}
			}

			for(uint8_t itr1 = 0; itr1 < pfcp_sess_est_rsp->up_fqcsid.number_of_csids; itr1++) {
					fqcsid->local_csid[fqcsid->num_csid++] =
						pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[itr1];
			}
			fqcsid->node_addr = pfcp_sess_est_rsp->up_fqcsid.node_address;
		}
	} else {
		tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->up_fseid.ipv4_address,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
				"the SGW-U CSID by SGW Node address, Error : %s \n",
				LOG_VALUE, strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = pfcp_sess_est_rsp->up_fseid.ipv4_address;
		fqcsid->node_addr = pfcp_sess_est_rsp->up_fseid.ipv4_address;
	}

	if (((context->sgw_fqcsid)->num_csid) || ((context->pgw_fqcsid)->num_csid)) {
		/* TODO: Add the handling if SGW or PGW not support Partial failure */
		/* Link peer node SGW or PGW csid with local csid */
		if ((context->cp_mode == SGWC) || (context->cp_mode == SAEGWC)) {
			ret = update_peer_csid_link(fqcsid, context->sgw_fqcsid);
		} else if (context->cp_mode == PGWC) {
			ret = update_peer_csid_link(fqcsid, context->pgw_fqcsid);
		}

		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Update and "
				"Link Peer node CSID with local CSID, Error : %s \n", LOG_VALUE,
				strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		/* Update entry for up session id with link local csid */
		sess_csid *sess_t = NULL;
		sess_csid *sess_tmp = NULL;
		if ((context->cp_mode == SGWC) || (context->cp_mode == SAEGWC)) {
			if (context->sgw_fqcsid) {
				sess_t = get_sess_csid_entry(
						(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1],
						UPDATE_NODE);
			}
		} else {
			/* PGWC */
			if (context->pgw_fqcsid) {
				sess_t = get_sess_csid_entry(
						(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1],
						UPDATE_NODE);
			}
		}

		if (sess_t == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get CSID "
				"entry, Error: %s \n", LOG_VALUE, strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		/* Link local csid with session id */
		sess_tmp = get_sess_csid_data_node(sess_t, pdn->seid);
		if(sess_tmp == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get node "
				"data for SEID: %x\n", LOG_VALUE, pdn->seid);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		/* Update up SEID in CSID linked list node */
		sess_tmp->up_seid = dp_sess_id;
	}

	/* Update the UP CSID in the context */
	context->up_fqcsid = fqcsid;

#endif /* USE_CSID */

	pdn->dp_seid = dp_sess_id;

	/* Update the UE state */
	pdn->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	if (context->cp_mode == SAEGWC || context->cp_mode == PGWC) {
		msg_len = set_create_session_response(gtpv2c_tx, context->sequence,
										context, pdn, is_piggybacked);
		if(is_piggybacked) {
			gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + msg_len);
			set_create_bearer_request(gtpv2c_cbr_t, context->sequence, pdn,
					pdn->default_bearer_id, 0, resp, is_piggybacked, FALSE);

			resp->state = CREATE_BER_REQ_SNT_STATE;
			pdn->state = CREATE_BER_REQ_SNT_STATE;
		}

		if (context->cp_mode == SAEGWC) {
			s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;
		}

		if (context->cp_mode == PGWC) {
			s5s8_recv_sockaddr.sin_addr.s_addr = pdn->s5s8_sgw_gtpc_ipv4.s_addr;
		}

		pdn->csr_sequence =0;

	} else if (context->cp_mode == SGWC) {
		uint16_t msg_len = 0;
		upf_context_t *upf_context = NULL;

		ret = rte_hash_lookup_data(upf_context_by_ip_hash,
				(const void*) &((context->pdns[ebi_index])->upf_ipv4.s_addr),
				(void **) &(upf_context));

		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NO ENTRY FOUND IN UPF "
				"HASH [%u]\n", LOG_VALUE, (context->pdns[ebi_index])->upf_ipv4.s_addr);
			return GTPV2C_CAUSE_INVALID_PEER;
		}

		ret = add_bearer_entry_by_sgw_s5s8_tied(pdn->s5s8_sgw_gtpc_teid, &bearer);
		if(ret) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to add bearer entry by sgw_s5s8_teid\n", LOG_VALUE);
			return ret;
		}

		if(context->indication_flag.oi == 1) {

			memset(gtpv2c_tx, 0, MAX_GTPV2C_UDP_LEN);
			set_modify_bearer_request(gtpv2c_tx, pdn, bearer);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				pdn->s5s8_pgw_gtpc_ipv4.s_addr;

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
				cs_req.sgw_fqcsid.node_address = pfcp_config.s5s8_ip.s_addr;
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
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "Failed to fill Create "
				"Session Request \n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		msg_len = encode_create_sess_req(
				&cs_req,
				(uint8_t*)gtpv2c_tx);

		msg_len = msg_len - IE_HEADER_SIZE;
		gtpv2c_header_t *header;
		header = (gtpv2c_header_t*) gtpv2c_tx;
		header->gtpc.message_len = htons(msg_len);

		if (ret < 0)
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to generate "
				"S5S8 SGWC Create Session Request.\n", LOG_VALUE);

		s5s8_recv_sockaddr.sin_addr.s_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;

		/* Update the session state */
		resp->state = CS_REQ_SNT_STATE;
		/* stored teid in csr header for clean up */
		resp->gtpc_msg.csr.header.teid.has_teid.teid = pdn->s5s8_sgw_gtpc_teid;

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

static int8_t
gtpc_recvd_sgw_fqcsid(gtp_fqcsid_ie_t *sgw_fqcsid,
		pdn_connection *pdn, eps_bearer *bearer, ue_context *context)
{
	int ret = 0;
	uint8_t pgw_tmp_csid = 0;
	/* Get the copy of existing SGW CSID */
	fqcsid_t sgw_tmp_csid_t = {0};
	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {
			memcpy(&sgw_tmp_csid_t, context->sgw_fqcsid, sizeof(fqcsid_t));
		}
	}

	uint8_t tmp_csid = 0;
	/* Validate the exsiting CSID */
	for (uint8_t inx = 0; inx < sgw_fqcsid->number_of_csids; inx++) {
		for (uint8_t inx1 = 0; inx1 < sgw_tmp_csid_t.num_csid; inx1++) {
			if (sgw_fqcsid->pdn_csid[inx] == sgw_tmp_csid_t.local_csid[inx1]) {
				tmp_csid = sgw_tmp_csid_t.local_csid[inx1];
				break;
			}
		}
	}

	if (!tmp_csid) {
		/* Get the copy of existing PGW CSID */
		fqcsid_t pgw_tmp_csid_t = {0};
		if (context->pgw_fqcsid != NULL) {
			if ((context->pgw_fqcsid)->num_csid) {
				memcpy(&pgw_tmp_csid_t, context->pgw_fqcsid, sizeof(fqcsid_t));
			}
		}

		/* Remove Exsiting SGW CSID associted with Session */
		memset(context->sgw_fqcsid, 0, sizeof(fqcsid_t));

		/* SGW FQ-CSID */
		/* Stored the SGW CSID by SGW Node address */
		ret = add_fqcsid_entry(sgw_fqcsid, context->sgw_fqcsid);
		if(ret)
			return ret;

		/* Update the entry for peer nodes */
		if (fill_peer_node_info(pdn, bearer)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill peer node info and assignment of the "
				"CSID Error: %s\n", LOG_VALUE, strerror(errno));
			return  GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (pdn->context->flag_fqcsid_modified == TRUE) {
			/* Validate the exsiting CSID or allocated new one */
			for (uint8_t inx1 = 0; inx1 < pgw_tmp_csid_t.num_csid; inx1++) {
				if ((context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1] ==
						pgw_tmp_csid_t.local_csid[inx1]) {
					pgw_tmp_csid = pgw_tmp_csid_t.local_csid[inx1];
					break;
				}
			}

			if (!pgw_tmp_csid) {
				for (uint8_t inx = 0; inx < pgw_tmp_csid_t.num_csid; inx++) {
					/* Remove the session link from old CSID */
					sess_csid *tmp1 = NULL;
					tmp1 = get_sess_csid_entry(pgw_tmp_csid_t.local_csid[inx], REMOVE_NODE);

					if (tmp1 != NULL) {
						/* Remove node from csid linked list */
						tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

						int8_t ret = 0;
						/* Update CSID Entry in table */
						ret = rte_hash_add_key_data(seids_by_csid_hash,
										&pgw_tmp_csid_t.local_csid[inx], tmp1);
						if (ret) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
									"\n\tError= %s\n",
									LOG_VALUE, pgw_tmp_csid_t.local_csid[inx],
									rte_strerror(abs(ret)));
							return GTPV2C_CAUSE_SYSTEM_FAILURE;
						}

						if (tmp1 == NULL) {
							/* Removing temporary local CSID associated with MME */
							remove_peer_temp_csid(context->mme_fqcsid, pgw_tmp_csid_t.local_csid[inx],
									S5S8_PGWC_PORT_ID);

							/* Removing temporary local CSID assocoated with SGWC */
							remove_peer_temp_csid(context->sgw_fqcsid, pgw_tmp_csid_t.local_csid[inx],
									S5S8_PGWC_PORT_ID);
						}
						/* Delete CSID from the context */
						for (uint8_t itr1 = 0; itr1 < (context->pgw_fqcsid)->num_csid; itr1++) {
							if ((context->pgw_fqcsid)->local_csid[itr1] == pgw_tmp_csid_t.local_csid[inx]) {
								for(uint8_t pos = itr1; pos < ((context->pgw_fqcsid)->num_csid - 1); pos++ ) {
									(context->pgw_fqcsid)->local_csid[pos] = (context->pgw_fqcsid)->local_csid[pos + 1];
								}
								(context->pgw_fqcsid)->num_csid--;
							}
						}
					} else {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to "
								"get Session ID entry for CSID:%u\n", LOG_VALUE,
								pgw_tmp_csid_t.local_csid[inx]);
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}

					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Remove session link from Old CSID:%u\n",
							LOG_VALUE, pgw_tmp_csid_t.local_csid[inx]);
				}
			}
			/* update entry for cp session id with link local csid */
			sess_csid *tmp = NULL;
			/* PGWC */
			tmp = get_sess_csid_entry(
					(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1],
					ADD_NODE);

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"session of CSID entry, Error %s \n",
					LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Link local csid with session id */
			/* Check head node created ot not */
			if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
				sess_csid *new_node = NULL;
				/* Add new node into csid linked list */
				new_node = add_sess_csid_data_node(tmp);
				if(new_node == NULL ) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
						"ADD new node into CSID linked list : %s\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				} else {
					new_node->cp_seid = pdn->seid;
					new_node->up_seid = pdn->dp_seid;
				}

			} else {
				tmp->cp_seid = pdn->seid;
				tmp->up_seid = pdn->dp_seid;
			}

			/* Generate the New CSID */
			if (!pgw_tmp_csid)
				return PRESENT;
		}

		/* Remove the Old CSID from the table */
		fqcsid_t *tmp_t = NULL;
		/* Get the Peer node CSID List */
		tmp_t = get_peer_addr_csids_entry(sgw_fqcsid->node_address, REMOVE_NODE);
		if (tmp_t != NULL) {
			for (uint8_t inx2 = 0; inx2 < tmp_t->num_csid; inx2++) {
				for (uint8_t inx3 = 0; inx3 < sgw_tmp_csid_t.num_csid; inx3++) {
					if (tmp_t->local_csid[inx2] == sgw_tmp_csid_t.local_csid[inx3]) {
						/* Removed old CSID from the list */
						for(uint8_t pos = inx2; pos < (tmp_t->num_csid - 1); pos++ ) {
							tmp_t->local_csid[pos] = tmp_t->local_csid[pos + 1];
						}
						/* Decrement the CSID List counter */
						tmp_t->num_csid--;
					}
				}
			}
		}
	}
	return 0;

}

int send_pfcp_sess_mod_req(pdn_connection *pdn, eps_bearer *bearer,
		mod_bearer_req_t *mb_req)
{

	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	int ebi_index = 0, index = 0;
	eps_bearer *bearers[MAX_BEARERS] = {NULL};
	uint8_t send_endmarker = 0;
	ue_context *context = NULL;
	eps_bearer *tmp_bearer = NULL;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE] = {0};
	pfcp_sess_mod_req.update_far_count = 0;

	ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	tmp_bearer = bearer;
	RTE_SET_USED(update_far);
	/* TODO: CHECK FOR BEARER MODIFCIATION */

	if(((pdn->context->sgwu_changed == TRUE) && (pdn->context->cp_mode == PGWC))  ||
			((pdn->context)->cp_mode == SAEGWC)) {
		for(uint8_t  j= 0; j< mb_req->bearer_count; j++) {
			for(uint8_t i =0 ;i< MAX_BEARERS; i++) {
				bearer = pdn->eps_bearers[i];
				if(bearer == NULL)
					continue;

				if(bearer->eps_bearer_id != mb_req->bearer_contexts_to_be_modified[j].eps_bearer_id.ebi_ebi) {
					continue;
				} else {
					if ((mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.header.len  != 0) ||
							(mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.header.len  != 0)) {
						if (mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.header.len  != 0){
							/* TAU change */
							if((bearer->s1u_enb_gtpu_ipv4.s_addr != 0) && (bearer->s1u_enb_gtpu_teid != 0)) {
								if((mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.teid_gre_key)
										!= bearer->s1u_enb_gtpu_teid  ||
										(mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.ipv4_address) !=
										bearer->s1u_enb_gtpu_ipv4.s_addr) {
									send_endmarker = 1;
								}
							}

							if(pdn->state == IDEL_STATE) {
								update_pdr_actions_flags(bearer);
							}

							bearer->s1u_enb_gtpu_ipv4.s_addr =
								mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.ipv4_address;
							bearer->s1u_enb_gtpu_teid =
								mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.teid_gre_key;
							update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
								bearer->s1u_enb_gtpu_teid;
							update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
								bearer->s1u_enb_gtpu_ipv4.s_addr;
							update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
								check_interface_type(mb_req->bearer_contexts_to_be_modified[j].s1_enodeb_fteid.interface_type,
										pdn->context->cp_mode);
							update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
								get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
							if ( pdn->context->cp_mode != PGWC) {
								update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
								update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(pdn->context);
							}
							pfcp_sess_mod_req.update_far_count++;
						}
						if (mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.header.len  != 0){
							if( ((bearer->s5s8_sgw_gtpu_ipv4.s_addr !=
											mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.ipv4_address) ||
										(bearer->s5s8_sgw_gtpu_teid !=
										 mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.teid_gre_key))){
								send_endmarker = 1;
							}
							bearer->s5s8_sgw_gtpu_ipv4.s_addr =
								mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.ipv4_address;
							bearer->s5s8_sgw_gtpu_teid =
								mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.teid_gre_key;
							update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
								bearer->s5s8_sgw_gtpu_teid;
							update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
								bearer->s5s8_sgw_gtpu_ipv4.s_addr;
							update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
								check_interface_type(mb_req->bearer_contexts_to_be_modified[j].s58_u_sgw_fteid.interface_type,
										pdn->context->cp_mode);
							update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
								get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
							if ( pdn->context->cp_mode != PGWC) {
								update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
								update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl = GET_DUP_STATUS(pdn->context);
							}
							pfcp_sess_mod_req.update_far_count++;
						}
						/* After SAEGWU --> PGWU update the PDR info */
						if ((pdn->context)->cp_mode_flag) {
							for(uint8_t pdr = 0; pdr < bearer->pdr_count; pdr++) {
								if (bearer->pdrs[pdr] == NULL) {
									continue;
								}
								if ((bearer->pdrs[pdr])->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {
									/* Update the local source IP Address and teid */
									(bearer->pdrs[pdr])->pdi.local_fteid.ipv4_address = bearer->s5s8_pgw_gtpu_ipv4.s_addr;
									/* Update the PDR info */
									set_update_pdr(&(pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count]),
										bearer->pdrs[pdr], (pdn->context)->cp_mode);
									/* Reset Precedance, No need to forward */
									memset(&(pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count].precedence), 0,
										sizeof(pfcp_precedence_ie_t));
									/* Reset FAR ID, No need to forward */
									memset(&(pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count].far_id), 0,
										sizeof(pfcp_far_id_ie_t));
									/* Update the PDR header length*/
									pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count].header.len -=
											(sizeof(pfcp_far_id_ie_t) + sizeof(pfcp_precedence_ie_t));
									pfcp_sess_mod_req.update_pdr_count++;
								}
							}
						}
						/*Added 0 in the last argument below as it is not X2 handover case*/
						bearers[index] = bearer;
						index++;
					}
					j++;
				}
			}
		}
	}

	/* After SAEGWU --> PGWU update the PDR info */
	if ((pdn->context)->cp_mode_flag) {
		/* Reset Flag */
		(pdn->context)->cp_mode_flag = FALSE;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearers, pdn,
				update_far, send_endmarker, index, pdn->context);

	context =  pdn->context;

#ifdef USE_CSID

	if(mb_req->mme_fqcsid.header.len != 0 ) {
		if ((mb_req->mme_fqcsid).number_of_csids) {

			if ((context != NULL) && (context->mme_fqcsid == NULL)) {
				context->mme_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
				if (context->mme_fqcsid == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate the "
							"memory for fqcsids entry\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
			}
			/* Remove Exsiting MME CSID associted with Session */
			memset(context->mme_fqcsid, 0, sizeof(fqcsid_t));

			/* Parse and stored MME FQ-CSID in the context */
			int ret = add_fqcsid_entry(&mb_req->mme_fqcsid, context->mme_fqcsid);
			if(ret)
				return ret;

			/* set MME FQ-CSID */
			set_fq_csid_t(&pfcp_sess_mod_req.mme_fqcsid, context->mme_fqcsid);
		}
	}

	if(mb_req->sgw_fqcsid.header.len != 0 ) {
		/* Parse and stored SGW FQ-CSID in the context */
		if (mb_req->sgw_fqcsid.number_of_csids) {
			int ret_t = 0;
			ret_t = gtpc_recvd_sgw_fqcsid(&mb_req->sgw_fqcsid, pdn, tmp_bearer, context);
			if ((ret_t != 0) && (ret_t != PRESENT)) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed Link peer CSID\n", LOG_VALUE);
				return ret_t;
			}
			/* Fill the Updated CSID in the Modification Request */
			/* Set SGW FQ-CSID */
			if (context->sgw_fqcsid != NULL) {
				if ((context->sgw_fqcsid)->num_csid) {
					fqcsid_t tmp_fqcsid = {0};

					set_fq_csid_t(&pfcp_sess_mod_req.sgw_c_fqcsid, context->sgw_fqcsid);
					if (context->cp_mode != PGWC) {
						(pfcp_sess_mod_req.sgw_c_fqcsid).node_address = pfcp_config.pfcp_ip.s_addr;
					}
					/* set PGWC FQ-CSID explicitlly zero */
					set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, &tmp_fqcsid);

					if (!pfcp_sess_mod_req.mme_fqcsid.number_of_csids) {
						/* set MME FQ-CSID explicitlly zero */
						set_fq_csid_t(&pfcp_sess_mod_req.mme_fqcsid, &tmp_fqcsid);
					}
				}
			}
			if (ret_t == PRESENT) {
				/* set PGWC FQ-CSID */
				set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, context->pgw_fqcsid);
				if (context->cp_mode == PGWC) {
					(pfcp_sess_mod_req.pgw_c_fqcsid).node_address = pfcp_config.pfcp_ip.s_addr;
				}
			}
		}
	}

	/*context->cp_mode == SAEGWC*/
	if (context->cp_mode != PGWC) {
		/* Get the copy of existing SGW CSID */
		fqcsid_t tmp_csid_t = {0};
		if (context->sgw_fqcsid != NULL) {
			if ((context->sgw_fqcsid)->num_csid) {
				memcpy(&tmp_csid_t, context->sgw_fqcsid, sizeof(fqcsid_t));
			}
		}

		/* Update the entry for peer nodes */
		if (fill_peer_node_info(pdn, tmp_bearer)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill peer node info and assignment of the "
				"CSID Error: %s\n", LOG_VALUE, strerror(errno));
			return  GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (context->flag_fqcsid_modified == TRUE) {
			uint8_t tmp_csid = 0;
			/* Validate the exsiting CSID or allocated new one */
			for (uint8_t inx1 = 0; inx1 < tmp_csid_t.num_csid; inx1++) {
				if ((context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1] ==
						tmp_csid_t.local_csid[inx1]) {
					tmp_csid = tmp_csid_t.local_csid[inx1];
					break;
				}
			}

			if (!tmp_csid) {
				for (uint8_t inx = 0; inx < tmp_csid_t.num_csid; inx++) {
					/* Remove the session link from old CSID */
					sess_csid *tmp1 = NULL;
					tmp1 = get_sess_csid_entry(tmp_csid_t.local_csid[inx], REMOVE_NODE);

					if (tmp1 != NULL) {
						/* Remove node from csid linked list */
						tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

						int8_t ret = 0;
						/* Update CSID Entry in table */
						ret = rte_hash_add_key_data(seids_by_csid_hash,
										&tmp_csid_t.local_csid[inx], tmp1);
						if (ret) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
									"\n\tError= %s\n",
									LOG_VALUE, tmp_csid_t.local_csid[inx],
									rte_strerror(abs(ret)));
							return GTPV2C_CAUSE_SYSTEM_FAILURE;
						}

						if (tmp1 == NULL) {
							/* Removing temporary local CSID associated with MME */
							remove_peer_temp_csid(context->mme_fqcsid, tmp_csid_t.local_csid[inx],
									S11_SGW_PORT_ID);

							/* Removing temporary local CSID assocoated with PGWC */
							remove_peer_temp_csid(context->pgw_fqcsid, tmp_csid_t.local_csid[inx],
									S5S8_SGWC_PORT_ID);
							/* Delete Local CSID entry */
							del_sess_csid_entry(tmp_csid_t.local_csid[inx]);
						}
						/* Delete CSID from the context */
						for (uint8_t itr1 = 0; itr1 < (context->sgw_fqcsid)->num_csid; itr1++) {
							if ((context->sgw_fqcsid)->local_csid[itr1] == tmp_csid_t.local_csid[inx]) {
								for(uint8_t pos = itr1; pos < ((context->sgw_fqcsid)->num_csid - 1); pos++ ) {
									(context->sgw_fqcsid)->local_csid[pos] = (context->sgw_fqcsid)->local_csid[pos + 1];
								}
								(context->sgw_fqcsid)->num_csid--;
							}
						}
					} else {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to "
								"get Session ID entry for CSID:%u\n", LOG_VALUE,
								tmp_csid);
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}

					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Remove session link from Old CSID:%u\n",
							LOG_VALUE, tmp_csid);
				}
			}

			/* update entry for cp session id with link local csid */
			sess_csid *tmp = NULL;
			tmp = get_sess_csid_entry(
					(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1],
					ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"session of CSID entry, Error %s \n",
					LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Link local csid with session id */
			/* Check head node created ot not */
			if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
				sess_csid *new_node = NULL;
				/* Add new node into csid linked list */
				new_node = add_sess_csid_data_node(tmp);
				if(new_node == NULL ) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
						"ADD new node into CSID linked list : %s\n", LOG_VALUE);
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
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to fill "
					"FQ-CSID in Sess EST Req ERROR: %s\n", LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
		}
	}


#endif /* USE_CSID */

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error sending PFCP Session "
			"Modification Request : %i\n", LOG_VALUE, errno);
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
#ifdef CP_BUILD
	add_pfcp_if_timer_entry(mb_req->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */

	/*Retrive the session information based on session id. */

	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found for "
			"session ID:%lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->context->sequence = mb_req->header.teid.has_teid.seq;

	for (int itr = 0 ; itr < mb_req->bearer_count ; itr++) {
		resp->eps_bearer_ids[itr] = mb_req->bearer_contexts_to_be_modified[ebi_index].eps_bearer_id.ebi_ebi;
	}

	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	pdn->proc = MODIFY_BEARER_PROCEDURE;
	resp->proc = pdn->proc;
	resp->cp_mode = pdn->context->cp_mode;
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



/**
 * @brief  : Function checks if uli information is changed
 * @param  : uli, data from incoming request
 * @param  : context, data stored in ue context
 * @param  : flag_check, flag to set if uli is changed
 * @return : Returns 0 on success, -1 otherwise
 */
void
check_for_uli_changes(gtp_user_loc_info_ie_t *uli, ue_context *context)
{

	uint8_t ret = 0;

	if(uli->tai) {

		ret = compare_tai(&uli->tai2, &context->uli.tai2);
		if(ret == FALSE) {
			context->uli_flag |= (1 << 0 );
			save_tai(&uli->tai2, &context->uli.tai2);
		}
	}

	if(uli->cgi) {
		ret = compare_cgi(&uli->cgi2, &context->uli.cgi2);
		if(ret == FALSE) {
			context->uli_flag |= ( 1<< 1 );
			save_cgi(&uli->cgi2, &context->uli.cgi2);
		}
	}
	if(uli->sai) {
		ret = compare_sai(&uli->sai2, &context->uli.sai2);
		if(ret == FALSE) {
			context->uli_flag |= (1 << 2 );
			save_sai(&uli->sai2, &context->uli.sai2);
		}
	}
	if(uli->rai) {
		ret = compare_rai(&uli->rai2, &context->uli.rai2);
		if(ret == FALSE) {
			context->uli_flag |= ( 1 << 3 );
			save_rai(&uli->rai2, &context->uli.rai2);
		}
	}
	if(uli->ecgi) {
		ret = compare_ecgi(&uli->ecgi2, &context->uli.ecgi2);
		if(ret == FALSE) {
			context->uli_flag |= (1 << 4);
			save_ecgi(&uli->ecgi2, &context->uli.ecgi2);
		}
	}
}

void update_pdr_actions_flags(eps_bearer *bearer)
{
	if (bearer != NULL) {
		for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
			if(bearer->pdrs[itr] != NULL) {
				if(bearer->pdrs[itr]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) {
					bearer->pdrs[itr]->far.actions.buff = FALSE;
					bearer->pdrs[itr]->far.actions.nocp = FALSE;
				}
			}
		}
	}
}

int8_t
update_ue_context(mod_bearer_req_t *mb_req, ue_context *context)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn = NULL;

	if(context != NULL ) {
		if(context->mbr_info.seq ==  mb_req->header.teid.has_teid.seq) {
			if(context->mbr_info.status == MBR_IN_PROGRESS) {
				/* Discarding re-transmitted mbr */
				return GTPC_RE_TRANSMITTED_REQ;
			}else{
				/* Restransmitted MBR but processing altready done for previous req */
				context->mbr_info.status = MBR_IN_PROGRESS;
			}
		}else{
			context->mbr_info.seq = mb_req->header.teid.has_teid.seq;
			context->mbr_info.status = MBR_IN_PROGRESS;
		}
	}

	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	if(mb_req->bearer_count != 0 ) {
		ebi_index = GET_EBI_INDEX(mb_req->bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (!(context->bearer_bitmap & (1 << ebi_index))) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Received modify bearer on non-existent EBI - "
				"Dropping packet while Update UE context\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
		bearer = context->eps_bearers[ebi_index];
		if (!bearer) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet while Update "
				"UE context\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
	} else {
		for(uint8_t i = 0; i <MAX_BEARERS; i++) {
			bearer = context->eps_bearers[i];
			if(bearer != NULL)
				break;
		}
	}

	pdn = bearer->pdn;

	if(pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to get pdn while Update UE context\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	/*Setting all the flags*/
	context->second_rat_count     = 0;
	context->uli_flag             = 0;
	context->second_rat_flag      = FALSE;
	context->ue_time_zone_flag    = FALSE;
	context->rat_type_flag        = FALSE;
	context->uci_flag             = FALSE;
	context->serving_nw_flag      = FALSE;
	context->ltem_rat_type_flag   = FALSE;
	context->flag_fqcsid_modified = FALSE;
	context->sgwu_changed         = FALSE;

	context->procedure  = MODIFY_BEARER_PROCEDURE;

	/*Update Secondary Rat Data if Received on MBR*/
	if(mb_req->second_rat_count != 0) {

		for(uint8_t i= 0; i < mb_req->second_rat_count; i++) {
			if (mb_req->secdry_rat_usage_data_rpt[i].irpgw == 1) {

				context->second_rat_count++;
				context->second_rat_flag = TRUE;
				context->second_rat[i].spare2 = mb_req->secdry_rat_usage_data_rpt[i].spare2;
				context->second_rat[i].irsgw = mb_req->secdry_rat_usage_data_rpt[i].irsgw;
				context->second_rat[i].irpgw = mb_req->secdry_rat_usage_data_rpt[i].irpgw;
				context->second_rat[i].rat_type = mb_req->secdry_rat_usage_data_rpt[i].secdry_rat_type;
				context->second_rat[i].eps_id = mb_req->secdry_rat_usage_data_rpt[i].ebi;
				context->second_rat[i].spare3 = mb_req->secdry_rat_usage_data_rpt[i].spare3;
				context->second_rat[i].start_timestamp = mb_req->secdry_rat_usage_data_rpt[i].start_timestamp;
				context->second_rat[i].end_timestamp = mb_req->secdry_rat_usage_data_rpt[i].end_timestamp;
				context->second_rat[i].usage_data_dl = mb_req->secdry_rat_usage_data_rpt[i].usage_data_dl;
				context->second_rat[i].usage_data_ul = mb_req->secdry_rat_usage_data_rpt[i].usage_data_ul;
			}
		}
	}

	if(mb_req->sender_fteid_ctl_plane.header.len) {

		/* Update new MME information */
		if(mb_req->sender_fteid_ctl_plane.interface_type == S11_MME_GTP_C ) {
			context->s11_mme_gtpc_teid = mb_req->sender_fteid_ctl_plane.teid_gre_key;
			context->s11_mme_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;
			s11_mme_sockaddr.sin_addr.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;

		} else if ((context->cp_mode == PGWC) &&
				(mb_req->sender_fteid_ctl_plane.interface_type == S5_S8_SGW_GTP_C)) {

			clLog(clSystemLog, eCLSeverityDebug,
					"Updating S5S8 SGWC FTEID AT PGWC in Case of SGWC Relocation\n\n");

			/* Update SGWC information */
			pdn->s5s8_sgw_gtpc_teid = mb_req->sender_fteid_ctl_plane.teid_gre_key;
			pdn->s5s8_sgw_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;
		}
	}

	/* Update time zone information*/
	if(mb_req->ue_time_zone.header.len) {
		if((mb_req->ue_time_zone.time_zone != context->tz.tz) ||
				(mb_req->ue_time_zone.daylt_svng_time != context->tz.dst)) {
			context->tz.tz = mb_req->ue_time_zone.time_zone;
			context->tz.dst = mb_req->ue_time_zone.daylt_svng_time;
			context->ue_time_zone_flag = TRUE;
		}
	}

	if(context->cp_mode == PGWC) {
		for(uint8_t i =0 ; i < MAX_BEARERS ; i++) {
			if (mb_req->bearer_contexts_to_be_modified[i].header.len  != 0) {
				if (mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.header.len  != 0) {
					eps_bearer *temp_bearer  = NULL;
					for(uint8_t b_count =0 ; b_count < MAX_BEARERS ; b_count++) {
						temp_bearer = pdn->eps_bearers[b_count];
						if(temp_bearer == NULL)
							continue;
						if(mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi ==
								temp_bearer->eps_bearer_id){
							if((temp_bearer->s5s8_sgw_gtpu_ipv4.s_addr !=
										mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.ipv4_address) ||
									(temp_bearer->s5s8_sgw_gtpu_teid !=
									 mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.teid_gre_key)) {
								context->sgwu_changed = TRUE;
								break;
							}
						}
					}
				}
			}
		}
	}

	/*The above flag will be set bit wise as
	 * Bit 7| Bit 6 | Bit 5 | Bit 4 | Bit 3|  Bit 2|  Bit 1|  Bit 0 |
	 *---------------------------------------------------------------
	 *|     |       |       | ECGI  | RAI  |  SAI  |  CGI  |  TAI   |
	 ----------------------------------------------------------------
	 */

	if(mb_req->uli.header.len != 0) {
		check_for_uli_changes(&mb_req->uli, context);
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
	if(mb_req->serving_network.header.len) {
		ret = compare_serving_network(mb_req, context);
		if(ret == FALSE) {
			context->serving_nw_flag = TRUE;
			save_serving_network(mb_req, context);
		}
	}

	/* LTE-M RAT type reporting to PGW flag */
	if(mb_req->indctn_flgs.header.len) {
		if(mb_req->indctn_flgs.indication_ltempi) {
			context->ltem_rat_type_flag = TRUE;
		}
	}

	return 0;
}


int process_pfcp_sess_mod_req_for_saegwc_pgwc(mod_bearer_req_t *mb_req,
		ue_context *context)
{
	int ebi_index = 0;
	int ret = 0;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;

	if(mb_req->bearer_count != 0 ) {
		ebi_index = GET_EBI_INDEX(mb_req->bearer_contexts_to_be_modified[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		if (!(context->bearer_bitmap & (1 << ebi_index))) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Received modify bearer on non-existent EBI - "
				"Dropping packet while Processing PFCP Session Modification "
				"Request \n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		bearer = context->eps_bearers[ebi_index];
		if (!bearer) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT "Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet while Processing PFCP "
				"Session Modification Request \n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
	} else {
		for (uint8_t i = 0; i < MAX_BEARERS; i++) {
			bearer = context->eps_bearers[i];
			if(bearer != NULL)
				break;
		}

	}
	pdn = bearer->pdn;
	pdn->proc = MODIFY_BEARER_PROCEDURE;

	if(mb_req->sgw_fqcsid.header.len != 0)
		context->flag_fqcsid_modified = TRUE;

	if(context->second_rat_flag == TRUE) {
			uint8_t trigg_buff[] = "secondary_rat_usage";

		for(uint8_t i = 0; i < context->second_rat_count; i++ ) {
			cdr second_rat_data = {0} ;
			struct timeval unix_start_time;
			struct timeval unix_end_time;

			second_rat_data.cdr_type = CDR_BY_SEC_RAT;
			second_rat_data.change_rat_type_flag = 1;
			/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
			second_rat_data.rat_type = (mb_req->secdry_rat_usage_data_rpt[i].secdry_rat_type == 0) ? 10 : 0;
			second_rat_data.bearer_id = mb_req->secdry_rat_usage_data_rpt[i].ebi;
			second_rat_data.seid = pdn->seid;
			second_rat_data.imsi = pdn->context->imsi;
			second_rat_data.start_time = mb_req->secdry_rat_usage_data_rpt[i].start_timestamp;
			second_rat_data.end_time = mb_req->secdry_rat_usage_data_rpt[i].end_timestamp;
			second_rat_data.data_volume_uplink = mb_req->secdry_rat_usage_data_rpt[i].usage_data_ul;
			second_rat_data.data_volume_downlink = mb_req->secdry_rat_usage_data_rpt[i].usage_data_dl;

			ntp_to_unix_time(&second_rat_data.start_time, &unix_start_time);
			ntp_to_unix_time(&second_rat_data.end_time, &unix_end_time);

			second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
			second_rat_data.data_start_time = 0;
			second_rat_data.data_end_time = 0;
			second_rat_data.total_data_volume = second_rat_data.data_volume_uplink + second_rat_data.data_volume_downlink;

			memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));
			if(generate_cdr_info(&second_rat_data) == -1) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to generate "
					"CDR\n",LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CDR For Secondary Rat "
				"is generated\n", LOG_VALUE);
		}
	}

	if(pdn->s5s8_sgw_gtpc_ipv4.s_addr != mb_req->sender_fteid_ctl_plane.ipv4_address) {
		pdn->old_sgw_addr = pdn->s5s8_sgw_gtpc_ipv4;
		pdn->old_sgw_addr_valid = TRUE;
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;
	}

	/*The ULI flag set bit  as
	 * Bit 7| Bit 6 | Bit 5 | Bit 4 | Bit 3|  Bit 2|  Bit 1|  Bit 0 |
	 *---------------------------------------------------------------
	 *|     |       |       | ECGI  | RAI  |  SAI  |  CGI  |  TAI   |
	 ----------------------------------------------------------------
	 */

	/* TODO something with modify_bearer_request.delay if set */
	if (pfcp_config.use_gx) {
		struct resp_info *resp = NULL;
		if(((context->uli_flag != FALSE) && (((context->event_trigger & (1 << ULI_EVENT_TRIGGER))) != 0))
			|| ((context->ue_time_zone_flag != FALSE) && (((context->event_trigger) & (1 << UE_TIMEZONE_EVT_TRIGGER)) != 0))
			|| ((context->rat_type_flag != FALSE) &&  ((context->event_trigger & (1 << RAT_EVENT_TRIGGER))) != 0)) {

			ret = gen_ccru_request(context, bearer, NULL);

			/*Retrive the session information based on session id. */
			if (get_sess_entry(pdn->seid, &resp) != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry "
					"Found for session ID:%lu\n", LOG_VALUE, pdn->seid);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
			resp->gtpc_msg.mbr = *mb_req;
			resp->cp_mode = context->cp_mode;

			return ret;
		}
	}

	ret = send_pfcp_sess_mod_req(pdn, bearer, mb_req);

	return ret;
}

int
process_sess_mod_req_del_cmd(pdn_connection *pdn)
{
	int ret = 0;
	ue_context *context = NULL;
	eps_bearer *bearers[MAX_BEARERS];
	int ebi = 0;
	struct resp_info *resp = NULL;
	int teid = UE_SESS_ID(pdn->seid);
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to update UE "
			"State for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn->seid);
		return  GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	s11_mme_sockaddr.sin_addr.s_addr =
		context->s11_mme_gtpc_ipv4.s_addr;

	for (uint8_t iCnt = 0; iCnt < resp->bearer_count; ++iCnt) {
		ebi = resp->eps_bearer_ids[iCnt];
		int ebi_index = GET_EBI_INDEX(ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		bearers[iCnt] = context->eps_bearers[ebi_index];
	}

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req ,pdn, bearers, resp->bearer_count);

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error sending PFCP Session "
			"Modification Request for Delete Bearer Command : %i\n",LOG_VALUE, errno);
	} else {

#ifdef CP_BUILD
		int ebi_index =  GET_EBI_INDEX(pdn->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return -1;
		}

		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */

	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update the sequence number */
	context->sequence = resp->gtpc_msg.del_bearer_cmd.header.teid.has_teid.seq;

	resp->msg_type = GTP_DELETE_BEARER_CMD;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	return 0;
}

int
process_delete_bearer_cmd_request(del_bearer_cmd_t *del_bearer_cmd,
							gtpv2c_header_t *gtpv2c_tx, ue_context *context)
{
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	int ebi_index = 0;
	struct resp_info *resp = NULL;

	for(uint8_t i=0; i<del_bearer_cmd->bearer_count; i++) {
		if(del_bearer_cmd->bearer_contexts[i].header.len == 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"MANDATORY IE MISSING"
				" For Delete Bearer Command\n",LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}
	}

	ebi_index = GET_EBI_INDEX(del_bearer_cmd->bearer_contexts[ebi_index].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "No Session Entry Found "
			"for session ID:%lu\n",LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	resp->bearer_count = del_bearer_cmd->bearer_count;
	for (uint8_t iCnt = 0; iCnt < del_bearer_cmd->bearer_count; ++iCnt) {

		if (del_bearer_cmd->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi == pdn->default_bearer_id) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Default Bearer ID "
				"is received for deactivation.\n", LOG_VALUE);
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}

		resp->eps_bearer_ids[iCnt] = del_bearer_cmd->bearer_contexts[iCnt].eps_bearer_id.ebi_ebi;
	}

	if (SAEGWC == context->cp_mode || PGWC == context->cp_mode) {
		if (ccru_req_for_bear_termination(pdn, bearer)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"CCR-UPDATE "
				"Failed For Delete Bearer Command %s \n", LOG_VALUE,
				strerror(errno));
			return -1;
		}
	} else if(SGWC == context->cp_mode) {

		set_delete_bearer_command(del_bearer_cmd, pdn, gtpv2c_tx);
		s5s8_recv_sockaddr.sin_addr.s_addr =
			               pdn->s5s8_pgw_gtpc_ipv4.s_addr;

	}
	pdn->state = CONNECTED_STATE;
	resp->msg_type = GTP_DELETE_BEARER_CMD;
	resp->state = CONNECTED_STATE;
	resp->gtpc_msg.del_bearer_cmd = *del_bearer_cmd;
	resp->gtpc_msg.del_bearer_cmd.header.teid.has_teid.seq = del_bearer_cmd->header.teid.has_teid.seq;
	resp->proc = pdn->proc;
	resp->cp_mode = context->cp_mode;
	return 0;
}

int
process_bearer_rsrc_cmd(bearer_rsrc_cmd_t *bearer_rsrc_cmd,
							gtpv2c_header_t *gtpv2c_tx, ue_context *context)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	/*store pti in context*/
	if(context->proc_trans_id != bearer_rsrc_cmd->pti.proc_trans_id) {
		context->proc_trans_id = bearer_rsrc_cmd->pti.proc_trans_id;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"PTI already in used\n ", LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	/*store ue initiated seq no in context.*/
	context->ue_initiated_seq_no = bearer_rsrc_cmd->header.teid.has_teid.seq;

	/*Get default bearer id i.e. lbi from BRC */
	ebi_index = GET_EBI_INDEX(bearer_rsrc_cmd->lbi.ebi_ebi);
	if(ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Invalid ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/*bearer id for which bearer resource mod req in BRC is received*/
	if(bearer_rsrc_cmd->eps_bearer_id.header.len != 0) {
		/*Check bearer is present or not for received ebi id*/
		ret = check_ebi_presence_in_ue(bearer_rsrc_cmd->eps_bearer_id.ebi_ebi, context);
		if(ret != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Invalid EBI,eps bearer not found"
					"for ebi : %d\n", LOG_VALUE, bearer_rsrc_cmd->eps_bearer_id.ebi_ebi);
			return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
		}

		ebi_index = GET_EBI_INDEX(bearer_rsrc_cmd->eps_bearer_id.ebi_ebi);
	}

	if(ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Invalid ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/*either use default bearer or dedicated*/
	bearer = context->eps_bearers[ebi_index];
	if (bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Bearer not found for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;;
	}

	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to get PDN ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;;
	}

	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"NO Session Entry Found for sess ID:%lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	if (SAEGWC == context->cp_mode || PGWC == context->cp_mode) {
		int ret = 0;
		if ((ret = gen_ccru_request(context , bearer,
						bearer_rsrc_cmd)) != 0) {
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failure in CCR-UPDATE Failed For UE requested "
					"bearer resource modification flow, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			} else {
				/*Error in TFT*/
				if(ret != 0)
					return ret;
			}
		}
	} else {
		/*Forword BRC on S5S8 to PGWC*/
		set_bearer_resource_command(bearer_rsrc_cmd, pdn,
										gtpv2c_tx);
		s5s8_recv_sockaddr.sin_addr.s_addr =
			               pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	}

	pdn->state = CONNECTED_STATE;
	resp->msg_type = GTP_BEARER_RESOURCE_CMD;
	resp->state = CONNECTED_STATE;
	resp->gtpc_msg.bearer_rsrc_cmd = *bearer_rsrc_cmd;
	resp->gtpc_msg.bearer_rsrc_cmd.header.teid.has_teid.seq = bearer_rsrc_cmd->header.teid.has_teid.seq;
	resp->proc = pdn->proc;

	return 0;
}

uint32_t
get_far_id(eps_bearer *bearer, int interface_value){
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
process_pfcp_sess_mod_request(mod_bearer_req_t *mb_req, ue_context *context)
{
	int ebi_index = 0;
	uint8_t enb_flag = 0;
	uint8_t send_endmarker = 0;
	eps_bearer *bearer  = NULL;
	eps_bearer *bearers[MAX_BEARERS] ={NULL};
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE] = {0};

	pfcp_sess_mod_req.update_far_count = 0;
	for(uint8_t i = 0; i < mb_req->bearer_count; i++) {

		if (!mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.header.len
				|| !mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Bearer Context not "
				"found for Modify Bearer Request, Dropping packet\n", LOG_VALUE);
			return GTPV2C_CAUSE_INVALID_LENGTH;
		}

		ebi_index = GET_EBI_INDEX(mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		if (!(context->bearer_bitmap & (1 << ebi_index))) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Received modify bearer on non-existent EBI - "
				"for while PFCP Session Modification Request Modify Bearer "
				"Request, Dropping packet\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		bearer = context->eps_bearers[ebi_index];
		if (!bearer) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Received modify bearer on non-existent EBI - "
				"for while PFCP Session Modification Request Modify Bearer "
				"Request, Dropping packet\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		pdn = bearer->pdn;
		pdn->proc = MODIFY_BEARER_PROCEDURE;

		if (mb_req->bearer_contexts_to_be_modified[i].s11_u_mme_fteid.header.len &&
				(context->s11_mme_gtpc_teid != mb_req->bearer_contexts_to_be_modified[i].s11_u_mme_fteid.teid_gre_key)) {

			context->s11_mme_gtpc_teid = mb_req->bearer_contexts_to_be_modified[i].s11_u_mme_fteid.teid_gre_key;
		}

		bearer->eps_bearer_id = mb_req->bearer_contexts_to_be_modified[i].eps_bearer_id.ebi_ebi;

		/* TODO: Not supporting Multi-PDN Scenario */
		if ((bearer->s1u_enb_gtpu_ipv4.s_addr) &&
				(bearer->s1u_enb_gtpu_ipv4.s_addr == mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address)) {
				enb_flag = PRESENT;
		}

		if (mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.header.len != 0) {

		/*NOTE: IDEL STATE means bearer is in Suspend State, so no need to send Send Endmarker */

			if((bearer->s1u_enb_gtpu_ipv4.s_addr != 0) && (bearer->s1u_enb_gtpu_teid != 0)) {
				if((mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.teid_gre_key)
						!= bearer->s1u_enb_gtpu_teid  ||
						(mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.ipv4_address) !=
						bearer->s1u_enb_gtpu_ipv4.s_addr) {

					send_endmarker = 1;
				}
			}



			if(pdn->state == IDEL_STATE) {
				update_pdr_actions_flags(bearer);
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
				check_interface_type(mb_req->bearer_contexts_to_be_modified[i].s1_enodeb_fteid.interface_type,
						context->cp_mode);
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
				check_interface_type(mb_req->bearer_contexts_to_be_modified[i].s58_u_sgw_fteid.interface_type,
						context->cp_mode);
			update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
				get_far_id(bearer, update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
			if ( context->cp_mode != PGWC) {
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl= GET_DUP_STATUS(pdn->context);
			}
			pfcp_sess_mod_req.update_far_count++;
		}

		bearers[i] = bearer;

	} /*forloop*/
	if(pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get PDN ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	bearer = context->eps_bearers[ebi_index];
	pdn = bearer->pdn;

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearers,
			pdn, update_far, send_endmarker, mb_req->bearer_count, context);

	/*Adding the secondary rat usage report to the CDR Entry when it it a E RAB
	 * MODIFICATION*/

	if(mb_req->second_rat_count != 0) {

		uint8_t trigg_buff[] = "secondary_rat_usage";

		for(uint8_t i =0; i< mb_req->second_rat_count; i++) {

			if(mb_req->secdry_rat_usage_data_rpt[i].irsgw == 1) {
				cdr second_rat_data = {0};
				struct timeval unix_start_time;
				struct timeval unix_end_time;

				second_rat_data.cdr_type = CDR_BY_SEC_RAT;
				second_rat_data.change_rat_type_flag = 1;
				/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
				second_rat_data.rat_type = (mb_req->secdry_rat_usage_data_rpt[i].secdry_rat_type == 0) ? 10 : 0;
				second_rat_data.bearer_id = mb_req->secdry_rat_usage_data_rpt[i].ebi;
				second_rat_data.seid = pdn->seid;
				second_rat_data.imsi = pdn->context->imsi;
				second_rat_data.start_time = mb_req->secdry_rat_usage_data_rpt[i].start_timestamp;
				second_rat_data.end_time = mb_req->secdry_rat_usage_data_rpt[i].end_timestamp;
				second_rat_data.data_volume_uplink = mb_req->secdry_rat_usage_data_rpt[i].usage_data_ul;
				second_rat_data.data_volume_downlink = mb_req->secdry_rat_usage_data_rpt[i].usage_data_dl;

				ntp_to_unix_time(&second_rat_data.start_time, &unix_start_time);
				ntp_to_unix_time(&second_rat_data.end_time, &unix_end_time);

				second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
				second_rat_data.data_start_time = 0;
				second_rat_data.data_end_time = 0;
				second_rat_data.total_data_volume = second_rat_data.data_volume_uplink + second_rat_data.data_volume_downlink;

				memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));

				if(generate_cdr_info(&second_rat_data) == -1) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to generate "
						"CDR\n",LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
			}
		}
	}

#ifdef USE_CSID
	/* Generate the permant CSID for SGW */
	if (context->cp_mode != PGWC) {
		/* Get the copy of existing SGW CSID */
		fqcsid_t tmp_csid_t = {0};
		if (context->sgw_fqcsid != NULL) {
			if ((context->sgw_fqcsid)->num_csid) {
				memcpy(&tmp_csid_t, context->sgw_fqcsid, sizeof(fqcsid_t));
			}
		}

		/* Update the entry for peer nodes */
		if (fill_peer_node_info(pdn, bearer)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill peer node info and assignment of the "
				"CSID Error: %s\n", LOG_VALUE, strerror(errno));
			return  GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		/* TODO: Multi-PDN Not supported */
		if (enb_flag) {
			context->flag_fqcsid_modified = FALSE;
		}

		if (context->flag_fqcsid_modified == TRUE) {
			uint8_t tmp_csid = 0;
			/* Validate the exsiting CSID or allocated new one */
			for (uint8_t inx1 = 0; inx1 < tmp_csid_t.num_csid; inx1++) {
				if ((context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1] ==
						tmp_csid_t.local_csid[inx1]) {
					tmp_csid = tmp_csid_t.local_csid[inx1];
					break;
				}
			}

			if (!tmp_csid) {
				for (uint8_t inx = 0; inx < tmp_csid_t.num_csid; inx++) {
					/* Remove the session link from old CSID */
					sess_csid *tmp1 = NULL;
					tmp1 = get_sess_csid_entry(tmp_csid_t.local_csid[inx], REMOVE_NODE);

					if (tmp1 != NULL) {
						/* Remove node from csid linked list */
						tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

						int8_t ret = 0;
						/* Update CSID Entry in table */
						ret = rte_hash_add_key_data(seids_by_csid_hash,
										&tmp_csid_t.local_csid[inx], tmp1);
						if (ret) {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
									"\n\tError= %s\n",
									LOG_VALUE, tmp_csid_t.local_csid[inx],
									rte_strerror(abs(ret)));
							return GTPV2C_CAUSE_SYSTEM_FAILURE;
						}
						if (tmp1 == NULL) {
							/* Removing temporary local CSID associated with MME */
							remove_peer_temp_csid(context->mme_fqcsid, tmp_csid_t.local_csid[inx],
									S11_SGW_PORT_ID);

							/* Removing temporary local CSID assocoated with PGWC */
							remove_peer_temp_csid(context->pgw_fqcsid, tmp_csid_t.local_csid[inx],
									S5S8_SGWC_PORT_ID);
							/* Delete Local CSID entry */
							del_sess_csid_entry(tmp_csid_t.local_csid[inx]);
						}
						/* Delete CSID from the context */
						for (uint8_t itr1 = 0; itr1 < (context->sgw_fqcsid)->num_csid; itr1++) {
							if ((context->sgw_fqcsid)->local_csid[itr1] == tmp_csid_t.local_csid[inx]) {
								for(uint8_t pos = itr1; pos < ((context->sgw_fqcsid)->num_csid - 1); pos++ ) {
									(context->sgw_fqcsid)->local_csid[pos] = (context->sgw_fqcsid)->local_csid[pos + 1];
								}
								(context->sgw_fqcsid)->num_csid--;
							}
						}

						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Remove session link from Old CSID:%u\n",
								LOG_VALUE, tmp_csid_t.local_csid[inx]);
				}
			}
		}

		/* update entry for cp session id with link local csid */
			sess_csid *tmp = NULL;
			tmp = get_sess_csid_entry(
					(context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1],
					ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to get session of CSID entry %s \n",
						LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Link local csid with session id */
			/* Check head node created ot not */
			if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
				sess_csid *new_node = NULL;
				/* Add new node into csid linked list */
				new_node = add_sess_csid_data_node(tmp);
				if(new_node == NULL ) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
						"ADD new node into CSID linked list : %s\n", LOG_VALUE);
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
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to fill "
					"FQ-CSID in Session Establishment Request, "
					"Error: %s\n", LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

		}
	}

#endif /* USE_CSID */

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending PFCP "
			"Session Modification Request for Modify Bearer Request %i\n",
			LOG_VALUE, errno);
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
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	/* Set create session response */
	resp->linked_eps_bearer_id = pdn->default_bearer_id;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	resp->cp_mode = context->cp_mode;
	memcpy(&resp->gtpc_msg.mbr, mb_req, sizeof(mod_bearer_req_t));

	return 0;
}

int
proc_pfcp_sess_mbr_udp_csid_req(upd_pdn_conn_set_req_t *upd_req)
{
	int ret = 0;
	ue_context *context = NULL;
	eps_bearer  *bearers[MAX_BEARERS], *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &upd_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if(upd_req->sgw_fqcsid.header.len == 0) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"SGWC FQCSID IS "
			"MISSING\n", LOG_VALUE);

		return GTPV2C_CAUSE_CONDITIONAL_IE_MISSING;
	}

	for(uint8_t i = 0; i< MAX_BEARERS; i++) {
		bearer  = context->eps_bearers[i];
		if(bearer == NULL)
			continue;
		else
			break;
	}

	if (bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NULL Bearer found while "
			"Update PDN Connection Set Request\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = bearer->pdn;
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NULL PDN found while "
			"Update PDN Connection Set Request\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearers[0] = bearer;
	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &upd_req->header, bearers, pdn, NULL, 0, 1, context);

#ifdef USE_CSID
	/* SGW FQ-CSID */
	if (upd_req->sgw_fqcsid.header.len) {
		if (upd_req->sgw_fqcsid.number_of_csids) {
			(pdn->context)->flag_fqcsid_modified = FALSE;
			int ret_t = 0;
			/* Parse and stored MME and SGW FQ-CSID in the context */
			ret_t = gtpc_recvd_sgw_fqcsid(&upd_req->sgw_fqcsid, pdn, bearer, context);
			if ((ret_t != 0) && (ret_t != PRESENT)) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed Link peer CSID\n", LOG_VALUE);
				return ret_t;
			}
			/* PGW Link local CSID with SGW CSID */
			if ((pdn->context)->cp_mode == PGWC) {
				if (((pdn->context)->sgw_fqcsid != NULL) &&
						((pdn->context)->flag_fqcsid_modified != TRUE)) {
					if (link_gtpc_peer_csids((pdn->context)->sgw_fqcsid,
								(pdn->context)->pgw_fqcsid, S5S8_PGWC_PORT_ID)) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
								"Local CSID entry to link with SGW FQCSID, Error : %s \n", LOG_VALUE,
								strerror(errno));
						return -1;
					}
				}
			}
			/* Fill the Updated CSID in the Modification Request */
			/* Set SGW FQ-CSID */
			if (context->sgw_fqcsid != NULL) {
				if ((context->sgw_fqcsid)->num_csid) {
					fqcsid_t tmp_fqcsid = {0};

					set_fq_csid_t(&pfcp_sess_mod_req.sgw_c_fqcsid, context->sgw_fqcsid);
					if (context->cp_mode != PGWC) {
						(pfcp_sess_mod_req.sgw_c_fqcsid).node_address = pfcp_config.pfcp_ip.s_addr;
					}
					/* set PGWC FQ-CSID explicitlly zero */
					set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, &tmp_fqcsid);
					/* set MME FQ-CSID explicitlly zero */
					set_fq_csid_t(&pfcp_sess_mod_req.mme_fqcsid, &tmp_fqcsid);
				}
			}
			if (ret_t == PRESENT) {
				/* set PGWC FQ-CSID */
				set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, context->pgw_fqcsid);
			}
		}
	}
#endif /* USE_CSID */

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	upf_pfcp_sockaddr.sin_addr.s_addr  = pdn->upf_ipv4.s_addr;

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending "
			"Update PDN Connection Set Request, Error : %s\n", LOG_VALUE,
			strerror(errno));
	}

	/* Update the Sequence number for the request */
	context->sequence = upd_req->header.teid.has_teid.seq;

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	pdn->proc = UPDATE_PDN_CONNECTION_PROC;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for session ID:%lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	/* Set create session response */
	resp->linked_eps_bearer_id = pdn->default_bearer_id;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	resp->gtpc_msg.upd_req = *upd_req;

	return 0;

}

rar_funtions
rar_process(pdn_connection *pdn, uint8_t proc){

	rar_funtions function = NULL;

	if(proc == DED_BER_ACTIVATION_PROC) {
		pdn->policy.num_charg_rule_install = 0;
		function = &gen_reauth_response;
	} else if(proc == PDN_GW_INIT_BEARER_DEACTIVATION) {
		pdn->policy.num_charg_rule_delete = 0;
		function = &gen_reauth_response;
	} else if(proc == UPDATE_BEARER_PROC){
		pdn->policy.num_charg_rule_modify = 0;
		function = &gen_reauth_response;
	}

	/* Keep the same order for function call
	 * else we will face problem in case of
	 * when qci/arp of a rule get changes and we have to
	 * delete that rule from one bearer and add the rule to
	 * another bearer
	 */
	if(pdn->policy.num_charg_rule_delete) {
		function = &gx_delete_bearer_req;
	} else if(pdn->policy.num_charg_rule_modify) {
		function = &gx_update_bearer_req;
	} else if(pdn->policy.num_charg_rule_install){
		function = &gx_create_bearer_req;
	}

	return function;

}

int
gen_reauth_response(pdn_connection *pdn)
{
	/* VS: Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg raa = {0};
	gx_context_t *gx_context = NULL;
	uint16_t msg_type_ofs = 0;
	uint16_t msg_body_ofs = 0;
	uint16_t rqst_ptr_ofs = 0;
	uint16_t msg_len_total = 0;

	if ((gx_context_entry_lookup(pdn->gx_sess_id, &gx_context)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
			"gx context not found for sess id %s\n",
			LOG_VALUE, pdn->gx_sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

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

	/* Set the Gx State for events */
	gx_context->state = RE_AUTH_ANS_SNT_STATE;

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_raa_calc_length(&raa.data.cp_raa);
	msg_body_ofs = GX_HEADER_LEN;
	rqst_ptr_ofs = msg_len + msg_body_ofs;
	msg_len_total = rqst_ptr_ofs + sizeof(pdn->rqst_ptr);
	raa.msg_len = msg_len_total;

	buffer = rte_zmalloc_socket(NULL, msg_len_total,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory for buffer while generating RAA, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
		return -1;
	}

	memcpy(buffer + msg_type_ofs, &raa.msg_type, sizeof(raa.msg_type));
	memcpy(buffer + sizeof(raa.msg_type), &raa.msg_len, sizeof(raa.msg_len));

	if (gx_raa_pack(&(raa.data.cp_raa),
		(unsigned char *)(buffer + msg_body_ofs),
		msg_len) == 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error while Packing RAA\n",
			LOG_VALUE);
		rte_free(buffer);
		return -1;
	}

	//memcpy((unsigned char *)(buffer + sizeof(raa.msg_type) + msg_len), &(context->eps_bearers[1]->rqst_ptr),
	memcpy((unsigned char *)(buffer + rqst_ptr_ofs), &(pdn->rqst_ptr),
			sizeof(pdn->rqst_ptr));

	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len_total);
			//msg_len + sizeof(raa.msg_type) + sizeof(unsigned long));

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton(CLI_GX_IP, &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_RAA, SENT, GX);
	rte_free(buffer);

	pdn->state = CONNECTED_STATE;
	gx_context->state = CONNECTED_STATE;
	pdn->policy.count = 0;

	return 0;
}

uint8_t
process_delete_bearer_pfcp_sess_response(uint64_t sess_id, ue_context *context,
							gtpv2c_header_t *gtpv2c_tx, struct resp_info *resp)
{
	pdn_connection *pdn = NULL;
	int ebi = UE_BEAR_ID(sess_id);
	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;
	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get PDN for "
			"ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (resp->msg_type == GX_RAR_MSG
		|| resp->msg_type == GTP_DELETE_BEARER_CMD
		|| resp->msg_type == GTP_DELETE_BEARER_REQ
		|| resp->msg_type == GTP_BEARER_RESOURCE_CMD) {

		uint8_t lbi = 0;
		uint8_t bearer_count = 0;
		uint8_t eps_bearer_ids[MAX_BEARERS];

		if(resp->msg_type == GX_RAR_MSG ||
				resp->msg_type == GTP_BEARER_RESOURCE_CMD) {

			get_charging_rule_remove_bearer_info(pdn,
				&lbi,eps_bearer_ids, &bearer_count);

		} else {

			lbi = resp->linked_eps_bearer_id;
			bearer_count = resp->bearer_count;
			memcpy(eps_bearer_ids, resp->eps_bearer_ids, MAX_BEARERS);

		}
		uint8_t pti = 0;
		/* Available if procedure is part of BEARER Resource Command */
		pti = context->proc_trans_id;

		uint32_t seq_no = 0;
		if((SGWC == pdn->context->cp_mode)
				&& (pdn->proc == PDN_GW_INIT_BEARER_DEACTIVATION)
				&& (!pti)) {
			seq_no = generate_seq_number();
		}else{
			seq_no = context->sequence;
		}

		set_delete_bearer_request(gtpv2c_tx, seq_no,
			pdn, lbi, pti, eps_bearer_ids, bearer_count);

		resp->state = DELETE_BER_REQ_SNT_STATE;
		pdn->state = DELETE_BER_REQ_SNT_STATE;

		if( PGWC == context->cp_mode ) {
			s5s8_recv_sockaddr.sin_addr.s_addr =
				pdn->s5s8_sgw_gtpc_ipv4.s_addr;
		} else {
			s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;
		}
		/* Reset the PTI Value */
		context->proc_trans_id = 0;

	} else if (resp->msg_type == GTP_DELETE_BEARER_RSP) {

		if ((SAEGWC == context->cp_mode) ||
			(PGWC == context->cp_mode)) {

			int ret = 0;
			if (resp->proc == PDN_GW_INIT_BEARER_DEACTIVATION) {


				delete_dedicated_bearers(pdn, resp->eps_bearer_ids,
												resp->bearer_count);
				rar_funtions rar_function = NULL;
				rar_function = rar_process(pdn,	pdn->proc);

				if(rar_function != NULL){
					ret = rar_function(pdn);
					if(ret)
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed in processing "
						"RAR function\n", LOG_VALUE);
				} else {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"None of the RAR function "
						"returned\n", LOG_VALUE);
				}
				resp->msg_type = GX_RAA_MSG;
				resp->proc = pdn->proc;

			} else if (resp->proc ==
				MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC) {

				/*extract ebi_id from array as all the ebi's will be of same pdn.*/
				int ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[0]);
				if (ebi_index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
				provision_ack_ccr(pdn, (context->eps_bearers[ebi_index]),
						RULE_ACTION_DELETE,NO_FAIL, &pro_ack_rule_array);
				delete_dedicated_bearers(pdn, resp->eps_bearer_ids,
												resp->bearer_count);
				resp->msg_type = GX_CCR_MSG;
			} else {
				if( resp->proc == UE_REQ_BER_RSRC_MOD_PROC) {
					int ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[0]);
					if (ebi_index == -1) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}
						pdn->proc = resp->proc;
						provision_ack_ccr(pdn,
								context->eps_bearers[ebi_index],
								RULE_ACTION_DELETE,NO_FAIL, &pro_ack_rule_array);
				}
				delete_dedicated_bearers(pdn, resp->eps_bearer_ids,
												resp->bearer_count);
				resp->msg_type = GX_CCR_MSG;
			}

			resp->state = pdn->state;
			s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;
			return 0;

		} else {

			int ebi_index = -1;
			uint32_t sequence = 0;

			/* Get seuence number from bearer*/
			if (resp->linked_eps_bearer_id > 0) {
				ebi_index = GET_EBI_INDEX(resp->linked_eps_bearer_id);
			}else{
				for(int itr = 0; itr < resp->bearer_count; itr++){
					ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[itr]);
					if (ebi_index != -1){
						break;
					}
				}
			}

			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}else{
				sequence = context->eps_bearers[ebi_index]->sequence;
			}

			set_delete_bearer_response(gtpv2c_tx, sequence,
				resp->linked_eps_bearer_id,
				resp->eps_bearer_ids, resp->bearer_count,
				pdn->s5s8_pgw_gtpc_teid);


			delete_dedicated_bearers(pdn, resp->eps_bearer_ids,
											resp->bearer_count);

			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr =
				pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		}
	}

	return 0;
}

uint8_t
process_pfcp_sess_upd_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint64_t sess_id = pfcp_sess_mod_rsp->header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE context "
			"for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	int ebi = UE_BEAR_ID(sess_id);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn for "
			"ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get bearer for "
			"ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;

	}
	return 0;
}


int
process_pfcp_sess_mod_resp_mbr_req(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp,
		gtpv2c_header_t *gtpv2c_tx, pdn_connection *pdn, struct resp_info *resp,
		eps_bearer *bearer, uint8_t *mbr_procedure)
{

	uint8_t cp_mode = 0;
	ue_context *context = NULL;
	uint64_t sess_id = pfcp_sess_mod_rsp->header.seid_seqno.has_seid.seid;
	int ebi = UE_BEAR_ID(sess_id);
	int ebi_index = GET_EBI_INDEX(ebi);
	struct teid_value_t *teid_value = NULL;
	int ret = 0;
	teid_key_t teid_key = {0};

	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;
	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	context = pdn->context;

	if(*mbr_procedure == NO_UPDATE_MBR) {

		set_modify_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer, &resp->gtpc_msg.mbr);
		resp->state = CONNECTED_STATE;

		if (PGWC != context->cp_mode) {
			s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;
		}

		uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len,ACC);

		process_cp_li_msg(
				pdn->seid, S11_INTFC_OUT, tx_buf, payload_length,
				ntohl(pfcp_config.s11_ip.s_addr), ntohl(s11_mme_sockaddr.sin_addr.s_addr),
				pfcp_config.s11_port, ntohs(s11_mme_sockaddr.sin_port));

		resp->state = CONNECTED_STATE;
		pdn->state =  CONNECTED_STATE;
		return 0;

	} else if (*mbr_procedure == UPDATE_PDN_CONNECTION) {

		resp->state =  UPD_PDN_CONN_SET_REQ_SNT_STATE;
		pdn->state =  UPD_PDN_CONN_SET_REQ_SNT_STATE;

#ifdef USE_CSID
		if ((context->cp_mode == SGWC)) {
			/* Update peer node csid */
			update_peer_node_csid(pfcp_sess_mod_rsp, context);

			uint16_t payload_length = 0;
			bzero(&s5s8_tx_buf, sizeof(s5s8_tx_buf));
			gtpv2c_header_t *gtpc_tx = (gtpv2c_header_t *)s5s8_tx_buf;

			upd_pdn_conn_set_req_t upd_pdn_set = {0};

			set_gtpv2c_teid_header((gtpv2c_header_t *)&upd_pdn_set.header,
					GTP_UPDATE_PDN_CONNECTION_SET_REQ, 0,
					context->sequence, 0);
			/* Add the entry for sequence and teid value for error handling */
			teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (teid_value == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
						"memory for teid value, Error : %s\n", LOG_VALUE,
						rte_strerror(rte_errno));
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			teid_value->teid = pdn->s5s8_sgw_gtpc_teid;
			teid_value->msg_type = gtpv2c_tx->gtpc.message_type;

			snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(pdn->proc),
							context->sequence);

			/* Add the entry for sequence and teid value for error handling */
			if (context->cp_mode != SAEGWC) {
				ret = add_seq_number_for_teid(teid_key, teid_value);
				if(ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
							"Sequence number for TEID: %u\n", LOG_VALUE,
							teid_value->teid);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
			}
			upd_pdn_set.header.teid.has_teid.teid =
										pdn->s5s8_pgw_gtpc_teid;

			set_gtpc_fqcsid_t(&upd_pdn_set.sgw_fqcsid, IE_INSTANCE_ONE,
					context->sgw_fqcsid);
			upd_pdn_set.sgw_fqcsid.node_address = pdn->s5s8_sgw_gtpc_ipv4.s_addr;

			uint16_t msg_len = 0;
			msg_len = encode_upd_pdn_conn_set_req(&upd_pdn_set, (uint8_t *)gtpc_tx);
			gtpc_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				(bearer->pdn->s5s8_pgw_gtpc_ipv4.s_addr);

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", LOG_VALUE,
					inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

			payload_length = ntohs(gtpc_tx->gtpc.message_len)
				+ sizeof(gtpc_tx->gtpc);

			gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
					(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len, SENT);

			cp_mode = context->cp_mode;
			add_gtpv2c_if_timer_entry(
					pdn->context->s11_sgw_gtpc_teid,
					&s5s8_recv_sockaddr, tx_buf, payload_length,
					ebi_index,
					S5S8_IFACE, cp_mode);

			/* copy packet for user level packet copying or li */
			if (context->dupl) {
				process_pkt_for_li(
						context, S5S8_C_INTFC_OUT, s5s8_tx_buf, payload_length,
						ntohl(pfcp_config.s5s8_ip.s_addr), ntohl(s5s8_recv_sockaddr.sin_addr.s_addr),
						pfcp_config.s5s8_port, ntohs(s5s8_recv_sockaddr.sin_port));
			}

		return 0;

		}
#endif /* USE_CSID */

	} else if (*mbr_procedure == FORWARD_MBR_REQUEST) {

		set_modify_bearer_request(gtpv2c_tx, pdn, bearer);
		s5s8_recv_sockaddr.sin_addr.s_addr =
			(bearer->pdn->s5s8_pgw_gtpc_ipv4.s_addr);

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", LOG_VALUE,
				inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

		uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len, SENT);

		cp_mode = pdn->context->cp_mode;
		add_gtpv2c_if_timer_entry(
				pdn->context->s11_sgw_gtpc_teid,
				&s5s8_recv_sockaddr, tx_buf, payload_length,
				ebi_index,
				S5S8_IFACE, cp_mode);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, s5s8_tx_buf, payload_length,
					ntohl(pfcp_config.s5s8_ip.s_addr), ntohl(s5s8_recv_sockaddr.sin_addr.s_addr),
					pfcp_config.s5s8_port, ntohs(s5s8_recv_sockaddr.sin_port));
		}

		resp->state =  MBR_REQ_SNT_STATE;
		pdn->state =  MBR_REQ_SNT_STATE;
		return 0;
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO STATE SET IN MBR  :%s\n", LOG_VALUE);
		/*No State Set*/
		return -1;
	}

	return 0;
}


uint8_t
process_pfcp_sess_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp,
		gtpv2c_header_t *gtpv2c_tx,ue_context *context,
		struct resp_info *resp)
{

	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn = NULL;
	uint64_t sess_id = pfcp_sess_mod_rsp->header.seid_seqno.has_seid.seid;

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	int ebi = UE_BEAR_ID(sess_id);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	bearer = context->eps_bearers[ebi_index];

	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to get pdn for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to get bearer for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (resp->msg_type == GTP_CREATE_SESSION_REQ) {
		/* Sent the CSR Response in the promotion case */
		if (context->cp_mode == SAEGWC) {
			/* Fill the Create session response */
			set_create_session_response(
					gtpv2c_tx, context->sequence, context, pdn, 0);
			pdn->csr_sequence = 0;
		}
	} else if (resp->msg_type == GTP_CREATE_SESSION_RSP) {
		/* Fill the Create session response */
		set_create_session_response(
				gtpv2c_tx, context->sequence, context, pdn, 0);
		pdn->csr_sequence = 0;

	} else if (resp->msg_type == GX_RAR_MSG ||
				resp->msg_type == GTP_BEARER_RESOURCE_CMD) {
			uint8_t pti = 0;
			if (resp->msg_type == GTP_BEARER_RESOURCE_CMD)
				pti  = context->proc_trans_id;

		ret = set_create_bearer_request(gtpv2c_tx, context->sequence, pdn,
				pdn->default_bearer_id, pti, resp, 0, FALSE);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;

		if (SAEGWC == context->cp_mode) {
			s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;
		} else {
			s5s8_recv_sockaddr.sin_addr.s_addr =
				pdn->s5s8_sgw_gtpc_ipv4.s_addr;
		}

		return ret;

	} else if (resp->msg_type == GTP_CREATE_BEARER_REQ) {

		/* TODO: Not handle PTI properly */
		if (context->proc_trans_id) {
			ret = set_create_bearer_request(gtpv2c_tx, context->sequence, pdn,
					pdn->default_bearer_id, context->proc_trans_id, resp, 0, FALSE);
		} else {
			ret = set_create_bearer_request(gtpv2c_tx, context->sequence, pdn,
					pdn->default_bearer_id, 0, resp, 0, TRUE);
		}

		context->proc_trans_id = 0;

		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
			context->s11_mme_gtpc_ipv4.s_addr;

		return ret;

	} else if (resp->msg_type == GTP_CREATE_BEARER_RSP) {

		if ((SAEGWC == context->cp_mode) || (PGWC == context->cp_mode)) {

			if(pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
				int index = GET_EBI_INDEX(resp->eps_bearer_ids[0]);
				if (index == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
				provision_ack_ccr(pdn, context->eps_bearers[index],
						RULE_ACTION_ADD, NO_FAIL, &pro_ack_rule_array);
				resp->msg_type = GX_CCR_MSG;
			} else {
				rar_funtions rar_function = NULL;
				rar_function = rar_process(pdn, pdn->proc);

				if(rar_function != NULL){
					ret = rar_function(pdn);
					if(ret)
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed in processing"
								"RAR function\n", LOG_VALUE);
				} else {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"None of the RAR function "
						"returned\n", LOG_VALUE);
				}
			}

			if (pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
				resp->msg_type = GX_CCR_MSG;
				resp->state = CONNECTED_STATE;
				pdn->state = CONNECTED_STATE;
			} else {
				resp->state = pdn->state;
				resp->msg_type = GX_RAA_MSG;
			}

			return 0;

		} else {
			uint32_t cbr_sequence = 0;
			ebi_index = -1;

			/* Get seuence number from bearer*/
			for(int itr = 0; itr < resp->bearer_count; itr++){
				ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[itr]);
				if (ebi_index != -1){
					break;
				}
			}
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			bearer = context->eps_bearers[ebi_index];
			cbr_sequence = bearer->sequence;
			set_create_bearer_response(
					gtpv2c_tx, cbr_sequence, pdn, resp->linked_eps_bearer_id, 0, resp);

			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;

			return 0;
		}
	} else if(resp->msg_type == GTP_DELETE_SESSION_REQ) {

		if (pdn->context->cp_mode == SGWC) {


			uint8_t encoded_msg[GTP_MSG_LEN] = {0};

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
						resp->linked_eps_bearer_id);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				pdn->s5s8_pgw_gtpc_ipv4.s_addr;

			/* Update the session state */
			resp->state = DS_REQ_SNT_STATE;

			/* Update the UE state */
			ebi_index = GET_EBI_INDEX(resp->linked_eps_bearer_id);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			ret = update_ue_state(context, DS_REQ_SNT_STATE, ebi_index);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					" update UE State for ebi_index : %d.\n", LOG_VALUE, ebi_index);
			}
			return 0;
		}

	} else if(resp->msg_type == GTP_RELEASE_ACCESS_BEARERS_REQ) {

		/* Update the session state */
		resp->state = IDEL_STATE;

		/* Update the UE state */
		pdn->state = IDEL_STATE;

		/* Fill the release bearer response */
		if(context->pfcp_sess_count == PRESENT) {
			uint16_t payload_length = 0;
			pfcp_sess_mod_rsp_t pfcp_sess_mod_resp ={0};

			set_release_access_bearer_response(gtpv2c_tx, pdn);

			s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s11_mme_sockaddr.sin_addr.s_addr :%s\n",
					LOG_VALUE,
					inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

			payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);

			gtpv2c_send(s11_fd, tx_buf, payload_length,
					(struct sockaddr *) &s11_mme_sockaddr,
					s11_mme_sockaddr_len,ACC);

			process_cp_li_msg(
					pfcp_sess_mod_resp.header.seid_seqno.has_seid.seid,
					S11_INTFC_OUT, tx_buf, payload_length,
					ntohl(pfcp_config.s11_ip.s_addr), ntohl(s11_mme_sockaddr.sin_addr.s_addr),
					pfcp_config.s11_port, ntohs(s11_mme_sockaddr.sin_port));
		} else {
			context->pfcp_sess_count--;
		}
		return 0;

	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"INVALID MSG TYPE", LOG_VALUE);
	}

	/* Update the session state */
	resp->state = CONNECTED_STATE;

	/* Update the UE state */
	pdn->state = CONNECTED_STATE;

	s11_mme_sockaddr.sin_addr.s_addr =
		context->s11_mme_gtpc_ipv4.s_addr;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s11_mme_sockaddr.sin_addr.s_addr :%s\n",
		LOG_VALUE,
		inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	return 0;
}

uint8_t
process_pfcp_sess_mod_resp_for_mod_proc(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"context for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	int ebi = UE_BEAR_ID(sess_id);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn "
			"for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get bearer "
			"for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if(SGWC == context->cp_mode) {

		if((context->second_rat_flag == TRUE) /*&& (context->second_rat.irpgw == 0)*/) {

			/* Fill the modify bearer response */
			set_modify_bearer_response_handover(gtpv2c_tx,
					context->sequence, context, bearer, &resp->gtpc_msg.mbr);
			resp->state = CONNECTED_STATE;
			/* Update the UE state */
			pdn->state = CONNECTED_STATE;
			return 0;
		}

		check_for_uli_changes(&resp->gtpc_msg.mbr.uli, pdn->context);
		set_modify_bearer_request(gtpv2c_tx, pdn, bearer);

		s5s8_recv_sockaddr.sin_addr.s_addr =
			pdn->s5s8_pgw_gtpc_ipv4.s_addr;

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

		if(SAEGWC == context->cp_mode){
			s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;
		}

		s5s8_recv_sockaddr.sin_addr.s_addr =
			pdn->s5s8_sgw_gtpc_ipv4.s_addr;

		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		pdn->state = CONNECTED_STATE;
	}
	return 0;
}

int
process_change_noti_request(change_noti_req_t *change_not_req, ue_context *context)
{
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;

	ebi_index = GET_EBI_INDEX(change_not_req->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get bearer "
			"for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	if(change_not_req->rat_type.header.len == 0)
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;

	pdn = bearer->pdn;

	if(change_not_req->imsi.header.len == 0) {

		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IMSI NOT FOUND in Change Notification Message\n", LOG_VALUE);
		return GTPV2C_CAUSE_IMSI_NOT_KNOWN;

	}

	context->sequence = change_not_req->header.teid.has_teid.seq;

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
			if(generate_cdr_info(&second_rat_data) == -1) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"failed to generate "
					"CDR\n",LOG_VALUE);
				return -1;
			}
		}
	}

	context->uli_flag = FALSE;
	check_for_uli_changes(&change_not_req->uli, pdn->context);

	if((pfcp_config.use_gx) && context->uli_flag != 0 ) {
		int ret = gen_ccru_request(pdn->context, bearer, NULL);
		return ret;
	}

	uint8_t payload_length = 0;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	set_change_notification_response(gtpv2c_tx, pdn);

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	if(context->cp_mode == PGWC) {
		s5s8_recv_sockaddr.sin_addr.s_addr =
			pdn->s5s8_sgw_gtpc_ipv4.s_addr;

		gtpv2c_send(s5s8_fd, tx_buf, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len,SENT);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					ntohl(pfcp_config.s5s8_ip.s_addr), ntohl(s5s8_recv_sockaddr.sin_addr.s_addr),
					pfcp_config.s5s8_port, ntohs(s5s8_recv_sockaddr.sin_port));
		}

	} else {

		s11_mme_sockaddr.sin_addr.s_addr =
			pdn->context->s11_mme_gtpc_ipv4.s_addr;

		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len, SENT);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S11_INTFC_OUT, tx_buf, payload_length,
					ntohl(pfcp_config.s11_ip.s_addr), ntohl(s11_mme_sockaddr.sin_addr.s_addr),
					pfcp_config.s11_port, ntohs(s11_mme_sockaddr.sin_port));
		}
	}

	return 0;
}

int
process_change_noti_response(change_noti_rsp_t *change_not_rsp, gtpv2c_header_t *gtpv2c_tx)
{
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int ret = 0;
	change_noti_rsp_t change_notification_rsp = {0};

	ret = get_ue_context_by_sgw_s5s8_teid(change_not_rsp->header.teid.has_teid.teid, &context);
	if (ret < 0 || !context) {
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ret = get_bearer_by_teid(change_not_rsp->header.teid.has_teid.teid, &bearer);
	if(ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get bearer "
			"for teid: %u\n", LOG_VALUE, change_not_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = bearer->pdn;

	set_gtpv2c_teid_header((gtpv2c_header_t *) &change_notification_rsp, GTP_CHANGE_NOTIFICATION_RSP,
		context->s11_mme_gtpc_teid, context->sequence, 0);

	set_cause_accepted(&change_notification_rsp.cause, IE_INSTANCE_ZERO);
	change_notification_rsp.cause.cause_value = change_not_rsp->cause.cause_value;

	memcpy(&change_notification_rsp.imsi.imsi_number_digits, &(context->imsi), context->imsi_len);
	set_ie_header(&change_notification_rsp.imsi.header, GTP_IE_IMSI, IE_INSTANCE_ZERO,
			context->imsi_len);

	s11_mme_sockaddr.sin_addr.s_addr =
		context->s11_mme_gtpc_ipv4.s_addr;

	uint16_t msg_len = 0;
	msg_len = encode_change_noti_rsp(&change_notification_rsp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

	pdn->state =  CONNECTED_STATE;
	pdn->proc = CHANGE_NOTIFICATION_PROC;
	return 0;

}

int
process_sgwc_delete_session_request(del_sess_req_t *del_req, ue_context *context)
{
	int ebi_index = 0;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	struct teid_value_t *teid_value = NULL;
	int ret = 0;
	teid_key_t teid_key = {0};

	ebi_index = GET_EBI_INDEX(del_req->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Received Delete Session "
			"on non-existent EBI : %d.Dropping packet\n",LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn "
			"for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, pdn, pdn->eps_bearers,
																MAX_BEARERS);

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	/* UPF ip address  */
	upf_pfcp_sockaddr.sin_addr.s_addr = pdn->upf_ipv4.s_addr;
	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending PFCP Session "
			"Modification Request for Delete Session Request %i\n", LOG_VALUE, errno);
	} else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update the sequence number */
	context->sequence = del_req->header.teid.has_teid.seq;

	teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (teid_value == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for Teid Value structure, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	teid_value->teid = pdn->s5s8_sgw_gtpc_teid;
	teid_value->msg_type = del_req->header.gtpc.message_type;

	snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(pdn->proc),
		del_req->header.teid.has_teid.seq);

	if (context->cp_mode != SAEGWC) {
		ret = add_seq_number_for_teid(teid_key, teid_value);
		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"Sequence number key for TEID: %u\n", LOG_VALUE,
					teid_value->teid);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry "
			"Found for sess ID : %lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	resp->gtpc_msg.dsr = *del_req;
	resp->linked_eps_bearer_id = del_req->lbi.ebi_ebi;
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	resp->cp_mode = pdn->context->cp_mode;

	return 0;
}

int
process_pfcp_sess_del_request(del_sess_req_t *ds_req, ue_context *context)
{

	int ret = 0;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	int ebi_index = GET_EBI_INDEX(ds_req->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Lookup and get context of delete request */
	ret = delete_context(ds_req->lbi, ds_req->header.teid.has_teid.teid, &context, &pdn);
	if (ret)
		return ret;

	if (pdn == NULL || context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn or "
			"UE context for ebi_index : %d\n ", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	/* Fill the target UPF ip address  */
	upf_pfcp_sockaddr.sin_addr.s_addr = pdn->upf_ipv4.s_addr;

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error sending pfcp session "
			"deletion request : %i\n", LOG_VALUE, errno);
		return -1;
	} else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update the sequence number */
	context->sequence = ds_req->header.teid.has_teid.seq;

	/* Update UE State */
	pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for sess ID : %lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	/* Store s11 struture data into sm_hash for sending delete response back to s11 */
	resp->gtpc_msg.dsr = *ds_req;
	resp->linked_eps_bearer_id = ds_req->lbi.ebi_ebi;
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	resp->cp_mode = context->cp_mode;
	resp->teid = context->s11_sgw_gtpc_teid;

	return 0;
}


int
process_pfcp_sess_del_request_delete_bearer_rsp(del_bearer_rsp_t *db_rsp)
{
	int ret = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	pdn_connection *pdn = NULL;
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	int ebi_index = GET_EBI_INDEX(db_rsp->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	ret = delete_context(db_rsp->lbi, db_rsp->header.teid.has_teid.teid,
														&context, &pdn);
	if (ret)
		return ret;

	if (pdn == NULL || context == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn or "
			"UE context for ebi_index : %d\n ", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (ret && ret!=-1)
		return ret;

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error sending Session "
			"Modification Request %i\n", LOG_VALUE, errno);
		return -1;
	} else  {

#ifdef CP_BUILD
		add_pfcp_if_timer_entry(db_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update the sequence number */
	context->sequence = db_rsp->header.teid.has_teid.seq;

	/* Update UE State */
	pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->linked_eps_bearer_id = db_rsp->lbi.ebi_ebi;
	resp->msg_type = GTP_DELETE_BEARER_RSP;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
	resp->proc = pdn->proc;
	resp->cp_mode = context->cp_mode;

	return 0;
}

int
delete_dedicated_bearers(pdn_connection *pdn,
		uint8_t bearer_ids[], uint8_t bearer_cntr)
{

	/* Delete multiple dedicated bearer of pdn */
	for (int iCnt = 0; iCnt < bearer_cntr; ++iCnt) {
		int ebi_index = GET_EBI_INDEX(bearer_ids[iCnt]);

		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return -1;
		}

		/* Delete PDR, QER of bearer */
		if (del_rule_entries(pdn, ebi_index)) {
			/* TODO: Error message handling in case deletion failed */
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to delete rule entries for "
				"ebi_index : %d \n", LOG_VALUE, ebi_index);
			return -1;
		}

		delete_bearer_context(pdn, ebi_index);
	}

	return 0;
}

int
del_rule_entries(pdn_connection *pdn, int ebi_index )
{
	int ret = 0;
	pdr_t *pdr_ctx =  NULL;

	/*Delete all pdr, far, qer entry from table */
	if (pfcp_config.use_gx) {
		for(uint8_t itr = 0; itr < pdn->eps_bearers[ebi_index]->qer_count; itr++) {
			if( del_qer_entry(pdn->eps_bearers[ebi_index]->qer_id[itr].qer_id) != 0 ){
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failure in deleting QER entry for ebi_index : %d, "
					"Error : %s \n", LOG_VALUE, ebi_index, strerror(ret));
			}
		}
	}

	for(uint8_t itr = 0; itr < pdn->eps_bearers[ebi_index]->pdr_count; itr++) {
		pdr_ctx = pdn->eps_bearers[ebi_index]->pdrs[itr];
		if(pdr_ctx == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"No PDR entry found for ebi_index : %d, "
				"Error : %s \n", LOG_VALUE, ebi_index, strerror(ret));
		} else {
			if( del_pdr_entry(pdr_ctx->rule_id) != 0 ){
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failure in deleting PDR entry for ebi_index : %d, "
					"Error : %s \n", LOG_VALUE, ebi_index, strerror(ret));
			}
			/* Reset PDR to NULL in bearer */
			pdn->eps_bearers[ebi_index]->pdrs[itr] = NULL;
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

			if (context->cp_mode != PGWC)
				csid = get_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
			else
				csid = get_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);

			if (csid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"MME CSID found null while clean up process "
					"for session entries %s \n", LOG_VALUE, strerror(errno));
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
				if (context->cp_mode != PGWC)
					ret = del_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
				else
					ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to delete peer MME csid entry %s \n", LOG_VALUE,
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

			if (context->cp_mode != PGWC)
				csid = get_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
			else
				csid = get_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
			if (csid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"SGW CSID found null while clean up process "
					"for session entries %s \n", LOG_VALUE, strerror(errno));
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
				if (context->cp_mode != PGWC)
					ret = del_peer_csid_entry(&key_t, S11_SGW_PORT_ID);
				else
					ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to delete peer SGW CSID entry %s \n", LOG_VALUE,
						strerror(errno));
					return -1;
				}
			}
		}
		if (context->sgw_fqcsid != NULL)
			rte_free(context->sgw_fqcsid);
	}

	if (context->cp_mode != SAEGWC) {
		/* Clean PGW FQ-CSID */
		if (context->pgw_fqcsid != NULL) {
			if ((context->pgw_fqcsid)->num_csid) {
				csid_t *csid = NULL;
				csid_key_t key_t = {0};
				key_t.local_csid = (context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1];
				key_t.node_addr = (context->pgw_fqcsid)->node_addr;

				if (context->cp_mode != PGWC)
					csid = get_peer_csid_entry(&key_t, S5S8_SGWC_PORT_ID);
				else
					csid = get_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
				if (csid == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"PGW CSID found null while clean up process "
						"for session entries %s \n", LOG_VALUE, strerror(errno));
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
					if (context->cp_mode != PGWC)
						ret = del_peer_csid_entry(&key_t, S5S8_SGWC_PORT_ID);
					else
						ret = del_peer_csid_entry(&key_t, S5S8_PGWC_PORT_ID);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to delete peer PGW CSID entry %s \n", LOG_VALUE,
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
					LOG_FORMAT"UP CSID found null while clean up process "
					"for session entries %s \n", LOG_VALUE, strerror(errno));
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
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to delete peer UP CSID entry %s \n", LOG_VALUE,
						strerror(errno));
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
		gx_msg *ccr_request, uint16_t *msglen, ue_context *context)
{
	int ebi_index = 0;
	uint16_t msg_len = 0;
	struct resp_info *resp = NULL;
	pdn_connection *pdn =  NULL;
	del_sess_rsp_t del_resp = {0};
	uint32_t sender_teid = 0;
	int ret = 0;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO response Entry "
			"Found for sess ID : %lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_DEL_RESP_RCVD_STATE;
	resp->cp_mode = context->cp_mode;

	ebi_index = GET_EBI_INDEX(resp->linked_eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn "
			"for ebi_index : %d ",LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the UE state */
	pdn->state = PFCP_SESS_DEL_RESP_RCVD_STATE;

	if ((pfcp_config.use_gx) && context->cp_mode != SGWC) {

		gx_context_t *gx_context = NULL;

		/* Retrive Gx_context based on Sess ID. */
		ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
				(const void*)(pdn->gx_sess_id), (void **)&gx_context);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN "
				"Gx HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
		/* Set the CP Mode, to check the CP mode after session deletion */
		gx_context->cp_mode = context->cp_mode;

		/* Set the Msg header type for CCR-T */
		ccr_request->msg_type = GX_CCR_MSG ;

		/* Set Credit Control Request type */
		ccr_request->data.ccr.presence.cc_request_type = PRESENT;
		ccr_request->data.ccr.cc_request_type = TERMINATION_REQUEST ;

		/* Set Credit Control Bearer opertaion type */
		ccr_request->data.ccr.presence.bearer_operation = PRESENT;
		ccr_request->data.ccr.bearer_operation = TERMINATION ;

		/* Fill the Credit Crontrol Request to send PCRF */
		if(fill_ccr_request(&ccr_request->data.ccr, context,
					ebi_index, pdn->gx_sess_id, 0) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed CCR request "
				"filling process\n", LOG_VALUE);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
		/* Update UE State */
		pdn->state = CCR_SNT_STATE;

		/* Set the Gx State for events */
		gx_context->state = CCR_SNT_STATE;
		gx_context->proc = pdn->proc;

		/* Calculate the max size of CCR msg to allocate the buffer */
		*msglen = gx_ccr_calc_length(&ccr_request->data.ccr);
		ccr_request->msg_len = *msglen + GX_HEADER_LEN;

	}

	if ( context->cp_mode == PGWC) {

		s5s8_recv_sockaddr.sin_addr.s_addr = pdn->s5s8_sgw_gtpc_ipv4.s_addr;
		sender_teid = pdn->s5s8_sgw_gtpc_teid;
		clLog(clSystemLog, eCLSeverityDebug, "Msg Sent to "LOG_FORMAT
				"IP Address :%s\n", LOG_VALUE,
				inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));
	} else {

		s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;
		sender_teid = context->s11_mme_gtpc_teid;
		clLog(clSystemLog, eCLSeverityDebug, "Msg Sent to "LOG_FORMAT
				"IP Address :%s\n", LOG_VALUE,
				inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	}

	/* Fill gtpv2c structure for sending on s11/s5s8 interface */
	fill_del_sess_rsp(&del_resp, context->sequence, sender_teid);

	/*Encode the S11 delete session response message. */
	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

	gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;
	header->gtpc.message_len = htons(msg_len -IE_HEADER_SIZE);

	/* Update status of dsr processing for ue */
	context->dsr_info.seq = 0;
	context->dsr_info.status = DSR_PROCESS_DONE;

	delete_sess_context(context, pdn);
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

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr, &upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in upf context "
			"lookup.Error:%d \n", LOG_VALUE, ret);
		return;
	}

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq, pdn->context->cp_mode);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	/* Adding FAR IE*/
	pfcp_sess_mod_req->update_far_count = 0;
	for (int index = 0; index < bearer_cntr; index++) {
		if (bearers[index] != NULL) {
			for(uint8_t itr = 0; itr < bearers[index]->pdr_count ; itr++) {
				pdr_ctxt = bearers[index]->pdrs[itr];
				if (pdr_ctxt) {
					/*Just need to Drop the packets that's why disabling
					 * all other supported action*/
					pdr_ctxt->far.actions.forw = FALSE;
					pdr_ctxt->far.actions.dupl = GET_DUP_STATUS(pdn->context);
					pdr_ctxt->far.actions.nocp = FALSE;
					pdr_ctxt->far.actions.buff = FALSE;
					pdr_ctxt->far.actions.drop = TRUE;

					set_update_far(&(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]),
																						&pdr_ctxt->far);
					pfcp_sess_mod_req->update_far_count++;
				}
			}
		}
	}
}

void
fill_pfcp_sess_mod_req_pgw_init_remove_pdr(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr)
{

	int ret = 0;
	uint32_t seq = 0;
	eps_bearer *bearer = NULL;
	pdr_t *pdr_ctxt = NULL;
	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr, &upf_ctx)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Error while extracting "
			"upf context: %d \n", LOG_VALUE, ret);
		return;
	}

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq, pdn->context->cp_mode);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid,  pfcp_config.pfcp_ip.s_addr);

	pfcp_sess_mod_req->remove_pdr_count = 0;
	for (uint8_t index = 0; index < bearer_cntr; index++){
		bearer = bearers[index];
		if(bearer != NULL) {

			for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					set_remove_pdr(&(pfcp_sess_mod_req->remove_pdr[pfcp_sess_mod_req->remove_pdr_count]),
																						pdr_ctxt->rule_id);
					pfcp_sess_mod_req->remove_pdr_count++;

				}
			}
		}

		bearer = NULL;
	}
}


uint8_t
process_pfcp_sess_mod_resp_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		ue_context *context)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[0]);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Update the UE state */
	ret = update_ue_state(context, PFCP_SESS_MOD_RESP_RCVD_STATE ,ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to update UE "
			"State\n", LOG_VALUE, context->pdns[ebi_index]->s5s8_pgw_gtpc_teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
			"bearer for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	/* Fill the modify bearer response */
	set_modify_bearer_response_handover(gtpv2c_tx,
			context->sequence, context, bearer, &resp->gtpc_msg.mbr);

	/* Update the session state */
	resp->state = CONNECTED_STATE;
	bearer->pdn->state = CONNECTED_STATE;

	/* Update the UE state */
	ret = update_ue_state(context, CONNECTED_STATE, ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to update UE "
			"State for ebi_index : %d \n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	s5s8_recv_sockaddr.sin_addr.s_addr = bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", LOG_VALUE,
			inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));
	return 0;
}


int
process_pfcp_sess_mod_resp_cs_cbr_request(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx, struct resp_info *resp)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);
	gtpv2c_header_t *gtpv2c_cbr_t = NULL;
	uint16_t msg_len = 0;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to update UE "
			"State for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	int ebi = UE_BEAR_ID(sess_id);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	bearer = context->eps_bearers[ebi_index];
	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get pdn "
			"for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		/*send mbr resp to mme and create brearer resp to pgw*/

		set_modify_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer, &resp->gtpc_msg.mbr);
		s11_mme_sockaddr.sin_addr.s_addr =
			context->s11_mme_gtpc_ipv4.s_addr;

		if ((SAEGWC == context->cp_mode)) {
			if (pfcp_config.use_gx) {

				rar_funtions rar_function = NULL;
				rar_function = rar_process(pdn,	pdn->proc);

				if (rar_function != NULL) {
					ret = rar_function(pdn);
					if(ret)
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed in processing"
							"RAR function\n", LOG_VALUE);
				} else {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"None of the RAR function "
						"returned\n", LOG_VALUE);
				}

				struct sockaddr_in saddr_in;
				saddr_in.sin_family = AF_INET;
				inet_aton(CLI_GX_IP, &(saddr_in.sin_addr));
				update_cli_stats(saddr_in.sin_addr.s_addr, OSS_RAA, SENT, GX);

				resp->state = pdn->state;

				return 0;

			}
		} else {
			int ebi_index = GET_EBI_INDEX(resp->eps_bearer_ids[0]);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			bearer = context->eps_bearers[ebi_index];
			set_create_bearer_response(
				gtpv2c_tx, bearer->sequence, pdn, resp->linked_eps_bearer_id, 0, resp);

			resp->state = CONNECTED_STATE;
			pdn->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr =
				bearer->pdn->s5s8_pgw_gtpc_ipv4.s_addr;

			return 0;
		}

	} else {

		/* Fill the create session  response */

		msg_len = set_create_session_response(
					gtpv2c_tx, context->sequence, context, bearer->pdn, 1);
		gtpv2c_cbr_t = (gtpv2c_header_t *)((uint8_t *)gtpv2c_tx + msg_len);

		/* Fill the Create bearer request*/
		ret = set_create_bearer_request(gtpv2c_cbr_t, context->sequence, pdn,
				pdn->default_bearer_id, 0, resp, 0, TRUE);


		s11_mme_sockaddr.sin_addr.s_addr =
			context->s11_mme_gtpc_ipv4.s_addr;
		resp->state = CREATE_BER_REQ_SNT_STATE;
		pdn->state = CREATE_BER_REQ_SNT_STATE;
		pdn->csr_sequence =0;


	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", LOG_VALUE,
			inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));
	return 0;
}

int8_t
check_if_bearer_index_free(ue_context *context, int ebi_index)
{
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		return -1;
	}
		return 0;
}

int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt)
{
	int ret = 0;
	int bearer_id = pdn_cntxt->num_bearer;
	for(uint8_t icnt = pdn_cntxt->num_bearer; icnt< MAX_BEARERS; icnt++){
		ret = check_if_bearer_index_free(pdn_cntxt->context, bearer_id);
		if(ret == 0){
			return bearer_id;
		} else {
			bearer_id++;
			continue;
		}
	}
	clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
	return -1;

}

void
send_pfcp_sess_mod_req_for_li(uint64_t imsi)
{
	int ret = 0;
	uint32_t seq = 0;
	uint8_t ebi_index = 0;
	pdr_t *pdr_ctxt = NULL;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_ctx = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req;
	imsi_id_hash_t *imsi_id_config = NULL;

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
			(void **) &(context));
	if (ret == -ENOENT){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"No data found for %x imsi\n"
				, LOG_VALUE, imsi);

		return;
	}

	if (NULL == context) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"UE context is NULL\n", LOG_VALUE);

		/* Ue is not attach yet, so no need to send modification request */
		return;
	}

	/* get user level packet copying token or id using imsi */
	ret = get_id_using_imsi(context->imsi, &imsi_id_config);
	if (ret < 0) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Not applicable for li\n",
				LOG_VALUE);

		if (PRESENT == context->dupl) {

			context->dupl = NOT_PRESENT;
			context->li_data_cntr = 0;
			memset(context->li_data, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_data_t));
		} else {

			return;
		}
	}

	if (NULL != imsi_id_config) {

		/* Fillup context from li hash */
		fill_li_config_in_context(context, imsi_id_config);
	}


	for (uint8_t bearerCntr = 0; bearerCntr < MAX_BEARERS; bearerCntr++) {

		if (NULL == context->eps_bearers[bearerCntr]) {

			continue;
		}

		bearer = context->eps_bearers[bearerCntr];
		pdn = bearer->pdn;

		if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
						&upf_ctx)) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: Lookup of upf %d \n",
					LOG_VALUE, ret);
			return;
		}

		memset(&pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

		seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

		set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header), PFCP_SESSION_MODIFICATION_REQUEST,
				HAS_SEID, seq, context->cp_mode);

		pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

		char pAddr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
		unsigned long node_value = inet_addr(pAddr);

		set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn->seid, node_value);

		pfcp_sess_mod_req.update_far_count = NOT_PRESENT;

		for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {

			pdr_ctxt = bearer->pdrs[itr];
			if (pdr_ctxt) {

				set_update_far(&(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count]), NULL);

				pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
						pdr_ctxt->far.far_id_value;

				pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl =
						GET_DUP_STATUS(pdn->context);
				pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;

				if (PRESENT == pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count].apply_action.dupl) {

					update_li_info_in_upd_dup_params(imsi_id_config, context,
							&(pfcp_sess_mod_req.update_far[pfcp_sess_mod_req.update_far_count]));
				}

				pfcp_sess_mod_req.update_far_count++;
			}
		}
	}

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error sending: %i\n",
				LOG_VALUE, errno);
	} else {
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
				&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
	}
}

uint8_t
fill_li_policy(uint8_t *li_policy, li_df_config_t *li_config, uint8_t cp_mode) {

	switch(cp_mode) {

		case SGWC: {

			if ((SX_COPY_DP_MSG == li_config->uiSxa) ||
					(SX_COPY_CP_DP_MSG == li_config->uiSxa)) {

				li_policy[FRWDING_PLCY_SX] = PRESENT;
			} else {
				li_policy[FRWDING_PLCY_SX] = NOT_PRESENT;
			}

			li_policy[FRWDING_PLCY_WEST_DIRECTION] = li_config->uiS1u;
			li_policy[FRWDING_PLCY_WEST_CONTENT] = li_config->uiS1uContent;

			li_policy[FRWDING_PLCY_EAST_DIRECTION] = li_config->uiSgwS5s8U;
			li_policy[FRWDING_PLCY_EAST_CONTENT] = li_config->uiSgwS5s8UContent;

			break;
		}

		case PGWC: {

			if ((SX_COPY_DP_MSG == li_config->uiSxb) ||
					(SX_COPY_CP_DP_MSG == li_config->uiSxb)) {

				li_policy[FRWDING_PLCY_SX] = PRESENT;
			} else {
				li_policy[FRWDING_PLCY_SX] = NOT_PRESENT;
			}

			li_policy[FRWDING_PLCY_WEST_DIRECTION] = li_config->uiPgwS5s8U;
			li_policy[FRWDING_PLCY_WEST_CONTENT] = li_config->uiPgwS5s8UContent;

			li_policy[FRWDING_PLCY_EAST_DIRECTION] = li_config->uiSgi;
			li_policy[FRWDING_PLCY_EAST_CONTENT] = li_config->uiSgiContent;

			break;
		}

		case SAEGWC: {

			if ((SX_COPY_DP_MSG == li_config->uiSxaSxb) ||
					(SX_COPY_CP_DP_MSG == li_config->uiSxaSxb)) {

				li_policy[FRWDING_PLCY_SX] = PRESENT;
			} else {
				li_policy[FRWDING_PLCY_SX] = NOT_PRESENT;
			}

			li_policy[FRWDING_PLCY_WEST_DIRECTION] = li_config->uiS1u;
			li_policy[FRWDING_PLCY_WEST_CONTENT] = li_config->uiS1uContent;

			li_policy[FRWDING_PLCY_EAST_DIRECTION] = li_config->uiSgi;
			li_policy[FRWDING_PLCY_EAST_CONTENT] = li_config->uiSgiContent;

			break;
		}
	}

	li_policy[FRWDING_PLCY_FORWARD] = li_config->uiForward;
	memcpy(&li_policy[FRWDING_PLCY_ID], &li_config->uiId, sizeof(uint64_t));

	return (FRWDING_PLCY_ID + sizeof(uint64_t));
}

int
update_li_info_in_dup_params(imsi_id_hash_t *imsi_id_config, ue_context *context,
		pfcp_create_far_ie_t *far) {

	int ret = 0;
	int dup_cntr = 0;
	uint8_t li_policy_len = 0;
	li_df_config_t *li_config = NULL;
	uint8_t li_policy[MAX_LI_POLICY_LIMIT] = {0};

	for (uint8_t cnt = 0; cnt < imsi_id_config->cntr; cnt++) {

		ret = get_li_config(imsi_id_config->ids[cnt], &li_config);
		if (!ret) {

			context->dupl = PRESENT;
			far->apply_action.dupl = GET_DUP_STATUS(context);
			if (far->apply_action.dupl == PRESENT) {

				li_policy_len = fill_li_policy(li_policy, li_config, context->cp_mode);

				uint16_t len = fill_dup_param(&(far->dupng_parms[dup_cntr]), li_policy,
						li_policy_len);
				far->header.len += len;
				dup_cntr++;
			}
		}
	}

	far->dupng_parms_count = dup_cntr;

	return 0;
}

int
update_li_info_in_upd_dup_params(imsi_id_hash_t *imsi_id_config, ue_context *context,
		pfcp_update_far_ie_t *far) {

	int ret = 0;
	int dup_cntr = 0;
	uint8_t li_policy_len = 0;
	li_df_config_t *li_config = NULL;
	uint8_t li_policy[MAX_LI_POLICY_LIMIT] = {0};

	for (uint8_t cnt = 0; cnt < imsi_id_config->cntr; cnt++) {

		ret = get_li_config(imsi_id_config->ids[cnt], &li_config);
		if (!ret) {

			context->dupl = PRESENT;
			far->apply_action.dupl = GET_DUP_STATUS(context);
			if (far->apply_action.dupl == PRESENT) {

				li_policy_len = fill_li_policy(li_policy, li_config, context->cp_mode);

				uint16_t len = fill_upd_dup_param(&(far->upd_dupng_parms[dup_cntr]), li_policy,
						li_policy_len);
				far->header.len += len;
				dup_cntr++;
			}
		}
	}

	far->upd_dupng_parms_count = dup_cntr;

	return 0;
}

int
process_pfcp_sess_setup(pdn_connection *pdn) {

	int ebi_index = 0;
	int ret = 0;
	uint8_t index = 0;
	upf_context_t *upf_context = NULL;
	struct resp_info *resp = NULL;

	/* Retrive EBI index from Default EBI */
	ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n",
			LOG_VALUE);
		return -1;
	}

	ret = process_pfcp_assoication_request(pdn, ebi_index);
	if (ret) {
		if(ret != -1) {
			send_error_resp(pdn, ret);
		}

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in Processing "
			"PFCP Association Request with cause %s \n", LOG_VALUE,
			cause_str(ret));
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Add UPF Entry for IP:"IPV4_ADDR"\n",
		 LOG_VALUE, IPV4_ADDR_HOST_FORMAT(pdn->upf_ipv4.s_addr));

	/* Retrive association state based on UPF IP. */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ipv4.s_addr), (void **) &(upf_context));

	/* send error response in case of pfcp est. fail using this data */
	if(upf_context->state == PFCP_ASSOC_RESP_RCVD_STATE) {
		ret = get_sess_entry(pdn->seid, &resp);
		if(ret != -1 && resp != NULL){
			if(pdn->context->cp_mode == PGWC) {
				resp->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = pdn->s5s8_sgw_gtpc_teid;
				resp->gtpc_msg.csr.header.teid.has_teid.teid = pdn->s5s8_pgw_gtpc_teid;
			}

			if(pdn->context->cp_mode == SAEGWC || pdn->context->cp_mode == SGWC) {
				resp->gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = pdn->context->s11_mme_gtpc_teid;
				resp->gtpc_msg.csr.header.teid.has_teid.teid = pdn->context->s11_sgw_gtpc_teid;
			}

			resp->gtpc_msg.csr.header.teid.has_teid.seq = pdn->context->sequence;
			for (uint8_t itr = 0; itr < MAX_BEARERS; ++itr) {
				if(pdn->eps_bearers[itr] != NULL){
					resp->gtpc_msg.csr.bearer_contexts_to_be_created[index].header.len =
						sizeof(uint8_t) + IE_HEADER_SIZE;
					resp->gtpc_msg.csr.bearer_contexts_to_be_created[index].eps_bearer_id.ebi_ebi =
						pdn->context->eps_bearers[itr]->eps_bearer_id;
					index++;
				}
			}
			resp->gtpc_msg.csr.bearer_count = index;
		}
	}

	return 0;
}

int
provision_ack_ccr(pdn_connection *pdn, eps_bearer *bearer,
					enum rule_action_t rule_action, enum rule_failure_code error_code,
					pro_ack_rule_array_t *rule_report) {


	/* Initialize the Gx Parameters */
	int ret = 0;
	int ebi_index = 0;
	uint16_t msg_len = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" NO ENTRY FOUND "
				"IN Gx HASH [%s]\n", LOG_VALUE,pdn->gx_sess_id);
		return -1;
	}

	/* Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = UPDATE_REQUEST ;
	ccr_request.data.ccr.presence.network_request_support = PRESENT;
	ccr_request.data.ccr.network_request_support = NETWORK_REQUEST_SUPPORTED;

	ccr_request.data.ccr.presence.charging_rule_report = PRESENT;
	ccr_request.data.ccr.charging_rule_report.count = rule_report->rule_cnt;

	ccr_request.data.ccr.charging_rule_report.list = rte_malloc_socket(NULL,
			(sizeof(GxChargingRuleReportList)*(rule_report->rule_cnt)),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(ccr_request.data.ccr.charging_rule_report.list == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
				"allocate memory for Charging rule report information avp : %s", LOG_VALUE,
				rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	for(int id = 0; id < rule_report->rule_cnt; id++) {
		 memset(&ccr_request.data.ccr.charging_rule_report.list[id].presence, 0 ,
				 sizeof(ccr_request.data.ccr.charging_rule_report.list[id].presence));
		ccr_request.data.ccr.charging_rule_report.list[id].presence.charging_rule_name = PRESENT;
		ccr_request.data.ccr.charging_rule_report.list[id].charging_rule_name.count = 1;
		ccr_request.data.ccr.charging_rule_report.list[id].charging_rule_name.list =
			rte_malloc_socket(NULL,(sizeof(GxChargingRuleNameOctetString)*1),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

		if(ccr_request.data.ccr.charging_rule_report.list[id].charging_rule_name.list == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					"allocate memory for Charging rule name avp : %s", LOG_VALUE,
					rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		ccr_request.data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].len =
			strlen(rule_report->rule[id].rule_name);
		memcpy(&ccr_request.data.ccr.charging_rule_report.list[id].charging_rule_name.list[0].val,
				rule_report->rule[id].rule_name, strlen(rule_report->rule[id].rule_name));

		ccr_request.data.ccr.charging_rule_report.list[id].presence.
			pcc_rule_status = PRESENT;

		if (error_code != 0 || rule_action == RULE_ACTION_DELETE ) {
			ccr_request.data.ccr.charging_rule_report.list[id].
				pcc_rule_status = INACTIVE;
		} else {
			ccr_request.data.ccr.charging_rule_report.list[id].
				pcc_rule_status = rule_report->rule[id].rule_status;
		}

		if(error_code != 0) {
			ccr_request.data.ccr.charging_rule_report.list[id].presence.rule_failure_code = PRESENT;
			ccr_request.data.ccr.charging_rule_report.list[id].rule_failure_code = error_code;
		}
	}

	uint8_t evnt_tigger_list[EVENT_TRIGGER_LIST] = {0};
	ccr_request.data.ccr.event_trigger.count = 0;

	/*Event-Trigger will send for succesful operation */
	if (error_code == 0) {
		if (rule_action == RULE_ACTION_ADD || rule_action ==  RULE_ACTION_MODIFY) {
			ccr_request.data.ccr.presence.event_trigger = PRESENT;
			evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] =
				SUCCESSFUL_RESOURCE_ALLOCATION;
		} else {
			ccr_request.data.ccr.presence.event_trigger = PRESENT;
			evnt_tigger_list[ccr_request.data.ccr.event_trigger.count++] =
				RESOURCE_RELEASE;
		}
	}


	ccr_request.data.ccr.event_trigger.list = (int32_t *)malloc(
			ccr_request.data.ccr.event_trigger.count * sizeof(int32_t));

	for(uint8_t count = 0; count < ccr_request.data.ccr.event_trigger.count; count++ ) {
		*(ccr_request.data.ccr.event_trigger.list + count) =
			evnt_tigger_list[count];
	}


	char *temp = inet_ntoa(pdn->ipv4);
	memcpy(ccr_request.data.ccr.framed_ip_address.val, &temp, strnlen(temp,(GX_FRAMED_IP_ADDRESS_LEN + 1)));
	ebi_index = GET_EBI_INDEX(bearer->eps_bearer_id);
	if(ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid"
				"ebi_index ", LOG_VALUE);
		return -1;
	}

	/* Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr,
				pdn->context, ebi_index,
				pdn->gx_sess_id,0) != 0) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed CCR request "
				"filling process\n", LOG_VALUE);
		return -1;
	}

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton(CLI_GX_IP, &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_UPDATE, SENT, GX);


	/* Update UE State */
	pdn->state = PROVISION_ACK_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = PROVISION_ACK_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = PROVISION_ACK_SNT_STATE;
	gx_context->proc = pdn->proc;

	/*Clear pti and ue_initiated_seq_no*/
	pdn->context->proc_trans_id = 0;
	pdn->context->ue_initiated_seq_no = 0;

	/* Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	ccr_request.msg_len = msg_len + GX_HEADER_LEN;
	buffer = rte_zmalloc_socket(NULL, msg_len + GX_HEADER_LEN,
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failure to allocate CCR Buffer"
			" memory structure: %s\n", LOG_VALUE, rte_strerror(rte_errno));
		return -1;
	}

	/* Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
	memcpy(buffer + sizeof(ccr_request.msg_type),
							&ccr_request.msg_len,
					sizeof(ccr_request.msg_len));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + GX_HEADER_LEN),
				msg_len) == 0) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR in Packing CCR "
				"Buffer\n", LOG_VALUE);
		rte_free(buffer);

		return -1;

	}
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + GX_HEADER_LEN);

	rte_free(buffer);
	free_dynamically_alloc_memory(&ccr_request);
	memset(rule_report, 0, sizeof(pro_ack_rule_array_t));

	return 0;
}

void
reset_resp_info_structure(struct resp_info *resp)
{
	if (resp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Response received is "
			"NULL\n", LOG_VALUE);
		return;
	}

	resp->proc = NONE_PROC;
	resp->state = SGWC_NONE_STATE;
	resp->linked_eps_bearer_id = 0;
	for(uint8_t iterator = 0 ; iterator <resp->bearer_count; iterator++){
		resp->eps_bearer_ids[iterator] = 0;
	}
	resp->bearer_count = 0;

	if(resp->gtpc_msg.csr.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.csr, 0, sizeof(create_sess_req_t));

	} else if(resp->gtpc_msg.cs_rsp.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.cs_rsp, 0, sizeof(create_sess_rsp_t));

	} else if(resp->gtpc_msg.mbr.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.mbr, 0, sizeof(mod_bearer_req_t));

	} else if(resp->gtpc_msg.cb_req.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.cb_req, 0, sizeof(create_bearer_req_t));

	} else if(resp->gtpc_msg.cb_rsp.header.gtpc.message_len != 0) {
		memset((void*)&resp->gtpc_msg.cb_rsp, 0, sizeof(create_bearer_rsp_t));

	} else if(resp->gtpc_msg.dsr.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.dsr, 0, sizeof(del_sess_req_t));

	} else if(resp->gtpc_msg.rel_acc_ber_req.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.rel_acc_ber_req, 0, sizeof(rel_acc_ber_req_t));

	} else if(resp->gtpc_msg.del_bearer_cmd.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.del_bearer_cmd, 0, sizeof(del_bearer_cmd_t));

	} else if(resp->gtpc_msg.bearer_rsrc_cmd.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.bearer_rsrc_cmd, 0, sizeof(bearer_rsrc_cmd_t));

	} else if(resp->gtpc_msg.change_not_req.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.change_not_req, 0, sizeof(change_noti_req_t));

	} else if(resp->gtpc_msg.db_req.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.db_req, 0, sizeof(del_bearer_req_t));

	} else if(resp->gtpc_msg.ub_req.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.ub_req, 0, sizeof(upd_bearer_req_t));

	} else if(resp->gtpc_msg.ub_rsp.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.ub_rsp, 0, sizeof(upd_bearer_rsp_t));

	} else if(resp->gtpc_msg.upd_req.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.upd_req, 0, sizeof(upd_pdn_conn_set_req_t));

	} else if(resp->gtpc_msg.upd_rsp.header.gtpc.message_len != 0) {
		memset((void *)&resp->gtpc_msg.upd_rsp, 0, sizeof(upd_pdn_conn_set_rsp_t));

	}

}

#endif

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

	if(RULECREATION_MODIFICATIONFAILURE == cause) {
		set_failed_rule_id(&(pfcp_sess_est_resp->failed_rule_id));
	}
}
#endif /* DP_BUILD */

int
check_pckt_fltr_id_in_rule(uint8_t pckt_id, eps_bearer *bearer) {

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Received pckt_id : %d\n",
			LOG_VALUE, pckt_id);

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"bearer->num_dynamic_filters : %d\n",
			LOG_VALUE, bearer->num_dynamic_filters);

	for( int rule_cnt = 0; rule_cnt < bearer->num_dynamic_filters; rule_cnt++) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"bearer->dynaic_rules[%d].num_flw_desc : %d\n",
				LOG_VALUE, rule_cnt, bearer->dynamic_rules[rule_cnt]->num_flw_desc);

		for( int pckt_cnt = 0; pckt_cnt < bearer->dynamic_rules[rule_cnt]->num_flw_desc; pckt_cnt++) {

			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"bearer->dynamic_rules[%d].flow_desc[%d].pckt_fltr_identifier : %d\n",
					LOG_VALUE, rule_cnt, pckt_cnt,
					bearer->dynamic_rules[rule_cnt]->flow_desc[pckt_cnt].pckt_fltr_identifier);

			if(pckt_id == bearer->dynamic_rules[rule_cnt]->flow_desc[pckt_cnt].pckt_fltr_identifier) {
				return rule_cnt;
			}
		}
	}

	return -1;
}

int
check_default_bearer_id_presence_in_ue(uint8_t bearer_id,
		ue_context *context) {

	if(context != NULL) {
		for (int pdn_cnt = 0; pdn_cnt < MAX_BEARERS; pdn_cnt++) {
			if(context->pdns[pdn_cnt] != NULL) {
				if(context->pdns[pdn_cnt]->default_bearer_id == bearer_id)
					return 0;
			}
		}
	} else {
		return -1;
	}
	return -1;
}

int
check_ebi_presence_in_ue(uint8_t bearer_id,
		ue_context *context) {

	if(context != NULL) {
		for (int bearer_cnt = 0; bearer_cnt < MAX_BEARERS; bearer_cnt++) {
			if(context->eps_bearers[bearer_cnt] != NULL) {
				if(context->eps_bearers[bearer_cnt]->eps_bearer_id == bearer_id)
					return 0;
			}
		}
	} else {
		return -1;
	}
	return -1;
}

