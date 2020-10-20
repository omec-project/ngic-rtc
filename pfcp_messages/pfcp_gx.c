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

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cfgfile.h>
#include <rte_string_fns.h>

//REVIEW: Need to check this: No need to add this header files
#include "pfcp.h"
#include "pfcp_enum.h"
#include "cp_config.h"
#include "cp_stats.h"
#include "gx.h"
#include "sm_enum.h"
#include "sm_struct.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_messages_encoder.h"
#include "cp_timer.h"
#include "gw_adapter.h"
#include "predef_rule_init.h"
#include "gtp_ies_decoder.h"
#include "enc_dec_bits.h"

#define PRESENT 1
#define NUM_VALS 16

/* Default Bearer Indication Values */
#define BIND_TO_DEFAULT_BEARER			0
#define BIND_TO_APPLICABLE_BEARER		1
/* Default Bearer Indication Values */

#define SET_EVENT(val,event) (val |=  (1UL<<event))

extern int pfcp_fd;
extern int pfcp_fd_v6;
extern int s5s8_fd;
extern int s5s8_fd_v6;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s5s8_sockaddr_ipv6_len;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s11_mme_sockaddr_ipv6_len;
extern int clSystemLog;


/* Assign the UE requested qos to default bearer*/
static int
check_ue_requested_qos(pdn_connection *pdn) {

	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"pdn_connection node is NULL\n", LOG_VALUE);
			return -1;
		}

	eps_bearer *bearer = NULL;
	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}
	bearer = pdn->eps_bearers[ebi_index];
	if (bearer->qos.qci != 0) {
		pdn->policy.default_bearer_qos_valid = TRUE;
		memcpy(&pdn->policy.default_bearer_qos, &bearer->qos, sizeof(bearer_qos_ie));
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"UE requested bearer qos is NULL\n", LOG_VALUE);
		return -1;
	}
	return 0;
}

/**
 * @brief  : Fill UE context default bearer information of default_eps_bearer_qos from CCA
 * @param  : context , eps bearer context
 * @param  : cca
 * @return : Returns 0 in case of success , -1 otherwise
 * */
static int
store_default_bearer_qos_in_policy(pdn_connection *pdn, GxDefaultEpsBearerQos qos)
{
	int ebi_index = 0;
	eps_bearer *bearer = NULL;
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"PDN Connection Node is NULL\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	bearer = pdn->eps_bearers[ebi_index];
	if(bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Bearer not found for ebi_index : %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn->policy.default_bearer_qos_valid = TRUE;
	bearer_qos_ie *def_qos = &pdn->policy.default_bearer_qos;

	if (qos.presence.qos_class_identifier == PRESENT) {
		def_qos->qci = qos.qos_class_identifier;
		bearer->qos.qci = qos.qos_class_identifier;
	}

	if(qos.presence.allocation_retention_priority == PRESENT) {
		if(qos.allocation_retention_priority.presence.priority_level == PRESENT){
			def_qos->arp.priority_level = qos.allocation_retention_priority.priority_level;
			bearer->qos.arp.priority_level = qos.allocation_retention_priority.priority_level;
		}
		if(qos.allocation_retention_priority.presence.pre_emption_capability == PRESENT){
			def_qos->arp.preemption_capability = qos.allocation_retention_priority.pre_emption_capability;
			bearer->qos.arp.preemption_capability = qos.allocation_retention_priority.pre_emption_capability;
		}
		if(qos.allocation_retention_priority.presence.pre_emption_vulnerability == PRESENT){
			def_qos->arp.preemption_vulnerability = qos.allocation_retention_priority.pre_emption_vulnerability;
			bearer->qos.arp.preemption_vulnerability = qos.allocation_retention_priority.pre_emption_vulnerability;
		}
	}
	return 0;
}

void
update_bearer_qos(eps_bearer *bearer)
{
	/* Firest reset to 0*/
	memset(&bearer->qos, 0, sizeof(bearer_qos_ie));
	for(int itr = 0; itr < bearer->num_dynamic_filters; itr++){

		/* QCI and ARP value same for all rule in single bearer*/
		dynamic_rule_t *dynamic_rule = bearer->dynamic_rules[itr];
		bearer->qos.qci = dynamic_rule->qos.qci;
		bearer->qos.arp.priority_level = dynamic_rule->qos.arp.priority_level;
		bearer->qos.arp.preemption_capability = dynamic_rule->qos.arp.preemption_capability;
		bearer->qos.arp.preemption_vulnerability = dynamic_rule->qos.arp.preemption_vulnerability;

		/* Bearer GBR will be SUM of all GBR*/
		bearer->qos.ul_gbr +=  dynamic_rule->qos.ul_gbr;
		bearer->qos.dl_gbr +=  dynamic_rule->qos.dl_gbr;

		/* Bearer MBR will be max of MBRs of all the rules*/
		if(bearer->qos.ul_mbr < dynamic_rule->qos.ul_mbr){
			bearer->qos.ul_mbr =  dynamic_rule->qos.ul_mbr;
		}
		if(bearer->qos.dl_mbr < dynamic_rule->qos.dl_mbr){
			bearer->qos.dl_mbr =  dynamic_rule->qos.dl_mbr;
		}
	}

	return;
}

/**
 * @brief  : Extracts  data form sdf string str and fills into packet filter
 * @param  : str
 * @param  : pkt_filter
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_sdf_strctr(char *str, sdf_pkt_fltr *pkt_filter)
{
	int nb_token = 0;
	char *str_fld[NUM_VALS];
	int offset = 0;

	/* VG: format of sdf string is  */
	/* action dir fom src_ip src_port to dst_ip dst_port" */

	nb_token = rte_strsplit(str, strnlen(str,MAX_SDF_DESC_LEN), str_fld, NUM_VALS, ' ');
	if (nb_token > NUM_VALS) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:Reach Max limit for sdf string \n",
			LOG_VALUE);
		return -1;
	}

	for(int indx=0; indx < nb_token; indx++){

		if( indx == 0 ){
			if(strncmp(str_fld[indx], "permit", NUM_VALS) != 0 ) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"AVP:Skip sdf filling for IP filter rule action : %s \n", LOG_VALUE, str_fld[indx]);
				return -1;
			}
		} else if(indx == 2) {
			pkt_filter->proto_id = atoi(str_fld[indx]);
		} else if (indx == 4){

			if(strncmp(str_fld[indx], "any", NUM_VALS) != 0 ){
				if( strstr(str_fld[indx], "/") != NULL) {
					int ip_token = 0;
					char *ip_fld[2];
					ip_token = rte_strsplit(str_fld[indx], strnlen(str_fld[indx],MAX_SDF_DESC_LEN), ip_fld, 2, '/');
					if (ip_token > 2) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:Reach Max limit for sdf src ip \n",
							LOG_VALUE);
						return -1;
					}
					if(strstr(ip_fld[0], ":") != NULL){
						if(inet_pton(AF_INET6, (const char *) ip_fld[0], (void *)(&pkt_filter->local_ip6_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:conv of src ip fails \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->local_ip_mask = atoi(ip_fld[1]);
						pkt_filter->v6 = PRESENT;
					}else if(strstr(ip_fld[0], ".") != NULL){
						if(inet_pton(AF_INET, (const char *) ip_fld[0], (void *)(&pkt_filter->local_ip_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:conv of src ip fails \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->local_ip_mask = atoi(ip_fld[1]);
						pkt_filter->v4 = PRESENT;
					}
				} else {
					if(strstr(str_fld[indx], ":") != NULL){
						if(inet_pton(AF_INET6, (const char *) str_fld[indx], (void *)(&pkt_filter->local_ip6_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "AVP:conv of src ip fails \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->v6 = PRESENT;
					}else if(strstr(str_fld[indx], ".") != NULL){
						if(inet_pton(AF_INET, (const char *) str_fld[indx], (void *)(&pkt_filter->local_ip_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "AVP:conv of src ip fails \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->v4 = PRESENT;
					}
				}
			}
		} else if(indx == 5){
			/*TODO VG : handling of multiple ports p1,p2,p3 etc*/
			if(strncmp(str_fld[indx], "to", NUM_VALS) != 0 ){
				if( strstr(str_fld[indx], "-") != NULL) {
					int port_token = 0;
					char *port_fld[2];
					port_token = rte_strsplit(str_fld[indx], strnlen(str_fld[indx],MAX_SDF_DESC_LEN), port_fld, 2, '-');

					if (port_token > 2) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "AVP:Reach Max limit for sdf src port \n",
							LOG_VALUE);
						return -1;
					}

					pkt_filter->local_port_low = atoi(port_fld[0]);
					pkt_filter->local_port_high = atoi(port_fld[1]);

				} else {
					pkt_filter->local_port_low = atoi(str_fld[indx]);
					pkt_filter->local_port_high = atoi(str_fld[indx]);
				}
			}else {
				offset++;
			}
		} else if (indx + offset == 7){

			if(strncmp(str_fld[indx], "any", NUM_VALS) != 0 ){
				if( strstr(str_fld[indx], "/") != NULL) {
					int ip_token = 0;
					char *ip_fld[2];
					ip_token = rte_strsplit(str_fld[indx], strnlen(str_fld[indx],MAX_SDF_DESC_LEN), ip_fld, 2, '/');
					if (ip_token > 2) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:Reach Max limit for sdf dst ip \n",
							LOG_VALUE);
						return -1;
					}
					if(strstr(ip_fld[0], ":") != NULL){
						if(inet_pton(AF_INET6, (const char *) ip_fld[0], (void *)(&pkt_filter->remote_ip6_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:conv of dst ip fails \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->remote_ip_mask = atoi(ip_fld[1]);
						pkt_filter->v6 = PRESENT;
					}else if(strstr(ip_fld[0], ".") != NULL){
						if(inet_pton(AF_INET, (const char *) ip_fld[0], (void *)(&pkt_filter->remote_ip_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:conv of dst ip fails \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->v4 = PRESENT;
						pkt_filter->remote_ip_mask = atoi(ip_fld[1]);
					}
				} else{
					if(strstr(str_fld[indx], ":") != NULL){
						if(inet_pton(AF_INET6, (const char *) str_fld[indx], (void *)(&pkt_filter->remote_ip6_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:conv of dst ip \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->v6 = PRESENT;
					}else if(strstr(str_fld[indx], ".") != NULL) {
						if(inet_pton(AF_INET, (const char *) str_fld[indx], (void *)(&pkt_filter->remote_ip_addr)) < 0){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:conv of dst ip \n",
								LOG_VALUE);
							return -1;
						}
						pkt_filter->v4 = PRESENT;
					}
				}
			}
		}  else if(indx + offset == 8){
			/*TODO VG : handling of multiple ports p1,p2,p3 etc*/

			if( strstr(str_fld[indx], "-") != NULL) {
				int port_token = 0;
				char *port_fld[2];
				port_token = rte_strsplit(str_fld[indx], strnlen(str_fld[indx],MAX_SDF_DESC_LEN), port_fld, 2, '-');

				if (port_token > 2) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:Reach Max limit for sdf dst port\n",
						LOG_VALUE);
					return -1;
				}

				pkt_filter->remote_port_low = atoi(port_fld[0]);
				pkt_filter->remote_port_high = atoi(port_fld[1]);

			} else {
				pkt_filter->remote_port_low = atoi(str_fld[indx]);
				pkt_filter->remote_port_high = atoi(str_fld[indx]);
			}
		}


	}

		return 0;
}

static struct mtr_entry *
get_mtr_entry(uint16_t idx)
{
	void *mtr_rule = NULL;
	struct mtr_entry *mtr = NULL;
	int ret = get_predef_rule_entry(idx, MTR_HASH, GET_RULE, (void **)&mtr_rule);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to Get MTR Rule from the internal table"
				"for Mtr_Indx: %u\n", LOG_VALUE, idx);
		return NULL;
	}

	mtr = (struct mtr_entry *)mtr_rule;
	return mtr;
}

/**
 * @brief  : Fills dynamic rule from given charging rule definition , and adds mapping of rule and bearer id
 * @param  : predefined_rule
 * @param  : rule_name
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_predefined_rule_in_bearer(pdn_connection *pdn, dynamic_rule_t *pdef_rule,
		rule_name_key_t *rule_name)
{
	uint32_t idx = 0;
	/* Retrive the PCC rule based on the rule name */
	pcc_rule_name rule = {0};
	memset(rule.rname, '\0', sizeof(rule.rname));
	strncpy(rule.rname, rule_name->rule_name, sizeof(rule.rname));

	struct pcc_rules *pcc = NULL;
	pcc = get_predef_pcc_rule_entry(&rule, GET_RULE);
	if (pcc == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to get PCC Rule by PCC rule name receivd in"
				"AVP charging rule name for Rule_Name: %s\n",
				LOG_VALUE, rule_name->rule_name);
		return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
	}


	pdef_rule->predefined_rule = TRUE;
	pdef_rule->online = pcc->online;
	pdef_rule->offline = pcc->offline;
	pdef_rule->flow_status = pcc->flow_status;
	pdef_rule->rating_group = pcc->rating_group;
	pdef_rule->reporting_level = pcc->report_level;
	pdef_rule->precedence = pcc->precedence;
	pdef_rule->service_id = pcc->service_id;

	if (pcc->sdf_idx_cnt) {
		pdef_rule->num_flw_desc = pcc->sdf_idx_cnt;

		/* Retrive the SDF rule based on the SDF Index */
		for (idx = 0; idx < pcc->sdf_idx_cnt; idx++) {
			void *sdf_rule_t = NULL;
			pkt_fltr *tmp_sdf = NULL;
			int ret = get_predef_rule_entry(pcc->sdf_idx[idx], SDF_HASH, GET_RULE, (void **)&sdf_rule_t);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to Get SDF Rule from the internal table"
						"for SDF_Indx: %u\n", LOG_VALUE, pcc->sdf_idx[idx]);
				continue;
			}
			/* Typecast sdf rule */
			tmp_sdf = (pkt_fltr *)sdf_rule_t;
			if (tmp_sdf == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed not found the sdf rule"
						"for SDF_Indx: %u\n", LOG_VALUE, pcc->sdf_idx[idx]);
				continue;
			}
			pdef_rule->flow_desc[idx].flow_direction = tmp_sdf->direction;
			pdef_rule->flow_desc[idx].sdf_flw_desc.proto_id = tmp_sdf->proto;
			pdef_rule->flow_desc[idx].sdf_flw_desc.proto_mask = tmp_sdf->proto_mask;
			pdef_rule->flow_desc[idx].sdf_flw_desc.direction = tmp_sdf->direction;
			pdef_rule->flow_desc[idx].sdf_flw_desc.local_ip_mask = tmp_sdf->local_ip_mask;
			pdef_rule->flow_desc[idx].sdf_flw_desc.remote_ip_mask = tmp_sdf->remote_ip_mask;
			pdef_rule->flow_desc[idx].sdf_flw_desc.local_port_low = ntohs(tmp_sdf->local_port_low);
			pdef_rule->flow_desc[idx].sdf_flw_desc.local_port_high = ntohs(tmp_sdf->local_port_high);
			pdef_rule->flow_desc[idx].sdf_flw_desc.remote_port_low = ntohs(tmp_sdf->remote_port_low);
			pdef_rule->flow_desc[idx].sdf_flw_desc.remote_port_high = ntohs(tmp_sdf->remote_port_high);

			if(tmp_sdf->v4){
				pdef_rule->flow_desc[idx].sdf_flw_desc.v4 = PRESENT;
				pdef_rule->flow_desc[idx].sdf_flw_desc.local_ip_addr = tmp_sdf->local_ip_addr;
				pdef_rule->flow_desc[idx].sdf_flw_desc.remote_ip_addr = tmp_sdf->remote_ip_addr;
			} else {
				pdef_rule->flow_desc[idx].sdf_flw_desc.v6 = PRESENT;
				pdef_rule->flow_desc[idx].sdf_flw_desc.local_ip6_addr = tmp_sdf->local_ip6_addr;
				pdef_rule->flow_desc[idx].sdf_flw_desc.remote_ip6_addr = tmp_sdf->remote_ip6_addr;

			}
			pdef_rule->flow_desc[idx].sdf_flw_desc.action = pcc->rule_status;


		}

	}else{
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: NO SDF Rule present for Rule name%s\n",
				LOG_VALUE,rule_name->rule_name);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Fill the MBR and GBR values */
	if (pcc->qos.mtr_profile_index) {
		struct mtr_entry *mtr = NULL;
		mtr = get_mtr_entry(pcc->qos.mtr_profile_index);
		if (mtr != NULL) {
			pdef_rule->qos.ul_mbr = mtr->ul_mbr;
			pdef_rule->qos.dl_mbr = mtr->dl_mbr;
			pdef_rule->qos.ul_gbr = mtr->ul_gbr;
			pdef_rule->qos.dl_gbr = mtr->dl_gbr;
		}else{
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: NO MTR Rule present for Rule name%s\n",
					LOG_VALUE,rule_name->rule_name);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	/* Fill the UE requested qos in the bearer */
	int ebi_index = 0;
	ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* TODO: Need to re-vist this code */
	eps_bearer *bearer = NULL;
	bearer = pdn->eps_bearers[ebi_index];
	if (bearer->qos.qci != 0) {
		pdn->policy.default_bearer_qos_valid = TRUE;
		memcpy(&pdn->policy.default_bearer_qos, &bearer->qos, sizeof(bearer_qos_ie));
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"UE requested bearer qos is NULL\n", LOG_VALUE);
		return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
	}

	/* QoS and ARP not there then use UE request qos */
	if(pcc->qos.qci == 0){
		memcpy(&pdef_rule->qos, &bearer->qos, sizeof(bearer_qos_ie));
	}else {
		pdef_rule->qos.qci = pcc->qos.qci;
		pdef_rule->qos.arp.priority_level = pcc->qos.arp.priority_level;
		pdef_rule->qos.arp.preemption_capability = pcc->qos.arp.pre_emption_capability;
		pdef_rule->qos.arp.preemption_vulnerability = pcc->qos.arp.pre_emption_vulnerability;
	}

	/* Fill the rule name in bearer */
	rule_name_key_t key = {0};

	strncpy(key.rule_name, (char *)(pcc->rule_name),
			sizeof(pcc->rule_name));

	memset(pdef_rule->rule_name, '\0', sizeof(pdef_rule->rule_name));
	strncpy(pdef_rule->rule_name,
			(char *)pcc->rule_name, sizeof(pcc->rule_name));
	return 0;
}

/**
 * @brief  : Fills dynamic rule from given charging rule definition , and adds mapping of rule and bearer id
 * @param  : dynamic_rule
 * @param  : rule_definition
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
fill_charging_rule_definition(dynamic_rule_t *dynamic_rule,
					 GxChargingRuleDefinition *rule_definition)
{
	int32_t idx = 0;

	if (rule_definition->presence.online == PRESENT)
	        dynamic_rule->online =  rule_definition->online;

	if (rule_definition->presence.offline == PRESENT)
	        dynamic_rule->offline = rule_definition->offline;

	if (rule_definition->presence.flow_status == PRESENT)
	        dynamic_rule->flow_status = rule_definition->flow_status;

	if (rule_definition->presence.reporting_level == PRESENT)
	        dynamic_rule->reporting_level = rule_definition->reporting_level;

	if (rule_definition->presence.precedence == PRESENT)
	        dynamic_rule->precedence = rule_definition->precedence;

	if (rule_definition->presence.service_identifier == PRESENT)
	        dynamic_rule->service_id = rule_definition->service_identifier;

	if (rule_definition->presence.rating_group == PRESENT)
	        dynamic_rule->rating_group = rule_definition->rating_group;

	if (rule_definition->presence.default_bearer_indication == PRESENT)
	        dynamic_rule->def_bearer_indication = rule_definition->default_bearer_indication;
	else
	        dynamic_rule->def_bearer_indication = BIND_TO_APPLICABLE_BEARER;


	if (rule_definition->presence.af_charging_identifier == PRESENT)
	{
	        /* CHAR*/
	        memcpy(dynamic_rule->af_charging_id_string,
	                        rule_definition->af_charging_identifier.val,
	                        rule_definition->af_charging_identifier.len);
	}

	if (rule_definition->presence.flow_information == PRESENT) {
			dynamic_rule->num_flw_desc = rule_definition->flow_information.count;

	        for(idx = 0; idx < rule_definition->flow_information.count; idx++)
	        {
	                if ((rule_definition->flow_information).list[idx].presence.flow_direction
	                                == PRESENT) {
	                        dynamic_rule->flow_desc[idx].flow_direction =
	                                (rule_definition->flow_information).list[idx].flow_direction;
			}

	                /* CHAR*/
	                if ((rule_definition->flow_information).list[idx].presence.flow_description
	                                == PRESENT) {

	                        memcpy(dynamic_rule->flow_desc[idx].sdf_flow_description,
	                                (rule_definition->flow_information).list[idx].flow_description.val,
	                                (rule_definition->flow_information).list[idx].flow_description.len);
							dynamic_rule->flow_desc[idx].flow_desc_len =
								(rule_definition->flow_information).list[idx].flow_description.len;

							fill_sdf_strctr(dynamic_rule->flow_desc[idx].sdf_flow_description,
									&(dynamic_rule->flow_desc[idx].sdf_flw_desc));

							/*VG assign direction in flow desc */
							dynamic_rule->flow_desc[idx].sdf_flw_desc.direction =(uint8_t)
	                                (rule_definition->flow_information).list[idx].flow_direction;

	                }
	        }
	}


	if(rule_definition->presence.qos_information == PRESENT)
	{
		GxQosInformation *qos = &(rule_definition->qos_information);

		dynamic_rule->qos.qci = qos->qos_class_identifier;
		if(qos->allocation_retention_priority.presence.priority_level)
			dynamic_rule->qos.arp.priority_level = qos->allocation_retention_priority.priority_level;
		if(qos->allocation_retention_priority.presence.pre_emption_capability)
			dynamic_rule->qos.arp.preemption_capability = qos->allocation_retention_priority.pre_emption_capability;
		if(qos->allocation_retention_priority.presence.pre_emption_vulnerability)
			dynamic_rule->qos.arp.preemption_vulnerability = qos->allocation_retention_priority.pre_emption_vulnerability;
		dynamic_rule->qos.ul_mbr =  qos->max_requested_bandwidth_ul;
		dynamic_rule->qos.dl_mbr =  qos->max_requested_bandwidth_dl;
		dynamic_rule->qos.ul_gbr =  qos->guaranteed_bitrate_ul;
		dynamic_rule->qos.dl_gbr =  qos->guaranteed_bitrate_dl;
	}

	if (rule_definition->presence.charging_rule_name == PRESENT) {
		rule_name_key_t key = {0};
		/* Commenting for compliation error Need to check
		id.bearer_id = bearer_id; */

		strncpy(key.rule_name, (char *)(rule_definition->charging_rule_name.val),
				rule_definition->charging_rule_name.len);

		memset(dynamic_rule->rule_name, '\0', sizeof(dynamic_rule->rule_name));
		strncpy(dynamic_rule->rule_name,
				(char *)rule_definition->charging_rule_name.val,
	            rule_definition->charging_rule_name.len);
	}

	return 0;
}

/**
 * @brief  : store the event tigger value received in CCA
 * @param  : pdn
 * @param  : GxEventTriggerList
 * @return : Returns 0 in case of success
 */
static int
store_event_trigger(pdn_connection *pdn, GxEventTriggerList *event_trigger)
{
	if(event_trigger != NULL) {
		for(uint8_t i = 0; i < event_trigger->count; i++) {
			int32_t val =  *event_trigger->list;

			/*Jumping the list to the next GxEventTriggerList*/
			event_trigger->list++;
			//pdn->context->event_trigger = val;
			//set_event_trigger_bit(pdn->context)
			SET_EVENT(pdn->context->event_trigger, val);
		}
	}

	return 0;
}

/**
 * @brief  : Delete the dynamic rule entry from the bearer
 * @param  : bearer, bearer from which rule should be remove
 * @param  : rule_name, rule name that should be remove
 * @return : Returns Nothing
 */
static void
delete_bearer_rule(eps_bearer *bearer, char *rule_name){

	uint8_t flag = 0;

	for(uint8_t itr = 0; itr < bearer->num_dynamic_filters; itr++){

		if(strncmp(rule_name, bearer->dynamic_rules[itr]->rule_name,
						sizeof(bearer->dynamic_rules[itr]->rule_name)) == 0){
			flag = 1;
			rte_free(bearer->dynamic_rules[itr]);
			bearer->dynamic_rules[itr] = NULL;
		}

		if(flag == 1 && itr != bearer->num_dynamic_filters - 1){

			bearer->dynamic_rules[itr] = bearer->dynamic_rules[itr + 1];
		}
	}

	if(flag){
		bearer->num_dynamic_filters--;
		bearer->dynamic_rules[bearer->num_dynamic_filters] = NULL;

	}else{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Given rule name %s not "
			"Found in bearer to remove\n", LOG_VALUE, rule_name);
	}

	if(bearer->qos_bearer_check == PRESENT) {
		update_bearer_qos(bearer);
	}

	return;
}
/**
 * @brief  : Update or Add new predefined rule into the bearer
 * @param  : bearer, bearer for which rule need to update
 * @param  : prdef_rule, The rule that need to update or add
 * @param  : rule_action, Action that need to perform on bearer either update a rule or add a new rule
 * @return : Returns 0 on success
 */
static int
update_prdef_bearer_rule(eps_bearer *bearer, dynamic_rule_t *pdef_rule,
		enum rule_action_t rule_action)
{
	if(rule_action == RULE_ACTION_ADD) {
		bearer->prdef_rules[bearer->num_prdef_filters] =
			rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (bearer->prdef_rules[bearer->num_prdef_filters] == NULL) {
			 clLog(clSystemLog, eCLSeverityCritical,
					 LOG_FORMAT"Failure to allocate predefined rule memory "
					 "structure: %s\n", LOG_VALUE,
					 rte_strerror(rte_errno));
			return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
		}

		memcpy((bearer->prdef_rules[bearer->num_prdef_filters]), pdef_rule,
				sizeof(dynamic_rule_t));
		bearer->num_prdef_filters++;

	} else {
		for(uint8_t itr = 0; itr < bearer->num_prdef_filters; itr++){
			if(strncmp(pdef_rule->rule_name, bearer->prdef_rules[itr]->rule_name,
						sizeof(pdef_rule->rule_name)) == 0) {
				memset(bearer->prdef_rules[itr], 0,
						sizeof(dynamic_rule_t));
				memcpy((bearer->prdef_rules[itr]), pdef_rule,
						sizeof(dynamic_rule_t));
				break;
			}
		}
	}
	return 0;
}


/**
 * @brief  : Update or Add new dynamic rule into the bearer
 * @param  : bearer, bearer for which rule need to update
 * @param  : dyn_rule, The rule that need to update or add
 * @param  : rule_action, Action that need to perform on bearer either update a rule or add a new rule
 * @return : Returns 0 on success
 */
static int
update_bearer_rule(eps_bearer *bearer, dynamic_rule_t *dyn_rule,
		enum rule_action_t rule_action)
{

	if(rule_action == RULE_ACTION_ADD) {

		/* As adding new rule so both TFT and QoS should modify*/
		bearer->flow_desc_check = PRESENT;
		bearer->qos_bearer_check = PRESENT;
		add_pdr_qer_for_rule(bearer, FALSE);
		bearer->dynamic_rules[bearer->num_dynamic_filters] = rte_zmalloc_socket(NULL,
									sizeof(dynamic_rule_t),
									RTE_CACHE_LINE_SIZE,
									rte_socket_id());
		if (bearer->dynamic_rules[bearer->num_dynamic_filters] == NULL) {
			 clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failure to allocate dynamic rule memory "
				"structure: %s \n", LOG_VALUE,
				rte_strerror(rte_errno));
			return GTPV2C_CAUSE_NO_MEMORY_AVAILABLE;
		}

		fill_pfcp_entry(bearer, dyn_rule);
		memcpy((bearer->dynamic_rules[bearer->num_dynamic_filters]), dyn_rule,
				sizeof(dynamic_rule_t));
		bearer->num_dynamic_filters++;
		if(bearer->qos_bearer_check == PRESENT) {

			update_bearer_qos(bearer);
		}

	}else {

		for(uint8_t itr = 0; itr < bearer->num_dynamic_filters; itr++){

			if(strncmp(dyn_rule->rule_name, bearer->dynamic_rules[itr]->rule_name,
						sizeof(dyn_rule->rule_name)) == 0){

				/* Reset pckt_fltr_identifier reassign at time of Update bearer Request*/
				for(uint8_t i = 0; i < bearer->dynamic_rules[itr]->num_flw_desc; i++){
					uint8_t pkt_filter_id = bearer->dynamic_rules[itr]->flow_desc[i].pckt_fltr_identifier;
					bearer->packet_filter_map[pkt_filter_id] = NOT_PRESENT;

				}

				bearer->flow_desc_check = compare_flow_description(bearer->dynamic_rules[itr],dyn_rule);
				bearer->qos_bearer_check = compare_bearer_qos(bearer->dynamic_rules[itr],dyn_rule);
				bearer->arp_bearer_check = compare_bearer_arp(bearer->dynamic_rules[itr],dyn_rule);
				if(bearer->flow_desc_check == PRESENT || bearer->qos_bearer_check == PRESENT) {
				memset(bearer->dynamic_rules[itr], 0,
						sizeof(dynamic_rule_t));
				memcpy((bearer->dynamic_rules[itr]), dyn_rule,
									sizeof(dynamic_rule_t));
				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"flow_description and QoS not "
							"change & Not expected\n", LOG_VALUE);
					return -1;
				}

				int pdr_count = 0;
				for(uint8_t itr2 = 0; itr2 < bearer->pdr_count; itr2++){
					if(pdr_count == 2)
						break;
					if(strncmp(dyn_rule->rule_name,
								bearer->pdrs[itr2]->rule_name,
									sizeof(dyn_rule->rule_name)) == 0) {
						if(pdr_count < 2){
							bearer->dynamic_rules[itr]->pdr[pdr_count++] = bearer->pdrs[itr2];
						}else{
							break;
						}

						fill_pdr_sdf_qer(bearer->pdrs[itr2], dyn_rule);
					}
				}

				if(bearer->qos_bearer_check == PRESENT) {

					update_bearer_qos(bearer);
				}
				break;
			}
		}
	}
	return 0;
}


/**
 * @brief  : Creates and fills dynamic/predefined rules for given bearer from received cca
 * @param  : context , eps bearer context
 * @param  : cca
 * @param  : bearer_id
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
store_dynamic_rules_in_policy(pdn_connection *pdn,
		GxChargingRuleInstallList * charging_rule_install,
		GxChargingRuleRemoveList * charging_rule_remove)
{

	rule_name_key_t rule_name = {0};
	GxChargingRuleDefinition *rule_definition = NULL;
	eps_bearer *bearer = NULL;
	int8_t bearer_index = -1;

	/* Clear Policy in PDN */
	pdn->policy.count = 0;
	pdn->policy.num_charg_rule_install = 0;
	pdn->policy.num_charg_rule_modify = 0;
	pdn->policy.num_charg_rule_delete = 0;
	dynamic_rule_t *rule = NULL;
	uint8_t num_rule_filters = 0;
	int ret = 0;

	if(charging_rule_install != NULL)
	{
		for (int32_t idx1 = 0; idx1 < charging_rule_install->count; idx1++)
		{
			if (charging_rule_install->list[idx1].presence.charging_rule_definition == PRESENT)
			{
				for(int32_t idx2 = 0; idx2 < charging_rule_install->list[idx1].charging_rule_definition.count; idx2++)
				{
					rule_definition =
						&(charging_rule_install->list[idx1].charging_rule_definition.list[idx2]);
					if (rule_definition->presence.charging_rule_name == PRESENT) {

						memset(rule_name.rule_name, '\0', sizeof(rule_name.rule_name));
						snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s%d",
								rule_definition->charging_rule_name.val, pdn->call_id);
						memset(&pdn->policy.pcc_rule[pdn->policy.count], 0, sizeof(pcc_rule_t));
						fill_charging_rule_definition(&(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule), rule_definition);
						pdn->policy.pcc_rule[pdn->policy.count].predefined_rule = FALSE;
						/* Extract Bearer on basis of QCI and ARP value */
						bearer = get_bearer(pdn, &pdn->policy.pcc_rule[pdn->policy.count].dyn_rule.qos);
						bearer_index = get_rule_name_entry(rule_name);
						if(bearer == NULL || bearer->num_dynamic_filters == 0) {

							if((bearer_index == -1) ||
									(bearer != NULL && bearer->num_dynamic_filters == 0) ||
									(pdn->eps_bearers[bearer_index] == NULL)){

								pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_ADD;
								pdn->policy.count++;
								pdn->policy.num_charg_rule_install++;

							}else{

								bearer = pdn->eps_bearers[bearer_index];

								if(bearer->num_dynamic_filters > 1){

									/* Remove the rule from older bearer and create new bearer */

									/* Create a new bearer */
									pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_ADD;
									pdn->policy.count++;
									pdn->policy.num_charg_rule_install++;

									/* Remove rule from older bearer */
									memset(&pdn->policy.pcc_rule[pdn->policy.count], 0, sizeof(pcc_rule_t));
									fill_charging_rule_definition(&(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule),
											rule_definition);
									pdn->policy.pcc_rule[pdn->policy.count].action =
										RULE_ACTION_MODIFY_REMOVE_RULE;
									bearer->action = RULE_ACTION_MODIFY_REMOVE_RULE;
									/* As Removing rule so both TFT and QoS should modify*/
									bearer->flow_desc_check = PRESENT;
									bearer->qos_bearer_check = PRESENT;
									pdn->policy.num_charg_rule_modify++;
									pdn->policy.count++;
								}else{

									update_bearer_rule(bearer,
											&(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule),
											RULE_ACTION_MODIFY);

									if(pdn->proc == HSS_INITIATED_SUB_QOS_MOD && bearer->arp_bearer_check == PRESENT) {
										/*Change arp values for all bearers*/
										change_arp_for_ded_bearer(pdn, &(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule.qos));
									}

									pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_MODIFY;
									bearer->action = RULE_ACTION_MODIFY;
									pdn->policy.count++;
									pdn->policy.num_charg_rule_modify++;
								}
							}
						} else {
							/* IF condition check is true this means
							 * Rule is already installed in that bearer
							 * the rule is updated that's why we recived the same
							 * same rule for Update
							 * Else recevied one new rule to add into the bearer
							 * */
							if(bearer->eps_bearer_id == (bearer_index + NUM_EBI_RESERVED)){
								ret = update_bearer_rule(bearer, &(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule),
										RULE_ACTION_MODIFY);
								if(ret)
									return ret;

								pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_MODIFY;
								bearer->action = RULE_ACTION_MODIFY;
								pdn->policy.count++;
								pdn->policy.num_charg_rule_modify++;
							}else{

								if(bearer_index == -1) {
									/* The rule is not with us*/
									 ret = update_bearer_rule(bearer, &(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule),
											RULE_ACTION_ADD);
									 if(ret)
										 return ret;

									pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_MODIFY_ADD_RULE;
									bearer->action = RULE_ACTION_MODIFY_ADD_RULE;
									pdn->policy.count++;
									pdn->policy.num_charg_rule_modify++;
								}else {
									/* The rule was previously installed on some other bearer*/

									/* Removing that rule from the older bearer*/
									if(pdn->eps_bearers[bearer_index]->num_dynamic_filters > 1){
										pdn->policy.pcc_rule[pdn->policy.count].action =
											RULE_ACTION_MODIFY_REMOVE_RULE;
										pdn->eps_bearers[bearer_index]->action = RULE_ACTION_MODIFY_REMOVE_RULE;

										/* As Removing rule so both TFT and QoS should modify*/
										pdn->eps_bearers[bearer_index]->flow_desc_check = PRESENT;
										pdn->eps_bearers[bearer_index]->qos_bearer_check = PRESENT;
										pdn->policy.count++;
										pdn->policy.num_charg_rule_modify++;
									}else {

										pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_DELETE;
										pdn->eps_bearers[bearer_index]->action = RULE_ACTION_DELETE;
										pdn->policy.count++;
										pdn->policy.num_charg_rule_delete++;
									}

									/* Adding that rule to new bearer */
									fill_charging_rule_definition(&(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule),
											rule_definition);

									update_bearer_rule(bearer, &(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule),
											RULE_ACTION_ADD);

									pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_MODIFY_ADD_RULE;
									bearer->action = RULE_ACTION_MODIFY_ADD_RULE;
									pdn->policy.count++;
									pdn->policy.num_charg_rule_modify++;
								}
							}
						}
					} else{
						//TODO: Rule without name not possible; Log IT ?
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Charging rule name is not present\n",LOG_VALUE);
						return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
					}
				}
			}
			if (charging_rule_install->list[idx1].presence.charging_rule_name == PRESENT) {
				GxChargingRuleNameOctetString *rule_string = NULL;

				/* Predefined Rule: Received only rule name from pcrf */
				for(int32_t idx2 = 0; idx2 < charging_rule_install->list[idx1].charging_rule_name.count; idx2++)
				{
					rule_string =
						&(charging_rule_install->list[idx1].charging_rule_name.list[idx2]);

					memset(rule_name.rule_name, '\0', sizeof(rule_name.rule_name));
					snprintf(rule_name.rule_name, RULE_NAME_LEN, "%s", rule_string->val);

					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"PCRF Send Predefined Charging rule name: %s\n",
							LOG_VALUE, rule_name.rule_name);

					pdn->policy.pcc_rule[pdn->policy.count].predefined_rule = TRUE;
					ret = fill_predefined_rule_in_bearer(pdn,
							&(pdn->policy.pcc_rule[pdn->policy.count].pdef_rule), &rule_name);
					if(ret){
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Failed to fill_predefined_rule_in_bearer for rule name: %s\n",
								LOG_VALUE, rule_name.rule_name);
						return ret;
					}

					/* Extract Bearer on basis of QCI and ARP value */
					bearer = get_bearer(pdn, &pdn->policy.pcc_rule[pdn->policy.count].pdef_rule.qos);
					if(bearer == NULL || bearer->num_prdef_filters == 0) {
						pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_ADD;
						pdn->policy.count++;
						pdn->policy.num_charg_rule_install++;
					} else {
						/* IF condition check is true this means
						 * Rule is already installed in that bearer
						 * the rule is updated that's why we recived the same
						 * same rule for Update
						 * Else recevied one new rule to add into the bearer
						 */
						if(bearer->eps_bearer_id == (get_rule_name_entry(rule_name) + NUM_EBI_RESERVED)){
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"In Predefine Rule currently does not support RULE_ACTION_MODIFY\n",
									LOG_VALUE);
							return GTPV2C_CAUSE_SYSTEM_FAILURE;
						}else{
							ret = update_prdef_bearer_rule(bearer, &(pdn->policy.pcc_rule[pdn->policy.count].pdef_rule),
									RULE_ACTION_ADD);
							if(ret)
								return ret;

							/* Adding rule to Hash as Rule End in Update bearer */
							bearer_id_t *id = NULL;
							id = malloc(sizeof(bearer_id_t));
							memset(id, 0 , sizeof(bearer_id_t));
							int ebi_index = GET_EBI_INDEX(bearer->eps_bearer_id);
							if (ebi_index == -1) {
								clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
								return GTPV2C_CAUSE_SYSTEM_FAILURE;
							}

							id->bearer_id = ebi_index;
							if (add_rule_name_entry(rule_name, id) != 0) {
								clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"Failed to add_rule_name_entry with rule_name\n",
										LOG_VALUE, rule_name.rule_name);
								return GTPV2C_CAUSE_SYSTEM_FAILURE;
							}
						}
						pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_MODIFY;
						bearer->action = RULE_ACTION_MODIFY;
						pdn->policy.count++;
						pdn->policy.num_charg_rule_modify++;
					}
				}
			}else{
				if (charging_rule_install->list[idx1].presence.charging_rule_definition != PRESENT){
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Charging rule name is not present\n",LOG_VALUE);
					return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
				}
			}
		}
	}

	if(charging_rule_remove != NULL)
	{
		for(int32_t idx1 = 0; idx1 < charging_rule_remove->count; idx1++)
		{
			if (charging_rule_remove->list[idx1].presence.charging_rule_name == PRESENT)
			{
				char rule_temp[RULE_NAME_LEN];

				/* Get the rule name and only store the name in dynamic rule_t */
				memset(rule_name.rule_name, '\0', RULE_NAME_LEN);
				memset(rule_temp, '\0', RULE_NAME_LEN);
				strncpy(rule_temp, (char *)charging_rule_remove->list[idx1].charging_rule_name.list[0].val,
						charging_rule_remove->list[idx1].charging_rule_name.list[0].len);

				if(pdn->policy.pcc_rule[pdn->policy.count].predefined_rule){
					rule = &pdn->policy.pcc_rule[pdn->policy.count].pdef_rule;
					snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s", rule_temp);
				}else{
					rule = &pdn->policy.pcc_rule[pdn->policy.count].dyn_rule;
					snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s%d",rule_temp, pdn->call_id);
				}

				memset(rule->rule_name, '\0', RULE_NAME_LEN);
				strncpy(rule->rule_name,
						(char *)(charging_rule_remove->list[idx1].charging_rule_name.list[0].val),
						(charging_rule_remove->list[idx1].charging_rule_name.list[0].len >  RULE_NAME_LEN ?
						RULE_NAME_LEN : charging_rule_remove->list[idx1].charging_rule_name.list[0].len));

				/* TODO: Need to remove comment */
				int8_t bearer_identifer = get_rule_name_entry(rule_name);
				if (bearer_identifer >= 0)
				{
					bearer = pdn->eps_bearers[bearer_identifer];

					if(pdn->policy.pcc_rule[pdn->policy.count].predefined_rule)
						num_rule_filters = bearer->num_prdef_filters;
					else
						num_rule_filters = bearer->num_dynamic_filters;

					if(num_rule_filters > 1){
						pdn->policy.pcc_rule[pdn->policy.count].action =
											RULE_ACTION_MODIFY_REMOVE_RULE;
						bearer->action = RULE_ACTION_MODIFY_REMOVE_RULE;
						/* As Removing rule so both TFT and QoS should modify*/
						bearer->flow_desc_check = PRESENT;
						bearer->qos_bearer_check = PRESENT;
						pdn->policy.num_charg_rule_modify++;
					} else {
						pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_DELETE;
						bearer->action = RULE_ACTION_DELETE;
						pdn->policy.num_charg_rule_delete++;
					}

					pdn->policy.count++;
				}
			}
		}
	}
	return 0;
}

/**
 * @brief  : Set UE requested Bearer QoS.
 * @param  : pdn, pdn connection details
 * @param  : dynamic_rule, structure for store dynami rule.
 * @return : Returns 0 on success, -1 otherwise
 */
static int
set_ue_requested_bearer_qos(pdn_connection *pdn, dynamic_rule_t *dynamic_rule) {
	int ebi_index = 0;
	eps_bearer *bearer = NULL;
	if (pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"pdn_connection node is NULL\n", LOG_VALUE);
		return -1;
	}

	ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	bearer = pdn->eps_bearers[ebi_index];
	if (bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Bearer not found for ebi_index %d\n", LOG_VALUE, ebi_index);
		return -1;
	}

	dynamic_rule->qos.qci = bearer->qos.qci;
	dynamic_rule->qos.arp.priority_level = bearer->qos.arp.priority_level;
	dynamic_rule->qos.arp.preemption_capability = bearer->qos.arp.preemption_capability;
	dynamic_rule->qos.arp.preemption_vulnerability = bearer->qos.arp.preemption_vulnerability;
	dynamic_rule->qos.ul_mbr =  bearer->qos.ul_mbr;
	dynamic_rule->qos.dl_mbr =  bearer->qos.dl_mbr;
	dynamic_rule->qos.ul_gbr =  bearer->qos.ul_gbr;
	dynamic_rule->qos.dl_gbr =  bearer->qos.dl_gbr;

	return 0;
}

/**
 * @brief  : Add EBI in rule name hash.
 * @param  : rule_name, rule name
 * @param  : call_id, call id
 * @param  : ebi, EPS Bearer ID
 * @param  : pdef_rule, specifies whether its a predefined rule or not
 * @return : Returns 0 on success, -1 otherwise
 */
static int
add_ebi_rule_name_entry(char *rule_name, uint32_t call_id, uint8_t ebi, bool pdef_rule)
{
	/* Adding rule and bearer id to a hash */
	rule_name_key_t key = {0};
	bearer_id_t *id;

	id = malloc(sizeof(bearer_id_t));
	memset(id, 0 , sizeof(bearer_id_t));

	int ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	id->bearer_id = ebi_index;
	if(pdef_rule){
		snprintf(key.rule_name, RULE_NAME_LEN, "%s", rule_name);
	}else{
		snprintf(key.rule_name, RULE_NAME_LEN, "%s%d", rule_name, call_id);
	}

	if (add_rule_name_entry(key, id) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add_rule_name_entry with rule_name\n",
				LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	return 0;
}

/**
 * @brief  : fill default sdf rule
 * @param  : type, whether ipv4 or ipv6
 * @param  : index, array index
 * @param  : sdf_rule_len, length of sdf rule
 * @param  : dynamic_rule, default rule
 * @return : Returns nothing.
 */
static void
fill_default_sdf_rule(uint8_t type, uint8_t index, uint8_t sdf_rule_len,
		dynamic_rule_t *dynamic_rule)
{

		if(type == IPV4_ADDR_TYPE){
			memcpy(dynamic_rule->flow_desc[index].sdf_flow_description,
					DEFAULT_SDF_RULE_IPV4, sdf_rule_len);
		} else {
			memcpy(dynamic_rule->flow_desc[index].sdf_flow_description,
					DEFAULT_SDF_RULE_IPV6, sdf_rule_len);
		}
		dynamic_rule->flow_desc[index].flow_desc_len = sdf_rule_len;

		fill_sdf_strctr(dynamic_rule->flow_desc[index].sdf_flow_description,
				&(dynamic_rule->flow_desc[index].sdf_flw_desc));

		if ((index%2) == SOURCE_INTERFACE_VALUE_ACCESS) {
			dynamic_rule->flow_desc[index].sdf_flw_desc.direction =
				TFT_DIRECTION_UPLINK_ONLY;
		} else if ((index%2) == SOURCE_INTERFACE_VALUE_CORE) {
			 dynamic_rule->flow_desc[index].sdf_flw_desc.direction =
				 TFT_DIRECTION_DOWNLINK_ONLY;
		}
}
/**
 * @brief  : Add default rule
 * @param  : default_flow_status, flow status details
 * @param  : default_precedence, Precedence details
 * @param  : pdn, pdn connection details
 * @return : Returns 0 on success, -1 otherwise
 */
static int
add_default_rule(uint8_t default_flow_status,
		uint8_t default_precedence, pdn_connection *pdn)
{
	uint8_t sdf_rule_len = 0;
	dynamic_rule_t *dynamic_rule = NULL;

	dynamic_rule = &(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule);
	pdn->policy.count++;
	if(pdn->pdn_type.ipv4 == 1 && pdn->pdn_type.ipv6 == 1){
		dynamic_rule->num_flw_desc = DEFAULT_NUM_SDF_RULE_v4_v6;
	} else {
		dynamic_rule->num_flw_desc = DEFAULT_NUM_SDF_RULE;
	}

	uint8_t count = 0;
	if(pdn->pdn_type.ipv4 == 1){
		sdf_rule_len = strnlen(DEFAULT_SDF_RULE_IPV4, MAX_SDF_DESC_LEN);
		for(uint8_t itr = 0; itr < DEFAULT_NUM_SDF_RULE; ++itr){
			fill_default_sdf_rule(IPV4_ADDR_TYPE, count++, sdf_rule_len, dynamic_rule);
		}

	}

	if ( pdn->pdn_type.ipv6 == 1){
		sdf_rule_len = strnlen(DEFAULT_SDF_RULE_IPV6, MAX_SDF_DESC_LEN);
		for(uint8_t itr = 0; itr < DEFAULT_NUM_SDF_RULE; ++itr){
			fill_default_sdf_rule(IPV6_ADDR_TYPE, count++, sdf_rule_len, dynamic_rule);
		}

	}

	dynamic_rule->precedence = default_precedence;

	dynamic_rule->flow_status = default_flow_status;

	return 0;
}

static void
store_rule_qos_in_bearer(pdn_connection *pdn, bearer_qos_ie *rule_qos){

	if(pdn == NULL || rule_qos == NULL){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" PDN or rule_qos is NULL"
										" So, Failed to update bearer QoS", LOG_VALUE);
		return;
	}

	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return;
	}

	eps_bearer *bearer = pdn->eps_bearers[ebi_index];
	if(bearer == NULL){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No default bearer found for"
																		" PDN", LOG_VALUE);
		return;
	}

	bearer->qos.qci =  rule_qos->qci;
/*	bearer->qos.ul_mbr =  rule_qos->ul_mbr;
	bearer->qos.dl_mbr =  rule_qos->dl_mbr;
	bearer->qos.ul_gbr =  rule_qos->ul_gbr;
	bearer->qos.dl_gbr =  rule_qos->dl_gbr;
*/
	bearer->qos.arp.preemption_vulnerability =  rule_qos->arp.preemption_vulnerability;
	bearer->qos.arp.priority_level =  rule_qos->arp.priority_level;
	bearer->qos.arp.preemption_capability =  rule_qos->arp.preemption_capability;
	return;

}

/**
 * @brief  : Search for rules on default bearer
 * @param  : pdn, pdn connection details
 * @return : Returns 0 on success, -1 otherwise
 */
static int
check_for_rules_on_default_bearer(pdn_connection *pdn)
{
	uint8_t idx = 0;

	for (idx = 0; idx < pdn->policy.num_charg_rule_install; idx++)
	{
		if (!pdn->policy.pcc_rule[idx].predefined_rule) {
			if ((BIND_TO_DEFAULT_BEARER ==
						pdn->policy.pcc_rule[idx].dyn_rule.def_bearer_indication) ||
					(compare_default_bearer_qos(&pdn->policy.default_bearer_qos,
												&pdn->policy.pcc_rule[idx].dyn_rule.qos) == 0))
			{
				store_rule_qos_in_bearer(pdn,
							&pdn->policy.pcc_rule[idx].dyn_rule.qos);
				return (add_ebi_rule_name_entry(pdn->policy.pcc_rule[idx].dyn_rule.rule_name,
							pdn->call_id, pdn->default_bearer_id, FALSE));

			}
		} else {
			if ((compare_default_bearer_qos(&pdn->policy.default_bearer_qos,
								&pdn->policy.pcc_rule[idx].pdef_rule.qos) == 0))
			{
				return (add_ebi_rule_name_entry(pdn->policy.pcc_rule[idx].pdef_rule.rule_name,
							pdn->call_id, pdn->default_bearer_id, TRUE));
			}
		}
	}
	/* set the default rule */
	if (config.add_default_rule) {

		/* set default rule name */
		memset(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule.rule_name,
				'\0', sizeof(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule.rule_name));
		strncpy(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule.rule_name,
				DEFAULT_RULE_NAME, RULE_NAME_LEN);

		set_ue_requested_bearer_qos(pdn,
				&(pdn->policy.pcc_rule[pdn->policy.count].dyn_rule));
		add_ebi_rule_name_entry(
				pdn->policy.pcc_rule[pdn->policy.count].dyn_rule.rule_name,
				pdn->call_id, pdn->default_bearer_id, FALSE);
		switch(config.add_default_rule) {
			case ADD_RULE_TO_ALLOW :
				add_default_rule(DEFAULT_FLOW_STATUS_FL_ENABLED,
						DEFAULT_PRECEDENCE, pdn);
				break;
			case ADD_RULE_TO_DENY :
				add_default_rule(DEFAULT_FLOW_STATUS_FL_DISABLED,
						DEFAULT_PRECEDENCE, pdn);
				break;

		}
		pdn->policy.pcc_rule[pdn->policy.count].action = RULE_ACTION_ADD;
		pdn->policy.count++;
		pdn->policy.num_charg_rule_install++;
		return 0;
	}
	clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Rules not found for default bearer\n", LOG_VALUE);
	return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
}

static
void decode_presence_area_action_from_cca(uint8_t *buf,
				presence_reproting_area_action_t *value){

	uint16_t decoded = 0;
	uint16_t total_decoded = 0;
	value->number_of_tai = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->number_of_rai = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->nbr_of_macro_enb = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->nbr_of_home_enb = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->number_of_ecgi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->number_of_sai = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->number_of_cgi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    total_decoded = total_decoded/CHAR_SIZE;
    if(value->number_of_tai > 0){
		for(int i = 0; i < value->number_of_tai; i++)
			total_decoded += decode_tai_field(buf + total_decoded, (tai_field_t *)&value->tais[i]);
    }
    if(value->nbr_of_macro_enb > 0){
		for(int i = 0; i < value->nbr_of_macro_enb; i++)
			total_decoded += decode_macro_enb_id_fld(buf + total_decoded,
						(macro_enb_id_fld_t *)&value->macro_enodeb_ids[i]);
    }
    if(value->nbr_of_home_enb > 0){
		for(int i = 0; i < value->nbr_of_home_enb; i++)
			total_decoded += decode_home_enb_id_fld(buf + total_decoded,
							(home_enb_id_fld_t *)&value->home_enb_ids[i]);
    }
    if(value->number_of_ecgi > 0){
		for(int i = 0; i < value->number_of_ecgi; i++)
			total_decoded += decode_ecgi_field(buf + total_decoded, (ecgi_field_t *)&value->ecgis[i]);
    }
    if(value->number_of_rai > 0){
		for(int i = 0; i < value->number_of_rai; i++)
			total_decoded += decode_rai_field(buf + total_decoded, (rai_field_t *)&value->rais[i]);
    }
    if(value->number_of_sai > 0){
		for(int i = 0; i < value->number_of_sai; i++)
			total_decoded += decode_sai_field(buf + total_decoded, (sai_field_t *)&value->sais[i]);
    }
    if( value->number_of_cgi > 0){
		for(int i = 0; i < value->number_of_cgi; i++)
			total_decoded += decode_cgi_field(buf + total_decoded, (cgi_field_t *)&value->cgis[i]);
    }
    total_decoded = total_decoded*CHAR_SIZE;
    value->nbr_of_extnded_macro_enb = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    total_decoded = total_decoded/CHAR_SIZE;
    if(value->nbr_of_extnded_macro_enb > 0){
		for(int i = 0; i < value->nbr_of_extnded_macro_enb; i++)
			total_decoded += decode_extnded_macro_enb_id_fld(buf + total_decoded,
				(extnded_macro_enb_id_fld_t *)&value->extended_macro_enodeb_ids[i]);
    }

}

void store_presence_reporting_area_info(pdn_connection *pdn_cntxt,
						GxPresenceReportingAreaInformation *pres_rprtng_area_info){
	ue_context *context = NULL;
	int ret = 0;
	ret = get_ue_context(UE_SESS_ID(pdn_cntxt->seid), &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
			"get UE Context for teid : %d \n", LOG_VALUE,
			UE_SESS_ID(pdn_cntxt->seid));
		return;
	}
	context->pra_flag = TRUE;
	context->pre_rptng_area_act.pres_rptng_area_idnt =
							*(uint32_t *)pres_rprtng_area_info->presence_reporting_area_identifier.val;
	context->pre_rptng_area_act.action = pres_rprtng_area_info->presence_reporting_area_status;
	decode_presence_area_action_from_cca(pres_rprtng_area_info->presence_reporting_area_elements_list.val,
																			&context->pre_rptng_area_act);
	return;

}

/* Parse gx CCA response and fill UE context and pfcp context */
int8_t
parse_gx_cca_msg(GxCCA *cca, pdn_connection **_pdn)
{

	int ret = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn_cntxt = NULL;
	struct resp_info *resp = NULL;

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&cca->session_id.val, &call_id);
	if (ret < 0) {
	        clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT":No Call Id found "
				"from session id:%s\n", LOG_VALUE, cca->session_id.val);
	        return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Retrieve PDN context based on call id */
	pdn_cntxt = get_pdn_conn_entry(call_id);
	if (pdn_cntxt == NULL)
	{
	    clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT":No valid pdn context "
			"found for CALL_ID:%u\n", LOG_VALUE, call_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	*_pdn = pdn_cntxt;

	if(cca->presence.presence_reporting_area_information)
		store_presence_reporting_area_info(pdn_cntxt, &cca->presence_reporting_area_information);



	/* Fill the BCM */
	pdn_cntxt->bearer_control_mode = cca->bearer_control_mode;

	/* Overwirte the CSR qos values with CCA default eps bearer qos values */
	if(cca->cc_request_type == INITIAL_REQUEST) {
		/* Check for implimentation wise Mandotory AVP */
		if ( cca->presence.charging_rule_install != PRESENT ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error : "
					"default_eps_bearer_qos is missing \n", LOG_VALUE);
			return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
		}

		/* Fill the BCM */
		pdn_cntxt->bearer_control_mode = cca->bearer_control_mode;

		/* Check for Default bearer QOS recevied from PCRF */
		if (cca->presence.default_eps_bearer_qos != PRESENT) {
			ret = check_ue_requested_qos(pdn_cntxt);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"AVP:default_eps_bearer_qos is missing \n",
						LOG_VALUE);
				return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
			}

		} else {
			ret = store_default_bearer_qos_in_policy(pdn_cntxt, cca->default_eps_bearer_qos);
			if (ret)
				return ret;
		}

		/* VS: Fill the dynamic rule from rule install structure of cca to policy */
		ret = store_dynamic_rules_in_policy(pdn_cntxt,
				&(cca->charging_rule_install), &(cca->charging_rule_remove));
		if (ret)
			return ret;

		/* No rule to install nor to remove */
		if(pdn_cntxt->policy.count == 0){
			return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
		}

		if(pdn_cntxt->policy.count > 1 ||
			((pdn_cntxt->policy.count == 1 ) &&
			((compare_default_bearer_qos(&pdn_cntxt->policy.default_bearer_qos,
				&pdn_cntxt->policy.pcc_rule[pdn_cntxt->policy.count - 1].pdef_rule.qos) != 0
			  && pdn_cntxt->policy.pcc_rule[pdn_cntxt->policy.count - 1].pdef_rule.qos.qci != 0) ||
			(compare_default_bearer_qos(&pdn_cntxt->policy.default_bearer_qos,
				&pdn_cntxt->policy.pcc_rule[pdn_cntxt->policy.count - 1].dyn_rule.qos) != 0
			 && pdn_cntxt->policy.pcc_rule[pdn_cntxt->policy.count - 1].dyn_rule.qos.qci != 0)))) {

			ret = store_rule_status_for_pro_ack(&pdn_cntxt->policy,
					&pdn_cntxt->pro_ack_rule_array);
			if(ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error in Provsion ACK Array\n",
						LOG_VALUE);

				return ret;
			}
		}

		ret = check_for_rules_on_default_bearer(pdn_cntxt);
		if (ret)
			return ret;
	} else if(pdn_cntxt->proc == HSS_INITIATED_SUB_QOS_MOD) {

		/*Retrive the session information based on session id. */
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
				"for sess ID:%lu\n", LOG_VALUE, (pdn_cntxt->seid));
			return -1;
		}
		if(cca->presence.charging_rule_install != PRESENT) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid message recived from "
				"PCRF \n", LOG_VALUE);
			return GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER;
		}

		/* Fill the dynamic rule from rule install structure of cca to policy */
		ret = store_dynamic_rules_in_policy(pdn_cntxt, &(cca->charging_rule_install),
				&(cca->charging_rule_remove));
		if (ret)
			return ret;

		if(cca->presence.qos_information == PRESENT) {
			int32_t qos_count = cca->qos_information.count;

			for(int idx=0; idx < qos_count; idx++) {

				pdn_cntxt->apn_ambr.ambr_uplink = cca->qos_information.list[idx].apn_aggregate_max_bitrate_ul;
				pdn_cntxt->apn_ambr.ambr_downlink = cca->qos_information.list[idx].apn_aggregate_max_bitrate_ul;
			}
		}

		/*Store rule name and their status for prov ack msg*/
		store_rule_status_for_pro_ack(&pdn_cntxt->policy, &pdn_cntxt->pro_ack_rule_array);
		/*initiate Update Bearer Request*/

		ret = gx_update_bearer_req(pdn_cntxt);

		if(ret)
			return ret;

		resp->msg_type = GTP_MODIFY_BEARER_CMD;
		resp->proc = HSS_INITIATED_SUB_QOS_MOD;
		pdn_cntxt->proc = HSS_INITIATED_SUB_QOS_MOD;

	}  else if(pdn_cntxt->proc == UE_REQ_BER_RSRC_MOD_PROC) {

		/*Retrive the session information based on session id. */
		if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
				"for sess ID:%lu\n", LOG_VALUE, (pdn_cntxt->seid));
			return -1;
		}

		/* Fill the dynamic rule from rule install structure of cca to policy */
		ret = store_dynamic_rules_in_policy(pdn_cntxt, &(cca->charging_rule_install),
				&(cca->charging_rule_remove));
		if (ret)
			return ret;
		/*Store rule name and their status for prov ack msg*/
		store_rule_status_for_pro_ack(&pdn_cntxt->policy,
				&pdn_cntxt->pro_ack_rule_array);

		rar_funtions rar_function = NULL;
		rar_function = rar_process(pdn_cntxt, NONE_PROC);

		if(rar_function != NULL){
			ret = rar_function(pdn_cntxt);
		} else {
			ret = DIAMETER_MISSING_AVP;
		}

		resp->msg_type = GTP_BEARER_RESOURCE_CMD;
		resp->proc = UE_REQ_BER_RSRC_MOD_PROC;
		pdn_cntxt->proc = UE_REQ_BER_RSRC_MOD_PROC;

		if(ret){
			return ret;
		}

	}

	ret = store_event_trigger(pdn_cntxt, &(cca->event_trigger));
	if (ret)
	        return ret;

	return 0;
}

int
gx_create_bearer_req(pdn_connection *pdn_cntxt){

	int ret = 0;
	uint32_t seq_no = 0;
	gx_context_t *gx_context = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	struct teid_value_t *teid_value = NULL;
	teid_key_t teid_key = {0};

	if ((pdn_cntxt->proc == UE_REQ_BER_RSRC_MOD_PROC)
		&& (pdn_cntxt->context != NULL)
		&& (pdn_cntxt->context)->ue_initiated_seq_no) {
		seq_no = (pdn_cntxt->context)->ue_initiated_seq_no;
	} else {
		seq_no = generate_seq_number();
	}

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn_cntxt->seid);
		return -1;
	}

	reset_resp_info_structure(resp);

	fill_pfcp_gx_sess_mod_req(&pfcp_sess_mod_req, pdn_cntxt, RULE_ACTION_ADD, resp);

	(pdn_cntxt->context)->sequence = seq_no;

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

	ret = set_dest_address(pdn_cntxt->upf_ip, &upf_pfcp_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	if ( pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error in sending PFCP Session "
			"Modification Request for Create Bearer Request, Error : %i\n", LOG_VALUE, errno);
	} else {
		int ebi_index = GET_EBI_INDEX(pdn_cntxt->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		if(pdn_cntxt->context->cp_mode == PGWC){
			add_pfcp_if_timer_entry(pdn_cntxt->s5s8_pgw_gtpc_teid, &upf_pfcp_sockaddr,
					pfcp_msg, encoded, ebi_index);
		}
		if(pdn_cntxt->context->cp_mode == SAEGWC)
		{
			add_pfcp_if_timer_entry(pdn_cntxt->context->s11_sgw_gtpc_teid, &upf_pfcp_sockaddr,
					pfcp_msg, encoded, ebi_index);
		}
	}

	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn_cntxt->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "NO ENTRY FOUND IN "
			"Gx HASH [%s]\n", LOG_VALUE, pdn_cntxt->gx_sess_id);
		return -1;
	}

	/* Update UE State */
	pdn_cntxt->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Set GX rar message */
	resp->msg_type = GX_RAR_MSG;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;


	/* Update UE Proc */
	pdn_cntxt->proc = DED_BER_ACTIVATION_PROC;

	resp->proc = DED_BER_ACTIVATION_PROC;

	pdn_cntxt->rqst_ptr = gx_context->rqst_ptr;

	teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (teid_value == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for teid value, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	/*Store TEID and msg_type*/
	teid_value->teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
	teid_value->msg_type = resp->msg_type;

	snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(resp->proc), seq_no);

	/* Add the entry for sequence and teid value for error handling */
	if (pdn_cntxt->context->cp_mode != SAEGWC) {
		ret = add_seq_number_for_teid(teid_key, teid_value);
		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"Sequence number for TEID: %u\n", LOG_VALUE,
					teid_value->teid);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}
	return 0;
}

int
gx_delete_bearer_req(pdn_connection *pdn_cntxt){

	int ret = 0;
	uint32_t seq_no = 0;
	gx_context_t *gx_context = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	struct teid_value_t *teid_value = NULL;
	teid_key_t teid_key = {0};

	if ((pdn_cntxt->proc == UE_REQ_BER_RSRC_MOD_PROC)
			&& (pdn_cntxt->context != NULL)
			&& (pdn_cntxt->context)->ue_initiated_seq_no) {
		seq_no = (pdn_cntxt->context)->ue_initiated_seq_no;
	} else {

		seq_no = generate_seq_number();
	}

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn_cntxt->seid);
		return -1;
	}

	reset_resp_info_structure(resp);

	fill_pfcp_gx_sess_mod_req(&pfcp_sess_mod_req, pdn_cntxt, RULE_ACTION_DELETE, resp);
	// Maintaining seq no in ue cntxt is not good idea, move it to PDN
	pdn_cntxt->context->sequence = seq_no;

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

	ret = set_dest_address(pdn_cntxt->upf_ip, &upf_pfcp_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	if ( pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr,SENT) < 0 ){
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error in sending PFCP Session "
			"Modification Request for Delete Bearer Request, Error : %i\n", LOG_VALUE, errno);
	} else {
		int ebi_index = GET_EBI_INDEX(pdn_cntxt->default_bearer_id);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		}

		if(pdn_cntxt->context->cp_mode == PGWC){
			add_pfcp_if_timer_entry(pdn_cntxt->s5s8_pgw_gtpc_teid, &upf_pfcp_sockaddr,
					pfcp_msg, encoded, ebi_index);
		}
		if(pdn_cntxt->context->cp_mode == SAEGWC)
		{
			add_pfcp_if_timer_entry(pdn_cntxt->context->s11_sgw_gtpc_teid, &upf_pfcp_sockaddr,
					pfcp_msg, encoded, ebi_index);
		}
	}

	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn_cntxt->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn_cntxt->gx_sess_id);
		return -1;
	}

	/* Update UE State */
	pdn_cntxt->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn_cntxt->seid);
		return -1;
	}

	/* Set GX rar message */
	resp->msg_type = GX_RAR_MSG;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;


	/* Update UE Proc */
	pdn_cntxt->proc = PDN_GW_INIT_BEARER_DEACTIVATION;

	resp->proc = PDN_GW_INIT_BEARER_DEACTIVATION;

	pdn_cntxt->rqst_ptr = gx_context->rqst_ptr;
	teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (teid_value == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for teid value, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	/*Store TEID and msg_type*/
	teid_value->teid = pdn_cntxt->s5s8_pgw_gtpc_teid;
	teid_value->msg_type = resp->msg_type;

	snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(resp->proc), seq_no);

	/* Add the entry for sequence and teid value for error handling */
	if (pdn_cntxt->context->cp_mode != SAEGWC) {
		ret = add_seq_number_for_teid(teid_key, teid_value);
		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"Sequence number for TEID: %u\n", LOG_VALUE,
					teid_value->teid);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}
	return 0;
}

int
gx_update_bearer_req(pdn_connection *pdn){

	int ret = 0;
	uint32_t seq_no = 0;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	upd_bearer_req_t ubr_req = {0};
	int send_ubr = 0;
	uint8_t len = 0;
	uint8_t cp_mode = 0;
	uint16_t payload_length = 0;
	struct teid_value_t *teid_value = NULL;
	teid_key_t teid_key = {0};

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	if ((pdn->proc == UE_REQ_BER_RSRC_MOD_PROC || pdn->proc == HSS_INITIATED_SUB_QOS_MOD)
			&& (pdn->context != NULL)
			&& (pdn->context)->ue_initiated_seq_no) {
		seq_no =(pdn->context)->ue_initiated_seq_no;
	} else {
		seq_no = generate_seq_number();
	}

	if (get_sess_entry(pdn->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn->seid);
		return DIAMETER_ERROR_USER_UNKNOWN;
	}

	reset_resp_info_structure(resp);
	/* Retrive the UE Context */
	ret = get_ue_context(UE_SESS_ID(pdn->seid), &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"Context for teid : %u \n", LOG_VALUE, UE_SESS_ID(pdn->seid));
		return DIAMETER_ERROR_USER_UNKNOWN;
	}

	/* Start Creating UBR request */

	if (pdn->proc == UE_REQ_BER_RSRC_MOD_PROC)
		set_pti(&ubr_req.pti, IE_INSTANCE_ZERO, context->proc_trans_id);

	cp_mode = context->cp_mode;

	if (context->cp_mode != PGWC) {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &ubr_req, GTP_UPDATE_BEARER_REQ,
				context->s11_mme_gtpc_teid, seq_no, 0);
	} else {
		set_gtpv2c_teid_header((gtpv2c_header_t *) &ubr_req, GTP_UPDATE_BEARER_REQ,
				pdn->s5s8_sgw_gtpc_teid, seq_no, 0);
	}
	ubr_req.apn_ambr.apn_ambr_uplnk = pdn->apn_ambr.ambr_uplink;
	ubr_req.apn_ambr.apn_ambr_dnlnk = pdn->apn_ambr.ambr_downlink;

	set_ie_header(&ubr_req.apn_ambr.header, GTP_IE_AGG_MAX_BIT_RATE, IE_INSTANCE_ZERO,
				sizeof(uint64_t));

	/* For now not supporting user location retrive
	set_ie_header(&ubr_req.indctn_flgs.header, GTP_IE_INDICATION, IE_INSTANCE_ZERO,
    	                           sizeof(gtp_indication_ie_t)- sizeof(ie_header_t));
	ubr_req.indctn_flgs.indication_retloc = 1;
	*/

	for (int32_t idx = 0; idx < pdn->policy.count ; idx++)
	{
		if (pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY ||
			pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_ADD_RULE ||
			pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_REMOVE_RULE ) {

			uint8_t tft_op_code = 0;

			if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY){
				tft_op_code = TFT_REPLACE_FILTER_EXISTING;
			}else if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_ADD_RULE){
				tft_op_code = TFT_ADD_FILTER_EXISTING;
			}else if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_REMOVE_RULE){
				tft_op_code = TFT_REMOVE_FILTER_EXISTING;
			}

			if(pdn->policy.pcc_rule[idx].action != RULE_ACTION_MODIFY_REMOVE_RULE){
				bearer = get_bearer(pdn, &pdn->policy.pcc_rule[idx].dyn_rule.qos);
			} else {
				rule_name_key_t rule_name = {0};
				memset(rule_name.rule_name, '\0', sizeof(rule_name.rule_name));
				snprintf(rule_name.rule_name, RULE_NAME_LEN, "%s%d",
						pdn->policy.pcc_rule[idx].dyn_rule.rule_name, pdn->call_id);
				int8_t bearer_id = get_rule_name_entry(rule_name);
				bearer = context->eps_bearers[bearer_id];
			}

			if(bearer == NULL){
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Bearer return is Null for that QoS recived in RAR: %d \n",
					LOG_VALUE);
				return DIAMETER_ERROR_USER_UNKNOWN;

			}
			if(bearer->qos_bearer_check != PRESENT && bearer->flow_desc_check !=PRESENT) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Flow description and"
						" Qos not Updated,Not Expected \n", LOG_VALUE);
				return DIAMETER_INVALID_AVP_VALUE;
			}
			if(bearer->action == pdn->policy.pcc_rule[idx].action){

				set_ie_header(&ubr_req.bearer_contexts[ubr_req.bearer_context_count].header,
													GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);

				if(bearer->flow_desc_check == PRESENT && pdn->proc != HSS_INITIATED_SUB_QOS_MOD) {

					len = set_bearer_tft(&ubr_req.bearer_contexts[ubr_req.bearer_context_count].tft,
											IE_INSTANCE_ZERO,
											tft_op_code,
											bearer,
											pdn->policy.pcc_rule[idx].dyn_rule.rule_name);
					ubr_req.bearer_contexts[ubr_req.bearer_context_count].header.len += len;

				}
				if(pdn->policy.pcc_rule[idx].action == RULE_ACTION_MODIFY_REMOVE_RULE)
					delete_bearer_rule(bearer, pdn->policy.pcc_rule[idx].dyn_rule.rule_name);
				if(bearer->qos_bearer_check == PRESENT) {

					set_bearer_qos(&ubr_req.bearer_contexts[idx].bearer_lvl_qos,
								IE_INSTANCE_ZERO, bearer);

					ubr_req.bearer_contexts[idx].header.len +=
						sizeof(gtp_bearer_qlty_of_svc_ie_t);

				}
				resp->eps_bearer_ids[resp->bearer_count++] = bearer->eps_bearer_id;

				set_ebi(&ubr_req.bearer_contexts[ubr_req.bearer_context_count].eps_bearer_id,
						IE_INSTANCE_ZERO, bearer->eps_bearer_id);
				ubr_req.bearer_contexts[ubr_req.bearer_context_count].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

				ubr_req.bearer_context_count++;
				send_ubr++;
			}
		}
	}
	if(bearer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Rule Name not Matching or Bearer is NULL, so can't initiate "
					"Update Bearer Req \n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	/*need to send mutiple bearer context for hss initiated flow in case of arp change*/
	if(pdn->proc == HSS_INITIATED_SUB_QOS_MOD
		&& bearer->arp_bearer_check == PRESENT) {
		uint8_t bearer_counter = 0;

		for(uint8_t idx = 0; idx < MAX_BEARERS; idx++) {
			bearer = pdn->eps_bearers[idx];
			if(bearer != NULL) {

				if(bearer->eps_bearer_id == pdn->default_bearer_id) {
					bearer_counter++;
					continue;
				}
				if(bearer->arp_bearer_check == PRESENT) {
					/*bearer context for dedicated bearer arp changes*/
					set_ie_header(&ubr_req.bearer_contexts[ubr_req.bearer_context_count].header,
													GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);

					set_bearer_qos(&ubr_req.bearer_contexts[bearer_counter].bearer_lvl_qos,
								IE_INSTANCE_ZERO, bearer);

					ubr_req.bearer_contexts[bearer_counter].header.len +=
						sizeof(gtp_bearer_qlty_of_svc_ie_t);

					resp->eps_bearer_ids[resp->bearer_count++] = bearer->eps_bearer_id;

					set_ebi(&ubr_req.bearer_contexts[ubr_req.bearer_context_count].eps_bearer_id,
							IE_INSTANCE_ZERO, bearer->eps_bearer_id);
					ubr_req.bearer_contexts[ubr_req.bearer_context_count].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

					ubr_req.bearer_context_count++;
					bearer_counter++;

				}
			}
		}
	}

	int ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI Index\n",
				LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	gx_context_t *gx_context = NULL;
	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN Gx "
			"HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
		return DIAMETER_UNKNOWN_SESSION_ID;
	}

	if(context->pra_flag){
		set_presence_reporting_area_action_ie(&ubr_req.pres_rptng_area_act, context);
		context->pra_flag = 0;
	}

	pdn->rqst_ptr = gx_context->rqst_ptr;


	/* Update UE State */
	pdn->state = UPDATE_BEARER_REQ_SNT_STATE;

	/* Update UE Proc */
	pdn->proc = UPDATE_BEARER_PROC;
	resp->proc =  UPDATE_BEARER_PROC;

	resp->msg_type = GTP_UPDATE_BEARER_REQ;
	resp->teid = UE_SESS_ID(pdn->seid);

	resp->state =  UPDATE_BEARER_REQ_SNT_STATE;


	if(send_ubr){
		memcpy(&resp->gtpc_msg.ub_req, &ubr_req, sizeof(upd_bearer_req_t));
		payload_length = encode_upd_bearer_req(&ubr_req, (uint8_t *)gtpv2c_tx);

		if(SAEGWC != context->cp_mode){
			//send S5S8 or on S11  interface update bearer request.

			ret = set_dest_address(pdn->s5s8_sgw_gtpc_ip, &s5s8_recv_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
					s5s8_recv_sockaddr,SENT);

			add_gtpv2c_if_timer_entry(
					context->s11_sgw_gtpc_teid,
					&s5s8_recv_sockaddr, tx_buf, payload_length,
					ebi_index, S5S8_IFACE, cp_mode);

			process_cp_li_msg(pdn->seid, S5S8_C_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s5s8_recv_sockaddr.type,
							config.s5s8_ip.s_addr,
							config.s5s8_ip_v6.s6_addr),
					fill_ip_info(s5s8_recv_sockaddr.type,
							s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
							s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s5s8_port,
					((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
						ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
		} else {
			ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
					s11_mme_sockaddr,SENT);

			add_gtpv2c_if_timer_entry(
					context->s11_sgw_gtpc_teid,
					&s11_mme_sockaddr, tx_buf, payload_length,
					ebi_index, S11_IFACE, cp_mode);

			process_cp_li_msg(pdn->seid, S11_INTFC_OUT, tx_buf, payload_length,
					fill_ip_info(s11_mme_sockaddr.type,
							config.s11_ip.s_addr,
							config.s11_ip_v6.s6_addr),
					fill_ip_info(s11_mme_sockaddr.type,
							s11_mme_sockaddr.ipv4.sin_addr.s_addr,
							s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
					config.s11_port,
					((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s11_mme_sockaddr.ipv4.sin_port) :
						ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
		}
	}
	teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (teid_value == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for teid value, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	/*Store TEID and msg_type*/
	teid_value->teid = pdn->s5s8_pgw_gtpc_teid;
	teid_value->msg_type = resp->msg_type;

	snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(resp->proc), seq_no);

	/* Add the entry for sequence and teid value for error handling */
	if (pdn->context->cp_mode != SAEGWC) {
		ret = add_seq_number_for_teid(teid_key, teid_value);
		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"Sequence number for TEID: %u\n", LOG_VALUE,
					teid_value->teid);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	return 0;
}

/*Handling of RAA message*/
int16_t
parse_gx_rar_msg(GxRAR *rar, pdn_connection *pdn_cntxt)
{
	int16_t ret = 0;
	struct resp_info *resp = NULL;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry Found "
			"for sess ID:%lu\n", LOG_VALUE, pdn_cntxt->seid);
		return -1;
	}

	reset_resp_info_structure(resp);

	resp->gx_msg.rar = *rar;

	if(rar->presence.default_eps_bearer_qos)
	{
		ret = store_default_bearer_qos_in_policy(pdn_cntxt, rar->default_eps_bearer_qos);
		if (ret)
			return ret;
	}
	ret = store_dynamic_rules_in_policy(pdn_cntxt,
			&(rar->charging_rule_install), &(rar->charging_rule_remove));
	if (ret){
	        return ret;
	}

	rar_funtions rar_function = NULL;
	rar_function = rar_process(pdn_cntxt, NONE_PROC);

	if(rar_function != NULL){
		ret = rar_function(pdn_cntxt);
	} else {
		ret = DIAMETER_MISSING_AVP;
	}

	if(ret){
		return ret;
	}

	/* Storing the Event Trigger received in RAA message*/
	ret = store_event_trigger(pdn_cntxt, &(rar->event_trigger));
	if (ret < 0)
		return ret;

	return 0;
}

void
get_charging_rule_remove_bearer_info(pdn_connection *pdn,
	uint8_t *lbi, uint8_t *ded_ebi, uint8_t *ber_cnt)
{
	int8_t bearer_id;

	for (int idx = 0; idx < pdn->policy.count; idx++) {
		if(RULE_ACTION_DELETE == pdn->policy.pcc_rule[idx].action)
		{
			rule_name_key_t rule_name = {0};

			if(pdn->policy.pcc_rule[idx].predefined_rule){
				snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s",
						pdn->policy.pcc_rule[idx].pdef_rule.rule_name);
			}else{
				snprintf(rule_name.rule_name, RULE_NAME_LEN,"%s%d",
					pdn->policy.pcc_rule[idx].dyn_rule.rule_name, pdn->call_id);
			}
			bearer_id = get_rule_name_entry(rule_name);
			if (-1 == bearer_id) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Invalid bearer_id=%d\n",
						LOG_VALUE, bearer_id);
				return;
			}
			if (pdn->default_bearer_id == (bearer_id + NUM_EBI_RESERVED)) {
				*lbi = pdn->default_bearer_id;
				*ber_cnt = pdn->num_bearer;
				for (int8_t iCnt = 0; iCnt < MAX_BEARERS; ++iCnt) {
					if (NULL != pdn->eps_bearers[iCnt]) {
						*ded_ebi = pdn->eps_bearers[iCnt]->eps_bearer_id;
						ded_ebi++;
					}
				}
				return;
			} else {
				*ded_ebi = bearer_id + NUM_EBI_RESERVED;
				ded_ebi++;
				*ber_cnt = *ber_cnt + NUM_EBI_RESERVED;
			}
		}
	}

	return;
}

int
compare_flow_description(dynamic_rule_t *old_dyn_rule, dynamic_rule_t *new_dyn_rule) {

	bool match_pkt_fltr = FALSE;
		if(old_dyn_rule->num_flw_desc != new_dyn_rule->num_flw_desc) {
			    clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"old_dyn_rule->num_flw_desc : %d\n",
						LOG_VALUE, old_dyn_rule->num_flw_desc);
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"new_dyn_rule->num_flw_desc : %d\n",
						LOG_VALUE, new_dyn_rule->num_flw_desc);
				return 1;
		}

		for( int old_pkt_cnt = 0; old_pkt_cnt < old_dyn_rule->num_flw_desc; old_pkt_cnt++) {
			match_pkt_fltr = FALSE;

			for( int new_pkt_cnt = 0; new_pkt_cnt < new_dyn_rule->num_flw_desc; new_pkt_cnt++) {

				if( (old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.proto_id !=
							new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.proto_id) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.proto_mask !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.proto_mask) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.direction !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.direction) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.action !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.action) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.local_ip_mask !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.local_ip_mask) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.remote_ip_mask !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.remote_ip_mask) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.local_port_low !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.local_port_low) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.local_port_high !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.local_port_high) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.remote_port_low !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.remote_port_low) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.remote_port_high !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.remote_port_high) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.local_ip_addr.s_addr !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.local_ip_addr.s_addr) ||

						(old_dyn_rule->flow_desc[old_pkt_cnt].sdf_flw_desc.remote_ip_addr.s_addr !=
						 new_dyn_rule->flow_desc[new_pkt_cnt].sdf_flw_desc.remote_ip_addr.s_addr)) {

							 if(new_pkt_cnt == (new_dyn_rule->num_flw_desc -1)
									 && match_pkt_fltr != TRUE ) {
								 return 1;
							 }
						 } else {
							 match_pkt_fltr = TRUE;
						 }
			}

		}

		return 0;
}

int
compare_bearer_qos(dynamic_rule_t *old_dyn_rule, dynamic_rule_t *new_dyn_rule) {

	if( (old_dyn_rule->qos.qci != new_dyn_rule->qos.qci) ||

			(old_dyn_rule->qos.ul_mbr != new_dyn_rule->qos.ul_mbr) ||

			(old_dyn_rule->qos.dl_mbr != new_dyn_rule->qos.dl_mbr) ||

			(old_dyn_rule->qos.ul_gbr != new_dyn_rule->qos.ul_gbr) ||

			(old_dyn_rule->qos.dl_gbr != new_dyn_rule->qos.dl_gbr) ||

			(old_dyn_rule->qos.arp.preemption_vulnerability != new_dyn_rule->qos.arp.preemption_vulnerability) ||

			(old_dyn_rule->qos.arp.priority_level != new_dyn_rule->qos.arp.priority_level) ||

			(old_dyn_rule->qos.arp.preemption_capability != new_dyn_rule->qos.arp.preemption_capability)) {

			return 1;
	}

			return 0;
}

int
store_rule_status_for_pro_ack(policy_t *policy,
		pro_ack_rule_array_t  *pro_ack_rule_array) {

	if(policy == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Policy is empty\n",
			LOG_VALUE);
		return -1;
	}

	for (int cnt=0; cnt < policy->count; cnt++) {
		if(policy->pcc_rule[cnt].predefined_rule){
			strncpy(pro_ack_rule_array->rule[cnt].rule_name,
					policy->pcc_rule[cnt].pdef_rule.rule_name,
					strlen(policy->pcc_rule[cnt].pdef_rule.rule_name));
		}else{
			strncpy(pro_ack_rule_array->rule[cnt].rule_name,
					policy->pcc_rule[cnt].dyn_rule.rule_name,
					strlen(policy->pcc_rule[cnt].dyn_rule.rule_name));
		}
		if(policy->pcc_rule[cnt].action != RULE_ACTION_MODIFY_REMOVE_RULE
				&& policy->pcc_rule[cnt].action != RULE_ACTION_DELETE) {
			pro_ack_rule_array->rule[cnt].rule_status = ACTIVE;
		} else {
			pro_ack_rule_array->rule[cnt].rule_status = INACTIVE;
		}
		pro_ack_rule_array->rule_cnt++;
	}

	return 0;
}

int
compare_bearer_arp(dynamic_rule_t *old_dyn_rule, dynamic_rule_t *new_dyn_rule) {

	if((old_dyn_rule->qos.arp.preemption_vulnerability != new_dyn_rule->qos.arp.preemption_vulnerability) ||

		(old_dyn_rule->qos.arp.priority_level != new_dyn_rule->qos.arp.priority_level) ||

		(old_dyn_rule->qos.arp.preemption_capability != new_dyn_rule->qos.arp.preemption_capability)) {

		return 1;
	}

		return 0;
}
void
change_arp_for_ded_bearer(pdn_connection *pdn, bearer_qos_ie *qos) {

	eps_bearer *bearer = NULL;

	for(uint8_t idx = 0; idx < MAX_BEARERS; idx++)
	{
		bearer = pdn->eps_bearers[idx];
		if(bearer != NULL)
		{

			if(bearer->eps_bearer_id == pdn->default_bearer_id)
				continue;
			if(bearer->arp_bearer_check == PRESENT) {
				bearer->qos.arp.preemption_vulnerability = qos->arp.preemption_vulnerability;
				bearer->qos.arp.priority_level = qos->arp.priority_level;
				bearer->qos.arp.preemption_capability = qos->arp.preemption_capability;
			}
		}
	}
	return;
}
