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

#include "pfcp.h"
#include "cp_config.h"
#include "cp_stats.h"
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cfgfile.h>
#include <rte_string_fns.h>

//REVIEW: Need to check this: No need to add this header files
#include "pfcp.h"
#include "sm_enum.h"
#include "cp_stats.h"
#include "sm_struct.h"
#include "pfcp_util.h"
#include "cp_config.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_messages_encoder.h"

#define PRESENT 1
#define NUM_VALS 9

extern int pfcp_fd;

/* VS: Fill UE context default bearer information of default_eps_bearer_qos from CCA */
static int
assign_default_bearer_eps_bearer_qos(eps_bearer *context, GxCCA *cca)
{

	if ((cca == NULL) && (context == NULL ))
		return -1;

	if (cca->presence.default_eps_bearer_qos != PRESENT) {
		clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:default_eps_bearer_qos is missing \n",
				__file__, __func__, __LINE__);
		return -1;
	}

	if (cca->default_eps_bearer_qos.presence.qos_class_identifier == PRESENT) {
	    context->qos.qci =
	        cca->default_eps_bearer_qos.qos_class_identifier;

	}


	if (cca->default_eps_bearer_qos.presence.allocation_retention_priority == PRESENT) {
	    if (cca->default_eps_bearer_qos.allocation_retention_priority.presence.priority_level == PRESENT)
	        context->qos.arp.priority_level =
	            cca->default_eps_bearer_qos.allocation_retention_priority.priority_level;


	    if (cca->default_eps_bearer_qos.allocation_retention_priority.presence.pre_emption_capability == PRESENT)
	        context->qos.arp.preemption_capability =
	            cca->default_eps_bearer_qos.allocation_retention_priority.pre_emption_capability;


	    if (cca->default_eps_bearer_qos.allocation_retention_priority.presence.pre_emption_vulnerability == PRESENT)
	        context->qos.arp.preemption_vulnerability =
	            cca->default_eps_bearer_qos.allocation_retention_priority.pre_emption_vulnerability;

	}

	return 0;
}

static void
fill_dedicated_bearer_qos(eps_bearer *bearer, GxChargingRuleDefinition *rule_definition)
{
	GxQosInformation *qos = &(rule_definition->qos_information);

	bearer->qos.qci = qos->qos_class_identifier;
	bearer->qos.arp.priority_level = qos->allocation_retention_priority.priority_level;
	bearer->qos.arp.preemption_capability = qos->allocation_retention_priority.pre_emption_capability;
	bearer->qos.arp.preemption_vulnerability = qos->allocation_retention_priority.pre_emption_vulnerability;
	bearer->qos.ul_mbr =  qos->max_requested_bandwidth_ul;
	bearer->qos.dl_mbr =  qos->max_requested_bandwidth_dl;
	bearer->qos.ul_gbr =  qos->guaranteed_bitrate_ul;
	//bearer->qos.ul_gbr =  qos->guaranteed_requested_bandwidth_ul;
	bearer->qos.dl_gbr =  qos->guaranteed_bitrate_dl;
	//bearer->qos.dl_gbr =  qos->guaranteed_requested_bandwidth_dl;
}

static void
get_charging_rule_name(GxChargingRuleDefinition *rule_definition, char rule_name[])
{
	rule_name[0] = '\0';
	if (rule_definition->presence.charging_rule_name == PRESENT)
	{
		memcpy(rule_name,
				rule_definition->charging_rule_name.val,
				rule_definition->charging_rule_name.len);

		rule_name[rule_definition->charging_rule_name.len] = '\0';
	}
}

static int
fill_sdf_strctr(char *str, sdf_pkt_fltr *pkt_filter)
{
	int nb_token = 0;
	char *str_fld[NUM_VALS];

	/* VG: format of sdf string is  */
	/* action dir fom src_ip src_port to dst_ip dst_port" */

	nb_token = rte_strsplit(str, strlen(str), str_fld, NUM_VALS, ' ');
	if (nb_token > NUM_VALS) {
		clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:Reach Max limit for sdf string \n",
				__file__, __func__, __LINE__);
		return -1;
	}

	for(int indx=0; indx < nb_token; indx++){

		if( indx == 0 ){
			if(strncmp(str_fld[0], "permit", strlen("permit")) != 0 ) {
                		clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:Skip sdf filling for IP filter rule action : %s \n",
				__file__, __func__, __LINE__,str_fld[0]);
                		return -1;
           		}
		} else if(indx == 2) {
			pkt_filter->proto_id = atoi(str_fld[2]);
		} else if (indx == 4){

			if( strstr(str_fld[4], "/") != NULL) {
				int ip_token = 0;
				char *ip_fld[2];
				ip_token = rte_strsplit(str_fld[4], strlen(str_fld[4]), ip_fld, 2, '/');
				if (ip_token > 2) {
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:Reach Max limit for sdf src ip \n",
							__file__, __func__, __LINE__);
					return -1;
				}
				if(inet_pton(AF_INET, (const char *) ip_fld[0], (void *)(&pkt_filter->local_ip_addr)) < 0){
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:conv of src ip fails \n",
							__file__, __func__, __LINE__);
					return -1;
				}

				pkt_filter->local_ip_mask = atoi(ip_fld[1]);
			} else {
				if(inet_pton(AF_INET, (const char *) str_fld[4], (void *)(&pkt_filter->local_ip_addr)) < 0){
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:conv of src ip fails \n",
							__file__, __func__, __LINE__);
					return -1;
				}
			}
		} else if(indx == 5){
			/*TODO VG : handling of multiple ports p1,p2,p3 etc*/

			if( strstr(str_fld[5], "-") != NULL) {
				int port_token = 0;
				char *port_fld[2];
				port_token = rte_strsplit(str_fld[5], strlen(str_fld[5]), port_fld, 2, '-');

				if (port_token > 2) {
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:Reach Max limit for sdf src port \n",
							__file__, __func__, __LINE__);
					return -1;
				}

				pkt_filter->local_port_low = atoi(port_fld[0]);
				pkt_filter->local_port_high = atoi(port_fld[1]);

			} else {
				pkt_filter->local_port_low = atoi(str_fld[5]);
			}
		} else if (indx == 7){

			if( strstr(str_fld[7], "/") != NULL) {
				int ip_token = 0;
				char *ip_fld[2];
				ip_token = rte_strsplit(str_fld[7], strlen(str_fld[7]), ip_fld, 2, '/');
				if (ip_token > 2) {
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:Reach Max limit for sdf dst ip \n",
							__file__, __func__, __LINE__);
					return -1;
				}
				if(inet_pton(AF_INET, (const char *) ip_fld[0], (void *)(&pkt_filter->remote_ip_addr)) < 0){
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:conv of dst ip fails \n",
							__file__, __func__, __LINE__);
					return -1;
				}

				pkt_filter->remote_ip_mask = atoi(ip_fld[1]);
			} else{
				if(inet_pton(AF_INET, (const char *) str_fld[7], (void *)(&pkt_filter->remote_ip_addr)) < 0){
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:conv of dst ip \n",
							__file__, __func__, __LINE__);
					return -1;
				}
			}
		} else if(indx == 8){
			/*TODO VG : handling of multiple ports p1,p2,p3 etc*/

			if( strstr(str_fld[8], "-") != NULL) {
				int port_token = 0;
				char *port_fld[2];
				port_token = rte_strsplit(str_fld[8], strlen(str_fld[8]), port_fld, 2, '-');

				if (port_token > 2) {
					clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:Reach Max limit for sdf dst port\n",
							__file__, __func__, __LINE__);
					return -1;
				}

				pkt_filter->remote_port_low = atoi(port_fld[0]);
				pkt_filter->remote_port_high = atoi(port_fld[1]);

			} else {
				pkt_filter->remote_port_low = atoi(str_fld[8]);
			}
		}
	}

		return 0;
}

static int
fill_charging_rule_definition(dynamic_rule_t *dynamic_rule,
					 GxChargingRuleDefinition *rule_definition, uint8_t bearer_id)
{
	int32_t idx = 0;
	bearer_id_t id = {0};

	/* VS: Allocate memory for dynamic rule */
//	dynamic_rule = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
//	    RTE_CACHE_LINE_SIZE, rte_socket_id());
//	if (dynamic_rule == NULL) {
//		fprintf(stderr, "Failure to allocate bearer id memory "
//				"structure: %s (%s:%d)\n",
//				rte_strerror(rte_errno),
//				__file__,
//				__LINE__);
//		return -1;
//	}

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

							fill_sdf_strctr(dynamic_rule->flow_desc[idx].sdf_flow_description,
									&(dynamic_rule->flow_desc[idx].sdf_flw_desc));

							/*VG assign direction in flow desc */
							dynamic_rule->flow_desc[idx].sdf_flw_desc.direction =(uint8_t)
	                                (rule_definition->flow_information).list[idx].flow_direction;

	                }
	        }
	}

	if (rule_definition->presence.charging_rule_name == PRESENT) {
		rule_name_key_t key = {0};
		id.bearer_id = bearer_id;

		memcpy(&key.rule_name, (char *)(rule_definition->charging_rule_name.val),
				rule_definition->charging_rule_name.len);

		memcpy(dynamic_rule->rule_name,
				rule_definition->charging_rule_name.val,
	            rule_definition->charging_rule_name.len);

		/* VS: Maintain the Rule Name and Bearer ID  mapping with call id */
		if (add_rule_name_entry(key, &id) != 0) {
			fprintf(stderr, "%s:%d Failed to add_rule_name_entry with rule_name\n",
					__func__, __LINE__);
			return -1;
		}
	}

	return 0;
}


static int
assign_rule_and_flow_description_in_bearer(eps_bearer *context, GxCCA *cca,
		uint8_t bearer_id)
{
	int32_t idx = 0, indx = 0, cnt = 0;

	for (idx = 0; idx < cca->charging_rule_install.count; idx++)
	{
	        if ((cca->charging_rule_install).list[idx].presence.charging_rule_definition == PRESENT)
	                for (indx = 0;
							indx < (cca->charging_rule_install).list[idx].charging_rule_definition.count;
							indx++)
	                {
						context->num_dynamic_filters =
						        (cca->charging_rule_install).list[idx].charging_rule_definition.count;

						for (cnt = 0; cnt < context->num_dynamic_filters; cnt++) {
							/* VS: Allocate memory for dynamic rule */
							context->dynamic_rules[cnt] = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
							    RTE_CACHE_LINE_SIZE, rte_socket_id());
							if (context->dynamic_rules[cnt] == NULL) {
								fprintf(stderr, "Failure to allocate dynamic rule memory "
										"structure: %s (%s:%d)\n",
										rte_strerror(rte_errno),
										__file__,
										__LINE__);
								return -1;
							}

	                        fill_charging_rule_definition(context->dynamic_rules[cnt],
	                                        (GxChargingRuleDefinition *)
											&((cca->charging_rule_install).list[idx].charging_rule_definition.list[cnt]),
											bearer_id);
						}
	                }
	}
	return 0;

}

static int8_t
compare_default_bearer_qos(bearer_qos_ie *qos,
					 GxQosInformation *qos_info)
{
	if (qos_info->presence.qos_class_identifier == PRESENT) {
		if (qos->qci != qos_info->qos_class_identifier) {
			clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
					__file__, __func__, __LINE__);
			return -1;
		}
	} else {
		if (!qos->qci) {
			clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
					__file__, __func__, __LINE__);
			return -1;
		}
	}

	if (qos_info->presence.allocation_retention_priority == PRESENT) {
		if (qos_info->allocation_retention_priority.presence.priority_level == PRESENT) {
			if (qos->arp.priority_level != qos_info->allocation_retention_priority.priority_level) {
				clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
						__file__, __func__, __LINE__);
				return -1;
			}
		} else {
			if (!qos->arp.priority_level) {
				clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
						__file__, __func__, __LINE__);
				return -1;
			}
		}

		if (qos_info->allocation_retention_priority.presence.pre_emption_capability == PRESENT) {
			if (qos->arp.preemption_capability != qos_info->allocation_retention_priority.pre_emption_capability) {
				clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
						__file__, __func__, __LINE__);
				return -1;
			}
		} else {
			if (!qos->arp.preemption_capability) {
				clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
						__file__, __func__, __LINE__);
				return -1;
			}
		}

		if (qos_info->allocation_retention_priority.presence.pre_emption_vulnerability == PRESENT) {
			if (qos->arp.preemption_vulnerability != qos_info->allocation_retention_priority.pre_emption_vulnerability) {
				clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
						__file__, __func__, __LINE__);
				return -1;
			}
		} else {
			if (!qos->arp.preemption_vulnerability) {
				clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
						__file__, __func__, __LINE__);
				return -1;
			}
		}
	} else {
		if (!qos->arp.priority_level) {
			clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
					__file__, __func__, __LINE__);
			return -1;
		} else if (!qos->arp.preemption_capability) {
			clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
					__file__, __func__, __LINE__);
			return -1;
		} else if (!qos->arp.preemption_vulnerability) {
			clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d \n",
					__file__, __func__, __LINE__);
			return -1;
		}
	}

	return 0;

}

static int8_t
retrieve_bearer_id(pdn_connection *pdn, GxCCA *cca)
{
	int32_t idx = 0, indx = 0;
	int8_t ret = 0, id = 0;


	for (idx = 0; idx < cca->charging_rule_install.count; idx++)
	{
	    if ((cca->charging_rule_install).list[idx].presence.charging_rule_definition == PRESENT) {
			for (indx = 0;
				indx < (cca->charging_rule_install).list[idx].charging_rule_definition.count;
				indx++)
			{
				for (id = 0;
						id < MAX_BEARERS;
						id++)
				{
					if (pdn->eps_bearers[id] == NULL)
						continue;

					if ((cca->charging_rule_install).list[idx].charging_rule_definition.list[indx].presence.qos_information == PRESENT) {
						ret = (compare_default_bearer_qos(&(pdn->eps_bearers[id])->qos,
								(GxQosInformation *)
								&((cca->charging_rule_install).list[idx].charging_rule_definition.list[indx].qos_information)));
						if (ret == 0)
							return id;
					} else {
						clLog(gxlogger, eCLSeverityCritical, "%s:%s:%d AVP:charging_rule_definition missing:"
								"AVP:Qos Information \n",
								__file__, __func__, __LINE__);
						return -1;
					}
				}
	       }
		}
	}
	return -1;
}

/* VS: TODO: Parse gx CCA response and fill UE context and pfcp context */
int8_t
parse_gx_cca_msg(GxCCA *cca, ue_context **_context)
{

	int ret = 0;
	int8_t bearer_id = 0;
	uint32_t call_id = 0;
	pdn_connection *pdn_cntxt = NULL;

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&cca->session_id.val, &call_id);
	if (ret < 0) {
	        fprintf(stderr, "%s:No Call Id found from session id:%s\n", __func__,
	                        cca->session_id.val);
	        return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn_cntxt = get_pdn_conn_entry(call_id);
	if (pdn_cntxt == NULL)
	{
	      fprintf(stderr, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
	                          __func__, call_id);
	      return -1;
	}

	/* Fill the BCM */
	pdn_cntxt->bearer_control_mode = cca->bearer_control_mode;


	/* VS: Overwirte the CSR qos values with CCA default eps bearer qos values */
	ret = assign_default_bearer_eps_bearer_qos(
	                pdn_cntxt->eps_bearers[pdn_cntxt->default_bearer_id - 5], cca);
	if (ret)
	        return ret;


	/* VS: Compare the default qos and CCA charging rule qos info and retrieve the bearer identifier */
	bearer_id = retrieve_bearer_id(pdn_cntxt, cca);
	if (bearer_id)
	        return bearer_id;

	/* VS: Fill the dynamic rule from rule install structure of cca */
	ret = assign_rule_and_flow_description_in_bearer(
	                pdn_cntxt->eps_bearers[bearer_id], cca, bearer_id);
	if (ret)
	        return ret;

	/* VS: Retrive the UE context to initiate the DNS and ASSOCIATION Request */
	*_context = pdn_cntxt->context;
	return bearer_id;
}

int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt)
{
	return pdn_cntxt->num_bearer;
}

int8_t
parse_gx_rar_msg(GxRAR *rar)
{
	int ret = 0;
	uint32_t call_id = 0;
	uint8_t bearer_id = 0;
	rule_name_key_t rule_key;
	ue_context *context = NULL;
	eps_bearer *ded_bearer = NULL;
	pdn_connection *pdn_cntxt = NULL;

	gx_context_t *gx_context = NULL;

	//dynamic_rule_t *dynamic_rule = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	//TODO :: Definfe generate_rar_seq
	uint32_t seq_no = generate_rar_seq();

	ded_bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (ded_bearer == NULL) {
		fprintf(stderr, "Failure to allocate bearer "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Extract the call id from session id */
	ret = retrieve_call_id((char *)&rar->session_id.val, &call_id);
	if (ret < 0) {
	        fprintf(stderr, "%s:No Call Id found from session id:%s\n", __func__,
	                        rar->session_id.val);
	        return -1;
	}

	/* Retrieve PDN context based on call id */
	pdn_cntxt = get_pdn_conn_entry(call_id);
	if (pdn_cntxt == NULL)
	{
	      fprintf(stderr, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
	                          __func__, call_id);
	      return -1;
	}

	/* VS: Retrive the UE Context */
	ret = get_ue_context(UE_SESS_ID(pdn_cntxt->seid), &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	context = pdn_cntxt->context;

	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn_cntxt->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		RTE_LOG_DP(ERR, CP, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
				pdn_cntxt->gx_sess_id);
		return -1;
	}

	for (int32_t idx = 0; idx < rar->charging_rule_install.count; idx++)
	{
		if ((rar->charging_rule_install).list[idx].presence.charging_rule_definition
				== PRESENT)
			for (
					int32_t indx = 0;
					indx < (rar->charging_rule_install).list[idx].charging_rule_definition.count;
					indx++
					)
			{
				for (
						int32_t cnt = 0;
						cnt < (rar->charging_rule_install).list[idx].charging_rule_definition.count;
						cnt++
						)
				{
					struct resp_info *resp = NULL;
					memset(&rule_key, 0, sizeof(rule_name_key_t));

					ded_bearer->dynamic_rules[cnt] = rte_zmalloc_socket(NULL, sizeof(dynamic_rule_t),
							    RTE_CACHE_LINE_SIZE, rte_socket_id());
					if (ded_bearer->dynamic_rules[cnt] == NULL) {
						fprintf(stderr, "Failure to allocate dynamic rule memory "
								"structure: %s (%s:%d)\n",
								rte_strerror(rte_errno),
								__file__,
								__LINE__);
						return -1;
					}

					get_charging_rule_name(
							&((rar->charging_rule_install).list[idx].charging_rule_definition.list[cnt]),
							rule_key.rule_name);
					if(rule_key.rule_name[0] == '\0')
					{
						/* 	this should not happen
							PCRF always send rule name
							Error andling required - Drop the RAR msg */
					}

					/* Commenting below line as currently we are not supporting modification rule
					 * if(get_rule_name_entry(rule_key) < 0) */
					{
						/*ded_bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
								RTE_CACHE_LINE_SIZE, rte_socket_id());
						if (ded_bearer == NULL) {
							fprintf(stderr, "Failure to allocate bearer "
									"structure: %s (%s:%d)\n",
									rte_strerror(rte_errno),
									__FILE__,
									__LINE__);
							return GTPV2C_CAUSE_SYSTEM_FAILURE;
						}*/
						ded_bearer->num_dynamic_filters =
							(rar->charging_rule_install).list[idx].charging_rule_definition.count;
						bearer_id = get_new_bearer_id(pdn_cntxt);
						ded_bearer->pdn = pdn_cntxt;
						pdn_cntxt->eps_bearers[bearer_id] = ded_bearer;
						context->eps_bearers[bearer_id] = ded_bearer;
						pdn_cntxt->num_bearer++;
						fill_charging_rule_definition(ded_bearer->dynamic_rules[cnt], // First rule on this bearer
								(GxChargingRuleDefinition *)
								&((rar->charging_rule_install).list[idx].charging_rule_definition.list[cnt]),
								bearer_id);
						fill_dedicated_bearer_qos(ded_bearer,  &((rar->charging_rule_install).list[idx].charging_rule_definition.list[cnt]));
						set_s5s8_pgw_gtpu_teid_using_pdn(ded_bearer, pdn_cntxt);
						fill_dedicated_bearer_info(ded_bearer, context, pdn_cntxt);
						pfcp_sess_mod_req.create_pdr_count = ded_bearer->pdr_count;
						fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, NULL, ded_bearer, pdn_cntxt, NULL, 0);
						// Maintaining seq no in ue cntxt is not good idea, move it to PDN
						pdn_cntxt->context->sequence = seq_no;

						uint8_t pfcp_msg[1024] = {0};
						int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
						pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
						header->message_len = htons(encoded - 4);

						if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
							printf("Error sending: %i\n",errno);
						} else {
							get_current_time(cp_stats.stat_timestamp);
						}


						/* Update UE State */
						(pdn_cntxt->context)->state = PFCP_SESS_MOD_REQ_SNT_STATE;

						/* Update UE Proc */
						(pdn_cntxt->context)->proc = DED_BER_ACTIVATION_PROC;

						/*Retrive the session information based on session id. */
						if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
							fprintf(stderr, "%s:%d NO Session Entry Found for sess ID:%lu\n",
									__func__, __LINE__, (pdn_cntxt->context)->pdns[bearer_id]->seid);
							return -1;
						}

						/* Set GX rar message */
						resp->eps_bearer_id = bearer_id + 5;
						resp->msg_type = GX_RAR_MSG;
						resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
						resp->proc = DED_BER_ACTIVATION_PROC;
					}
					/* Commenting below line as currently we are not supporting modification rule
					 * else
					{
						Its a bearer modification
						printf("%s: Modifcation\n", __func__);
					} */
				}
			}
	}

	memcpy( &(context->eps_bearers[bearer_id]->rqst_ptr), &(gx_context->rqst_ptr),
			sizeof(unsigned long));

	return 0;
}

