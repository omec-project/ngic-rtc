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

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_cfgfile.h>

#include "up_main.h"
#include "util.h"
#include "interface.h"
#include "dp_ipc_api.h"


#ifdef PRINT_NEW_RULE_ENTRY
/**
 * @Name : print_sel_type_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
void
print_sel_type_val(struct adc_rules *adc)
{
	if (NULL != adc) {
	struct in_addr addr = {0};
		switch (adc->sel_type) {
			case DOMAIN_NAME:
				RTE_LOG_DP(NOTICE, DP, " ---> Domain Name :%s\n",
						adc->u.domain_name);
				break;

			case DOMAIN_IP_ADDR:
				addr.s_addr = ntohl(adc->u.domain_ip.u.ipv4_addr);
				RTE_LOG_DP(NOTICE, DP, " ---> Domain Ip :%s\n",
						inet_ntoa(addr));
				break;

			case DOMAIN_IP_ADDR_PREFIX:
				addr.s_addr = ntohl(adc->u.domain_ip.u.ipv4_addr);
				RTE_LOG_DP(NOTICE, DP, " ---> Domain Ip :%s\n",
						inet_ntoa(addr));
				RTE_LOG_DP(NOTICE, DP, " ---> Domain Prefix :%u\n",
						adc->u.domain_prefix.prefix);
				break;

			default:
				RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
						adc->sel_type);
				break;
		}
	}
}

/**
 * @Name : print_adc_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
void
print_adc_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		RTE_LOG_DP(NOTICE, DP, "=========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> ADC Rule Method ::\n");
		RTE_LOG_DP(NOTICE, DP, "=========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> Rule id : %d\n", adc->rule_id);

		print_sel_type_val(adc);

		RTE_LOG_DP(NOTICE, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_pcc_val
 * @arguments : [In] pointer to pcc rule structure element
 * @return : void
 * @Description : Function to print PCC rules values.
 */
void
print_pcc_val(struct pcc_rules *pcc)
{
	if (NULL != pcc) {
		RTE_LOG_DP(NOTICE, DP, "=========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> PCC Rule Method ::\n");
		RTE_LOG_DP(NOTICE, DP, "=========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> Rule id : %d\n", pcc->rule_id);
		RTE_LOG_DP(NOTICE, DP, " ---> metering_method :%d\n",
				pcc->metering_method);
		RTE_LOG_DP(NOTICE, DP, " ---> charging_mode :%d\n",
				pcc->charging_mode);
		RTE_LOG_DP(NOTICE, DP, " ---> rating_group :%d\n",
				pcc->rating_group);
		RTE_LOG_DP(NOTICE, DP, " ---> rule_status :%d\n",
				pcc->rule_status);
		RTE_LOG_DP(NOTICE, DP, " ---> gate_status :%d\n",
				pcc->gate_status);
		RTE_LOG_DP(NOTICE, DP, " ---> session_cont :%d\n",
				pcc->session_cont);
		RTE_LOG_DP(NOTICE, DP, " ---> monitoring_key :%d\n",
				pcc->monitoring_key);
		RTE_LOG_DP(NOTICE, DP, " ---> precedence :%d\n",
				pcc->precedence);
		RTE_LOG_DP(NOTICE, DP, " ---> level_of_report :%d\n",
				pcc->report_level);
		RTE_LOG_DP(NOTICE, DP, " ---> mute_status :%d\n",
				pcc->mute_notify);
		RTE_LOG_DP(NOTICE, DP, " ---> drop_pkt_count :%ld\n",
				pcc->drop_pkt_count);
		RTE_LOG_DP(NOTICE, DP, " ---> redirect_info :%d\n",
				pcc->redirect_info.info);
		RTE_LOG_DP(NOTICE, DP, " ---> ul_mbr_mtr_profile_idx :%d\n",
				pcc->qos.ul_mtr_profile_index);
		RTE_LOG_DP(NOTICE, DP, " ---> dl_mbr_mtr_profile_idx :%d\n",
				pcc->qos.dl_mtr_profile_index);
		RTE_LOG_DP(NOTICE, DP, " ---> ADC Index :%d\n",
				pcc->adc_idx);
		RTE_LOG_DP(NOTICE, DP, " ---> SDF Index count:%d\n",
				pcc->sdf_idx_cnt);
		for(int i =0; i< pcc->sdf_idx_cnt; ++i)
			RTE_LOG_DP(NOTICE, DP, " ---> SDF IDx [%d]:%d\n",
					i, pcc->sdf_idx[i]);
		RTE_LOG_DP(NOTICE, DP, " ---> rule_name:%s\n", pcc->rule_name);
		RTE_LOG_DP(NOTICE, DP, " ---> sponsor_id:%s\n", pcc->sponsor_id);
		RTE_LOG_DP(NOTICE, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_mtr_val
 * @arguments : [In] pointer to mtr entry structure element
 * @return : void
 * @Description : Function to print METER rules values.
 */
void
print_mtr_val(struct mtr_entry *mtr)
{
	if (NULL != mtr) {
		RTE_LOG_DP(NOTICE, DP, "=========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> Meter Rule Method ::\n");
		RTE_LOG_DP(NOTICE, DP, "=========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> Meter profile index :%d\n",
				mtr->mtr_profile_index);
		RTE_LOG_DP(NOTICE, DP, " ---> Meter CIR :%ld\n",
				mtr->mtr_param.cir);
		RTE_LOG_DP(NOTICE, DP, " ---> Meter CBS :%ld\n",
				mtr->mtr_param.cbs);
		RTE_LOG_DP(NOTICE, DP, " ---> Meter EBS :%ld\n",
				mtr->mtr_param.ebs);
		RTE_LOG_DP(NOTICE, DP, " ---> Metering Method :%d\n",
				mtr->metering_method);
		RTE_LOG_DP(NOTICE, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_sdf_val
 * @arguments : [In] pointer to pkt_filter structure element
 * @return : void
 * @Description : Function to print SDF rules values.
 */
void
print_sdf_val(struct pkt_filter *sdf)
{
	if (NULL != sdf) {
		RTE_LOG_DP(NOTICE, DP, "==========================================\n");
		RTE_LOG_DP(NOTICE, DP, " ---> SDF Rule Method ::\n");
		RTE_LOG_DP(NOTICE, DP, "==========================================\n");

		switch (sdf->sel_rule_type) {
			case RULE_STRING:
				RTE_LOG_DP(NOTICE, DP, " ---> pcc_rule_id :%d\n",
						sdf->pcc_rule_id);
				RTE_LOG_DP(NOTICE, DP, " ---> rule_type :%d\n",
						sdf->sel_rule_type);
				RTE_LOG_DP(NOTICE, DP, " ---> rule_str : %s\n",
						sdf->u.rule_str);
				RTE_LOG_DP(NOTICE, DP, "====================================\n\n");
				break;

			case FIVE_TUPLE:
				/*TODO: rule should be in struct
				 * five_tuple_rule
				 * This field is currently not used
				 */
				break;

			default:
				RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
						sdf->sel_rule_type);
				break;
		}
	}
}
#endif /*PRINT_NEW_RULE_ENTRY*/

/**
 * Name : parse_adc_val
 * argument :
 * selctor type pointed to adc rule type
 * [In] pointer (arm) to zmq rcv structure element
 * [Out] pointer (adc) to adc rules structure element
 * @return
 * 0 - success
 * -1 - fail
 * Description : Function to parse adc rules values into
 * adc_rules struct.
 * Here parse values as per selector type (DOMAIN_NAME,
 * DOMAIN_IP_ADDR, and DOMAIN_IP_ADDR_PREFIX), domain name,
 * domain ip addr, domain prefix parameters values from recv buf and
 * stored into adc_rules struct.
 * ref.doc: message_sdn.docx
 * section : Table No.11 ADC Rules
 */
int
parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc)
{
		if (arm != NULL) {
			switch (sel_type) {
				case DOMAIN_NAME:
					strncpy(adc->u.domain_name, (char *)((arm)+1),
							*(uint8_t *)(arm));

#ifdef PRINT_NEW_RULE_ENTRY
					print_adc_val(adc);
#endif
					return 0;

				case DOMAIN_IP_ADDR_PREFIX:
					adc->u.domain_ip.u.ipv4_addr =
						ntohl(*(uint32_t *)(arm));
					adc->u.domain_prefix.prefix =
						rte_bswap16(*(uint16_t *)((arm) + 4));
#ifdef PRINT_NEW_RULE_ENTRY
					print_adc_val(adc);
#endif  /* PRINT_NEW_RULE_ENTRY */
					return 0;

				case DOMAIN_IP_ADDR:
					adc->u.domain_ip.u.ipv4_addr =
						ntohl(*(uint32_t *)(arm));
#ifdef PRINT_NEW_RULE_ENTRY
					print_adc_val(adc);
#endif  /* PRINT_NEW_RULE_ENTRY */
					return 0;

				default:
					RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
							sel_type);
					return -1;
			}
		}
		return -1;
}

/**
 * @Name : get_sdf_indices
 * @argument :
 * [IN] sdf_idx : String containing comma separater SDF index values
 * [OUT] out_sdf_idx : Array of integers converted from sdf_idx
 * @return : 0 - success, -1 fail
 * @Description : Convert sdf_idx array in to array of integers for SDF index
 * values.
 * Sample input : "[0, 1, 2, 3]"
 */
uint32_t
get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx)
{
	char *tmp = strtok (sdf_idx,",");
	int i = 0;

	while ((NULL != tmp) && (i < MAX_SDF_IDX_COUNT)) {
		out_sdf_idx[i++] = atoi(tmp);
		tmp = strtok (NULL, ",");
	}
	return i;
}

