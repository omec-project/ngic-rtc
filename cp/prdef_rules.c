
/*
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

#include "cp.h"
#include "gw_adapter.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "packet_filters.h"
#include "vepc_cp_dp_api.h"
#include "predef_rule_init.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_session.h"

/* Maximum Rule counts */
#define MAX_RULE_CNT 16

const char *TFT_direction_str[] = {
		[TFT_DIRECTION_DOWNLINK_ONLY] = "DOWNLINK_ONLY ",
		[TFT_DIRECTION_UPLINK_ONLY] = "UPLINK_ONLY   ",
		[TFT_DIRECTION_BIDIRECTIONAL] = "BIDIRECTIONAL " };

extern int pfcp_fd;
extern int pfcp_fd_v6;
extern pfcp_config_t config;
extern peer_addr_t upf_pfcp_sockaddr;
extern int clSystemLog;
/* Validate the index already not in the list*/
static int8_t
check_exsting_indx_val(uint32_t indx, uint32_t num_cnt, uint32_t *rules_arr)
{
	for (uint32_t idx = 0; idx < num_cnt; idx++) {
		if (rules_arr[idx] == indx) {
			return PRESENT;
		}
	}
	return 0;
}

static struct pkt_filter *
build_sdf_rules(uint16_t index, pkt_fltr *sdf_filter)
{
	char local_ip[IPV6_STR_LEN];
	char remote_ip[IPV6_STR_LEN];

	if(PRESENT == sdf_filter->v4){
		snprintf(local_ip, sizeof(local_ip), "%s",
				inet_ntoa(sdf_filter->local_ip_addr));
		snprintf(remote_ip, sizeof(remote_ip), "%s",
				inet_ntoa(sdf_filter->remote_ip_addr));
	} else {
		inet_ntop(AF_INET6, sdf_filter->local_ip6_addr.s6_addr, local_ip, IPV6_STR_LEN);
		inet_ntop(AF_INET6, sdf_filter->remote_ip6_addr.s6_addr, remote_ip, IPV6_STR_LEN);
	}
	struct pkt_filter pktf = {
			.rule_id = index
	};
	pktf.direction = sdf_filter->direction;

	/* CP always send the SDF rule in Downlink Format */
	if(sdf_filter->v4){
		if ((sdf_filter->direction == TFT_DIRECTION_DOWNLINK_ONLY)
				|| (sdf_filter->direction == TFT_DIRECTION_UPLINK_ONLY)
				|| (sdf_filter->direction == TFT_DIRECTION_BIDIRECTIONAL)) {
			/* Downlink Format */
			snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8
					" %"PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
					" 0x%"PRIx8"/0x%"PRIx8"\n",
					local_ip, sdf_filter->local_ip_mask, remote_ip,
					sdf_filter->remote_ip_mask,
					ntohs(sdf_filter->local_port_low),
					ntohs(sdf_filter->local_port_high),
					ntohs(sdf_filter->remote_port_low),
					ntohs(sdf_filter->remote_port_high),
					sdf_filter->proto, sdf_filter->proto_mask);
		}else{
			clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT "SDF flow direction not present for ipv4\n", 
			LOG_VALUE);
			return NULL;
		}

	}else if(sdf_filter->v6){
		if ((sdf_filter->direction == TFT_DIRECTION_DOWNLINK_ONLY)
				|| (sdf_filter->direction == TFT_DIRECTION_UPLINK_ONLY)
				|| (sdf_filter->direction == TFT_DIRECTION_BIDIRECTIONAL)) {
			/* Downlink Format */
			snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8
					" 0x%"PRIx8"/0x%"PRIx8"\n",
					local_ip, sdf_filter->local_ip_mask, remote_ip,
					sdf_filter->remote_ip_mask,
					sdf_filter->proto, sdf_filter->proto_mask);
		}else{
			clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT "SDF flow direction not present for ipv6\n", 
			LOG_VALUE);
			return NULL;
		}
	} else {
		clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT "SDF flow direction not present\n", 
		LOG_VALUE);
		return NULL;
	}
	clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "Installing %s pkt_filter #%"PRIu16" : %s",
	    LOG_VALUE,TFT_direction_str[sdf_filter->direction], index,
		pktf.u.rule_str);

	struct pkt_filter *pktf_t = NULL;
	/* allocate memory for rule entry*/
	pktf_t = rte_zmalloc("SDF_rule_Infos", sizeof(struct pkt_filter), RTE_CACHE_LINE_SIZE);
	if (pktf_t == NULL) {
	    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for rule entry.\n",
				LOG_VALUE);
	    return NULL;
	}
	memcpy(pktf_t, &pktf, sizeof(struct pkt_filter));
	return pktf_t;
}


/* Send the Rules on user-plane */
static int8_t
dump_rule_on_up(node_address_t upf_ip, struct msgbuf *msg_payload)
{
	int ret = 0;
	/* Fill the PFD MGMT Request and send to UP */
	pfcp_pfd_mgmt_req_t *pfd_mgmt_req = NULL;

	/* Initilized the obj with 0*/
	pfd_mgmt_req = malloc(sizeof(pfcp_pfd_mgmt_req_t));
	memset(pfd_mgmt_req, 0, sizeof(pfcp_pfd_mgmt_req_t));

	/* Fill the rule in pfd content custom ie as rule string */
	set_pfd_contents(&pfd_mgmt_req->app_ids_pfds[0].pfd_context[0].pfd_contents[0],
			msg_payload);

	/*Fill/Set the pfd request header */
	fill_pfcp_pfd_mgmt_req(pfd_mgmt_req, 0);

	/* Encode the PFD MGMT Request */
	uint8_t pfd_msg[PFCP_MSG_LEN] = {0};
	uint16_t pfd_msg_len = encode_pfcp_pfd_mgmt_req_t(pfd_mgmt_req, pfd_msg);

	/* Set the destination UPF IP Adress */

	ret = set_dest_address(upf_ip, &upf_pfcp_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	/* Send the PFD MGMT Request to UPF */

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfd_msg, pfd_msg_len,
								upf_pfcp_sockaddr, SENT) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: pfcp_send(): %i\n",
				LOG_VALUE, errno);
		free(pfd_mgmt_req);
		return -1;
	}
	free(pfd_mgmt_req);
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"pfcp_send() sent rule to UP\n",
			LOG_VALUE);

	return 0;
}

/* Send the predefined rules SDF, MTR, ADC, and PCC on UP.*/
int8_t
dump_predefined_rules_on_up(node_address_t upf_ip)
{
	int ret = 0;
	uint32_t mtr_rule_cnt = 0;
	uint32_t mtr_rule_indx[MAX_RULE_CNT] = {0};
	uint32_t adc_rule_cnt = 0;
	uint32_t adc_rule_indx[MAX_RULE_CNT] = {0};
	uint32_t sdf_rule_cnt = 0;
	uint32_t sdf_rule_indx[MAX_RULE_CNT] = {0};

	clLog(clSystemLog, eCLSeverityInfo,
			LOG_FORMAT"Started UP_Addr:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr));

	/* Get PCC rule name entry from centralized location to dump rules on UP*/
	rules_struct *rule = NULL;
	rule = get_map_rule_entry(config.pfcp_ip.s_addr, GET_RULE);
	if (rule != NULL) {
		rules_struct *current = NULL;
		current = rule;

		while (current != NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"PCC Rule retrive from the internal table and map,"
					"Rule_Name: %s, Node_Count:%u\n", LOG_VALUE, current->rule_name.rname,
					current->rule_cnt);

			/* Retrive the PCC rule based on the rule name */
			struct pcc_rules *pcc = NULL;
			pcc = get_predef_pcc_rule_entry(&current->rule_name, GET_RULE);
			if (pcc == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to PCC Rule from the centralized map table"
						" for Rule_Name: %s\n", LOG_VALUE, current->rule_name.rname);
				/* Assign Next node address */
				rule = current->next;
				/* Get the next node */
				current = rule;
				continue;
			}

			/* Parse and dump the PCC rule on UP */
			struct msgbuf msg_payload = {0};
			if (build_rules_up_msg(MSG_PCC_TBL_ADD, (void *)pcc, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to build PCC Rule struct to dump on UP"
						" for Rule_Name: %s\n", LOG_VALUE, pcc->rule_name);
				/* Assign Next node address */
				rule = current->next;
				/* Get the next node */
				current = rule;
				continue;
			}

			/* Dump PCC rule on UPF*/
			if (dump_rule_on_up(upf_ip, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to send PCC rule on UP"
						" for Rule_Name: %s\n", LOG_VALUE, pcc->rule_name);
				/* Assign Next node address */
				rule = current->next;
				/* Get the next node */
				current = rule;
				continue;
			}

			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sent the PCC rule '%s' on the UP:"IPV4_ADDR"\n",
					LOG_VALUE, pcc->rule_name, IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr));

			/* Get Attached SDF Rule Index */
			if (pcc->sdf_idx_cnt) {
				for (uint32_t indx = 0; indx < pcc->sdf_idx_cnt; indx++) {
					if(!check_exsting_indx_val(pcc->sdf_idx[indx], sdf_rule_cnt, sdf_rule_indx)) {
						sdf_rule_indx[sdf_rule_cnt++] = pcc->sdf_idx[indx];
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Get the unique attached SDF Indx: %u from pcc\n",
								LOG_VALUE, pcc->sdf_idx[indx]);
					}
				}
			}

			/* Get Attached ADC Rule Index */
			if (pcc->adc_idx_cnt) {
				for (uint32_t indx = 0; indx < pcc->adc_idx_cnt; indx++) {
					if(!check_exsting_indx_val(pcc->adc_idx[indx], adc_rule_cnt, adc_rule_indx)) {
						adc_rule_indx[adc_rule_cnt++] = pcc->adc_idx[indx];
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Get the unique attached ADC Indx: %u from pcc\n",
								LOG_VALUE, pcc->adc_idx[indx]);
					}
				}
			}

			/* Get Attached MTR Rule Index */
			if (pcc->qos.mtr_profile_index) {
				if(!check_exsting_indx_val(pcc->qos.mtr_profile_index,
							mtr_rule_cnt, mtr_rule_indx)) {
					mtr_rule_indx[mtr_rule_cnt++] = pcc->qos.mtr_profile_index;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Get the unique attached UL MTR Profile Indx: %u from pcc\n",
							LOG_VALUE, pcc->qos.mtr_profile_index);
				}
			}

			/* Assign Next node address */
			rule = current->next;

			/* Get the next node */
			current = rule;
		}

		/* Retrive the MTR rule based on the Meter Index */
		for (uint32_t idx = 0; idx < mtr_rule_cnt; idx++) {
			void *mtr_rule = NULL;
			ret = get_predef_rule_entry(mtr_rule_indx[idx], MTR_HASH, GET_RULE, &mtr_rule);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to Get MTR Rule from the internal table"
						"for Mtr_Indx: %u\n", LOG_VALUE, mtr_rule_indx[idx]);
				continue;
			}

			/* Parse and dump the MTR rule on UP */
			struct msgbuf msg_payload = {0};
			if (build_rules_up_msg(MSG_MTR_ADD, mtr_rule, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to build MTR Rule struct to dump on UP"
						" for MTR_Index: %u\n", LOG_VALUE, mtr_rule_indx[idx]);
				continue;
			}

			/* Dump MTR rule on UPF*/
			if (dump_rule_on_up(upf_ip, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to send MTR rule on UP"
						" for MTR_Indx: %u\n", LOG_VALUE, mtr_rule_indx[idx]);
				continue;
			}
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sent the MTR rule Index '%u' on the UP:"IPV4_ADDR"\n",
					LOG_VALUE, mtr_rule_indx[idx], IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr));
		}

		/* Retrive the ADC rule based on the ADC Index */
		for (uint32_t idx1 = 0; idx1 < adc_rule_cnt; idx1++) {
			void *adc_rule = NULL;
			ret = get_predef_rule_entry(adc_rule_indx[idx1], ADC_HASH, GET_RULE, &adc_rule);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to Get ADC Rule from the internal table"
						"for ADC_Indx: %u\n", LOG_VALUE, adc_rule_indx[idx1]);
				continue;
			}

			/* Parse and dump the ADC rule on UP */
			struct msgbuf msg_payload = {0};
			if (build_rules_up_msg(MSG_ADC_TBL_ADD, adc_rule, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to build ADC Rule struct to dump on UP"
						" for ADC_Indx: %u\n", LOG_VALUE, adc_rule_indx[idx1]);
				continue;
			}

			/* Dump ADC rule on UPF*/
			if (dump_rule_on_up(upf_ip, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to send ADC rule on UP"
						" for ADC_Indx: %u\n", LOG_VALUE, adc_rule_indx[idx1]);
				continue;
			}
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sent the ADC rule Index '%u' on the UP:"IPV4_ADDR"\n",
					LOG_VALUE, adc_rule_indx[idx1], IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr));
		}

		/* Retrive the SDF rule based on the SDF Index */
		for (uint32_t idx2 = 0; idx2 < sdf_rule_cnt; idx2++) {
			void *sdf_rule_t = NULL;
			pkt_fltr *tmp_sdf = NULL;
			ret = get_predef_rule_entry(sdf_rule_indx[idx2], SDF_HASH, GET_RULE, &sdf_rule_t);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to Get SDF Rule from the internal table"
						"for SDF_Indx: %u\n", LOG_VALUE, sdf_rule_indx[idx2]);
				continue;
			}
			/* Typecast sdf rule */
			tmp_sdf = (pkt_fltr *)sdf_rule_t;
			if (tmp_sdf == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed not found the sdf rule"
						"for SDF_Indx: %u\n", LOG_VALUE, sdf_rule_indx[idx2]);
				continue;
			}

			struct pkt_filter *sdf_rule = NULL;
			sdf_rule = build_sdf_rules(sdf_rule_indx[idx2], tmp_sdf);
			if (sdf_rule == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to create the sdf rule"
						"for SDF_Indx: %u\n", LOG_VALUE, sdf_rule_indx[idx2]);
				continue;
			}

			/* Parse and dump the SDF rule on UP */
			struct msgbuf msg_payload = {0};
			if (build_rules_up_msg(MSG_SDF_ADD, (void *)sdf_rule, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to build SDF Rule struct to dump on UP"
						" for SDF_Indx: %u\n", LOG_VALUE, sdf_rule_indx[idx2]);
				continue;
			}

			/* Dump SDF rule on UPF*/
			if (dump_rule_on_up(upf_ip, &msg_payload) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to send SDF rule on UP"
						" for SDF_Indx: %u\n", LOG_VALUE, sdf_rule_indx[idx2]);
				continue;
			}
			rte_free(sdf_rule);
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sent the SDF rule Index '%u' on the UP:"IPV4_ADDR"\n",
					LOG_VALUE, sdf_rule_indx[idx2], IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr));
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to Get PCC Rule from centralized map table\n",
				LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityInfo,
			LOG_FORMAT"END UP_Addr:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr));

	return 0;
}
