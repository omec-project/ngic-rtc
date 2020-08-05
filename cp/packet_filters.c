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

#include <rte_acl.h>
#include <rte_cfgfile.h>

#include "ue.h"
#include "cp.h"
#include "util.h"
#include "clogger.h"
#include "packet_filters.h"
#include "vepc_cp_dp_api.h"
#include "predef_rule_init.h"

extern pfcp_config_t pfcp_config;

const char *direction_str[] = {
		[TFT_DIRECTION_DOWNLINK_ONLY] = "DOWNLINK_ONLY ",
		[TFT_DIRECTION_UPLINK_ONLY] = "UPLINK_ONLY   ",
		[TFT_DIRECTION_BIDIRECTIONAL] = "BIDIRECTIONAL " };

const pkt_fltr catch_all = {
		.direction = TFT_DIRECTION_BIDIRECTIONAL,
		.remote_ip_addr.s_addr = 0,
		.remote_ip_mask = 0,
		.remote_port_low = 0,
		.remote_port_high = UINT16_MAX,
		.proto = 0,
		.proto_mask = 0,
		.local_ip_addr.s_addr = 0,
		.local_ip_mask = 0,
		.local_port_low = 0,
		.local_port_high = UINT16_MAX, };

struct mtr_entry *mtr_profiles[METER_PROFILE_SDF_TABLE_SIZE] = {
		[0] = NULL, /* index = 0 is invalid */
};

struct pcc_rules *pcc_filters[PCC_TABLE_SIZE] = {
		[0] = NULL, /* index = 0 is invalid */
};

pkt_fltr *sdf_filters[SDF_FILTER_TABLE_SIZE] = {
		[0] = NULL, /* index = 0 is invalid */
};
packet_filter *packet_filters[SDF_FILTER_TABLE_SIZE] = {
		[0] = NULL, /* index = 0 is invalid */
};

uint16_t num_mtr_profiles;
uint16_t num_packet_filters = FIRST_FILTER_ID;
uint16_t num_sdf_filters = FIRST_FILTER_ID;
uint16_t num_pcc_filter = FIRST_FILTER_ID;
uint32_t num_adc_rules;
uint32_t adc_rule_id[MAX_ADC_RULES];
uint64_t cbs;
uint64_t ebs;
uint16_t ulambr_idx;
uint16_t dlambr_idx;

/**
 * @brief  : Converts char string to number
 * @param  : name , char string to be converted
 * @return : Returns converted number
 */
static uint32_t name_to_num(const char *name)
{
	/*TODO : change strlen with strnlen with proper size (n)*/
	uint32_t num = 0;
	int i;

	for (i = strlen(name) - 1; i >= 0; i--)
		num = (num << 4) | (name[i] - 'a');
	return num;
}

int
get_packet_filter_id(const pkt_fltr *pf)
{
	uint16_t index;
	for (index = FIRST_FILTER_ID; index < num_packet_filters; ++index) {
		if (!memcmp(pf, &packet_filters[index]->pkt_fltr,
				sizeof(pkt_fltr)))
			return index;
	}
	return -ENOENT;
}

uint8_t
get_packet_filter_direction(uint16_t index)
{
	return packet_filters[index]->pkt_fltr.direction;
}

packet_filter *
get_packet_filter(uint16_t index)
{
	if (unlikely(index >= num_packet_filters))
		return NULL;
	return packet_filters[index];
}

void
reset_packet_filter(pkt_fltr *pf)
{
	memcpy(pf, &catch_all, sizeof(pkt_fltr));
}

int meter_profile_index_get(uint64_t cir)
{
	int index;
	uint64_t CIR = cir >> 3; /* Convert bit rate into bytes */

	for (index = 0; index < num_mtr_profiles; index++) {
		if (mtr_profiles[index]->mtr_param.cir == CIR)
			return mtr_profiles[index]->mtr_profile_index;
	}

	return 0;
}

void
push_sdf_rules(uint16_t index)
{
	struct dp_id dp_id = { .id = DPN_ID };

	char local_ip[INET_ADDRSTRLEN];
	char remote_ip[INET_ADDRSTRLEN];

	snprintf(local_ip, sizeof(local_ip), "%s",
	    inet_ntoa(sdf_filters[index]->local_ip_addr));
	snprintf(remote_ip, sizeof(remote_ip), "%s",
	    inet_ntoa(sdf_filters[index]->remote_ip_addr));

	struct pkt_filter pktf = {
			.rule_id = index
	};

	if (sdf_filters[index]->direction & TFT_DIRECTION_DOWNLINK_ONLY) {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8
			" %"PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
			" 0x%"PRIx8"/0x%"PRIx8"\n",
			remote_ip, sdf_filters[index]->remote_ip_mask, local_ip,
			sdf_filters[index]->local_ip_mask,
			ntohs(sdf_filters[index]->remote_port_low),
			ntohs(sdf_filters[index]->remote_port_high),
			ntohs(sdf_filters[index]->local_port_low),
			ntohs(sdf_filters[index]->local_port_high),
			sdf_filters[index]->proto, sdf_filters[index]->proto_mask);
		if (sdf_filters[index]->direction ==
				TFT_DIRECTION_BIDIRECTIONAL)
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Ignoring uplink portion of packet "
					"filter for now\n", LOG_VALUE);
	} else if (sdf_filters[index]->direction & TFT_DIRECTION_UPLINK_ONLY) {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
			PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
			PRIx8"/0x%"PRIx8"\n",
			local_ip, sdf_filters[index]->local_ip_mask, remote_ip,
			sdf_filters[index]->remote_ip_mask,
			ntohs(sdf_filters[index]->local_port_low),
			ntohs(sdf_filters[index]->local_port_high),
			ntohs(sdf_filters[index]->remote_port_low),
			ntohs(sdf_filters[index]->remote_port_high),
			sdf_filters[index]->proto, sdf_filters[index]->proto_mask);
	}

	clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Installing %s pkt_filter #%"PRIu16" : %s", LOG_VALUE,
	    direction_str[sdf_filters[index]->direction], index,
		pktf.u.rule_str);

	if (sdf_filter_entry_add(dp_id, pktf) < 0)
		rte_exit(EXIT_FAILURE,"SDF filter entry add fail !!!");
}

/**
 * @brief  : Initialize meter profiles
 * @param  : No param
 * @return : Returns nothing
 */
static void
init_mtr_profile(void)
{
	unsigned no_of_idx = 0;
	unsigned i = 0;
	struct rte_cfgfile *file =
			rte_cfgfile_load(METER_PROFILE_FILE, 0);
	const char *entry;
//	struct dp_id dp_id = { .id = DPN_ID };

	if (file == NULL)
		rte_panic("Cannot load configuration file %s\n",
				METER_PROFILE_FILE);

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "NUM_OF_IDX");
	if (!entry)
		rte_panic("Invalid metering index\n");
	no_of_idx = atoi(entry);

	for (i = 1; i <= no_of_idx; ++i) {
		char sectionname[64];
		struct mtr_entry mtr_entry = {0};

		snprintf(sectionname, sizeof(sectionname),
				"ENTRY_%u", i);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"CIR");
		if (!entry)
			rte_panic("Invalid CIR configuration\n");
		mtr_entry.mtr_param.cir = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"CBS");
		if (!entry)
			rte_panic("Invalid CBS configuration\n");
		mtr_entry.mtr_param.cbs = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"EBS");
		if (!entry)
			rte_panic("Invalid EBS configuration\n");
		mtr_entry.mtr_param.ebs = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"UL_MBR");
		if (!entry)
			rte_panic("Invalid UL_MBR configuration\n");
		mtr_entry.ul_mbr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"DL_MBR");
		if (!entry)
			rte_panic("Invalid DL_MBR configuration\n");
		mtr_entry.dl_mbr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"UL_GBR");
		if (entry)
			mtr_entry.ul_gbr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"DL_GBR");
		if (entry)
			mtr_entry.dl_gbr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"UL_AMBR");
		if (entry)
			mtr_entry.ul_ambr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"DL_AMBR");
		if (entry)
			mtr_entry.dl_ambr = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"MTR_PROFILE_IDX");
		if (!entry)
			rte_panic("Invalid MTR_PROFILE_IDX configuration\n");
		mtr_entry.mtr_profile_index = atoi(entry);
		int ret = 0;
		ret = get_predef_rule_entry(mtr_entry.mtr_profile_index,
				MTR_HASH, ADD_RULE, (void **)&mtr_entry);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
			       LOG_FORMAT"Error: Failed to add Meter Rule in the internal table, MTR_Indx:%u\n",
			       LOG_VALUE, mtr_entry.mtr_profile_index);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"MTR Rule Added in the internal table,"
					"Rule_Index:%u\n", LOG_VALUE, mtr_entry.mtr_profile_index);
		}
	}

	if (file != NULL) {
		rte_cfgfile_close(file);
		file = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"%s file operation is successfully performed\n",
				LOG_VALUE, METER_PROFILE_FILE);
	}
}

/**
 * @brief  : Initialize sdf rules
 * @param  : No param
 * @return : Returns nothing
 */
static void
init_sdf_rules(void)
{
	unsigned num_sdf_rules = 0;
	unsigned i = 0;
	const char *entry = NULL;
	struct rte_cfgfile *file = rte_cfgfile_load(SDF_RULE_FILE, 0);

	if (NULL == file)
		rte_panic("Cannot load configuration file %s\n",
				SDF_RULE_FILE);

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "NUM_SDF_FILTERS");

	if (!entry)
		rte_panic("Invalid sdf configuration file format\n");

	num_sdf_rules = atoi(entry);

	for (i = 1; i <= num_sdf_rules; ++i) {
		char sectionname[64] = {0};
		int ret = 0;
		struct in_addr tmp_addr;
		pkt_fltr pf;

		reset_packet_filter(&pf);
		snprintf(sectionname, sizeof(sectionname),
				"SDF_FILTER_%u", i);

		entry = rte_cfgfile_get_entry(file, sectionname, "DIRECTION");
		if (entry) {
			if (strcmp(entry, "bidirectional") == 0){
				pf.direction = TFT_DIRECTION_BIDIRECTIONAL;
			}
			else if (strcmp(entry, "uplink_only") == 0)
				pf.direction = TFT_DIRECTION_UPLINK_ONLY;
			else if (strcmp(entry, "downlink_only") == 0)
				pf.direction = TFT_DIRECTION_DOWNLINK_ONLY;
			else
				rte_panic("Invalid SDF direction. Supported : uplink_only,"
						"downlink_only\n");
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "IPV4_REMOTE");
		if (entry) {
			if (inet_aton(entry, &pf.remote_ip_addr) == 0)
				rte_panic("Invalid address %s in section %s "
						"sdf config file %s\n",
						entry, sectionname, SDF_RULE_FILE);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"IPV4_REMOTE_MASK");
		if (entry) {
			ret = inet_aton(entry, &tmp_addr);
			if (ret == 0
			    || __builtin_clzl(~tmp_addr.s_addr)
				+ __builtin_ctzl(tmp_addr.s_addr) != 32){

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid address %s in section %s "
						"sdf config file %s. Setting to default 32.\n", LOG_VALUE,
						entry, sectionname, SDF_RULE_FILE);
				 pf.remote_ip_mask = 32;
			} else
				pf.remote_ip_mask =
						__builtin_popcountl(tmp_addr.s_addr);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"REMOTE_LOW_LIMIT_PORT");
		if (entry)
			pf.remote_port_low = htons((uint16_t) atoi(entry));

		entry = rte_cfgfile_get_entry(file, sectionname,
				"REMOTE_HIGH_LIMIT_PORT");
		if (entry)
			pf.remote_port_high = htons((uint16_t) atoi(entry));

		entry = rte_cfgfile_get_entry(file, sectionname, "PROTOCOL");
		if (entry) {
			pf.proto = atoi(entry);
			pf.proto_mask = UINT8_MAX;
		} else {
			/* Validate Protocol is set or not */
			rte_panic("ERROR: PROTOCOL type field is not configured in SDF Rule,"
					" Check the configured rules in sdf_rules.cfg file..!!\n\n");
		}


		entry = rte_cfgfile_get_entry(file, sectionname, "IPV4_LOCAL");
		if (entry) {
			if (inet_aton(entry, &pf.local_ip_addr) == 0)
				rte_panic("Invalid address %s in section %s "
						"sdf config file %s\n",
						entry, sectionname, SDF_RULE_FILE);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"IPV4_LOCAL_MASK");
		if (entry) {
			ret = inet_aton(entry, &tmp_addr);
			if (ret == 0
			    || __builtin_clzl(~tmp_addr.s_addr)
			    + __builtin_ctzl(tmp_addr.s_addr) != 32){

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid address %s in section %s "
						"sdf config file %s. Setting to default 32.\n", LOG_VALUE,
						entry, sectionname, SDF_RULE_FILE);
				pf.remote_ip_mask = 32;
			} else
				pf.local_ip_mask = __builtin_popcountl(tmp_addr.s_addr);
		}

		entry = rte_cfgfile_get_entry(file, sectionname,
				"LOCAL_LOW_LIMIT_PORT");
		if (entry)
			pf.local_port_low = htons((uint16_t) atoi(entry));


		entry = rte_cfgfile_get_entry(file, sectionname,
				"LOCAL_HIGH_LIMIT_PORT");
		if (entry)
			pf.local_port_high = htons((uint16_t) atoi(entry));

		/* Sotred the SDF rules in centralized location by sdf_index */
		ret = get_predef_rule_entry(i, SDF_HASH, ADD_RULE, (void **)&pf);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: Failed to add SDF Rule in the internal table\n",
					LOG_VALUE);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"SDF Rule Added in the internal table,"
					"Rule_Index: %u\n", LOG_VALUE, i);
		}

	}

	if (file != NULL) {
		rte_cfgfile_close(file);
		file = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"%s file operation is successfully performed\n",
			LOG_VALUE, SDF_RULE_FILE);
	}

}

/**
 * @brief  : Initialize pcc rules
 * @param  : No param
 * @return : Returns nothing
 */
static void
init_pcc_rules(void)
{
	unsigned num_pcc_rules = 0;
	unsigned i = 0;
	const char *entry = NULL;
	struct rte_cfgfile *file = rte_cfgfile_load(PCC_RULE_FILE, 0);

	if (NULL == file)
		rte_panic("Cannot load configuration file %s\n",
				PCC_RULE_FILE);

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "NUM_PCC_FILTERS");

	if (!entry)
		rte_panic("Invalid pcc configuration file format\n");

	num_pcc_rules = atoi(entry);

	for (i = 1; i <= num_pcc_rules; ++i) {
		char sectionname[64] = {0};
		struct pcc_rules tmp_pcc = {0};
		pcc_rule_name key = {0};
		memset(key.rname, '\0', sizeof(key.rname));

		snprintf(sectionname, sizeof(sectionname),
				"PCC_FILTER_%u", i);

		entry = rte_cfgfile_get_entry(file, sectionname, "RULE_NAME");
		if (entry) {
			strncpy(tmp_pcc.rule_name, entry, sizeof(tmp_pcc.rule_name));
			strncpy(key.rname, entry, sizeof(key.rname));
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "RATING_GROUP");
		if (!entry)
			rte_panic(
			    "Invalid pcc configuration file format - "
			    "each filter must contain RATING_GROUP entry\n");
		tmp_pcc.rating_group = atoi(entry);
		if(0 == tmp_pcc.rating_group) {
			tmp_pcc.rating_group = name_to_num(entry);
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "SERVICE_ID");
		if (entry) {
			tmp_pcc.service_id = atoi(entry);
			if(0 == tmp_pcc.service_id)
				tmp_pcc.service_id = name_to_num(entry);
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "RULE_STATUS");
		if (entry)
			tmp_pcc.rule_status = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "UL_GATE_STATUS");
		if (entry)
			tmp_pcc.ul_gate_status = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "DL_GATE_STATUS");
		if (entry)
			tmp_pcc.dl_gate_status = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "SESSION_CONT");
		if (entry)
			tmp_pcc.session_cont = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "REPORT_LEVEL");
		if (entry)
			tmp_pcc.report_level = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "CHARGING_MODE");
		if (entry)
			tmp_pcc.charging_mode = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "METERING_METHOD");
		if (entry)
			tmp_pcc.metering_method = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "MUTE_NOTIFY");
		if (entry)
			tmp_pcc.mute_notify = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "MONITORING_KEY");
		if (entry)
			tmp_pcc.monitoring_key = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "SPONSOR_ID");
		if (entry)
			strncpy(tmp_pcc.sponsor_id, entry, sizeof(tmp_pcc.sponsor_id));

		entry = rte_cfgfile_get_entry(file, sectionname, "REDIRECT_INFO");
		if (entry)
			tmp_pcc.redirect_info.info = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "PRECEDENCE");
		if (entry)
			tmp_pcc.precedence = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "DROP_PKT_COUNT");
		if (entry)
			tmp_pcc.drop_pkt_count = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "ONLINE");
		if (entry)
			tmp_pcc.online = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "OFFLINE");
		if (entry)
			tmp_pcc.offline = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "FLOW_STATUS");
		if (entry)
			tmp_pcc.flow_status = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "QoS_CLASS_IDENTIFIER");
		if (entry)
			tmp_pcc.qos.qci = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "PRIORITY_LEVEL");
		if (entry)
			tmp_pcc.qos.arp.priority_level = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "PRE_EMPTION_CAPABILITY");
		if (entry)
			tmp_pcc.qos.arp.pre_emption_capability = atoi(entry);

		entry = rte_cfgfile_get_entry(file, sectionname, "PRE_EMPTION_VULNERABILITY");
		if (entry)
			tmp_pcc.qos.arp.pre_emption_vulnerability = atoi(entry);

		entry = rte_cfgfile_get_entry(file,
					sectionname, "MTR_PROFILE_IDX");
		if (!entry)
			rte_panic("Invalid MTR_PROFILE_IDX configuration\n");

		tmp_pcc.qos.mtr_profile_index = atoi(entry);

		/** Read mapped ADC or SDF rules. Either ADC or SDF rules will be
		 * present, not both. SDF count will be 0 if ADC rules are present.*/
		tmp_pcc.sdf_idx_cnt = 0;
		entry = rte_cfgfile_get_entry(file,
					sectionname, "ADC_FILTER_IDX");
		if (!entry) {
			/*No ADC entry, so check for SDF entry*/
			entry = rte_cfgfile_get_entry(file,
					sectionname, "SDF_FILTER_IDX");
			if (!entry)
				rte_panic("Missing SDF or ADC rule for PCC rule %d\n",i);

			char *next = NULL;
			uint16_t sdf_cnt = 0;
			/*SDF entries format : "1, 2: 10, 30"*/
			for(int x=0; x < MAX_SDF_IDX_COUNT; ++x) {
				errno = 0;
				int sdf_idx = strtol(entry, &next, 10);
				if (errno != 0) {
					perror("strtol");
					rte_panic("Invalid SDF index value\n");
				}
				if('\0' == *entry) break;
				/*If non number e.g.',', then ignore and continue*/
				if(entry == next && (0 == sdf_idx)){
					entry = ++next;
					continue;
				}
				entry = next;
				tmp_pcc.sdf_idx[sdf_cnt++] = sdf_idx;
			}
			tmp_pcc.sdf_idx_cnt = sdf_cnt;
		} else {
			char *next = NULL;
			uint16_t adc_cnt = 0;
			/* ADC entries format : "1, 2: 10, 30"*/
			for(int x=0; x < MAX_ADC_IDX_COUNT; ++x) {
				errno = 0;
				int adc_idx = strtol(entry, &next, 10);
				if (errno != 0) {
					perror("strtol");
					rte_panic("Invalid ADC index value\n");
				}
				if('\0' == *entry) break;
				/*If non number e.g.',', then ignore and continue*/
				if(entry == next && (0 == adc_idx)){
					entry = ++next;
					continue;
				}
				entry = next;
				tmp_pcc.adc_idx[adc_cnt++] = adc_idx;
			}
			tmp_pcc.adc_idx_cnt = adc_cnt;
		}

		/* Stored the PCC rule in centralized location by using Rule Name*/
		struct pcc_rules *pcc = NULL;
		pcc = get_predef_pcc_rule_entry(&key, ADD_RULE);
		if (pcc != NULL) {
			memcpy(pcc, &tmp_pcc, sizeof(struct pcc_rules));

			/* Add PCC rule name in centralized location to dump rules on UP*/
			rules_struct *rule = NULL;
			rule = get_map_rule_entry(ntohl(pfcp_config.pfcp_ip.s_addr), ADD_RULE);
			if (rule != NULL) {
				if (rule->rule_cnt != 0) {
					rules_struct *new_node = NULL;
					/* Calculate the memory size to allocate */
					uint16_t size = sizeof(rules_struct);

					/* allocate memory for rule entry*/
					new_node = rte_zmalloc("Rules_Infos", size, RTE_CACHE_LINE_SIZE);
					if (new_node == NULL) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to allocate memory for rule entry.\n",
								LOG_VALUE);
						return;
					}

					/* Set/Stored the rule name in the centralized location */
					memcpy(new_node->rule_name.rname, key.rname, sizeof(key.rname));

					/* Insert the node into the LL */
					if (insert_rule_name_node(rule, new_node) < 0) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add node entry in LL\n",
								LOG_VALUE);
						return;
					}
				}else {
					/* Set/Stored the rule name in the centralized location */
					memcpy(rule->rule_name.rname, key.rname, sizeof(key.rname));
					rule->rule_cnt++;
				}
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"PCC Rule add/inserted in the internal table and map,"
						"Rule_Name: %s, Node_Count:%u\n", LOG_VALUE, key.rname, rule->rule_cnt);
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to add PCC Rule in the centralized map table\n",
						LOG_VALUE);
			}
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: Failed to add PCC Rule in the internal table\n",
					LOG_VALUE);
		}

	}
	if (file != NULL) {
		rte_cfgfile_close(file);
		file = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"%s file operation is successfully performed\n",
			LOG_VALUE, PCC_RULE_FILE);
	}
	num_pcc_filter = FIRST_FILTER_ID; /*Reset num_pcc_filter*/
}

void
init_packet_filters(void)
{
	/* init pcc rule tables on dp*/
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined PCC rules\n", LOG_VALUE);
	init_pcc_rules();
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined pcc rules completed\n", LOG_VALUE);

	/* init dpn meter profile table before configuring pcc/adc rules*/
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined meter rules\n", LOG_VALUE);
	init_mtr_profile();
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined meter rules completed\n", LOG_VALUE);

	/* init dpn sdf rules table configuring on dp*/
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined sdf rules\n", LOG_VALUE);
	init_sdf_rules();
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined sdf rules completed\n", LOG_VALUE);
}

/**
 * @brief  : Prints adc rule info
 * @param  : adc_rule, rule info to be printed
 * @return : Returns nothing
 */
static void print_adc_rule(struct adc_rules adc_rule)
{
	clLog(clSystemLog, eCLSeverityDebug,"%-8u ", adc_rule.rule_id);
	switch (adc_rule.sel_type) {
	case DOMAIN_IP_ADDR:
		clLog(clSystemLog, eCLSeverityDebug,"%-10s " IPV4_ADDR, "IP",
			IPV4_ADDR_HOST_FORMAT(adc_rule.u.domain_ip.u.ipv4_addr));
		break;
	case DOMAIN_IP_ADDR_PREFIX:
		clLog(clSystemLog, eCLSeverityDebug,"%-10s " IPV4_ADDR"/%d ", "IP_PREFIX",
			IPV4_ADDR_HOST_FORMAT(adc_rule.u.domain_prefix.ip_addr.u.ipv4_addr),
			adc_rule.u.domain_prefix.prefix);
		break;
	case DOMAIN_NAME:
		clLog(clSystemLog, eCLSeverityDebug,"%-10s %-35s ", "DOMAIN",
			 adc_rule.u.domain_name);
		break;
	default:
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"ERROR IN ADC RULE", LOG_VALUE);
	}
}

void
parse_adc_rules(void)
{
	unsigned num_adc_rules = 0;
	unsigned i = 0;
	uint32_t rule_id = 1;
	const char *entry = NULL;
	//struct dp_id dp_id = { .id = DPN_ID };
	struct rte_cfgfile *file = rte_cfgfile_load(ADC_RULE_FILE, 0);

	if (file == NULL)
		rte_panic("Cannot load configuration file %s\n",
				ADC_RULE_FILE);

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "NUM_ADC_RULES");

	if (!entry)
		rte_panic("Invalid adc configuration file format\n");

	num_adc_rules = atoi(entry);

	for (i = 1; i <= num_adc_rules; ++i) {
		char sectionname[64] = {0};
		struct adc_rules tmp_adc = { 0 };
		struct in_addr addr;

		snprintf(sectionname, sizeof(sectionname),
				"ADC_RULE_%u", i);

		entry = rte_cfgfile_get_entry(file, sectionname,
				"ADC_TYPE");

		if (!entry)
			rte_panic("Invalid ADC TYPE configuration file format\n");

		tmp_adc.sel_type = atoi(entry);

		switch (tmp_adc.sel_type) {
			case DOMAIN_NAME:
				entry = rte_cfgfile_get_entry(file, sectionname,
						"DOMAIN");
				if(entry)
					strncpy(tmp_adc.u.domain_name, entry,
							sizeof(tmp_adc.u.domain_name));
				break;

			case DOMAIN_IP_ADDR:
				entry = rte_cfgfile_get_entry(file, sectionname,
						"IP");

				if (entry) {
					inet_aton(entry, &addr);
					tmp_adc.u.domain_ip.u.ipv4_addr = ntohl(addr.s_addr);
					tmp_adc.u.domain_ip.iptype = IPTYPE_IPV4;
				}
				break;

			case DOMAIN_IP_ADDR_PREFIX:
				entry = rte_cfgfile_get_entry(file, sectionname,
						"IP");

				if (entry) {
					inet_aton(entry, &addr);
					tmp_adc.u.domain_ip.u.ipv4_addr = ntohl(addr.s_addr);
					tmp_adc.u.domain_ip.iptype = IPTYPE_IPV4;
				}

				entry = rte_cfgfile_get_entry(file, sectionname,
						"PREFIX");

				if (entry)
					tmp_adc.u.domain_prefix.prefix = atoi(entry);

				break;

			default:
				rte_exit(EXIT_FAILURE, "Unexpected ADC TYPE : %d\n",
						tmp_adc.sel_type);
		}


		/* Add Default rule */
		adc_rule_id[rule_id - 1] = rule_id;
		tmp_adc.rule_id = rule_id++;
		int ret = 0;
		ret = get_predef_rule_entry(tmp_adc.rule_id, ADC_HASH, ADD_RULE, (void **)&tmp_adc);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: Failed to add ADC Rule in the internal table\n",
					LOG_VALUE);
		} else {
			print_adc_rule(tmp_adc);
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ADC Rule Added in the internal table, ADC_Indx:%u\n",
					LOG_VALUE, tmp_adc.rule_id);
		}
		//if (adc_entry_add(dp_id, tmp_adc) < 0)
		//	rte_exit(EXIT_FAILURE, "ADC entry add fail !!!");
		//print_adc_rule(tmp_adc);
	}
	if (file != NULL) {
		rte_cfgfile_close(file);
		file = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"%s file operation is successfully performed\n",
			LOG_VALUE, ADC_RULE_FILE);
	}
	num_adc_rules = rule_id - 1;


}

